//! Generic bin-packing functionality

use sbtc::idpack::BitmapSegmenter;
use sbtc::idpack::Segmenter as _;

use crate::GOSSIPSUB_MAX_TRANSMIT_SIZE;
use crate::MAX_MEMPOOL_PACKAGE_SIZE;
use crate::MAX_MEMPOOL_PACKAGE_TX_COUNT;

use super::utxo::MAX_BASE_TX_VSIZE;
use super::utxo::OP_RETURN_AVAILABLE_SIZE;

/// Protobuf overhead per `TxRequestIds` element in the
/// `BitcoinPreSignRequest.request_package` field. Here bag refers to a
/// TxRequestIds.
///
/// Each `TxRequestIds` embedded in the `request_package` field incurs a
/// 1-byte field tag and a length varint. The varint size depends on the
/// encoded size of the inner `TxRequestIds` message:
///
/// - a 1-byte varint when encoding less than 128 bytes
/// - a 2-byte varint when encoding between 128 and 16383 bytes
/// - a 3-byte varint when encoding between 16384 and 2097152 bytes
///
/// A single `TxRequestIds` can exceed 16383 bytes because withdrawals are
/// mainly limited by the withdrawal ID OP_RETURN limit, which can hold 600
/// consecutive IDs. At 93 bytes each, we can have a ~55000 byte
/// `TxRequestIds`. So we use the worst case of 3-byte varint plus a 1-byte
/// field tag.
const BAG_OVERHEAD: usize = 4;

/// The protobuf overhead in bytes of wrapping a `BitcoinPreSignRequest`
/// inside a `Signed<SignerMessage>` in libp2p gossipsub.
///
/// Note that the gossipsub `max_transmit_size` check applies to the
/// encoded `Signed<SignerMessage>` bytes during publishing, and the full
/// wire frame on receive [1].
///
/// This overhead accounts for:
/// 1. The `fee_rate` and `last_fees` fields of the `BitcoinPreSignRequest`
///    message.
/// 2. The protobuf fields added by the `Signed<SignerMessage>` wrappers,
///    which includes the ECDSA signature, signer public key, and bitcoin
///    chain tip block hash.
/// 3. The protobuf fields added by libp2p-gossipsub. Each published
///    message is wrapped in a Message protobuf. The `Message` proto adds
///    five fields around our payload [2]:
///
///    ```proto
///    message Message {
///        optional bytes from = 1;
///        optional bytes data = 2;
///        optional bytes seqno = 3;
///        required string topic = 4;
///        optional bytes signature = 5;
///        optional bytes key = 6;
///    }
///    ```
///
///    These fields are populated in `build_raw_message` [3] in libp2p and
///    have the following max sizes:
///    1. 75 bytes. The `from` field is a peer ID, which is a
///       Multihash<64>. It needs 73 bytes in Rust and maxes out at 75
///       bytes serialized.
///    2. The `data` field contains our serialized `Signed<SignerMessage>`
///       message.
///    3. 8 bytes. The `seqno` field is a u64 number.
///    4. 11 bytes. The `topic` field is our topic string, and we use
///       "sbtc-signer" as the topic.
///    5. 73 bytes. The `signature` field is the secp256k1 signature over
///       the message, DER encoded.
///    6. 33 bytes. The `key` field is the secp256k1 compressed public key
///       of the signer.
///
/// [1]: <https://github.com/libp2p/rust-libp2p/blob/84153a559bdbcb92a48413dd2a31035800cb882d/misc/quick-protobuf-codec/src/lib.rs#L74-L89>
/// [2]: <https://github.com/libp2p/rust-libp2p/blob/84153a559bdbcb92a48413dd2a31035800cb882d/protocols/gossipsub/src/generated/rpc.proto#L16-L23>
/// [3]: <https://github.com/libp2p/rust-libp2p/blob/84153a559bdbcb92a48413dd2a31035800cb882d/protocols/gossipsub/src/behaviour.rs#L2810-L2821>
///
/// Note that this overhead varies slightly with the inner payload size
/// because protobuf length varints grow with the encoded length. A
/// Signed<SignerMessage> with an empty `BitcoinPreSignRequest` measures
/// 162 bytes of overhead; and measures 168 bytes of overhead with a
/// near-maximum-size `BitcoinPreSignRequest`. And as we can see from
/// above, the libp2p gossipsub code adds around 200 bytes of overhead.
const SIGNED_MESSAGE_OVERHEAD: usize = 1024;

/// Maximum serialized size of a `BitcoinPreSignRequest` message, not
/// accounting for the `fee_rate` and `last_fees` fields.
///
/// The gossipsub [`GOSSIPSUB_MAX_TRANSMIT_SIZE`] limits the total encoded
/// `Signed<SignerMessage>` size. After subtracting the
/// [`SIGNED_MESSAGE_OVERHEAD`] for the `Signed` and `SignerMessage`
/// protobuf wrapper, this is the remaining budget for the
/// `BitcoinPreSignRequest` payload.
pub const MAX_PRESIGN_REQUEST_SIZE: usize = GOSSIPSUB_MAX_TRANSMIT_SIZE - SIGNED_MESSAGE_OVERHEAD;

/// The maximum vsize of all items in a package.
///
/// A bitcoin transaction package is a group of one or more transactions
/// where:
/// 1. Each transaction is unconfirmed, and
/// 2. Each transaction has at least one input that is an outpoint from
///    another transaction in the group or each transaction has an output
///    that another transaction in the group spends or the group consists
///    of one transaction.
///
/// This constant is derived from bitcoin core, and has the property that
/// if the packager ensure that the total vsize of the items in the package
/// are under this limit, then the transaction package will be under the
/// bitcoin vsize limit.
const PACKAGE_MAX_VSIZE: u64 =
    ((MAX_MEMPOOL_PACKAGE_SIZE - MAX_MEMPOOL_PACKAGE_TX_COUNT * MAX_BASE_TX_VSIZE) / 5000) * 5000;

/// Package a list of items into optimal bags according to specified
/// constraints.
///
/// This function implements a variant of the Best-Fit-Decreasing bin packing
/// algorithm. Items are sorted by "weight" (votes against) in decreasing order
/// before being placed into optimal bags.
///
/// ## Constraints
///
/// Each bag is subject to the following constraints:
/// 1. The combined votes against cannot exceed `max_votes_against`
/// 2. The number of items requiring signatures cannot exceed
///    `max_needs_signature`
/// 3. Withdrawal IDs must fit within the OP_RETURN size limit (~77 bytes)
/// 4. The total virtual size across all bags must not exceed
///    [`PACKAGE_MAX_VSIZE`]
///
/// ## Parameters
/// - `items`: Collection of items to be packaged
/// - `max_votes_against`: Maximum allowed votes against for any bag
/// - `max_needs_signature`: Maximum number of items requiring signatures in a
///   bag
///
/// ## Notes
/// - Items that exceed constraints individually are silently ignored
///
/// ## Returns
/// An iterator over vectors, where each inner vector represents a bag of
/// compatible items.
pub fn compute_optimal_packages<I, T>(
    items: I,
    max_votes_against: u32,
    max_needs_signature: u16,
) -> impl Iterator<Item = Vec<T>>
where
    I: IntoIterator<Item = T>,
    T: Weighted,
{
    // Now we just add each item into a bag, and return the
    // collection of bags afterward.
    // Create config and packager
    let config = PackagerConfig::new(max_votes_against, max_needs_signature);
    let mut packager = BestFitPackager::new(config);

    for item in items {
        packager.insert_item(item);
    }

    packager.finalize()
}

/// A trait for items that can be packaged together according to specific
/// constraints. Used by [`compute_optimal_packages`].
///
/// This trait captures the key properties that determine whether items can be
/// combined in a single Bitcoin transaction:
///
/// 1. How the signers have voted on the request,
/// 2. Whether we are dealing with a deposit or a withdrawal request,
/// 3. The virtual size of the request when included in a sweep transaction.
/// 4. Whether the withdrawal IDs can fit within an OP_RETURN output's
///    size limits.
///
/// This trait has methods that capture all of these factors.
pub trait Weighted {
    /// Whether the item needs a signature or not.
    ///
    /// If a request needs a signature, then including it requires a signing
    /// round and that takes time. Since we try to get all inputs signed well
    /// before the arrival of the next bitcoin block, we cap the number of items
    /// that need a signature.
    ///
    /// ## Returns
    /// `true` if this item will consume one of the limited signature slots in a
    /// bag.
    fn needs_signature(&self) -> bool;

    /// Returns a bitmap where a bit that is set to 1 indicates a signer
    /// voted against this item.
    ///
    /// The combined votes against (using bitwise OR) for all items in a bag
    /// must not exceed the `max_votes_against` threshold.
    ///
    /// ## Returns
    /// A bitmap representing votes against this item.
    fn votes(&self) -> u128;

    /// The virtual size of the item in vbytes. This is supposed to be the
    /// total bitcoin weight of the request once signed on the bitcoin
    /// blockchain.
    ///
    /// For deposits, this is the input UTXO size including witness data.
    /// For withdrawals, this is the entire output vsize.
    ///
    /// ## Returns
    /// The vsize in vbytes.
    fn vsize(&self) -> u64;

    /// The withdrawal ID for this item, if it's a withdrawal request.
    ///
    /// Must return `Some(_)` for withdrawals and `None` otherwise. For
    /// withdrawals, the ID is used to encode a bitmap in the OP_RETURN output.
    ///
    /// ## Returns
    /// `Some(id)` for withdrawals, `None` for other item types.
    fn withdrawal_id(&self) -> Option<u64> {
        None
    }

    /// The number of bytes this item's request identifier would occupy in
    /// the serialized `BitcoinPreSignRequest`.
    fn presign_weight(&self) -> usize;
}

/// Configuration parameters for the bin packing algorithm.
///
/// Defines the constraints applied during the packaging process to ensure
/// transactions are valid according to Bitcoin network rules and sBTC security
/// policies.
#[derive(Debug, Clone, Copy)]
struct PackagerConfig {
    /// Maximum allowed votes against for any bag.
    ///
    /// This limits how many signers can vote against items in a single bag. If
    /// the combined votes against exceeds this threshold, items are placed in
    /// separate bags.
    max_votes_against: u32,
    /// Maximum number of items requiring signatures in a bag.
    ///
    /// Due to performance and timing constraints, we limit the number of items
    /// that need signatures in a single bag.
    max_signatures: u16,
    /// Maximum virtual size for all bags combined.
    ///
    /// Derived from Bitcoin Core's package relay limits to ensure transactions
    /// are accepted by the network.
    max_total_vsize: u64,
    /// Maximum available size for encoding withdrawal IDs in OP_RETURN.
    ///
    /// Enforcement of this limit prevents transaction rejection due to
    /// oversized OP_RETURN outputs.
    max_op_return_size: usize,
    /// Maximum total serialized size of request identifiers across all
    /// bags, in bytes when serialized as a `BitcoinPreSignRequest`.
    ///
    /// This prevents the `BitcoinPreSignRequest` from exceeding the
    /// gossipsub wire message size limit.
    max_total_presign_size: usize,
}

impl PackagerConfig {
    /// Create a new configuration with the given vote and signature limits.
    ///
    /// ## Parameters
    /// - `max_votes_against`: Maximum allowed votes against for any bag
    /// - `max_signatures`: Maximum number of items requiring signatures in a
    ///   bag
    ///
    /// ## Returns
    /// A new `PackagerConfig` with default values for other constraints.
    fn new(max_votes_against: u32, max_signatures: u16) -> Self {
        Self {
            max_votes_against,
            max_signatures,
            max_total_vsize: PACKAGE_MAX_VSIZE,
            max_op_return_size: OP_RETURN_AVAILABLE_SIZE,
            max_total_presign_size: MAX_PRESIGN_REQUEST_SIZE,
        }
    }
}

/// A container for compatible items that can be packaged together in a Bitcoin
/// transaction.
///
/// Each bag enforces multiple constraints including vote patterns, signature
/// requirements, and withdrawal ID size limits.
///
/// Bags are optimized to group items with similar voting patterns when
/// possible.
#[derive(Debug, Clone)]
struct Bag<T> {
    /// Configuration constraints for this bag
    config: PackagerConfig,
    /// Items contained in this bag
    items: Vec<T>,
    /// Combined votes bitmap (using bitwise OR)
    votes_bitmap: u128,
    /// Count of items requiring signatures
    items_needing_signatures: u16,
    /// Total virtual size of items in this bag
    vsize: u64,
    /// Sorted list of withdrawal IDs in this bag
    withdrawal_ids: Vec<u64>,
}

impl<T> Bag<T>
where
    T: Weighted,
{
    /// Create a new empty bag with the provided configuration.
    ///
    /// ## Parameters
    /// - `config`: Configuration constraints for the bag
    ///
    /// ## Returns
    /// A new empty bag.
    fn new(config: PackagerConfig) -> Self {
        Bag {
            config,
            votes_bitmap: 0,
            items_needing_signatures: 0,
            vsize: 0,
            items: Vec::new(),
            withdrawal_ids: Vec::new(),
        }
    }

    /// Create a new bag from a single item.
    ///
    /// ## Parameters
    /// - `config`: Configuration constraints for the bag
    /// - `item`: Initial item to add to the bag
    ///
    /// ## Returns
    /// A new bag containing the item.
    fn with_item(config: PackagerConfig, item: T) -> Self {
        let mut bag = Self::new(config);
        bag.add_item(item);
        bag
    }

    /// Add an item to the bag.
    ///
    /// Updates internal state including votes, signatures needed, vsize, and
    /// withdrawal IDs.
    ///
    /// ## Parameters
    /// - `item`: Item to add to the bag
    fn add_item(&mut self, item: T) {
        self.votes_bitmap |= item.votes();
        self.items_needing_signatures += item.needs_signature() as u16;
        self.vsize += item.vsize();

        if let Some(id) = item.withdrawal_id() {
            match self.withdrawal_ids.binary_search(&id) {
                Ok(_) => {} // ID already exists, do nothing
                Err(pos) => self.withdrawal_ids.insert(pos, id),
            }
        }

        self.items.push(item);
    }

    /// Check if an item is compatible with this bag according to all
    /// constraints.
    ///
    /// An item is compatible when:
    /// 1. Combined votes against ≤ max_votes_against
    /// 2. Combined signature requirements ≤ max_signatures
    /// 3. Withdrawal ID (if any) fits within remaining OP_RETURN space
    ///
    /// ## Parameters
    /// - `item`: Item to check for compatibility
    ///
    /// ## Returns
    /// `true` if the item can be safely added to this bag.
    fn is_compatible(&self, item: &T) -> bool {
        self.votes_compatible(item)
            && self.signatures_compatible(item)
            && self.withdrawal_id_compatible(item)
    }

    /// Check if an item's votes are compatible with this bag.
    ///
    /// ## Parameters
    /// - `item`: Item to check for vote compatibility
    ///
    /// ## Returns
    /// `true` if the combined votes don't exceed the maximum allowed.
    fn votes_compatible(&self, item: &T) -> bool {
        let combined_votes = self.votes_bitmap | item.votes();
        combined_votes.count_ones() <= self.config.max_votes_against
    }

    /// Check if an item's signature requirement is compatible with this bag.
    ///
    /// ## Parameters
    /// - `item`: Item to check for signature compatibility
    ///
    /// ## Returns
    /// `true` if adding the item wouldn't exceed the signature limit.
    fn signatures_compatible(&self, item: &T) -> bool {
        let sig = item.needs_signature() as u16;
        self.items_needing_signatures + sig <= self.config.max_signatures
    }

    /// Check if an item's withdrawal ID is compatible with this bag.
    ///
    /// ## Parameters
    /// - `item`: Item to check for withdrawal ID compatibility
    ///
    /// ## Returns
    /// `true` if the item's withdrawal ID can fit in this bag's OP_RETURN.
    fn withdrawal_id_compatible(&self, item: &T) -> bool {
        let Some(id) = item.withdrawal_id() else {
            return true;
        };

        self.can_add_withdrawal_id(id)
    }

    /// Calculate compatibility score between item and bag (smaller is better).
    ///
    /// The score is based on how different the vote patterns are (using XOR).
    /// Lower scores indicate items with more similar voting patterns.
    ///
    /// ## Parameters
    /// - `item`: Item to calculate compatibility score for
    ///
    /// ## Returns
    /// A score where lower values indicate better compatibility.
    fn compatibility_score(&self, item: &T) -> u32 {
        // XOR measures how different the vote patterns are
        (self.votes_bitmap ^ item.votes()).count_ones()
    }

    /// Check if adding a single withdrawal ID would exceed the OP_RETURN size
    /// limit.
    ///
    /// ## Parameters
    /// - `new_id`: Withdrawal ID to check
    ///
    /// ## Returns
    /// - `true` if the ID can be added
    /// - `false` if adding the ID would exceed size limits
    ///
    /// ## Implementation Notes
    /// This method simulates adding the new withdrawal ID to the bag's existing
    /// IDs while maintaining sorted order. The [`BitmapSegmenter`] is then used
    /// to estimate the size of the combined IDs, which requires sorted and
    /// de-duplicated IDs.
    fn can_add_withdrawal_id(&self, new_id: u64) -> bool {
        // If no existing IDs then the range is 0, so we can add any ID
        if self.withdrawal_ids.is_empty() {
            return true;
        }

        // Check if ID already exists (would have no effect on size)
        match self.withdrawal_ids.binary_search(&new_id) {
            Ok(_) => true, // ID already in the list
            Err(pos) => {
                // Create combined IDs with new ID inserted at correct position
                let mut combined_ids = Vec::with_capacity(self.withdrawal_ids.len() + 1);
                combined_ids.extend_from_slice(&self.withdrawal_ids[0..pos]);
                combined_ids.push(new_id);
                combined_ids.extend_from_slice(&self.withdrawal_ids[pos..]);

                // Check if the combined IDs fit
                self.can_fit_withdrawal_ids(&combined_ids)
            }
        }
    }

    /// Check if a set of withdrawal IDs can fit within the OP_RETURN size
    /// limit.
    ///
    /// ## Parameters
    /// - `ids`: Collection of withdrawal IDs to check
    ///
    /// ## Returns
    /// - `true` if the IDs will fit within the OP_RETURN size limits.
    /// - `false` if the IDs exceed the size limits, or an error occurs during
    ///   estimation (for example if the id's have become unsorted or contain
    ///   duplicates).
    fn can_fit_withdrawal_ids(&self, ids: &[u64]) -> bool {
        if ids.is_empty() {
            return true;
        }

        BitmapSegmenter
            .estimate_size(ids)
            .map_or_else(
                |error| {
                    tracing::warn!(%error, withdrawal_ids = ?ids, "error estimating packaged withdrawal id size");
                    false
                },
                |size| size <= self.config.max_op_return_size
            )
    }
}

/// Implementation of the Best-Fit bin packing algorithm for compatible items.
///
/// This packager attempts to:
/// 1. Group items with similar voting patterns together
/// 2. Respect signature limits for each bag
/// 3. Ensure withdrawal IDs fit within OP_RETURN size limits
/// 4. Keep total virtual size within Bitcoin network limits
///
/// ## Implementation Notes
/// - Items that exceed individual limits are silently ignored
/// - Items that would cause the total vsize to exceed limits are ignored
#[derive(Debug)]
struct BestFitPackager<T> {
    /// All created bags of compatible items
    bags: Vec<Bag<T>>,
    /// Configuration constraints
    config: PackagerConfig,
    /// Running total of virtual size across all bags
    total_vsize: u64,
    /// Running total of how many bytes the identifiers will take in a
    /// serialized `BitcoinPreSignRequest`, across all bags.
    total_presign_size: usize,
}

impl<T: Weighted> BestFitPackager<T> {
    fn new(config: PackagerConfig) -> Self {
        Self {
            bags: Vec::new(),
            config,
            total_vsize: 0,
            total_presign_size: 0,
        }
    }

    /// Find the best bag to insert a new item.
    ///
    /// "Best" is defined as the compatible bag with the lowest compatibility score.
    ///
    /// ## Parameters
    /// - `item`: Item to find a bag for
    ///
    /// ## Returns
    /// A mutable reference to the best bag, or `None` if no compatible bag exists.
    fn find_best_bag(&mut self, item: &T) -> Option<&mut Bag<T>> {
        self.bags
            .iter_mut()
            .filter(|bag| bag.is_compatible(item))
            .min_by_key(|bag| bag.compatibility_score(item))
    }

    /// Try to insert an item into the best-fit bag, or create a new one.
    ///
    /// Items that exceed individual limits or would cause the total vsize
    /// or encoded size to exceed the limits are silently ignored.
    ///
    /// ## Parameters
    /// - `item`: Item to insert
    ///
    /// ## Notes
    /// - This method silently ignores items that exceed either individual
    ///   or aggregate limits.
    fn insert_item(&mut self, item: T) {
        let votes_against = item.votes().count_ones();
        let total_package_vsize = self.total_vsize.saturating_add(item.vsize());
        let mut total_presign_size = self
            .total_presign_size
            .saturating_add(item.presign_weight());

        // Early exits for items exceeding our bag-independent limits.
        if votes_against > self.config.max_votes_against
            || total_package_vsize > self.config.max_total_vsize
            || total_presign_size > self.config.max_total_presign_size
        {
            return;
        }

        // Use find_best_bag or create a new bag
        match self.find_best_bag(&item) {
            Some(bag) => bag.add_item(item),
            None => {
                // A new bag means a new `TxRequestIds` element in the
                // serialized `BitcoinPreSignRequest.request_package`
                // protobuf field, which adds a field tag and a length
                // varint. We account for those bytes using the
                // `BAG_OVERHEAD` constant.
                total_presign_size = total_presign_size.saturating_add(BAG_OVERHEAD);
                // Maybe adding a new bag will push us over the limit, and
                // if so, we return early and do not add the item to any
                // bag.
                if total_presign_size > self.config.max_total_presign_size {
                    return;
                }
                self.bags.push(Bag::with_item(self.config, item));
            }
        }

        // Add to totals after we've decided to add the item to a bag.
        self.total_vsize = total_package_vsize;
        self.total_presign_size = total_presign_size;
    }

    /// Consumes the packager and returns an iterator over the packed item
    /// groups.
    ///
    /// ## Returns
    /// An iterator that yields each bag's contents as a `Vec<T>`, preserving
    /// the original compatibility constraints established during insertion.
    fn finalize(self) -> impl Iterator<Item = Vec<T>> {
        self.bags.into_iter().map(|bag| bag.items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;
    use bitvec::array::BitArray;
    use bitvec::field::BitField as _;
    use fake::Fake as _;
    use prost::Message as _;
    use rand::Rng;
    use rand::prelude::SliceRandom as _;
    use signer::testing::get_rng;
    use std::sync::atomic::AtomicU64;
    use test_case::test_case;

    use crate::bitcoin::utxo::DepositRequest;
    use crate::bitcoin::utxo::Fees;
    use crate::bitcoin::utxo::PROTOBUF_ENCODED_SIZE_OVERHEAD;
    use crate::bitcoin::utxo::RequestRef;
    use crate::bitcoin::utxo::WithdrawalRequest;
    use crate::bitcoin::validation::TxRequestIds;
    use crate::ecdsa::Signed;
    use crate::keys::PrivateKey;
    use crate::keys::PublicKey;
    use crate::message::BitcoinPreSignRequest;
    use crate::message::Payload;
    use crate::message::SignerMessage;
    use crate::proto;
    use crate::storage::model::BitcoinBlockHash;
    use crate::storage::model::ScriptPubKey;
    use crate::storage::model::TaprootScriptHash;
    use crate::testing::dummy::Unit;

    /// Maximum bytes an `OutPoint` identifier adds to the serialized
    /// [`BitcoinPreSignRequest`](crate::message::BitcoinPreSignRequest).
    ///
    /// This is the worst-case protobuf encoding size of an `OutPoint` when
    /// embedded in a `TxRequestIds.deposits` field. The value accounts
    /// for the field tag, length varint, and the full encoding of
    /// `BitcoinTxid(Uint256)` + `uint32 vout`.
    const DEPOSIT_PRESIGN_WEIGHT: usize = 48;

    /// Maximum bytes a withdrawal `QualifiedRequestId` identifier adds to
    /// the serialized
    /// [`BitcoinPreSignRequest`](crate::message::BitcoinPreSignRequest).
    ///
    /// This is the worst-case protobuf encoding size of a
    /// `QualifiedRequestId` when embedded in a `TxRequestIds.withdrawals`
    /// field.
    const WITHDRAWAL_PRESIGN_WEIGHT: usize = 93;

    impl<T> BestFitPackager<T>
    where
        T: Weighted,
    {
        /// Create a new bag with the given items and add it to the packager.
        fn new_bag(&mut self, items: Vec<T>) -> &mut Bag<T> {
            let bag = Bag::from_items(self.config, items);
            self.bags.push(bag);
            self.bags.last_mut().unwrap()
        }
    }

    impl<T> Bag<T>
    where
        T: Weighted,
    {
        /// Add multiple items to the bag.
        fn add_items(&mut self, items: Vec<T>) {
            for item in items {
                self.add_item(item);
            }
        }

        /// Create a new bag from a collection of items.
        fn from_items(config: PackagerConfig, items: Vec<T>) -> Self {
            let mut bag = Bag {
                config,
                items: Vec::new(),
                votes_bitmap: 0,
                items_needing_signatures: 0,
                vsize: 0,
                withdrawal_ids: Vec::new(),
            };
            bag.add_items(items);
            bag
        }
    }

    #[derive(Debug, Default, Copy, Clone, PartialEq)]
    struct RequestItem {
        // Votes _against_ the request. A `true` value means a vote against.
        votes: [bool; 5],
        /// Whether this request needs a signature.
        needs_signature: bool,
        /// The virtual size of the request.
        vsize: u64,
        /// The withdrawal request ID for this item, if it's a withdrawal.
        withdrawal_id: Option<u64>,
    }

    static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(0);

    impl RequestItem {
        /// Create a new request item with no votes against.
        fn no_votes() -> Self {
            Self::default()
        }

        /// Create a new request item with all votes against.
        fn all_votes() -> Self {
            Self {
                votes: [true; 5],
                ..Default::default()
            }
        }

        /// Create a new request item with specific votes against.
        ///
        /// ## Parameters
        /// - `votes`: Collection of signer indices (1-based) who vote against this item
        fn with_votes(votes: &[usize]) -> Self {
            let mut vote_array = [false; 5];
            for &index in votes {
                vote_array[index - 1] = true;
            }

            Self {
                votes: vote_array,
                ..Default::default()
            }
        }

        /// Create a new request item with a single vote against.
        ///
        /// ## Parameters
        /// - `signer`: The signer index (1-based) who votes against this item
        fn with_vote(signer: usize) -> Self {
            let mut votes = [false; 5];
            votes[signer - 1] = true;
            Self { votes, ..Default::default() }
        }

        /// Create a new request item with random votes against.
        fn with_rng(rng: &mut impl Rng) -> Self {
            let mut votes = [false; 5];
            for vote in &mut votes {
                *vote = rng.gen_bool(0.5);
            }
            let needs_signature = rng.gen_bool(0.5);
            let vsize = rng.gen_range(1..=10000);
            let withdrawal_id = if !needs_signature {
                Some(NEXT_REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
            } else {
                None
            };

            Self {
                votes,
                needs_signature,
                vsize,
                withdrawal_id,
            }
        }

        /// Set the `needs_signature` field to true, indicating that signing
        /// is required for this request.
        fn sig_required(mut self) -> Self {
            self.needs_signature = true;
            self
        }

        /// Sets the withdrawal request ID for this item.
        fn wid(mut self, withdrawal_id: u64) -> Self {
            self.withdrawal_id = Some(withdrawal_id);
            self
        }

        /// Sets the virtual size for this item.
        fn vsize(mut self, vsize: u64) -> Self {
            self.vsize = vsize;
            self
        }
    }

    impl Weighted for RequestItem {
        fn needs_signature(&self) -> bool {
            self.needs_signature
        }

        fn votes(&self) -> u128 {
            let mut votes = BitArray::<[u8; 16]>::ZERO;
            for (index, value) in self.votes.iter().copied().enumerate() {
                votes.set(index, value);
            }
            votes.load()
        }

        fn vsize(&self) -> u64 {
            self.vsize
        }

        fn withdrawal_id(&self) -> Option<u64> {
            self.withdrawal_id
        }

        fn presign_weight(&self) -> usize {
            if self.needs_signature() {
                DEPOSIT_PRESIGN_WEIGHT
            } else {
                WITHDRAWAL_PRESIGN_WEIGHT
            }
        }
    }

    struct VotesTestCase<const N: usize> {
        /// The item input into `compute_optimal_packages`.
        items: Vec<RequestItem>,
        /// Used when calling `compute_optimal_packages`.
        max_needs_signature: u16,
        /// Used when calling `compute_optimal_packages`.
        max_votes_against: u32,
        /// After calling `compute_optimal_packages` with the `items` here,
        /// `N` is the expected number of bags, and the `usize`s are the
        /// expected number of items in each bag.
        expected_bag_sizes: [usize; N],
        /// After calling `compute_optimal_packages` with the `items` here,
        /// `N` is the expected number of bags, and the `u64`s are the
        /// expected vsizes of each bag.
        expected_bag_vsizes: [u64; N],
    }

    /// Tests the complete bin-packing algorithm across multiple scenarios including:
    /// - No votes against
    /// - Same votes against
    /// - Different votes requiring multiple bags
    /// - Signature limits causing splits
    /// - Size constraints being enforced
    #[test_case(VotesTestCase {
        items: vec![RequestItem::no_votes(); 6],
        max_needs_signature: 100,
        max_votes_against: 1,
        expected_bag_sizes: [6],
        expected_bag_vsizes: [0],
    } ; "no-votes-against-one-package")]
    #[test_case(VotesTestCase {
        items: vec![RequestItem::with_vote(5); 6],
        max_needs_signature: 100,
        max_votes_against: 1,
        expected_bag_sizes: [6],
        expected_bag_vsizes: [0],
    } ; "same-votes-against-one-package")]
    #[test_case(VotesTestCase {
        items: vec![
            RequestItem::with_vote(5),
            RequestItem::with_vote(5),
            RequestItem::with_vote(4),
            RequestItem::with_vote(4),
            RequestItem::no_votes(),
        ],
        max_needs_signature: 100,
        max_votes_against: 1,
        expected_bag_sizes: [3, 2],
        expected_bag_vsizes: [0, 0],
    } ; "two-different-votes-against-two-packages")]
    #[test_case(VotesTestCase {
        items: vec![RequestItem::no_votes().sig_required(); 25],
        max_needs_signature: 10,
        max_votes_against: 1,
        expected_bag_sizes: [10, 10, 5],
        expected_bag_vsizes: [0, 0, 0],
    } ; "splits-when-too-many-required-signatures")]
    #[test_case(VotesTestCase {
        items: vec![RequestItem::no_votes().vsize(4000); 25],
        max_needs_signature: 10,
        max_votes_against: 1,
        expected_bag_sizes: [23],
        expected_bag_vsizes: [92000],
    } ; "ignores-when-vsize-exceeds-max")]
    #[test_case(VotesTestCase {
        items: vec![
            RequestItem::with_votes(&[4, 5]),
            RequestItem::with_votes(&[2, 3]),
            RequestItem::with_votes(&[1, 2]),
            RequestItem::with_vote(1),
            RequestItem::with_vote(2),
            RequestItem::with_vote(3),
        ],
        max_needs_signature: 100,
        max_votes_against: 3,
        expected_bag_sizes: [1, 5],
        expected_bag_vsizes: [0, 0],
    } ; "votes-against-placement")]
    fn returns_optimal_placements<const N: usize>(case: VotesTestCase<N>) {
        let ans =
            compute_optimal_packages(case.items, case.max_votes_against, case.max_needs_signature);
        let collection = ans.collect::<Vec<_>>();
        let iter = collection
            .iter()
            .zip(case.expected_bag_sizes)
            .zip(case.expected_bag_vsizes);

        assert_eq!(collection.len(), N);
        for ((bag, expected_size), expected_vsize) in iter {
            assert_eq!(bag.len(), expected_size);
            let package_vsize = bag.iter().map(|item| item.vsize()).sum::<u64>();
            assert_eq!(package_vsize, expected_vsize);

            // Now for the bitcoin requirement
            more_asserts::assert_le!(package_vsize, PACKAGE_MAX_VSIZE);
        }
    }

    /// Tests that the OP_RETURN size estimation correctly identifies both small sets that fit
    /// and large sets that exceed the size limit.
    #[test]
    fn test_can_fit_withdrawal_ids() {
        let config = PackagerConfig::new(1, 10);
        let bag = Bag::<RequestItem>::new(config);

        // Small set should fit
        assert!(bag.can_fit_withdrawal_ids(&[1, 2, 3, 4, 5]));

        // Generate a large set with poor compression characteristics
        // (values spaced far apart won't compress efficiently with bitmap encoding)
        let large_set: Vec<u64> = (0..75).map(|i| i * 1000).collect();
        assert!(!bag.can_fit_withdrawal_ids(&large_set));
    }

    #[test]
    fn item_order_matters_in_compute_optimal_packages() {
        let mut rng = get_rng();
        let len = rng.gen_range(25..=100) as usize;
        let mut items = Vec::with_capacity(len);
        for _ in 0..len {
            items.push(RequestItem::with_rng(&mut rng));
        }

        let max_needs_signature = 100;
        let max_votes_against = 3;
        let packages1 =
            compute_optimal_packages(items.clone(), max_votes_against, max_needs_signature)
                .collect::<Vec<_>>();

        items.shuffle(&mut rng);

        let packages2 = compute_optimal_packages(items, max_votes_against, max_needs_signature)
            .collect::<Vec<_>>();

        assert_ne!(packages1, packages2);
    }

    /// Tests that bags correctly collect, sort, and deduplicate withdrawal IDs.
    #[test]
    fn test_bag_collects_withdrawal_ids() {
        // Create a bag with one withdrawal ID
        let config = PackagerConfig::new(1, 10);
        let mut bag = Bag::new(config);
        bag.add_item(RequestItem::no_votes().wid(42));

        assert_eq!(bag.withdrawal_ids.len(), 1);
        assert_eq!(bag.withdrawal_ids[0], 42);

        // Add more IDs in non-sorted order
        bag.add_items(vec![
            RequestItem::no_votes().wid(100),
            RequestItem::no_votes().wid(5), // Smaller than existing IDs
            RequestItem::no_votes().wid(200),
            RequestItem::no_votes().wid(50),
            RequestItem::no_votes(),         // Not a withdrawal
            RequestItem::no_votes().wid(42), // Duplicate ID
        ]);

        // Verify correct number of unique IDs
        assert_eq!(bag.withdrawal_ids.len(), 5);

        // Verify IDs are sorted
        let expected_ids = [5, 42, 50, 100, 200];
        assert_eq!(bag.withdrawal_ids, expected_ids);

        // IDs should already be sorted, so this should work properly
        assert!(bag.can_fit_withdrawal_ids(&bag.withdrawal_ids));
    }

    /// Tests that vote compatibility correctly evaluates different combinations
    /// of votes against the maximum allowed threshold. Verifies both positive
    /// and negative cases.
    #[test_case(&[1], &[], 1 => true; "one_vote_one_max")]
    #[test_case(&[1, 2], &[], 1 => false; "two_votes_one_max")]
    #[test_case(&[1], &[2], 1 => false; "different_votes_exceed_max")]
    #[test_case(&[1], &[1], 1 => true; "same_votes_within_max")]
    #[test_case(&[1, 2], &[1], 2 => true; "combined_unique_votes_at_limit")]
    fn test_votes_compatible(bag_votes: &[usize], item_votes: &[usize], max_votes: u32) -> bool {
        let config = PackagerConfig::new(max_votes, 5);
        let bag = Bag::from_items(config, vec![RequestItem::with_votes(bag_votes).vsize(10)]);
        let item = RequestItem::with_votes(item_votes).vsize(10);
        bag.votes_compatible(&item)
    }

    /// Tests signature requirement compatibility across different scenarios
    /// including:
    /// - No signatures required
    /// - At capacity
    /// - Below capacity
    /// - Exceeding capacity
    #[test_case(0, false, 1 => true; "no_sigs_in_bag_no_sig_required")]
    #[test_case(5, false, 5 => true; "max_sigs_in_bag_no_sig_required")]
    #[test_case(4, true, 5 => true; "under_max_sigs_sig_required")]
    #[test_case(5, true, 5 => false; "at_max_sigs_sig_required")]
    fn test_signatures_compatible(bag_sigs: u16, item_needs_sig: bool, max_sigs: u16) -> bool {
        let config = PackagerConfig::new(2, max_sigs);

        // Create a bag with the specified number of signatures
        let mut bag = Bag::from_items(
            config,
            vec![], // Empty initially
        );

        // Add items requiring signatures to match bag_sigs
        for _ in 0..bag_sigs {
            bag.items_needing_signatures += 1;
        }

        // Create item that may or may not need a signature
        let mut item = RequestItem::no_votes().vsize(10);
        if item_needs_sig {
            item = item.sig_required();
        }

        bag.signatures_compatible(&item)
    }

    /// Tests withdrawal ID compatibility for various scenarios:
    /// - Empty withdrawal ID lists
    /// - Small ID ranges
    /// - IDs within existing ranges
    /// - IDs that exceed OP_RETURN size limits
    #[test_case(vec![], None => true; "no_withdrawal_id")]
    #[test_case(vec![1, 2, 3], Some(4) => true; "compatible_withdrawal_id")]
    #[test_case(vec![], Some(42) => true; "single_withdrawal_id")]
    #[test_case((1..50).collect::<Vec<u64>>(), Some(300) => true; "many_small_ids_compatible")]
    #[test_case(vec![1, 2, 4, 5], Some(3) => true; "new_id_within_existing_range")]
    fn test_withdrawal_id_compatible(bag_ids: Vec<u64>, item_id: Option<u64>) -> bool {
        let config = PackagerConfig::new(2, 5);

        // Create a bag with specified withdrawal IDs
        let mut bag = Bag::new(config);

        // Add withdrawal IDs
        for id in bag_ids {
            bag.withdrawal_ids.push(id);
        }
        bag.withdrawal_ids.sort();

        // Create item with optional withdrawal ID
        let item = match item_id {
            Some(id) => RequestItem::no_votes().wid(id).vsize(10),
            None => RequestItem::no_votes().vsize(10),
        };

        bag.withdrawal_id_compatible(&item)
    }

    /// Test withdrawal id compatibility at the exact OP_RETURN size boundary.
    #[test]
    fn test_withdrawal_id_compatible_at_exact_op_return_boundary() {
        let mut ids: Vec<u64> = Vec::new();
        let mut next_id: u64 = 0;

        // Fill the ID list until we've precisely exceeded the OP_RETURN limit
        while BitmapSegmenter.estimate_size(&ids).unwrap() <= OP_RETURN_AVAILABLE_SIZE {
            ids.push(next_id);
            next_id += 1;
        }

        // At this point ids are just over the limit - remove the last one
        // to get ≤ OP_RETURN_AVAILABLE_SIZE
        ids.pop();

        // Verify that the new size is at/under the limit
        let safe_size = BitmapSegmenter.estimate_size(&ids).unwrap();
        more_asserts::assert_le!(
            safe_size,
            OP_RETURN_AVAILABLE_SIZE,
            "expected safe size to be under the limit"
        );

        // The last ID in the list is now the last safe ID. Remove it so we can
        // do a proper verification below
        let last_safe_id = ids.pop().unwrap();

        // Create the bag with the IDs that are just under the limit
        let config = PackagerConfig::new(2, 5);
        let mut bag = Bag::<RequestItem>::new(config);
        bag.withdrawal_ids = ids;

        // This ID should be compatible
        let last_safe_item = RequestItem::no_votes().wid(last_safe_id);
        assert!(
            bag.withdrawal_id_compatible(&last_safe_item),
            "expected last safe ID to be compatible"
        );
        bag.withdrawal_ids.push(last_safe_id); // Re-add the ID to the bag

        // This ID should push us over the limit (next_id is the first ID that would
        // exceed the limit)
        let too_big_item = RequestItem::no_votes().wid(next_id);
        assert!(
            !bag.is_compatible(&too_big_item),
            "expected too big ID to be incompatible"
        );
    }

    /// Tests the combined compatibility evaluation including votes, signatures,
    /// and withdrawal ID constraints. Ensures all constraints must be satisfied
    /// for an item to be compatible.
    #[test]
    fn test_is_compatible() {
        let config = PackagerConfig::new(2, 5);

        // Create a bag with 1 vote against and 2 signatures needed
        let bag = Bag::from_items(
            config,
            vec![
                RequestItem::with_vote(1).sig_required().vsize(10),
                RequestItem::no_votes().sig_required().vsize(10),
            ],
        );

        // Compatible item (no additional votes against, needs signature)
        assert!(bag.is_compatible(&RequestItem::with_vote(1).sig_required().vsize(10)));

        // Incompatible item (too many votes against)
        assert!(!bag.is_compatible(&RequestItem::with_votes(&[2, 3]).vsize(10)));

        // Incompatible item (too many signatures needed)
        let full_sig_bag = Bag::from_items(
            config,
            vec![RequestItem::no_votes().sig_required().vsize(10); 5],
        );

        // This would make 6 signatures, exceeding our limit of 5
        assert!(!full_sig_bag.is_compatible(&RequestItem::all_votes().sig_required().vsize(10)));
    }

    /// Tests the algorithm's ability to score compatibility between items with
    /// different voting patterns. Lower scores indicate more similar voting
    /// patterns.
    #[test_case(&[1], &[1] => 0; "identical_votes")]
    #[test_case(&[2], &[1] => 2; "two_differences")]
    #[test_case(&[1, 2], &[1] => 1; "one_difference")]
    fn test_compatibility_score(bag_votes: &[usize], item_votes: &[usize]) -> u32 {
        let config = PackagerConfig::new(5, 10);
        let bag = Bag::from_items(config, vec![RequestItem::with_votes(bag_votes).vsize(10)]);
        let item = RequestItem::with_votes(item_votes).vsize(10);
        bag.compatibility_score(&item)
    }

    /// Tests the bin-packing algorithm's ability to find the optimal bag for
    /// placement based on compatibility score and constraints. Includes
    /// withdrawal ID space considerations.
    #[test_case(
        // Simple case - finds first bag (with vote 1)
        vec![RequestItem::with_vote(1)],
        vec![RequestItem::with_vote(2)],
        vec![RequestItem::with_vote(3)],
        RequestItem::with_vote(1),
        Some(0)
        ; "finds_exact_match")]
    #[test_case(
        // Complex case - finds best compatible bag
        vec![RequestItem::with_votes(&[1, 2, 3])],
        vec![RequestItem::with_votes(&[1, 2])],
        vec![RequestItem::with_vote(1)],
        RequestItem::with_vote(1),
        Some(2)
        ; "finds_most_compatible_bag")]
    #[test_case(
        // Incompatible with all bags
        vec![RequestItem::with_vote(1)],
        vec![RequestItem::with_vote(2)],
        vec![RequestItem::with_vote(3)],
        RequestItem::all_votes(),
        None
        ; "incompatible_with_all_bags")]
    #[test_case(
        // Bag 1: Nearly full OP_RETURN (large range of IDs)
        (0..580).map(|id| RequestItem::no_votes().wid(id)).collect(),
        // Bag 2: Has room for more IDs (small range)
        vec![RequestItem::no_votes().wid(100_000), RequestItem::no_votes().wid(100_001)],
        // Bag 3: Nearly full OP_RETURN (different large range)
        (1000..1580).map(|id| RequestItem::no_votes().wid(id)).collect(),
        // Item with ID that fits in bag 2's range
        RequestItem::no_votes().wid(100_010),
        Some(1) // Should select bag 2 (index 1)
        ; "selects_bag_with_room_for_withdrawal_id")]
    fn test_find_best_bag(
        bag1_items: Vec<RequestItem>,
        bag2_items: Vec<RequestItem>,
        bag3_items: Vec<RequestItem>,
        test_item: RequestItem,
        expected_result: Option<usize>,
    ) {
        let config = PackagerConfig::new(2, 5);
        let mut packager = BestFitPackager::<RequestItem>::new(config);

        // Setup bags
        packager.new_bag(bag1_items);
        packager.new_bag(bag2_items);
        packager.new_bag(bag3_items);

        // Extract the index directly using the same logic
        let best_bag_index = packager
            .bags
            .iter()
            .enumerate()
            .filter(|(_, bag)| bag.is_compatible(&test_item))
            .min_by_key(|(_, bag)| bag.compatibility_score(&test_item))
            .map(|(index, _)| index);

        // Verify expected result matches the direct calculation
        assert_eq!(best_bag_index, expected_result);

        // Verify the actual method returns the right bag
        let best_bag = packager.find_best_bag(&test_item);
        assert_eq!(best_bag.is_some(), best_bag_index.is_some());
    }

    /// Tests item insertion logic including:
    /// - Creating new bags
    /// - Adding to existing compatible bags
    /// - Silently ignoring items that exceed limits
    /// - Handling withdrawal ID constraints
    #[test]
    fn test_insert_item() {
        let config = PackagerConfig::new(2, 5);
        let mut packager = BestFitPackager::<RequestItem>::new(config);

        // Add first item - should create a new bag
        packager.insert_item(RequestItem::with_vote(1).vsize(10));
        assert_eq!(packager.bags.len(), 1); // No change
        assert_eq!(packager.bags[0].items.len(), 1); // +1
        assert_eq!(packager.bags[0].vsize, 10); // 10

        // Add compatible item (same voting, withdrawal) - should go in existing bag
        packager.insert_item(RequestItem::with_vote(1).wid(1).vsize(10));
        assert_eq!(packager.bags.len(), 1); // No change
        assert_eq!(packager.bags[0].items.len(), 2); // +1
        assert_eq!(packager.bags[0].vsize, 20); // +10

        // Add compatible item (different voting) - should go in existing bag
        // Note: This is compatible because the combined votes (positions 1,2) equal 2,
        // which doesn't exceed our max_votes_against limit of 2
        packager.insert_item(RequestItem::with_votes(&[1, 2]).vsize(10));
        assert_eq!(packager.bags.len(), 1); // No change
        assert_eq!(packager.bags[0].items.len(), 3); // +1
        assert_eq!(packager.bags[0].vsize, 30); // +10

        // Add item that exceeds vote limit - should be ignored
        packager.insert_item(RequestItem::all_votes().vsize(10));
        assert_eq!(packager.bags.len(), 1); // No change
        assert_eq!(packager.bags[0].items.len(), 3); // No change
        assert_eq!(packager.bags[0].vsize, 30); // No change

        // Add incompatible item (different voting pattern) - should create new bag
        packager.insert_item(RequestItem::with_votes(&[4, 5]).vsize(10));
        assert_eq!(packager.bags.len(), 2); // +1
        assert_eq!(packager.bags[0].items.len(), 3); // (bag 0) No change
        assert_eq!(packager.bags[1].items.len(), 1); // (bag 1) +1
        assert_eq!(packager.bags[0].vsize, 30); // (bag 0) No change
        assert_eq!(packager.bags[1].vsize, 10); // (bag 1) 10

        // Add item that exceeds vsize limit
        let original_vsize = packager.total_vsize;
        packager.insert_item(RequestItem::no_votes().vsize(PACKAGE_MAX_VSIZE - original_vsize + 1));
        assert_eq!(packager.bags.len(), 2); // No change
        assert_eq!(packager.bags[0].items.len(), 3); // No change
        assert_eq!(packager.total_vsize, original_vsize); // No change to vsize

        // Check that we can trigger the OP_RETURN size limit roll-over
        (2..592).step_by(5).for_each(|id| {
            packager.insert_item(RequestItem::with_votes(&[1, 2]).wid(id));
        });
        assert_eq!(packager.bags.len(), 2); // we should be really close to the limit (no change)
        packager.insert_item(RequestItem::with_votes(&[1, 2]).wid(10_000));
        assert_eq!(packager.bags.len(), 3); // +1
    }

    /// End-to-end test of withdrawal ID handling in the packaging algorithm,
    /// verifying that IDs are properly distributed into bags that respect OP_RETURN size limits.
    #[test]
    fn test_withdrawal_id_packaging() {
        // Create a set of items with various withdrawal IDs
        let mut items = (0..600)
            .map(|id| RequestItem::no_votes().wid(id))
            .collect::<Vec<_>>();
        items.push(RequestItem::no_votes().sig_required().vsize(10)); // Regular deposit
        items.push(RequestItem::no_votes().wid(1000));
        items.push(RequestItem::no_votes().wid(2000));
        items.push(RequestItem::with_vote(1).wid(3000)); // Different vote pattern
        items.push(RequestItem::no_votes().wid(10000)); // Large ID

        let bags = compute_optimal_packages(items, 1, 5).collect::<Vec<_>>();

        // Verify multiple bags were created due to both vote and withdrawal ID constraints
        assert!(bags.len() > 1);

        // Verify each bag has the right vote pattern and withdrawal IDs
        for bag in &bags {
            // Check vote constraint
            let combined_votes = bag.iter().fold(0u128, |acc, item| acc | item.votes());

            // Collect withdrawal IDs
            let mut withdrawal_ids: Vec<u64> =
                bag.iter().filter_map(|item| item.withdrawal_id).collect();
            withdrawal_ids.sort_unstable();

            // Verify vote constraint is maintained
            assert!(
                combined_votes.count_ones() <= 1,
                "bag has more votes against than allowed: {}",
                combined_votes.count_ones()
            );

            // Verify withdrawal IDs can fit in OP_RETURN
            if !withdrawal_ids.is_empty() {
                let segmenter = BitmapSegmenter;
                let size = segmenter.estimate_size(&withdrawal_ids).unwrap();
                assert!(
                    size <= OP_RETURN_AVAILABLE_SIZE,
                    "withdrawal IDs exceed OP_RETURN size: {size} > {OP_RETURN_AVAILABLE_SIZE}"
                );
            }
        }
    }

    /// Tests that the presign size limit is enforced by the packager.
    /// Items are silently ignored when adding them would exceed the
    /// [`MAX_PRESIGN_REQUEST_SIZE`] limit. The first item inserted also
    /// creates a bag, which charges [`BAG_OVERHEAD`], so the effective
    /// capacity for item weights is `MAX_PRESIGN_REQUEST_SIZE -
    /// BAG_OVERHEAD`.
    #[test]
    fn test_insert_item_respects_presign_size_limit() {
        let max_signatures = 10000;
        let config = PackagerConfig::new(5, max_signatures);
        let mut packager = BestFitPackager::<RequestItem>::new(config);

        // Each deposit has presign weight DEPOSIT_PRESIGN_WEIGHT (48 bytes).
        // The first item also creates a bag, which charges BAG_OVERHEAD.
        // Fill up to just under the limit.
        let max_deposits = (MAX_PRESIGN_REQUEST_SIZE - BAG_OVERHEAD) / DEPOSIT_PRESIGN_WEIGHT;
        // Let's make sure that the max_signatures isn't limiting us;
        more_asserts::assert_lt!(max_deposits, max_signatures as usize);

        for _ in 0..max_deposits {
            packager.insert_item(RequestItem::no_votes().sig_required());
        }
        assert_eq!(
            packager.total_presign_size,
            max_deposits * DEPOSIT_PRESIGN_WEIGHT + BAG_OVERHEAD
        );

        // The next deposit should be rejected because it would exceed the limit.
        let before = packager.total_presign_size;
        packager.insert_item(RequestItem::no_votes().sig_required());
        assert_eq!(packager.total_presign_size, before);

        // Verify that a withdrawal (93 bytes) is also rejected.
        packager.insert_item(RequestItem::no_votes().wid(1));
        assert_eq!(packager.total_presign_size, before);
    }

    /// Verify that [`DepositRequest::presign_weight`] equals the standalone
    /// protobuf `encoded_len()` of the `OutPoint` plus the
    /// [`PROTOBUF_ENCODED_SIZE_OVERHEAD`] (field tag + length varint)
    /// incurred when the item is embedded in a `TxRequestIds.deposits`
    /// repeated field.
    #[test]
    fn deposit_presign_weight_matches_proto_encoding() {
        let mut rng = get_rng();

        let secret_key = secp256k1::SecretKey::new(&mut rng);
        let signers_public_key = secret_key.x_only_public_key(secp256k1::SECP256K1).0;

        for _ in 0..10 {
            let deposit = DepositRequest {
                outpoint: Unit.fake_with_rng::<bitcoin::OutPoint, _>(&mut rng),
                max_fee: 10_000,
                signer_bitmap: BitArray::ZERO,
                amount: 100_000,
                deposit_script: bitcoin::ScriptBuf::new(),
                reclaim_script_hash: TaprootScriptHash::zeros(),
                signers_public_key,
            };

            let proto_outpoint = proto::OutPoint::from(deposit.outpoint);
            let encoded_length = proto_outpoint.encode_to_vec().len();
            let encoded_length_with_overhead = encoded_length + PROTOBUF_ENCODED_SIZE_OVERHEAD;

            assert_eq!(encoded_length_with_overhead, deposit.presign_weight());
        }
    }

    /// Verify that [`WithdrawalRequest::presign_weight`] equals the
    /// standalone protobuf `encoded_len()` of the `QualifiedRequestId`
    /// plus the [`PROTOBUF_ENCODED_SIZE_OVERHEAD`] (field tag + length
    /// varint) incurred when the item is embedded in a
    /// `TxRequestIds.withdrawals` repeated field.
    #[test]
    fn withdrawal_presign_weight_matches_proto_encoding() {
        let mut rng = get_rng();

        for _ in 0..10 {
            let withdrawal = WithdrawalRequest {
                request_id: fake::Faker.fake_with_rng::<u64, _>(&mut rng),
                txid: fake::Faker.fake_with_rng(&mut rng),
                block_hash: fake::Faker.fake_with_rng(&mut rng),
                amount: 50_000,
                max_fee: 10_000,
                script_pubkey: fake::Faker.fake_with_rng::<ScriptPubKey, _>(&mut rng),
                signer_bitmap: BitArray::ZERO,
            };

            let proto_qualified_id = proto::QualifiedRequestId::from(withdrawal.qualified_id());
            let encoded_length = proto_qualified_id.encode_to_vec().len();
            let encoded_length_with_overhead = encoded_length + PROTOBUF_ENCODED_SIZE_OVERHEAD;

            assert_eq!(encoded_length_with_overhead, withdrawal.presign_weight());
        }
    }

    /// Verify that [`SIGNED_MESSAGE_OVERHEAD`] covers the protobuf
    /// overhead of wrapping a `BitcoinPreSignRequest` inside a
    /// `Signed<SignerMessage>`.
    ///
    /// The gossipsub `max_transmit_size` check is on the encoded
    /// `Signed<SignerMessage>` bytes passed to
    /// `gossipsub::Behaviour::publish`, not the gossipsub wire frame.
    /// So the only overhead is the `Signed` and `SignerMessage` protobuf
    /// wrapper fields.
    ///
    /// The overhead varies slightly with payload size because protobuf
    /// length varints grow with the encoded length. This test measures
    /// both extremes (empty and large payload) to show the maximum
    /// possible overhead and that `SIGNED_MESSAGE_OVERHEAD` covers it.
    #[test]
    fn signed_message_overhead_covers_wrapper() {
        let mut rng = get_rng();

        let private_key = PrivateKey::new(&mut rng);
        let digest: [u8; 32] = [0xff; 32];
        let signature = private_key.sign_ecdsa(&secp256k1::Message::from_digest(digest));
        let public_key = PublicKey::from_private_key(&private_key);
        let chain_tip = BitcoinBlockHash::from([0xff; 32]);

        // Helper: measure overhead for a given BitcoinPreSignRequest.
        let measure_overhead = |presign_request: BitcoinPreSignRequest| -> usize {
            let presign_request_size =
                crate::proto::BitcoinPreSignRequest::from(presign_request.clone()).encoded_len();
            let signed = Signed {
                inner: SignerMessage {
                    bitcoin_chain_tip: chain_tip,
                    payload: Payload::BitcoinPreSignRequest(presign_request),
                },
                signature,
                signer_public_key: public_key,
            };
            let signed_size = crate::proto::Signed::from(signed).encoded_len();
            signed_size - presign_request_size
        };

        // With an empty presign_request the length varints are minimal (1 byte each).
        let empty_overhead = measure_overhead(BitcoinPreSignRequest {
            request_package: Vec::new(),
            fee_rate: 0.0,
            last_fees: None,
        });

        // With a large PSR (~MAX_PRESIGN_REQUEST_SIZE bytes) the length
        // varints are at their largest (3 bytes each for ~64 KiB values).
        // We fill the request_package with enough deposits to reach the
        // target size.
        let deposits_needed = MAX_PRESIGN_REQUEST_SIZE / DEPOSIT_PRESIGN_WEIGHT;
        let large_presign_request = BitcoinPreSignRequest {
            request_package: vec![crate::bitcoin::validation::TxRequestIds {
                deposits: std::iter::repeat_n(
                    bitcoin::OutPoint {
                        txid: bitcoin::Txid::from_byte_array([0xff; 32]),
                        vout: u32::MAX,
                    },
                    deposits_needed,
                )
                .collect(),
                withdrawals: Vec::new(),
            }],
            fee_rate: 25.0,
            last_fees: Some(Fees { total: u64::MAX, rate: 25.0 }),
        };
        let large_overhead = measure_overhead(large_presign_request);

        // The large-payload overhead is the worst case because the length
        // varints are at their maximum. Assert the exact measured values
        // so this test catches any proto schema changes that affect the
        // overhead.
        more_asserts::assert_ge!(empty_overhead, 162);
        more_asserts::assert_le!(empty_overhead, 164);
        more_asserts::assert_ge!(large_overhead, 166);
        more_asserts::assert_le!(large_overhead, 168);
        more_asserts::assert_ge!(SIGNED_MESSAGE_OVERHEAD, large_overhead);
    }

    /// End-to-end test that the BestFitPackager produces packages whose
    /// serialized `Signed<SignerMessage>` encoding fits within
    /// [`GOSSIPSUB_MAX_TRANSMIT_SIZE`].
    ///
    /// In this test we: generate many random deposit and withdrawal
    /// requests, package them with [`BestFitPackager`], convert each bag
    /// to [`TxRequestIds`], build a [`BitcoinPreSignRequest`], wrap it in
    /// a `Signed<SignerMessage>`, and assert the final encoded size is
    /// within limits.
    #[test_case::test_case(true, 2000, 2000; "with-shuffling")]
    #[test_case::test_case(false, 2000, 2000; "without-shuffling")]
    #[test_case::test_case(false, 0, 2000; "without-shuffling-no-deposits")]
    #[test_case::test_case(false, 2000, 0; "without-shuffling-no-withdrawals")]
    fn presign_request_respects_gossipsub_limits(
        shuffling: bool,
        num_deposits: u64,
        num_withdrawals: u64,
    ) {
        let mut rng = get_rng();

        // Generate a large mix of random deposits and withdrawals.
        // Use enough items to stress the packager and fill multiple bags.
        let secret_key = secp256k1::SecretKey::new(&mut rng);
        let signers_public_key = secret_key.x_only_public_key(secp256k1::SECP256K1).0;

        let deposits: Vec<DepositRequest> = (0..num_deposits)
            .map(|_| DepositRequest {
                outpoint: Unit.fake_with_rng::<bitcoin::OutPoint, _>(&mut rng),
                max_fee: 10_000,
                signer_bitmap: BitArray::ZERO,
                amount: 100_000,
                deposit_script: bitcoin::ScriptBuf::new(),
                reclaim_script_hash: TaprootScriptHash::zeros(),
                signers_public_key,
            })
            .collect();

        let withdrawals: Vec<WithdrawalRequest> = (0..num_withdrawals)
            .map(|request_id| WithdrawalRequest {
                request_id,
                txid: fake::Faker.fake_with_rng(&mut rng),
                block_hash: fake::Faker.fake_with_rng(&mut rng),
                amount: 50_000,
                max_fee: 10_000,
                script_pubkey: fake::Faker.fake_with_rng::<ScriptPubKey, _>(&mut rng),
                signer_bitmap: BitArray::ZERO,
            })
            .collect();

        let mut items: Vec<RequestRef> = deposits
            .iter()
            .map(RequestRef::Deposit)
            .chain(withdrawals.iter().map(RequestRef::Withdrawal))
            .collect();

        if shuffling {
            // Let's shuffle so that deposits don't take up all of the
            // vbyte space in the transaction package. However, this limits
            // the number of withdrawals that can fit because the OP_RETURN
            // bitmap fills up more quickly.
            items.shuffle(&mut rng);
        }

        let max_votes_against = 3;
        let max_needs_signature = crate::DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX;

        // Time to package the above items. We do so manually, instead of
        // going through the `compute_optimal_packages` function, so that
        // we can set the max_total_vsize to a large value to make sure
        // that we stop producing bags because of the pre-sign request
        // size. We also want to inspect the total_presign_size and check
        // it against reality.
        let mut config = PackagerConfig::new(max_votes_against, max_needs_signature);
        // We want the max_total_vsize to be as large as possible to make
        // sure that we only stop adding items because of the pre-sign
        // request size.
        config.max_total_vsize = u64::MAX;
        let mut packager = BestFitPackager::new(config);

        for item in items {
            packager.insert_item(item);
        }

        let estimated_size = packager.total_presign_size;
        let bags = packager.finalize();

        // Build a BitcoinPreSignRequest from all bags, mimicking the code in
        // SbtcRequests::construct_transactions.
        let request_package: Vec<TxRequestIds> = bags
            .map(|bag| TxRequestIds::from(&crate::bitcoin::utxo::Requests::new(bag)))
            .collect();

        // In local runs the bag count has been between 18 and 20.
        let num_bags = request_package.len();
        // The packager enforces the presign serialization size limits
        // using only request identifiers; it does not include `fee_rate`
        // or `last_fees` in that estimate. For this check we build a
        // `BitcoinPreSignRequest` with `fee_rate` 0.0 and `last_fees` None
        // so the encoded size matches what the packager assumed.
        let mut presign = BitcoinPreSignRequest {
            request_package,
            fee_rate: 0.0,
            last_fees: None,
        };

        let proto_presign = crate::proto::BitcoinPreSignRequest::from(presign.clone());
        let actual_size = proto_presign.encoded_len();

        // Both the actual size and the estimated size must be less than the
        // MAX_PRESIGN_REQUEST_SIZE.
        more_asserts::assert_le!(actual_size, MAX_PRESIGN_REQUEST_SIZE);
        more_asserts::assert_le!(estimated_size, MAX_PRESIGN_REQUEST_SIZE);

        // `BAG_OVERHEAD` assumes the worst case for each nested
        // `TxRequestIds` in `request_package`: a 1-byte field tag plus a
        // 3-byte length varint (4 bytes total). This worst case covers
        // bags whose encoded `TxRequestIds` reaches >= 16384 bytes, such
        // as a withdrawal-heavy bag. Smaller bags use fewer varint bytes,
        // so the real overhead can be 2 or 3 bytes per bag, making our
        // running total conservatively high. The two asserts below require
        // `actual_size <= estimated_size` and allow at most two bytes of
        // slack per bag to make up for our potential overestimate.
        more_asserts::assert_le!(estimated_size - num_bags * 2, actual_size);
        more_asserts::assert_le!(actual_size, estimated_size);

        // Now we add in the fee rate and some last fees to make the final
        // check more realistic.
        presign.fee_rate = 25.1234567;
        presign.last_fees = Some(Fees {
            total: u64::MAX,
            rate: 25.1234567,
        });

        // Wrap the presign request in a Signed<SignerMessage>, since the
        // signed message is what gets encoded and broadcast.
        let private_key = PrivateKey::new(&mut rng);
        let digest: [u8; 32] = [0xff; 32];
        let signature = private_key.sign_ecdsa(&secp256k1::Message::from_digest(digest));
        let public_key = PublicKey::from_private_key(&private_key);
        let chain_tip = BitcoinBlockHash::from([0xff; 32]);

        let signed = Signed {
            inner: SignerMessage {
                bitcoin_chain_tip: chain_tip,
                payload: Payload::BitcoinPreSignRequest(presign),
            },
            signature,
            signer_public_key: public_key,
        };

        // Now let's make sure that the encoded size is less than the
        // protocol limit.
        let encoded_size = crate::proto::Signed::from(signed).encoded_len();

        more_asserts::assert_le!(encoded_size, GOSSIPSUB_MAX_TRANSMIT_SIZE);
    }
}
