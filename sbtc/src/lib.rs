//! # SBTC Common Library
//!
//! This library provides common functionality for the sBTC project, including logging setup
use std::sync::LazyLock;

use bitcoin::XOnlyPublicKey;

pub mod deposits;
pub mod error;
pub mod events;
pub mod idpack;
pub mod leb128;
pub mod signer_keys;

pub use signer_keys::KeySetId;
pub use signer_keys::SignerKeySet;
pub use signer_keys::derive_signing_public_key;
pub use signer_keys::derive_signing_secret_key;

#[cfg(any(test, feature = "webhooks"))]
pub mod webhooks;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// Maximum number of signing keys in a v2 key set.
///
/// The Ledger Bitcoin app has two relevant, distinct limits:
///
/// - `multi_a` and `sortedmulti_a` expressions support at most 16 public keys.
///   The parser applies the app's
///   [`MAX_PUBKEYS_PER_MULTISIG`](https://github.com/LedgerHQ/app-bitcoin/blob/58ab28b388c659afd47fa361b93c6117b883c941/src/common/wallet.h#L17-L19)
///   limit to these expressions
///   [here](https://github.com/LedgerHQ/app-bitcoin/blob/58ab28b388c659afd47fa361b93c6117b883c941/src/common/wallet.c#L1782-L1796).
/// - A wallet policy may contain at most 15 public keys, as defined by
///   [`MAX_N_KEYS_IN_WALLET_POLICY`](https://github.com/LedgerHQ/app-bitcoin/blob/58ab28b388c659afd47fa361b93c6117b883c941/src/common/wallet.h#L46-L48).
///
/// This protocol-level cap follows the 16-key `multi_a` limit.
/// Also, see <https://github.com/stacks-sbtc/sbtc/issues/1694>.
pub const MAX_SIGNERS: usize = 16;

/// The x-coordinate public key with no known discrete logarithm.
///
/// # Notes
///
/// This particular X-coordinate was discussed in the original taproot BIP
/// on spending rules BIP-0341[1]. Specifically, the X-coordinate is formed
/// by taking the hash of the standard uncompressed encoding of the
/// secp256k1 base point G as the X-coordinate. In that BIP the authors
/// wrote the X-coordinate that is reproduced below.
///
/// [1]: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
#[rustfmt::skip]
pub const NUMS_X_COORDINATE: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
    0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
    0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Returns a public key with no known private key, since it has no known
/// discrete logarithm.
///
/// # Notes
///
/// This function returns the public key to used in the key-spend path of
/// the taproot `scriptPubKey`. Since we do not want a key-spend path for
/// sBTC deposit transactions, this public key is such that it does not
/// have a known private key.
pub static UNSPENDABLE_TAPROOT_KEY: LazyLock<XOnlyPublicKey> =
    LazyLock::new(|| XOnlyPublicKey::from_slice(&NUMS_X_COORDINATE).unwrap());

/// This is the number of bitcoin blocks that the signers will wait before
/// acting on a withdrawal request. We do this to ensure that the
/// withdrawal request is deemed final on the Stacks blockchain.
///
/// The value here was taken from the last paragraph of the opening comment
/// of https://github.com/stacks-network/sbtc/discussions/12 and in the
/// comments of https://github.com/stacks-network/sbtc/issues/16.
pub const WITHDRAWAL_MIN_CONFIRMATIONS: u64 = 6;

/// The maximum length, in bytes, of the portion of a reclaim script that
/// follows the `<lock-time> OP_CSV`.
///
/// This value was chosen to allow for most known reclaim scripts, while
/// keeping potential storage costs low on Emily.
pub const MAX_RECLAIM_SCRIPT_LENGTH: usize = 2048;
