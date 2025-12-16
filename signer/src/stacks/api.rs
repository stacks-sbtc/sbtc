//! A module with structs that interact with the Stacks API.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::future::Future;
use std::ops::RangeInclusive;
use std::sync::LazyLock;
use std::time::Duration;
use std::time::Instant;

use bitcoin::Amount;
use bitcoin::OutPoint;
use blockstack_lib::burnchains::Txid;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
use blockstack_lib::chainstate::stacks::StacksBlock as PreNakamotoBlock;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::chainstate::stacks::TokenTransferMemo;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::chainstate::stacks::db::blocks::MINIMUM_TX_FEE_RATE_PER_BYTE;
use blockstack_lib::clarity::vm::types::PrincipalData;
use blockstack_lib::clarity::vm::types::StandardPrincipalData;
use blockstack_lib::codec::StacksMessageCodec as _;
use blockstack_lib::net::api::getaccount::AccountEntryResponse;
use blockstack_lib::net::api::getcontractsrc::ContractSrcResponse;
use blockstack_lib::net::api::getsortition::SortitionInfo;
use blockstack_lib::net::api::postfeerate::FeeRateEstimateRequestBody;
use blockstack_lib::net::api::postfeerate::RPCFeeEstimate;
use blockstack_lib::net::api::postfeerate::RPCFeeEstimateResponse;
use blockstack_lib::types::chainstate::StacksAddress;
use blockstack_lib::types::chainstate::StacksBlockId;
use clarity::types::chainstate::BlockHeaderHash;
use clarity::vm::Value;
use clarity::vm::types::OptionalData;
use clarity::vm::types::TupleData;
use clarity::vm::types::{BuffData, ListData, SequenceData};
use reqwest::StatusCode;
use reqwest::header::CONTENT_LENGTH;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Deserializer};
use url::Url;

use crate::config::Settings;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::metrics::Metrics;
use crate::storage::DbRead as _;
use crate::storage::DbWrite as _;
use crate::storage::Transactable;
use crate::storage::TransactionHandle as _;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinBlockHeight;
use crate::storage::model::ConsensusHash;
use crate::storage::model::StacksBlock;
use crate::storage::model::StacksBlockHash;
use crate::storage::model::StacksBlockHeight;
use crate::storage::model::StacksTxId;
use crate::storage::model::ToLittleEndianOrder as _;
use crate::util::ApiFallbackClient;

use super::contracts::AsTxPayload;
use super::contracts::SmartContract;
use super::wallet::SignerWallet;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The multiplier to use when estimating the fee based on payload-size.
const TX_FEE_TX_SIZE_MULTIPLIER: u64 = 2 * MINIMUM_TX_FEE_RATE_PER_BYTE;

/// The max fee in microSTX for a stacks transaction. Used as a backstop in
/// case the stacks node returns wonky values. This is 10 STX.
const MAX_TX_FEE: u64 = 10_000_000;

const EPOCH_3_0_ID: &str = "Epoch30";

/// This is the name of the MAP in the sbtc-registry smart contract that
/// stores the status of a withdrawal request.
const WITHDRAWAL_STATUS_MAP_NAME: &str = "withdrawal-status";

/// This is the name of the read-only function in the sbtc-registry smart
/// contract that returns the status of a deposit request.
const GET_DEPOSIT_STATUS_FN_NAME: &str = "get-deposit-status";

/// This is the name of the read-only function in the sbtc-registry smart
/// contract that returns the current signer set data.
const GET_SIGNER_SET_DATA_FN_NAME: &str = "get-current-signer-data";

/// This is the name of the read-only function in the sbtc-token smart
/// contract that returns the total supply of sBTC.
const GET_TOTAL_SUPPLY_FN_NAME: &str = "get-total-supply";

/// This is the name of the data variable in the sbtc-registry smart contract
/// that stores the current aggregate public key of the signers.
const CURRENT_AGGREGATE_PUBKEY_DATA_VAR_NAME: &str = "current-aggregate-pubkey";

/// This is a dummy STX transfer payload used only for estimating STX
/// transfer costs.
static DUMMY_STX_TRANSFER_PAYLOAD: LazyLock<TransactionPayload> = LazyLock::new(|| {
    TransactionPayload::TokenTransfer(
        PrincipalData::Standard(StandardPrincipalData::null_principal()),
        0,
        TokenTransferMemo([0; 34]),
    )
});

/// The names of all the read-only functions, data variables, and map names
/// used in the signers for any of the sbtc smart contracts.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct ClarityName(pub &'static str);

impl std::fmt::Display for ClarityName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

trait ExtractFee {
    fn extract_fee(&self, priority: FeePriority) -> Option<RPCFeeEstimate>;
}

impl ExtractFee for RPCFeeEstimateResponse {
    fn extract_fee(&self, priority: FeePriority) -> Option<RPCFeeEstimate> {
        // As of this writing the RPC response includes exactly 3 estimates
        // (the low, medium, and high priority estimates). It's noteworthy
        // if this changes so we log it but the code here is robust to such
        // a change.
        let num_estimates = self.estimations.len();
        if num_estimates != 3 {
            tracing::info!("Unexpected number of fee estimates: {num_estimates}");
        }

        // Use pattern matching to directly access the low, medium, and high estimates
        match priority {
            FeePriority::Low => self
                .estimations
                .iter()
                .min_by_key(|estimate| estimate.fee)
                .cloned(),
            FeePriority::Medium => {
                let mut sorted_estimations = self.estimations.clone();
                sorted_estimations.sort_by_key(|estimate| estimate.fee);
                sorted_estimations.get(num_estimates / 2).cloned()
            }
            FeePriority::High => self
                .estimations
                .iter()
                .max_by_key(|estimate| estimate.fee)
                .cloned(),
        }
    }
}

/// An enum representing the types of estimates returns by the stacks node.
///
/// The when a stacks node returns an estimate for the transaction fee it
/// returns a Low, middle, and High fee. It has a few fee different
/// estimators for arriving at the returned estimates. One uses a weighted
/// percentile approach where "larger" transactions have move weight[1],
/// while another is uses the execution cost and takes the 5th, 50th, and
/// 95th percentile of fees[2].
///
/// [^1]: https://github.com/stacks-network/stacks-core/blob/47db1d0a8bf70eda1c93cb3e0731bdf5595f7baa/stackslib/src/cost_estimates/fee_medians.rs#L33-L51
/// [^2]: https://github.com/stacks-network/stacks-core/blob/47db1d0a8bf70eda1c93cb3e0731bdf5595f7baa/stackslib/src/cost_estimates/fee_scalar.rs#L30-L42
#[derive(Debug, Clone, Copy)]
pub enum FeePriority {
    /// Think of it as the 5th percentile of all fees by execution cost.
    Low,
    /// Think of it as the 50th percentile of all fees by execution cost.
    Medium,
    /// Think of it as the 95th percentile of all fees by execution cost.
    High,
}

/// Structure describing the info about signer set currently stored in the
/// sbtc-registry smart contract on Stacks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct SignerSetInfo {
    /// The aggregate key of the most recently confirmed key rotation
    /// contract call on Stacks.
    pub aggregate_key: PublicKey,
    /// The set of sBTC signers public keys.
    pub signer_set: BTreeSet<PublicKey>,
    /// The number of signatures required to sign a transaction.
    /// This is the number of signature shares necessary to successfully sign a
    /// bitcoin transaction spending a UTXO locked with the above aggregate key,
    /// and the number of signers necessary to sign a Stacks transaction under
    /// the signers' principal.
    pub signatures_required: u16,
}

/// A trait detailing the interface with the Stacks API and Stacks Nodes.
#[cfg_attr(any(test, feature = "testing"), mockall::automock)]
pub trait StacksInteract: Send + Sync {
    /// Retrieve the current signers set data from the `sbtc-registry`
    /// smart contract.
    ///
    /// This is done by making a `POST /v2/contracts/call-read/<contract-principal>/sbtc-registry/get-current-signer-data`
    /// request.
    fn get_current_signer_set_info(
        &self,
        contract_principal: &StacksAddress,
    ) -> impl Future<Output = Result<Option<SignerSetInfo>, Error>> + Send;

    /// Retrieve the current signers' aggregate key from the `sbtc-registry` contract.
    ///
    /// This is done by making a `GET /v2/data_var/<contract-principal>/sbtc-registry/current-aggregate-pubkey`
    /// request.
    fn get_current_signers_aggregate_key(
        &self,
        contract_principal: &StacksAddress,
    ) -> impl Future<Output = Result<Option<PublicKey>, Error>> + Send;

    /// Retrieve a boolean value from the stacks node indicating whether
    /// sBTC has been minted for the deposit request.
    ///
    /// The request is made to `POST
    /// /v2/contracts/call-read/<contract-principal>/sbtc-registry/get-deposit-status`.
    fn is_deposit_completed(
        &self,
        contract_principal: &StacksAddress,
        outpoint: &OutPoint,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// Retrieve a boolean value from the stacks node indicating whether
    /// the withdrawal request has a response transaction either accepting
    /// or rejecting the request.
    ///
    /// The request is made to `POST
    /// /v2/map_entry/<contract-principal>/<contract-name>/<map-name>`
    fn is_withdrawal_completed(
        &self,
        contract_principal: &StacksAddress,
        request_id: u64,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// Get the latest account info for the given address.
    fn get_account(
        &self,
        address: &StacksAddress,
    ) -> impl Future<Output = Result<AccountInfo, Error>> + Send;

    /// Submit a transaction to a Stacks node.
    fn submit_tx(
        &self,
        tx: &StacksTransaction,
    ) -> impl Future<Output = Result<SubmitTxResponse, Error>> + Send;

    /// Fetch the raw stacks nakamoto block from a Stacks node given the
    /// Stacks block ID.
    fn get_block(
        &self,
        block_id: &StacksBlockHash,
    ) -> impl Future<Output = Result<NakamotoBlock, Error>> + Send;

    /// Returns `Ok` if the given block ID is a pre-Nakamoto block, otherwise
    /// (the block doesn't exist or is a Nakamoto one) `Err` is returned.
    fn check_pre_nakamoto_block(
        &self,
        block_id: &StacksBlockHash,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Get information about the current tenure.
    ///
    /// This function is analogous to the GET /v3/tenures/info stacks node
    /// endpoint for retrieving tenure information.
    fn get_tenure_info(&self) -> impl Future<Output = Result<GetTenureInfoResponse, Error>> + Send;
    /// Get information about the sortition associated to a consensus hash
    fn get_sortition_info(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> impl Future<Output = Result<SortitionInfo, Error>> + Send;
    /// Estimate the priority transaction fees given the input transaction
    /// and the current state of the mempool. The result will be the
    /// estimated total transaction fee in microSTX.
    ///
    /// This function usually uses the POST /v2/fees/transaction endpoint
    /// of a stacks node.
    #[cfg_attr(any(test, feature = "testing"), mockall::concretize)]
    fn estimate_fees<T>(
        &self,
        wallet: &SignerWallet,
        payload: &T,
        priority: FeePriority,
    ) -> impl Future<Output = Result<u64, Error>> + Send
    where
        T: AsTxPayload + Send + Sync;

    /// Attempt to get information from a Stacks node about whether or not it is
    /// in a pre- or post-Nakamoto epoch (3.0).
    ///
    /// Returns a [`StacksEpochStatus`] variant if successful. If the Stacks node
    /// does not report an entry for Epoch 3.0, then an
    /// [`Error::MissingNakamotoStartHeight`] error is returned.
    fn get_epoch_status(&self) -> impl Future<Output = Result<StacksEpochStatus, Error>> + Send;

    /// Get information about the current node.
    fn get_node_info(&self) -> impl Future<Output = Result<GetNodeInfoResponse, Error>> + Send;

    /// Get the source of a deployed smart contract.
    ///
    /// # Notes
    ///
    /// This is useful just to know whether a contract has been deployed
    /// already or not. If the smart contract has not been deployed yet,
    /// the stacks node returns a 404 Not Found.
    fn get_contract_source(
        &self,
        address: &StacksAddress,
        contract_name: &str,
    ) -> impl Future<Output = Result<ContractSrcResponse, Error>> + Send;

    /// Get the total supply of sBTC from the `sbtc-token` smart contract.
    fn get_sbtc_total_supply(
        &self,
        sender: &StacksAddress,
    ) -> impl Future<Output = Result<Amount, Error>> + Send;

    /// Get tenure headers for given bitcoin block height
    fn get_tenure_headers(
        &self,
        burnchain_block_height: BitcoinBlockHeight,
    ) -> impl Future<Output = Result<TenureBlockHeaders, Error>> + Send;
}

/// A slimmed down [`NakamotoBlockHeader`]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StacksBlockHeader {
    /// The total number of StacksBlocks and NakamotoBlocks preceding this
    /// block in this block's history.
    pub block_height: StacksBlockHeight,
    /// The identifier for a block. It is the hash of the this block's
    /// header hash and the block's consensus hash.
    pub block_id: StacksBlockHash,
    /// The index block hash of the immediate parent of this block. This is
    /// the hash of the parent block's hash and consensus hash.
    pub parent_block_id: StacksBlockHash,
}

impl From<NakamotoBlockHeader> for StacksBlockHeader {
    fn from(value: NakamotoBlockHeader) -> Self {
        StacksBlockHeader {
            block_height: value.chain_length.into(),
            block_id: value.block_id().into(),
            parent_block_id: value.parent_block_id.into(),
        }
    }
}

/// This struct represents a non-empty subset of the Stacks block headers
/// that were created during a tenure.
#[derive(Debug, PartialEq)]
#[cfg_attr(any(test, feature = "testing"), derive(Clone))]
pub struct TenureBlockHeaders {
    /// The subset of Stacks block headers that of Nakamoto blocks that
    /// were created during a tenure. This is always non-empty.
    headers: Vec<StacksBlockHeader>,
    /// The bitcoin block that this tenure builds off of.
    pub anchor_block_hash: BitcoinBlockHash,
    /// The height of the bitcoin block associated with the above block
    /// hash.
    pub anchor_block_height: BitcoinBlockHeight,
}

impl TenureBlockHeaders {
    /// Get all the headers contained in this object.
    ///
    /// # Note
    ///
    /// * The returned slice is nonempty.
    /// * The struct doesn't need to contain all the headers of stacks
    ///   blocks in a tenure.
    pub fn headers(&self) -> &[StacksBlockHeader] {
        &self.headers
    }

    /// Create a new one
    pub fn try_new(headers: Vec<StacksBlockHeader>, info: SortitionInfo) -> Result<Self, Error> {
        if headers.is_empty() {
            return Err(Error::EmptyStacksTenure);
        }
        Ok(Self {
            headers,
            anchor_block_hash: info.burn_block_hash.into(),
            anchor_block_height: info.burn_block_height.into(),
        })
    }

    /// Get the minimum block height in the tenure.
    pub fn start_height(&self) -> StacksBlockHeight {
        // SAFETY: It is okay to unwrap here because we know that the
        // tenure is non-empty. The struct upholds this invariant upon
        // creation.
        self.headers.iter().map(|h| h.block_height).min().unwrap()
    }

    /// Get the height of the block with the greatest height of all blocks
    /// held within this struct.
    pub fn end_height(&self) -> StacksBlockHeight {
        // SAFETY: It is okay to unwrap here because we know that the
        // tenure is non-empty. The struct upholds this invariant upon
        // creation.
        self.headers.iter().map(|h| h.block_height).max().unwrap()
    }
}

/// An iterator over [`StacksBlock`]s
pub struct StacksBlockIter {
    /// The underlying iterator
    iter: std::vec::IntoIter<StacksBlockHeader>,
    /// The bitcoin block that this tenure builds off of.
    anchor_block_hash: BitcoinBlockHash,
}

impl Iterator for StacksBlockIter {
    type Item = StacksBlock;
    fn next(&mut self) -> Option<Self::Item> {
        let header = self.iter.next()?;
        Some(StacksBlock {
            block_hash: header.block_id,
            block_height: header.block_height,
            parent_hash: header.parent_block_id,
            bitcoin_anchor: self.anchor_block_hash,
        })
    }
}

impl std::iter::IntoIterator for TenureBlockHeaders {
    type Item = StacksBlock;
    type IntoIter = StacksBlockIter;

    fn into_iter(self) -> Self::IntoIter {
        StacksBlockIter {
            iter: self.headers.into_iter(),
            anchor_block_hash: self.anchor_block_hash,
        }
    }
}

/// These are the rejection reason codes for submitting a transaction
///
/// The official documentation specifies what to expect when there is a
/// rejection, and that documentation can be found here:
/// https://github.com/stacks-network/stacks-core/blob/2.5.0.0.5/docs/rpc-endpoints.md
#[derive(Debug, Clone, Copy, serde::Deserialize, strum::IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(feature = "testing", derive(serde::Serialize))]
pub enum RejectionReason {
    /// From MemPoolRejection::SerializationFailure
    Serialization,
    /// From MemPoolRejection::DeserializationFailure
    Deserialization,
    /// From MemPoolRejection::FailedToValidate
    SignatureValidation,
    /// From MemPoolRejection::FeeTooLow
    FeeTooLow,
    /// From MemPoolRejection::BadNonces
    BadNonce,
    /// From MemPoolRejection::NotEnoughFunds
    NotEnoughFunds,
    /// From MemPoolRejection::NoSuchContract
    NoSuchContract,
    /// From MemPoolRejection::NoSuchPublicFunction
    NoSuchPublicFunction,
    /// From MemPoolRejection::BadFunctionArgument
    BadFunctionArgument,
    /// From MemPoolRejection::ContractAlreadyExists
    ContractAlreadyExists,
    /// From MemPoolRejection::PoisonMicroblocksDoNotConflict
    PoisonMicroblocksDoNotConflict,
    /// From MemPoolRejection::NoAnchorBlockWithPubkeyHash
    PoisonMicroblockHasUnknownPubKeyHash,
    /// From MemPoolRejection::InvalidMicroblocks
    PoisonMicroblockIsInvalid,
    /// From MemPoolRejection::BadAddressVersionByte
    BadAddressVersionByte,
    /// From MemPoolRejection::NoCoinbaseViaMempool
    NoCoinbaseViaMempool,
    /// From MemPoolRejection::NoTenureChangeViaMempool
    NoTenureChangeViaMempool,
    /// From MemPoolRejection::NoSuchChainTip
    ServerFailureNoSuchChainTip,
    /// From MemPoolRejection::ConflictingNonceInMempool
    ConflictingNonceInMempool,
    /// From MemPoolRejection::TooMuchChaining
    TooMuchChaining,
    /// From MemPoolRejection::BadTransactionVersion
    BadTransactionVersion,
    /// From MemPoolRejection::TransferRecipientIsSender
    TransferRecipientCannotEqualSender,
    /// From MemPoolRejection::TransferAmountMustBePositive
    TransferAmountMustBePositive,
    /// From MemPoolRejection::DBError or MemPoolRejection::Other
    ServerFailureDatabase,
    /// From MemPoolRejection::EstimatorError
    EstimatorError,
    /// From MemPoolRejection::TemporarilyBlacklisted
    TemporarilyBlacklisted,
}

/// A rejection response from the node.
///
/// The official documentation specifies what to expect when there is a
/// rejection, and that documentation can be found here:
/// https://github.com/stacks-network/stacks-core/blob/2.5.0.0.5/docs/rpc-endpoints.md
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "testing", derive(serde::Serialize))]
pub struct TxRejection {
    /// The error message. It should always be the string "transaction
    /// rejection".
    pub error: String,
    /// The reason code for the rejection.
    pub reason: RejectionReason,
    /// More details about the reason for the rejection.
    pub reason_data: Option<serde_json::Value>,
    /// The transaction ID of the rejected transaction.
    pub txid: Txid,
}

impl std::fmt::Display for TxRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason_str: &'static str = self.reason.into();
        write!(f, "transaction rejected from stacks mempool: {reason_str}")
    }
}

impl std::error::Error for TxRejection {}

/// The response from a POST /v2/transactions request
///
/// The stacks node returns three types of responses, either:
/// 1. A 200 status hex encoded txid in the response body (on acceptance)
/// 2. A 400 status with a JSON object body (on rejection),
/// 3. A 400/500 status string message about some other error (such as
///    using an unsupported address mode).
///
/// All good with the first response type, but the second response type
/// could be due to the fee being too low or because of a bad nonce. These
/// are retryable "error", so we distinguish them from the third kinds of
/// errors, which are likely not retryable.
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
pub enum SubmitTxResponse {
    /// The transaction ID for the submitted transaction.
    Acceptance(StacksTxId),
    /// The response when the transaction is rejected from the node.
    Rejection(TxRejection),
}

/// The account info for a stacks address.
pub struct AccountInfo {
    /// The total balance of the account in micro-STX. This amount includes
    /// the amount locked.
    pub balance: u128,
    /// The amount locked (stacked) in micro-STX.
    pub locked: u128,
    /// The height of the stacks block where the above locked micro-STX
    /// will be unlocked.
    pub unlock_height: StacksBlockHeight,
    /// The next nonce for the account.
    pub nonce: u64,
}

/// The response from a GET /v2/data_var/<contract-principal>/<contract-name>/<var-name> request.
#[derive(Debug, Deserialize)]
pub struct DataVarResponse {
    /// The value of the data variable.
    #[serde(deserialize_with = "clarity_value_deserializer")]
    pub data: Value,
}

/// The request body for a POST /v2/contracts/call-read/<contract-principal>/<contract-name>/<fn-name> request.
#[derive(Debug, serde::Serialize)]
pub struct CallReadRequest {
    /// The simulated address of the sender.
    pub sender: String,
    /// The arguments to the function in index-order.
    pub arguments: Vec<String>,
}

/// The response from a POST /v2/contracts/call-read/<contract-principal>/<contract-name>/<fn-name> request.
#[derive(Debug, Deserialize)]
pub struct CallReadResponse {
    /// The result of the function call.
    #[serde(deserialize_with = "clarity_value_deserializer")]
    pub result: Value,
}

/// Helper function for converting a hexadecimal string into an integer.
fn parse_hex_u128(hex: &str) -> Result<u128, Error> {
    let hex_str = hex.trim_start_matches("0x");
    u128::from_str_radix(hex_str, 16).map_err(Error::ParseHexInt)
}

impl TryFrom<AccountEntryResponse> for AccountInfo {
    type Error = Error;

    fn try_from(value: AccountEntryResponse) -> Result<Self, Self::Error> {
        Ok(AccountInfo {
            balance: parse_hex_u128(&value.balance)?,
            locked: parse_hex_u128(&value.locked)?,
            nonce: value.nonce,
            unlock_height: value.unlock_height.into(),
        })
    }
}

/// The response from a GET /v2/info request to stacks-core
///
/// This type contains only a subset of the full response from stacks-core,
/// you can find the full response here:
/// <https://github.com/stacks-network/stacks-core/blob/bd9ee6310516b31ef4ecce07e42e73ed0f774ada/stackslib/src/net/api/getinfo.rs#L53-L85>
///
/// Note that the stacks blockchain information here is the same
/// corresponding fields returned from the `/v3/tenures/info` response.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GetNodeInfoResponse {
    /// The height of the tip of the canonical bitcoin blockchain.
    pub burn_block_height: BitcoinBlockHeight,
    /// The version of the stacks node that is connected to this signer.
    pub server_version: String,
    /// The height of the tip of the canonical stacks blockchain.
    pub stacks_tip_height: StacksBlockHeight,
    /// The block header hash of the tip of the canonical stacks
    /// blockchain. This is hashed with the consensus hash to create the
    /// block id.
    pub stacks_tip: BlockHeaderHash,
    /// The consensus hash of the tip of the canonical stacks blockchain.
    pub stacks_tip_consensus_hash: ConsensusHash,
}

impl GetNodeInfoResponse {
    /// Create a StacksBlockHash from the tip information of the canonical
    /// stacks blockchain.
    pub fn stacks_chain_tip(&self) -> StacksBlockHash {
        let bytes = self.stacks_tip_consensus_hash.into_bytes();
        let sortition_consensus_hash = blockstack_lib::chainstate::burn::ConsensusHash(bytes);
        StacksBlockId::new(&sortition_consensus_hash, &self.stacks_tip).into()
    }
}

/// The response from a GET /v3/tenures/info request to stacks-core.
///
/// This type contains the view of this node's current tenure.
#[derive(Debug, PartialEq, Clone, serde::Deserialize)]
pub struct GetTenureInfoResponse {
    /// The highest known consensus hash (identifies the current tenure)
    pub consensus_hash: ConsensusHash,
    /// The tenure-start block ID of the current tenure
    pub tenure_start_block_id: StacksBlockHash,
    /// The consensus hash of the parent tenure
    pub parent_consensus_hash: ConsensusHash,
    /// The block hash of the parent tenure's start block
    pub parent_tenure_start_block_id: StacksBlockHash,
    /// The highest Stacks block ID in the current tenure
    pub tip_block_id: StacksBlockHash,
    /// The height of this tip
    pub tip_height: StacksBlockHeight,
    /// Which reward cycle we're in
    pub reward_cycle: u64,
}

/// Minimal model type representing an epoch entry in a `/v2/pox` response,
/// including only fields which we currently use.
///
/// Specifically, we do *not* use the `StacksEpochId` enum type from stacks-core
/// as it would break if Stacks introduces new epochs prior to our dependencies
/// being updated.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PoxEpoch {
    /// String representation of the epoch ID, e.g. `Epoch11`, `Epoch30`, `Epoch33`, etc.
    epoch_id: String,
    /// The Bitcoin block height at which this epoch activates.
    start_height: BitcoinBlockHeight,
}

/// Minimal response type for the `/v2/pox` endpoint, including only fields
/// which we currently use.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PoxResponse {
    /// The current Bitcoin block height, as known by the Stacks node based on
    /// its current Stacks tenure. Note that if the Stacks node is behind, this
    /// may be lower than the actual current Bitcoin block height.
    current_burnchain_block_height: BitcoinBlockHeight,
    /// The list of all known epochs, including their start heights. Used
    /// primarily to determine the start height of Stacks epoch 3.0 (Nakamoto).
    epochs: Vec<PoxEpoch>,
}

/// Information regarding whether or not we are in pre- or post-Nakamoto era.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StacksEpochStatus {
    /// We are in the pre-Nakamoto era.
    PreNakamoto {
        /// The current Bitcoin block height, as known by the Stacks node based on
        /// its current Stacks tenure. Note that if the Stacks node is behind, this
        /// may be lower than the actual current Bitcoin block height.
        reported_bitcoin_height: BitcoinBlockHeight,
        /// The bitcoin block height at which the Nakamoto era (epoch 3.0+) starts.
        nakamoto_start_height: BitcoinBlockHeight,
    },
    /// We are in the post-Nakamoto era.
    PostNakamoto {
        /// The bitcoin block height at which the Nakamoto era started.
        nakamoto_start_height: BitcoinBlockHeight,
    },
}

impl StacksEpochStatus {
    /// Returns the bitcoin block height at which the Nakamoto era starts (epoch 3.0).
    pub fn nakamoto_start_height(&self) -> BitcoinBlockHeight {
        match self {
            StacksEpochStatus::PreNakamoto { nakamoto_start_height, .. } => *nakamoto_start_height,
            StacksEpochStatus::PostNakamoto { nakamoto_start_height } => *nakamoto_start_height,
        }
    }
}

impl TryFrom<PoxResponse> for StacksEpochStatus {
    type Error = Error;
    fn try_from(value: PoxResponse) -> Result<Self, Self::Error> {
        let current = value.current_burnchain_block_height;
        let maybe_start = value
            .epochs
            .into_iter()
            .find(|e| e.epoch_id == EPOCH_3_0_ID)
            .map(|e| e.start_height);

        match maybe_start {
            Some(start) if current < start => Ok(StacksEpochStatus::PreNakamoto {
                reported_bitcoin_height: current,
                nakamoto_start_height: start,
            }),
            Some(start) => Ok(StacksEpochStatus::PostNakamoto { nakamoto_start_height: start }),
            None => Err(Error::MissingNakamotoStartHeight),
        }
    }
}

/// A client for interacting with Stacks nodes and the Stacks API
#[derive(Debug, Clone)]
pub struct StacksClient {
    /// The base url for the Stacks node's RPC API.
    pub endpoint: Url,
    /// The client used to make the request.
    pub client: reqwest::Client,
}

impl StacksClient {
    /// Create a new instance of the Stacks client using the given
    /// StacksSettings.
    pub fn new(url: Url) -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()?;

        Ok(Self { endpoint: url, client })
    }

    /// Calls a read-only public function on a given smart contract.
    #[tracing::instrument(skip_all)]
    pub async fn call_read(
        &self,
        contract_principal: &StacksAddress,
        contract_name: SmartContract,
        fn_name: ClarityName,
        sender: &StacksAddress,
        arguments: &[Value],
    ) -> Result<Value, Error> {
        let path = format!(
            "/v2/contracts/call-read/{contract_principal}/{contract_name}/{fn_name}?tip=latest"
        );

        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        // Turns out that serializing clarity values to hex can panic. One
        // such case happens when the buff-data is too large, more than one
        // MBs worth. For our uses this should never happen.
        let arguments = arguments
            .iter()
            .map(|value| value.serialize_to_hex())
            .collect::<Result<Vec<String>, _>>()
            .map_err(Box::new)
            .map_err(Error::ClarityValueSerialization)?;

        let body = CallReadRequest {
            sender: sender.to_string(),
            arguments,
        };

        tracing::debug!(
            %contract_principal,
            %contract_name,
            %fn_name,
            "Fetching contract data variable"
        );

        let instant = Instant::now();
        let response = self
            .client
            .post(url)
            .timeout(REQUEST_TIMEOUT)
            .json(&body)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        Metrics::record_call_read(instant.elapsed(), contract_name, fn_name, &response);

        response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .json::<CallReadResponse>()
            .await
            .map_err(Error::UnexpectedStacksResponse)
            .map(|x| x.result)
    }

    /// Retrieve the latest value of a data variable from the specified contract.
    ///
    /// This is done by making a
    /// `GET /v2/data_var/<contract-principal>/<contract-name>/<var-name>`
    /// request. In the request we specify that the proof should not be included
    /// in the response.
    #[tracing::instrument(skip_all)]
    pub async fn get_data_var(
        &self,
        contract_principal: &StacksAddress,
        contract_name: SmartContract,
        var_name: ClarityName,
    ) -> Result<Value, Error> {
        let path = format!("/v2/data_var/{contract_principal}/{contract_name}/{var_name}?proof=0");

        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        tracing::debug!(
            %contract_principal,
            %contract_name,
            %var_name,
            "fetching contract data variable"
        );

        let instant = Instant::now();
        let response = self
            .client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        Metrics::record_data_var(instant.elapsed(), contract_name, var_name, &response);

        response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .json::<DataVarResponse>()
            .await
            .map_err(Error::UnexpectedStacksResponse)
            .map(|x| x.data)
    }

    /// Retrieve the value of a map entry from the specified contract.
    ///
    /// This is done by making a `POST
    /// /v2/map_entry/<contract-principal>/<contract-name>/<map-name>`
    /// request. In the request we specify that the proof should not be
    /// included in the response.
    ///
    /// See here for the source handler of this endpoint:
    /// https://github.com/stacks-network/stacks-core/blob/c1a1f50fddcbc11054fae537103423e21221665a/stackslib/src/net/api/getmapentry.rs#L82-L97
    #[tracing::instrument(skip_all)]
    pub async fn get_map_entry(
        &self,
        contract_principal: &StacksAddress,
        contract_name: SmartContract,
        map_name: ClarityName,
        map_entry: &Value,
    ) -> Result<Option<Value>, Error> {
        let path = format!("/v2/map_entry/{contract_principal}/{contract_name}/{map_name}?proof=0");

        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        tracing::debug!(
            %contract_principal,
            %contract_name,
            %map_name,
            "fetching contract map entry"
        );

        let body = map_entry
            .serialize_to_hex()
            .map_err(Box::new)
            .map_err(Error::ClarityValueSerialization)?;

        let instant = Instant::now();
        let response = self
            .client
            .post(url)
            .timeout(REQUEST_TIMEOUT)
            .json(&serde_json::Value::String(body))
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        Metrics::record_map_entry(instant.elapsed(), contract_name, map_name, &response);
        // It looks like the stacks node returns a 404 if the data is not
        // available, see
        // https://github.com/stacks-network/stacks-core/blob/c1a1f50fddcbc11054fae537103423e21221665a/stackslib/src/net/api/getmapentry.rs#L223-L225C22
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .json::<DataVarResponse>()
            .await
            .map_err(Error::UnexpectedStacksResponse)
            .map(|x| Some(x.data))
    }

    /// Get the latest account info for the given address.
    ///
    /// This is done by making a GET /v2/accounts/<principal> request. In
    /// the request we specify that the nonce and balance proofs should not
    /// be included in the response.
    #[tracing::instrument(skip_all)]
    pub async fn get_account(&self, address: &StacksAddress) -> Result<AccountInfo, Error> {
        let path = format!("/v2/accounts/{address}?proof=0");
        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        tracing::debug!(%address, "fetching the latest account information");

        let response = self
            .client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .json::<AccountEntryResponse>()
            .await
            .map_err(Error::UnexpectedStacksResponse)
            .and_then(AccountInfo::try_from)
    }

    /// Get the source of a deployed smart contract.
    ///
    /// # Notes
    ///
    /// This is done by makes a `GET
    /// /v2/contracts/source/<deployer-address>/<contract-name>?proof=0`
    /// request to the stacks node. This is useful just to know whether a
    /// contract has been deployed already or not. If the smart contract
    /// has not been deployed yet, the stacks node returns a 404 Not Found.
    #[tracing::instrument(skip_all)]
    pub async fn get_contract_source(
        &self,
        address: &StacksAddress,
        contract_name: &str,
    ) -> Result<ContractSrcResponse, Error> {
        let path = format!("/v2/contracts/source/{address}/{contract_name}?proof=0");
        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        let response = self
            .client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .json()
            .await
            .map_err(Error::UnexpectedStacksResponse)
    }

    /// Submit a transaction to a Stacks node.
    ///
    /// This is done by making a POST /v2/transactions request to a Stacks
    /// node. That endpoint supports two different content-types in the
    /// request body: JSON, and an octet-stream. This function always sends
    /// the raw transaction bytes as an octet-stream.
    #[tracing::instrument(skip_all)]
    pub async fn submit_tx(&self, tx: &StacksTransaction) -> Result<SubmitTxResponse, Error> {
        let path = "/v2/transactions";
        let url = self
            .endpoint
            .join(path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Borrowed(path)))?;

        tracing::debug!(txid = %tx.txid(), "submitting transaction to the stacks node");
        let body = tx.serialize_to_vec();

        let response: reqwest::Response = self
            .client
            .post(url)
            .timeout(REQUEST_TIMEOUT)
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_LENGTH, body.len())
            .body(body)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        response
            .json()
            .await
            .map_err(Error::UnexpectedStacksResponse)
    }

    /// Estimate the current mempool transaction fees.
    ///
    /// This is done by making a POST /v2/fees/transaction request to a
    /// Stacks node. The response provides 3 estimates by default, but
    /// sometimes the stacks node cannot estimate the fees. When the node
    /// cannot estimate the fees, it returns a 400 response with a simple
    /// string message. This function does not try to distinguish between
    /// the different error modes.
    ///
    /// The docs for this RPC can be found here:
    /// https://docs.stacks.co/stacks-101/api#v2-fees-transaction
    #[tracing::instrument(skip_all)]
    pub async fn get_fee_estimate<T>(
        &self,
        payload: &T,
        tx_size: Option<u64>,
    ) -> Result<RPCFeeEstimateResponse, Error>
    where
        T: AsTxPayload + Send,
    {
        let path = "/v2/fees/transaction";
        let url = self
            .endpoint
            .join(path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Borrowed(path)))?;

        let tx_payload = payload.tx_payload().serialize_to_vec();
        let request_body = FeeRateEstimateRequestBody {
            estimated_len: tx_size,
            transaction_payload: blockstack_lib::util::hash::to_hex(&tx_payload),
        };
        let body = serde_json::to_string(&request_body).map_err(Error::JsonSerialize)?;

        tracing::debug!("making request to the stacks node for a tx fee estimate");
        let response: reqwest::Response = self
            .client
            .post(url)
            .timeout(REQUEST_TIMEOUT)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .body(body)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        // Only parse the JSON if it's a success status, otherwise return
        // an error.
        response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .json()
            .await
            .map_err(Error::UnexpectedStacksResponse)
    }

    /// Fetch the raw stacks nakamoto block from a Stacks node given the
    /// Stacks block ID.
    ///
    /// # Note
    ///
    /// If the given block ID does not exist or is an ID for a non-Nakamoto
    /// block then a Result::Err is returned.
    #[tracing::instrument(skip(self))]
    async fn get_block(&self, block_id: &StacksBlockHash) -> Result<NakamotoBlock, Error> {
        let path = format!("/v3/blocks/{}", block_id.to_hex());
        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        tracing::debug!("making request to the stacks node for the raw nakamoto block");

        let response = self
            .client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        let resp = response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .bytes()
            .await
            .map_err(Error::UnexpectedStacksResponse)?;

        NakamotoBlock::consensus_deserialize(&mut &*resp)
            .map_err(|err| Error::DecodeNakamotoBlock(err, *block_id))
    }

    /// Returns `Ok` if the given block ID is a pre-Nakamoto block, otherwise
    /// (the block doesn't exist or is a Nakamoto one) `Err` is returned.
    #[tracing::instrument(skip(self))]
    async fn check_pre_nakamoto_block(&self, block_id: &StacksBlockHash) -> Result<(), Error> {
        let path = format!("/v2/blocks/{}", block_id.to_hex());
        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        tracing::debug!("making request to the stacks node for the raw pre-nakamoto block");

        let response = self
            .client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        let resp = response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .bytes()
            .await
            .map_err(Error::UnexpectedStacksResponse)?;

        // Ensure we got a pre nakamoto block, just in case they change the v2
        // API to be forward compatible
        let _ = PreNakamotoBlock::consensus_deserialize(&mut &*resp).map_err(Error::StacksCodec)?;

        Ok(())
    }

    /// Make a GET /v3/tenures/<block-id> request for Nakamoto ancestor
    /// blocks with the same tenure as the given block ID from a Stacks
    /// node, and return the relevant parts of the headers of those blocks.
    ///
    /// # Notes
    ///
    /// * The GET /v3/tenures/<block-id> response is capped at ~16 MB, so a
    ///   single request may not return all Nakamoto blocks.
    /// * The response includes the Nakamoto block for the given block id.
    /// * If the given block ID does not exist or is an ID for a
    ///   non-Nakamoto block then a Result::Err is returned.
    #[tracing::instrument(skip(self))]
    async fn get_tenure_headers_raw(
        &self,
        block_id: &StacksBlockHash,
    ) -> Result<Vec<StacksBlockHeader>, Error> {
        let path = format!("/v3/tenures/{}", block_id.to_hex());
        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        tracing::debug!("making request to the stacks node for the raw nakamoto block");

        let response = self
            .client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        // The response here does not detail the number of blocks in the
        // response. So we essentially take the same implementation given
        // in [`StacksHttpResponse::decode_nakamoto_tenure`], which just
        // keeps decoding until there are no more bytes.
        let resp = response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .bytes()
            .await
            .map_err(Error::UnexpectedStacksResponse)?;

        let bytes: &mut &[u8] = &mut resp.as_ref();
        let mut headers = Vec::new();

        while !bytes.is_empty() {
            let block = NakamotoBlock::consensus_deserialize(bytes)
                .map_err(|err| Error::DecodeNakamotoTenure(err, *block_id))?;

            headers.push(block.header.into());
        }

        Ok(headers)
    }

    /// Get information about the current tenure.
    ///
    /// Uses the GET /v3/tenures/info stacks node endpoint for retrieving
    /// tenure information.
    #[tracing::instrument(skip(self))]
    pub async fn get_tenure_info(&self) -> Result<GetTenureInfoResponse, Error> {
        let path = "/v3/tenures/info";
        let url = self
            .endpoint
            .join(path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Borrowed(path)))?;

        tracing::debug!("making request to the stacks node for the current tenure info");
        let response = self
            .client
            .get(url.clone())
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .json()
            .await
            .map_err(Error::UnexpectedStacksResponse)
    }

    /// Get information about the sortition related to a consensus hash.
    ///
    /// Uses the GET /v3/sortitions stacks node endpoint for retrieving
    /// sortition information.
    #[tracing::instrument(skip(self))]
    pub async fn get_sortition_info(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Result<SortitionInfo, Error> {
        let path = format!("/v3/sortitions/consensus/{consensus_hash}");
        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        tracing::debug!("making request to the stacks node for sortition info");
        let response = self
            .client
            .get(url.clone())
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .json::<Vec<SortitionInfo>>()
            .await
            .map_err(Error::UnexpectedStacksResponse)
            .and_then(|result| {
                // For `consensus` lookups we expect to get a list with a single element
                // https://github.com/stacks-network/stacks-core/blob/40059a57cd27e740c5e9d91a833fb2c975b0bf0b/docs/rpc/openapi.yaml#L693
                result
                    .into_iter()
                    .next()
                    .ok_or(Error::InvalidStacksResponse("missing sortition info"))
            })
    }

    /// Get PoX information from the Stacks node.
    #[tracing::instrument(skip(self))]
    pub async fn get_pox_info(&self) -> Result<PoxResponse, Error> {
        let path = "/v2/pox";
        let url = self
            .endpoint
            .join(path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Borrowed(path)))?;

        tracing::debug!("making request to the stacks node for the current PoX info");
        let response = self
            .client
            .get(url.clone())
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .json()
            .await
            .map_err(Error::UnexpectedStacksResponse)
    }

    /// Get information about the current node.
    #[tracing::instrument(skip(self))]
    pub async fn get_node_info(&self) -> Result<GetNodeInfoResponse, Error> {
        let path = "/v2/info";
        let url = self
            .endpoint
            .join(path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Borrowed(path)))?;

        tracing::debug!("making request to the stacks node for the current node info");
        let response = self
            .client
            .get(url.clone())
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .json()
            .await
            .map_err(Error::UnexpectedStacksResponse)
    }
}

/// Fetch all Nakamoto block headers that are not already stored in the
/// datastore, starting at the given [`StacksBlockHash`] and store them in
/// the database.
///
/// This function fetches all unknown nakamoto blocks that are on the
/// canonical chain identified by the given StacksBlockHash chain tip that
/// not already stored in the database. It fetches these blocks one tenure
/// at a time, and then writes them to the `stacks_blocks` table in a
/// transaction. After all such blocks have been fetched, the function
/// commits the written blocks. Things are done this way to ensure that
/// updates to the `stacks_blocks` table are done atomically.
pub async fn update_db_with_unknown_ancestors<S, D>(
    stacks: &S,
    storage: &D,
    burnchain_block_height: BitcoinBlockHeight,
) -> Result<RangeInclusive<StacksBlockHeight>, Error>
where
    S: StacksInteract,
    D: Transactable + Send + Sync,
{
    let db = storage.begin_transaction().await?;
    let mut tenure = stacks.get_tenure_headers(burnchain_block_height).await?;
    let end_height = tenure.end_height();
    let nakamoto_start_height = stacks.get_epoch_status().await?.nakamoto_start_height();

    let mut anchor_block_height = tenure.anchor_block_height;

    loop {
        db.write_stacks_block_headers(&tenure).await?;
        // We won't get anymore Nakamoto blocks before this point, so
        // time to stop.
        if anchor_block_height <= nakamoto_start_height {
            tracing::debug!(
                %nakamoto_start_height,
                last_chain_length = %tenure.anchor_block_height,
                "all Nakamoto blocks fetched; stopping"
            );
            break;
        }
        // Tenure blocks are always non-empty, and this invariant is upheld
        // by the type. So no need to worry about the early break.
        let Some(header) = tenure.headers().last() else {
            break;
        };
        // We've seen this parent already, so time to stop.
        if db.stacks_block_exists(&header.parent_block_id).await? {
            tracing::debug!("parent block known in the database");
            break;
        }
        // There are more blocks to fetch, so let's get them. This assumes
        // optimistically that the parent is still a Nakamoto block (and so has
        // a tenure); if that's not the case, we get an `Err` here.
        let tenure_headers_result = stacks.get_tenure_headers(anchor_block_height - 1).await;
        anchor_block_height = anchor_block_height - 1;
        let tenure_headers = match tenure_headers_result {
            Ok(tenure_headers) => tenure_headers,
            Err(error) => {
                // A 404 could mean that we reached the Nakamoto start height
                // and we tried fetching a tenure for a pre-Nakamoto block
                if stacks
                    .check_pre_nakamoto_block(&header.parent_block_id)
                    .await
                    .is_ok()
                {
                    tracing::debug!(
                        %nakamoto_start_height,
                        last_chain_length = %tenure.anchor_block_height,
                        "all Nakamoto blocks fetched; stopping"
                    );
                    break;
                }
                // A 404 could also mean there is a bitcoin block with no stacks
                // blocks anchored.
                // TODO: can there be other reasons for a 404?
                if let Error::StacksNodeResponse(ref reqwest_error) = error {
                    if reqwest_error.status() == Some(StatusCode::NOT_FOUND) {
                        continue;
                    }
                }
                return Err(error);
            }
        };
        tenure = tenure_headers;
    }

    let start_height = tenure.start_height();

    db.commit().await?;

    tracing::debug!(%start_height, %end_height, "finished updating the stacks_blocks table");
    Ok(RangeInclusive::new(start_height, end_height))
}

/// A deserializer for Clarity's [`Value`] type that deserializes a hex-encoded
/// string which was serialized using Clarity's consensus serialization format.
fn clarity_value_deserializer<'de, D>(deserializer: D) -> Result<Value, D::Error>
where
    D: Deserializer<'de>,
{
    Value::try_deserialize_hex_untyped(&String::deserialize(deserializer)?)
        .map_err(serde::de::Error::custom)
}

/// Extract a set of public keys from a Clarity value.
///
/// The value is expected to be a sequence of 33 byte buffers, each of
/// which represents a compressed public key.
fn extract_signer_set(value: Value) -> Result<BTreeSet<PublicKey>, Error> {
    match value {
        // Iterate through each record in the list and convert it to a
        // public key. If the record is not a buffer, then return an error.
        Value::Sequence(SequenceData::List(ListData { data, .. })) => {
            data.into_iter().map(extract_public_key).collect()
        }
        // We expected the top-level value to be a list of buffers,
        // but we got something else.
        _ => Err(Error::InvalidStacksResponse(
            "expected a sequence but got something else",
        )),
    }
}

/// Extract a public key from a Clarity value.
///
/// In the sbtc-registry smart contract, public keys are compressed and
/// stored as 33 byte buffers.
fn extract_public_key(value: Value) -> Result<PublicKey, Error> {
    match value {
        Value::Sequence(SequenceData::Buffer(BuffData { data })) => PublicKey::from_slice(&data),
        _ => Err(Error::InvalidStacksResponse(
            "expected a buffer but got something else",
        )),
    }
}

/// Extract a aggregate key from a Clarity value.
///
/// In the sbtc-registry smart contract, the aggregate key is stored in the
/// `current-aggregate-pubkey` data var and is initialized to the 0x00
/// byte, allowing use to distinguish between the initial value and an
/// actual public key in that case. Ok(None) is returned if the value is
/// the initial value.
fn extract_aggregate_key(value: Value) -> Result<Option<PublicKey>, Error> {
    match value {
        Value::Sequence(SequenceData::Buffer(BuffData { data })) => {
            // The initial value of the data var is all zeros
            if data.as_slice() == [0u8] {
                Ok(None)
            } else {
                PublicKey::from_slice(&data).map(Some)
            }
        }
        _ => Err(Error::InvalidStacksResponse(
            "expected a buffer but got something else",
        )),
    }
}

/// Extract a signature threshold from a Clarity value.
///
/// In the sbtc-registry smart contract, the signature threshold is stored
/// in the `current-signature-threshold` data var and is initialized to 0,
/// allowing use to distinguish between the initial value and an actual
/// signature threshold. Ok(None) is returned if the value is the initial
/// value.
fn extract_signatures_required(value: Value) -> Result<Option<u16>, Error> {
    match value {
        Value::UInt(0) => Ok(None),
        Value::UInt(threshold) => Ok(Some(
            threshold.try_into().map_err(|_| Error::TypeConversion)?,
        )),
        _ => Err(Error::InvalidStacksResponse(
            "expected a uint but got something else",
        )),
    }
}

#[derive(Debug, Deserialize)]
struct GetTenureHeadersApiResponse {
    #[serde(rename = "burn_block_height")]
    pub bitcoin_block_height: BitcoinBlockHeight,
    #[serde(rename = "burn_block_hash")]
    pub bitcoin_block_hash: BitcoinBlockHash,
    pub stacks_blocks: Vec<GetTenureHeadersApiStacksBlock>,
}

#[derive(Debug, Deserialize)]
struct GetTenureHeadersApiStacksBlock {
    pub block_id: StacksBlockHash,
    pub parent_block_id: StacksBlockHash,
    pub height: StacksBlockHeight,
}

impl From<GetTenureHeadersApiResponse> for TenureBlockHeaders {
    fn from(value: GetTenureHeadersApiResponse) -> Self {
        TenureBlockHeaders {
            headers: value
                .stacks_blocks
                .iter()
                .map(|header| StacksBlockHeader {
                    block_height: header.height,
                    block_id: header.block_id,
                    parent_block_id: header.parent_block_id,
                })
                .collect::<Vec<StacksBlockHeader>>(),
            anchor_block_hash: value.bitcoin_block_hash,
            anchor_block_height: value.bitcoin_block_height,
        }
    }
}

impl StacksInteract for StacksClient {
    #[tracing::instrument(skip(self))]
    async fn get_tenure_headers(
        &self,
        bitcoin_block_height: BitcoinBlockHeight,
    ) -> Result<TenureBlockHeaders, Error> {
        let path = format!("/v3/tenures/blocks/height/{}", bitcoin_block_height);
        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        tracing::debug!("making request to the stacks node for the tenure headers");

        let headers = self
            .client
            .get(url.clone())
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .json::<GetTenureHeadersApiResponse>()
            .await?
            .into();
        Ok(headers)
    }

    async fn get_current_signer_set_info(
        &self,
        contract_principal: &StacksAddress,
    ) -> Result<Option<SignerSetInfo>, Error> {
        let result = self
            .call_read(
                contract_principal,
                SmartContract::SbtcRegistry,
                ClarityName(GET_SIGNER_SET_DATA_FN_NAME),
                contract_principal,
                &[],
            )
            .await?;

        match result {
            Value::Tuple(TupleData { mut data_map, .. }) => {
                let maybe_aggregate_key = data_map
                    .remove("current-aggregate-pubkey")
                    .map(extract_aggregate_key);
                let maybe_signer_set = data_map
                    .remove("current-signer-set")
                    .map(extract_signer_set);
                let maybe_signatures_required = data_map
                    .remove("current-signature-threshold")
                    .map(extract_signatures_required);

                let Some(Some(aggregate_key)) = maybe_aggregate_key.transpose()? else {
                    return Ok(None);
                };
                let Some(signer_set) = maybe_signer_set.transpose()? else {
                    return Ok(None);
                };
                let Some(Some(signatures_required)) = maybe_signatures_required.transpose()? else {
                    return Ok(None);
                };

                Ok(Some(SignerSetInfo {
                    aggregate_key,
                    signatures_required,
                    signer_set,
                }))
            }
            _ => Err(Error::InvalidStacksResponse(
                "expected a tuple but got something else",
            )),
        }
    }

    async fn get_current_signers_aggregate_key(
        &self,
        contract_principal: &StacksAddress,
    ) -> Result<Option<PublicKey>, Error> {
        let value = self
            .get_data_var(
                contract_principal,
                SmartContract::SbtcRegistry,
                ClarityName(CURRENT_AGGREGATE_PUBKEY_DATA_VAR_NAME),
            )
            .await?;

        extract_aggregate_key(value)
    }

    async fn is_deposit_completed(
        &self,
        deployer: &StacksAddress,
        outpoint: &OutPoint,
    ) -> Result<bool, Error> {
        let contract_name = SmartContract::SbtcRegistry;
        let fn_name = ClarityName(GET_DEPOSIT_STATUS_FN_NAME);

        // The transaction IDs are written in little endian format when
        // making the contract call that sets the deposit status, so we
        // need to do that here to make sure that it works as expected.
        let txid_data = outpoint.txid.to_le_bytes().to_vec();
        let txid = BuffData { data: txid_data };
        let arguments = [
            Value::Sequence(SequenceData::Buffer(txid)),
            Value::UInt(outpoint.vout as u128),
        ];
        let result = self
            .call_read(deployer, contract_name, fn_name, deployer, &arguments)
            .await?;

        // The `get-deposit-status` read-only function retrieves values
        // from a map in the smart contract using the `map-get?` Clarity
        // function. This map stores boolean values, setting them to `true`
        // when a deposit is completed and not setting them otherwise.
        // Therefore, a missing value implicitly means `false`.
        match result {
            Value::Optional(OptionalData { data }) => Ok(data.is_some()),
            _ => Err(Error::InvalidStacksResponse("did not get optional data")),
        }
    }

    async fn is_withdrawal_completed(
        &self,
        deployer: &StacksAddress,
        request_id: u64,
    ) -> Result<bool, Error> {
        let contract_name = SmartContract::SbtcRegistry;
        let map_name = ClarityName(WITHDRAWAL_STATUS_MAP_NAME);

        let map_entry = Value::UInt(request_id as u128);
        let result = self
            .get_map_entry(deployer, contract_name, map_name, &map_entry)
            .await?;

        // This map `withdrawal-status` in the smart contract stores
        // boolean values, setting them to `true` when a withdrawal is
        // accepted and `false` when rejected. Either value means the
        // request has been completed, while a missing value implicitly
        // means that the request has not been completed.
        match result {
            Some(Value::Optional(OptionalData { data })) => Ok(data.is_some()),
            _ => Err(Error::InvalidStacksResponse("did not get optional data")),
        }
    }

    async fn get_account(&self, address: &StacksAddress) -> Result<AccountInfo, Error> {
        self.get_account(address).await
    }

    async fn submit_tx(&self, tx: &StacksTransaction) -> Result<SubmitTxResponse, Error> {
        self.submit_tx(tx).await
    }

    async fn get_block(&self, block_id: &StacksBlockHash) -> Result<NakamotoBlock, Error> {
        self.get_block(block_id).await
    }

    async fn check_pre_nakamoto_block(&self, block_id: &StacksBlockHash) -> Result<(), Error> {
        self.check_pre_nakamoto_block(block_id).await
    }

    async fn get_tenure_info(&self) -> Result<GetTenureInfoResponse, Error> {
        self.get_tenure_info().await
    }

    async fn get_sortition_info(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Result<SortitionInfo, Error> {
        self.get_sortition_info(consensus_hash).await
    }

    /// Estimate the high priority transaction fee for the input
    /// transaction call given the current state of the mempool.
    ///
    /// This function attempts to use the POST /v2/fees/transaction
    /// endpoint on a stacks node to estimate the current high priority
    /// transaction fee for a given transaction. If the node does not
    /// have enough information to provide an estimate, we then get the
    /// current high priority fee for an STX transfer and use that as an
    /// estimate for the transaction fee.
    async fn estimate_fees<T>(
        &self,
        wallet: &SignerWallet,
        payload: &T,
        priority: FeePriority,
    ) -> Result<u64, Error>
    where
        T: AsTxPayload + Send + Sync,
    {
        let transaction_size = super::wallet::get_full_tx_size(payload, wallet)?;

        // In Stacks core, the minimum fee is 1 mSTX per byte, so take the
        // transaction size and multiply it by the TX_FEE_TX_SIZE_MULTIPLIER
        // here to ensure that 1) we'll be accepted in the mempool, 2) that we
        // have a decent margin above the absolute minimum fee.
        let default_min_fee = (transaction_size * TX_FEE_TX_SIZE_MULTIPLIER).min(MAX_TX_FEE);

        // Estimate attempt #1 - actual payload
        //
        // First we attempt to estimate the fee using the actual transaction
        // payload.
        let tx_size = Some(transaction_size);
        let tx_fee_estimate_response = self.get_fee_estimate(payload, tx_size).await;

        // If we get a valid response, then we use the fee estimate we received,
        // just ensuring that it doesn't exceed our maximum fee.
        match tx_fee_estimate_response {
            Ok(resp) => {
                let estimate = resp.extract_fee(priority).map(|estimate| estimate.fee);

                // If we got a valid estimate, then we use it.
                if let Some(estimate) = estimate {
                    return Ok(estimate.min(MAX_TX_FEE));
                }

                tracing::warn!(
                    "received a fee estimate response, but it did not contain a fee for the specified priority, falling back to STX transfer fee estimation"
                );
            }
            Err(error) => {
                tracing::warn!(%error, "could not estimate contract call fees using the transaction, falling back to STX transfer fee estimation");
            }
        }

        // Estimate attempt #2 - STX transfer
        //
        // Estimating STX transfers is simple since the estimate
        // doesn't depend on the recipient, amount, or memo. So a
        // dummy transfer payload will do.
        let stx_transfer_estimate_response = self
            .get_fee_estimate(&*DUMMY_STX_TRANSFER_PAYLOAD, None)
            .await;

        // If we get a valid response, then we use the fee estimate we received,
        // falling back to our calculated default minimum fee if for some reason
        // either we received an error or the estimate was malformed/didn't
        // contain a fee for the specified priority.
        match stx_transfer_estimate_response {
            Ok(resp) => {
                let rate = resp.extract_fee(priority).map(|estimate| estimate.fee_rate);

                // If for some reason we couldn't get the rate for the specified
                // priority, then we fall back to the default minimum fee.
                let Some(rate) = rate else {
                    return Ok(default_min_fee);
                };

                let estimate = ((rate * transaction_size as f64) as u64)
                    .min(MAX_TX_FEE) // Ensure we don't exceed our maximum fee
                    .max(transaction_size * MINIMUM_TX_FEE_RATE_PER_BYTE); // Ensure we don't go below the absolute minimum fee

                Ok(estimate)
            }
            Err(error) => {
                tracing::warn!(%error, "could not estimate STX fees using the Stacks node, falling back to transaction-size-based estimation");
                // Fallback to our calculated minimum fee if we couldn't get an estimate
                // from a Stacks node.
                Ok(default_min_fee)
            }
        }
    }

    async fn get_epoch_status(&self) -> Result<StacksEpochStatus, Error> {
        self.get_pox_info().await?.try_into()
    }

    async fn get_node_info(&self) -> Result<GetNodeInfoResponse, Error> {
        self.get_node_info().await
    }

    /// Get the source of a deployed smart contract.
    ///
    /// # Notes
    ///
    /// This is useful just to know whether a contract has been deployed
    /// already or not. If the smart contract has not been deployed yet,
    /// the stacks node returns a 404 Not Found.
    async fn get_contract_source(
        &self,
        address: &StacksAddress,
        contract_name: &str,
    ) -> Result<ContractSrcResponse, Error> {
        self.get_contract_source(address, contract_name).await
    }

    async fn get_sbtc_total_supply(&self, deployer: &StacksAddress) -> Result<Amount, Error> {
        let result = self
            .call_read(
                deployer,
                SmartContract::SbtcToken,
                ClarityName(GET_TOTAL_SUPPLY_FN_NAME),
                deployer,
                &[],
            )
            .await?;

        match result {
            Value::Response(response) => match *response.data {
                Value::UInt(total_supply) => Ok(Amount::from_sat(
                    u64::try_from(total_supply)
                        .map_err(|_| Error::InvalidStacksResponse("total supply is too large"))?,
                )),
                _ => Err(Error::InvalidStacksResponse(
                    "expected a uint but got something else",
                )),
            },
            _ => Err(Error::InvalidStacksResponse(
                "expected a response but got something else",
            )),
        }
    }
}

impl StacksInteract for ApiFallbackClient<StacksClient> {
    async fn get_current_signer_set_info(
        &self,
        contract_principal: &StacksAddress,
    ) -> Result<Option<SignerSetInfo>, Error> {
        self.exec(|client, retry| async move {
            let result = client.get_current_signer_set_info(contract_principal).await;
            retry.abort_if(|| matches!(result, Err(Error::InvalidStacksResponse(_))));
            result
        })
        .await
    }

    async fn get_tenure_headers(
        &self,
        burnchain_block_height: BitcoinBlockHeight,
    ) -> Result<TenureBlockHeaders, Error> {
        self.exec(|client, retry| async move {
            let result = client.get_tenure_headers(burnchain_block_height).await;
            retry.abort_if(|| matches!(result, Err(Error::InvalidStacksResponse(_))));
            result
        })
        .await
    }

    async fn get_current_signers_aggregate_key(
        &self,
        contract_principal: &StacksAddress,
    ) -> Result<Option<PublicKey>, Error> {
        self.exec(|client, retry| async move {
            let result = client
                .get_current_signers_aggregate_key(contract_principal)
                .await;
            retry.abort_if(|| matches!(result, Err(Error::InvalidStacksResponse(_))));
            result
        })
        .await
    }

    async fn is_deposit_completed(
        &self,
        contract_principal: &StacksAddress,
        outpoint: &OutPoint,
    ) -> Result<bool, Error> {
        self.exec(|client, retry| async move {
            let result = client
                .is_deposit_completed(contract_principal, outpoint)
                .await;
            retry.abort_if(|| matches!(result, Err(Error::InvalidStacksResponse(_))));
            result
        })
        .await
    }

    async fn is_withdrawal_completed(
        &self,
        contract_principal: &StacksAddress,
        request_id: u64,
    ) -> Result<bool, Error> {
        self.exec(|client, retry| async move {
            let result = client
                .is_withdrawal_completed(contract_principal, request_id)
                .await;
            retry.abort_if(|| matches!(result, Err(Error::InvalidStacksResponse(_))));
            result
        })
        .await
    }

    async fn get_account(&self, address: &StacksAddress) -> Result<AccountInfo, Error> {
        self.exec(|client, _| client.get_account(address)).await
    }

    async fn submit_tx(&self, tx: &StacksTransaction) -> Result<SubmitTxResponse, Error> {
        self.exec(|client, _| client.submit_tx(tx)).await
    }

    async fn get_block(&self, block_id: &StacksBlockHash) -> Result<NakamotoBlock, Error> {
        self.exec(|client, _| client.get_block(block_id)).await
    }

    async fn check_pre_nakamoto_block(&self, block_id: &StacksBlockHash) -> Result<(), Error> {
        self.exec(|client, _| client.check_pre_nakamoto_block(block_id))
            .await
    }

    async fn get_tenure_info(&self) -> Result<GetTenureInfoResponse, Error> {
        self.exec(|client, _| client.get_tenure_info()).await
    }

    async fn get_sortition_info(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Result<SortitionInfo, Error> {
        self.exec(|client, _| client.get_sortition_info(consensus_hash))
            .await
    }

    async fn estimate_fees<T>(
        &self,
        wallet: &SignerWallet,
        payload: &T,
        priority: FeePriority,
    ) -> Result<u64, Error>
    where
        T: AsTxPayload + Send + Sync,
    {
        self.exec(|client, _| StacksClient::estimate_fees(client, wallet, payload, priority))
            .await
    }

    async fn get_epoch_status(&self) -> Result<StacksEpochStatus, Error> {
        self.exec(|client, _| client.get_epoch_status()).await
    }

    async fn get_node_info(&self) -> Result<GetNodeInfoResponse, Error> {
        self.exec(|client, _| client.get_node_info()).await
    }

    async fn get_contract_source(
        &self,
        address: &StacksAddress,
        contract_name: &str,
    ) -> Result<ContractSrcResponse, Error> {
        // TODO: We need to properly catch catch certain errors and let
        // them pass. In particular, this error is fine:
        // ```rust
        // Error::StacksNodeResponse(error)
        //      if error.status() == Some(reqwest::StatusCode::NOT_FOUND)
        // ```
        self.get_client()
            .get_contract_source(address, contract_name)
            .await
    }

    async fn get_sbtc_total_supply(&self, deployer: &StacksAddress) -> Result<Amount, Error> {
        self.exec(|client, _| client.get_sbtc_total_supply(deployer))
            .await
    }
}

impl TryFrom<&Settings> for ApiFallbackClient<StacksClient> {
    type Error = Error;

    fn try_from(settings: &Settings) -> Result<Self, Self::Error> {
        let clients = settings
            .stacks
            .endpoints
            .iter()
            .map(|url| StacksClient::new(url.clone()))
            .collect::<Result<Vec<_>, _>>()?;

        ApiFallbackClient::new(clients).map_err(Error::FallbackClient)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::NetworkKind;
    use crate::keys::{PrivateKey, PublicKey};
    use crate::stacks::wallet::get_full_tx_size;
    use crate::storage::memory::Store;

    use assert_matches::assert_matches;
    use clarity::types::Address as _;
    use clarity::vm::ClarityName;
    use clarity::vm::types::{
        BuffData, BufferLength, ListData, ListTypeData, SequenceData, SequenceSubtype,
        TypeSignature,
    };
    use rand::rngs::OsRng;
    use secp256k1::Keypair;
    use test_case::test_case;
    use test_log::test;

    use super::*;

    fn generate_wallet(num_keys: u16, signatures_required: u16) -> SignerWallet {
        let network_kind = NetworkKind::Regtest;

        let public_keys = std::iter::repeat_with(|| Keypair::new_global(&mut OsRng))
            .map(|kp| kp.public_key().into())
            .take(num_keys as usize)
            .collect::<Vec<_>>();

        SignerWallet::new(&public_keys, signatures_required, network_kind, 0).unwrap()
    }

    #[ignore = "This is an integration test that hasn't been setup for CI yet"]
    #[test(tokio::test)]
    async fn fetch_unknown_ancestors_works() {
        let db = crate::testing::storage::new_test_database().await;

        let settings = Settings::new_from_default_config().unwrap();
        // This is an integration test that will read from the config, which provides
        // a list of endpoints, so we use the fallback client.
        let client: ApiFallbackClient<StacksClient> = TryFrom::try_from(&settings).unwrap();

        let info = client.get_tenure_info().await.unwrap();
        let btc_info = client
            .get_sortition_info(&info.consensus_hash)
            .await
            .unwrap();
        let tenures =
            update_db_with_unknown_ancestors(&client, &db, btc_info.burn_block_height.into()).await;

        assert!(tenures.is_ok());

        crate::testing::storage::drop_db(db).await;
    }

    #[ignore = "This is an integration test that uses the real testnet"]
    #[test_case(|url| StacksClient::new(url).unwrap(); "stacks-client")]
    #[test_case(|url| ApiFallbackClient::new(vec![StacksClient::new(url).unwrap()]).unwrap(); "fallback-client")]
    #[tokio::test]
    async fn fetch_unknown_ancestors_works_in_testnet<F, C>(client: F)
    where
        C: StacksInteract,
        F: Fn(Url) -> C,
    {
        let db = crate::testing::storage::new_test_database().await;

        let client = client(Url::parse("https://api.testnet.hiro.so/").unwrap());

        // Testnet currently has the following structure:
        //
        // BTC 1865 <- Stacks 319
        // BTC 1900 -- nakamoto_start_height
        // BTC 1901 <- Stacks 320, ..., 744
        // BTC 1998 <- Stacks 745, ..., 750, ... 791

        // This is the block id for block 319 (pre-Nakamoto) on testnet
        let pre_nakamoto_block_id = StacksBlockId::from_hex(
            "0d7cb8c66040d87fc17f39e1b5c36bc7fb5c4d97cc611a168e2cca186848be1e",
        )
        .unwrap()
        .into();
        assert!(
            client
                .check_pre_nakamoto_block(&pre_nakamoto_block_id)
                .await
                .is_ok()
        );

        // This is the block id for block 750 on testnet
        let nakamoto_block_id = StacksBlockId::from_hex(
            "ad133146e79ff5eccf9eecc51d9eea35947031c5d91d61afc3a1df63d6c198e7",
        )
        .unwrap()
        .into();
        assert!(
            client
                .check_pre_nakamoto_block(&nakamoto_block_id)
                .await
                .is_err()
        );

        let tenures = update_db_with_unknown_ancestors(&client, &db, 1998u64.into()).await;

        let block_height_range = tenures.unwrap();

        let expected =
            RangeInclusive::new(StacksBlockHeight::new(320), StacksBlockHeight::new(791));
        assert_eq!(block_height_range, expected);

        let (min_block_height, max_block_height, count) = sqlx::query_as::<_, (i64, i64, i64)>(
            r#"SELECT 
                 MIN(block_height) as min_block_height
               , MAX(block_height) as max_block_height
               , COUNT(DISTINCT block_hash) as count
             FROM sbtc_signer.stacks_blocks"#,
        )
        .fetch_one(db.pool())
        .await
        .unwrap();

        assert_eq!(count, max_block_height - min_block_height + 1);
        assert_eq!(min_block_height, **expected.start() as i64);
        assert_eq!(max_block_height, **expected.end() as i64);

        crate::testing::storage::drop_db(db).await;
    }

    /// Test that get_blocks works as expected.
    ///
    /// The author took the following steps to set up this test:
    /// 1. Get Nakamoto running locally. This was done using
    ///    https://github.com/hirosystems/stacks-regtest-env/blob/feat/signer/docker-compose.yml
    ///    where the STACKS_BLOCKCHAIN_COMMIT was changed to
    ///    "3d96d53b35409859ca2baa2f0b6ddaa1fbd80265" and the
    ///    MINE_INTERVAL_EPOCH3 was set to "60s".
    /// 2. After Nakamoto is running, use a dummy test like
    ///    `fetching_last_tenure_blocks_works` to get the blocks for an
    ///    actual tenure. Note the block IDs for the first and last
    ///    `NakamotoBlock`s in the result. Note that the tenure info only
    ///    gives you the start block ids, you'll need to get the actual
    ///    block to get the last block in a tenure.
    /// 3. Use the block IDs from step (2) to make two curl requests:
    ///     * The tenure starting with the end block:
    ///     ```bash
    ///     curl http://localhost:20443/v3/tenures/<tenure-end-block-id> \
    ///         --output tests/fixtures/tenure-blocks-0-<tenure-end-block-id>.bin \
    ///         -vvv
    ///     ```
    ///     * The tenure starting at the tenure start block:
    ///     ```bash
    ///     curl http://localhost:20443/v3/tenures/<tenure-start-block-id> \
    ///         --output tests/fixtures/tenure-blocks-1-<tenure-start-block-id>.bin \
    ///         -vvv
    ///     ```
    /// 4. Done
    #[test_case(|url| StacksClient::new(url).unwrap(); "stacks-client")]
    #[test_case(|url| ApiFallbackClient::new(vec![StacksClient::new(url).unwrap()]).unwrap(); "fallback-client")]
    #[tokio::test]
    async fn get_blocks_test<F, C>(client: F)
    where
        C: StacksInteract,
        F: Fn(Url) -> C,
    {
        // Okay we need to set up the server to returned what a stacks node
        // would return. We load up a file that contains a response from an
        // actual stacks node in regtest mode.
        let path = "tests/fixtures/stacksapi-v3-tenures-blocks.json".to_string();

        let mut stacks_node_server = mockito::Server::new_async().await;
        let endpoint_tenure_headers = "/v3/tenures/blocks/height/900000".to_string();
        let first_mock = stacks_node_server
            .mock("GET", endpoint_tenure_headers.as_str())
            .with_status(200)
            .with_body_from_file(path)
            .expect(1)
            .create();

        let client = client(url::Url::parse(stacks_node_server.url().as_str()).unwrap());

        // The moment of truth, do the requests succeed?
        let headers = client.get_tenure_headers(900_000u64.into()).await.unwrap();
        assert_eq!(headers.headers.len(), 39);
        assert_eq!(headers.start_height(), 1507195u64.into());
        assert_eq!(headers.end_height(), 1507233u64.into());

        first_mock.assert();
    }

    #[tokio::test]
    async fn get_sbtc_total_supply_works() {
        let raw_json_response = r#"{
            "okay": true,
            "result": "0x070100000000000000000000000000000539"
        }"#;

        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("POST", "/v2/contracts/call-read/SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS/sbtc-token/get-total-supply?tip=latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(1)
            .create();

        let client = StacksClient::new(stacks_node_server.url().parse().unwrap()).unwrap();
        let result = client
            .get_sbtc_total_supply(
                &StacksAddress::from_string("SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS").unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(result, Amount::from_sat(1337));
        mock.assert();
    }

    #[test_case(|url| StacksClient::new(url).unwrap(); "stacks-client")]
    #[test_case(|url| ApiFallbackClient::new(vec![StacksClient::new(url).unwrap()]).unwrap(); "fallback-client")]
    #[tokio::test]
    async fn get_tenure_info_works<F, C>(client: F)
    where
        C: StacksInteract,
        F: Fn(Url) -> C,
    {
        let raw_json_response = r#"{
            "consensus_hash": "e42b3a9ffce62376e1f36cf76c33cc23d9305de1",
            "tenure_start_block_id": "e08c740242092eb0b5f74756ce203db048a5156e444df531a7c29e2d952cf628",
            "parent_consensus_hash": "d9693fbdf0a9bab9ee5ffd3c4f52fef6e1da1899",
            "parent_tenure_start_block_id": "8ff4eb1ed4a2f83faada29f6012b7f86f476eafed9921dff8d2c14cdfa30da94",
            "tip_block_id": "8f61dc41560560e8122609e82966740075929ed663543d9ad6733f8fc32876c5",
            "tip_height": 2037,
            "reward_cycle": 11
        }"#;

        let mut stacks_node_server = mockito::Server::new_async().await;
        let first_mock = stacks_node_server
            .mock("GET", "/v3/tenures/info")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(1)
            .create();

        let client = client(url::Url::parse(stacks_node_server.url().as_str()).unwrap());
        let resp = client.get_tenure_info().await.unwrap();
        let expected: GetTenureInfoResponse = serde_json::from_str(raw_json_response).unwrap();

        assert_eq!(resp, expected);
        first_mock.assert();
    }

    /// Helper method for generating a list of public keys.
    fn generate_pubkeys(count: u16) -> Vec<PublicKey> {
        (0..count)
            .map(|_| PublicKey::from_private_key(&PrivateKey::new(&mut rand::thread_rng())))
            .collect()
    }

    /// Helper method for creating a list of public keys as a Clarity [`Value::Sequence`].
    fn create_clarity_pubkey_list(public_keys: &[PublicKey]) -> Vec<Value> {
        public_keys
            .iter()
            .map(|pk| {
                Value::Sequence(SequenceData::Buffer(BuffData {
                    data: pk.serialize().to_vec(),
                }))
            })
            .collect()
    }

    #[test_case(|url| StacksClient::new(url).unwrap(); "stacks-client")]
    #[test_case(|url| ApiFallbackClient::new(vec![StacksClient::new(url).unwrap()]).unwrap(); "fallback-client")]
    #[tokio::test]
    async fn get_current_signer_set_fails_when_value_not_a_sequence<F, C>(client: F)
    where
        C: StacksInteract,
        F: Fn(Url) -> C,
    {
        let clarity_value = Value::Int(1234);
        let json_response = serde_json::json!({
            "okay": true,
            "result": format!("0x{}", clarity_value.serialize_to_hex().unwrap()),
        });
        let raw_json_response = serde_json::to_string(&json_response).unwrap();
        // Setup our mock server
        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("POST", "/v2/contracts/call-read/ST000000000000000000002AMW42H/sbtc-registry/get-current-signer-data?tip=latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&raw_json_response)
            .expect(1)
            .create();

        // Setup our Stacks client
        let client = client(url::Url::parse(stacks_node_server.url().as_str()).unwrap());

        // Make the request to the mock server
        let resp = client
            .get_current_signer_set_info(&StacksAddress::burn_address(false))
            .await;

        let err = resp.unwrap_err();
        assert!(matches!(err, Error::InvalidStacksResponse(_)));
        mock.assert();
    }

    #[test_case(0, |url| StacksClient::new(url).unwrap(); "stacks-client-empty-list")]
    #[test_case(128, |url| StacksClient::new(url).unwrap(); "stacks-client-list-128")]
    #[test_case(0, |url| ApiFallbackClient::new(vec![StacksClient::new(url).unwrap()]).unwrap(); "fallback-client-empty-list")]
    #[test_case(128, |url| ApiFallbackClient::new(vec![StacksClient::new(url).unwrap()]).unwrap(); "fallback-client-list-128")]
    #[tokio::test]
    async fn get_current_signer_set_info_works<F, C>(list_size: u16, client: F)
    where
        C: StacksInteract,
        F: Fn(Url) -> C,
    {
        // Create our simulated response JSON. This uses the same method to generate
        // the serialized list of public keys as the actual Stacks node does.
        let public_keys = generate_pubkeys(list_size);
        let signer_set = Value::Sequence(SequenceData::List(ListData {
            data: create_clarity_pubkey_list(&public_keys),
            type_signature: ListTypeData::new_list(
                TypeSignature::list_of(
                    TypeSignature::SequenceType(SequenceSubtype::BufferType(
                        BufferLength::try_from(33_usize).unwrap(),
                    )),
                    33,
                )
                .expect("failed to create sequence type signature"),
                128,
            )
            .expect("failed to create list type signature"),
        }));
        let aggregate_key = generate_pubkeys(list_size.min(1)).pop();
        let aggregate_key_clarity = Value::Sequence(SequenceData::Buffer(BuffData {
            data: aggregate_key
                .map(|pk| pk.serialize().to_vec())
                // 0x00 is the initial value of the aggregate key in the
                // sbtc-registry contract.
                .unwrap_or(vec![0; 1]),
        }));
        // The format of the response JSON is `{"data": "0x<serialized-value>"}` (excluding the proof).

        let tuple_data = [
            (
                ClarityName::from("current-signature-threshold"),
                Value::UInt(list_size as u128),
            ),
            (ClarityName::from("current-signer-set"), signer_set),
            (
                ClarityName::from("current-aggregate-pubkey"),
                aggregate_key_clarity,
            ),
        ]
        .to_vec();

        let clarity_value = Value::Tuple(TupleData::from_data(tuple_data).unwrap());

        let json_response = serde_json::json!({
            "okay": true,
            "result": format!("0x{}", clarity_value.serialize_to_hex().unwrap()),
        });
        let raw_json_response = serde_json::to_string(&json_response).unwrap();

        // Setup our mock server
        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("POST", "/v2/contracts/call-read/ST000000000000000000002AMW42H/sbtc-registry/get-current-signer-data?tip=latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&raw_json_response)
            .expect(1)
            .create();

        // Setup our Stacks client
        let client = client(url::Url::parse(stacks_node_server.url().as_str()).unwrap());

        // Make the request to the mock server
        let resp = client
            .get_current_signer_set_info(&StacksAddress::burn_address(false))
            .await
            .unwrap();

        let expected = aggregate_key.map(|aggregate_key| SignerSetInfo {
            aggregate_key,
            signer_set: public_keys.into_iter().collect(),
            signatures_required: list_size,
        });

        // Assert that the response is what we expect
        assert_eq!(resp, expected);
        mock.assert();
    }

    #[test_case(|url| StacksClient::new(url).unwrap(), false; "stacks-client-some")]
    #[test_case(|url| StacksClient::new(url).unwrap(), true; "stacks-client-none")]
    #[test_case(|url| ApiFallbackClient::new(vec![StacksClient::new(url).unwrap()]).unwrap(), false; "fallback-client-some")]
    #[test_case(|url| ApiFallbackClient::new(vec![StacksClient::new(url).unwrap()]).unwrap(), true; "fallback-client-none")]
    #[tokio::test]
    async fn get_current_signers_aggregate_key_works<F, C>(client: F, return_none: bool)
    where
        C: StacksInteract,
        F: Fn(Url) -> C,
    {
        let aggregate_key = generate_pubkeys(1)[0];

        let data;
        let expected;
        if return_none {
            // 0x00 is the initial value of the signers' aggregate key in
            // the sbtc-registry contract, and
            // get_current_signers_aggregate_key should return None when we
            // receive it.
            data = vec![0];
            expected = None;
        } else {
            data = aggregate_key.serialize().to_vec();
            expected = Some(aggregate_key);
        }
        let aggregate_key_clarity = Value::Sequence(SequenceData::Buffer(BuffData { data }));

        // The format of the response JSON is `{"data": "0x<serialized-value>"}` (excluding the proof).
        let raw_json_response = format!(
            r#"{{"data":"0x{}"}}"#,
            Value::serialize_to_hex(&aggregate_key_clarity).expect("failed to serialize value")
        );

        // Setup our mock server
        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("GET", "/v2/data_var/ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM/sbtc-registry/current-aggregate-pubkey?proof=0")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&raw_json_response)
            .expect(1)
            .create();

        // Setup our Stacks client
        let client = client(url::Url::parse(stacks_node_server.url().as_str()).unwrap());

        // Make the request to the mock server
        let resp = client
            .get_current_signers_aggregate_key(
                &StacksAddress::from_string("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM")
                    .expect("failed to parse stacks address"),
            )
            .await
            .unwrap();

        // Assert that the response is what we expect
        assert_eq!(resp, expected);
        mock.assert();
    }

    #[test_case(0; "empty-list")]
    #[test_case(128; "list-128")]
    #[tokio::test]
    async fn get_data_var_works(list_size: u16) {
        // Create our simulated response JSON. This uses the same method to generate
        // the serialized list of public keys as the actual Stacks node does.
        let signer_set = Value::Sequence(SequenceData::List(ListData {
            data: create_clarity_pubkey_list(&generate_pubkeys(list_size)),
            type_signature: ListTypeData::new_list(
                TypeSignature::list_of(
                    TypeSignature::SequenceType(SequenceSubtype::BufferType(
                        BufferLength::try_from(33_usize).unwrap(),
                    )),
                    33,
                )
                .expect("failed to create sequence type signature"),
                128,
            )
            .expect("failed to create list type signature"),
        }));
        // The format of the response JSON is `{"data": "0x<serialized-value>"}` (excluding the proof).
        let raw_json_response = format!(
            r#"{{"data":"0x{}"}}"#,
            Value::serialize_to_hex(&signer_set).expect("failed to serialize value")
        );

        // Setup our mock server
        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("GET", "/v2/data_var/ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM/sbtc-registry/current-signer-set?proof=0")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&raw_json_response)
            .expect(1)
            .create();

        // Setup our Stacks client. We use a regular client here because we're
        // testing the `get_data_var` method.
        let client =
            StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();

        // Make the request to the mock server
        let resp = client
            .get_data_var(
                &StacksAddress::from_string("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM")
                    .expect("failed to parse stacks address"),
                SmartContract::SbtcRegistry,
                ClarityName("current-signer-set"),
            )
            .await
            .unwrap();

        // Assert that the response is what we expect
        let expected: DataVarResponse = serde_json::from_str(&raw_json_response).unwrap();
        assert_eq!(&resp, &expected.data);
        mock.assert();
    }

    #[test_case(Some(true); "complete-deposit")]
    #[test_case(None; "incomplete-deposit")]
    #[tokio::test]
    async fn is_deposit_completed_works(expected_response: Option<bool>) {
        // Create our simulated response JSON.
        let data = expected_response.map(|x| Box::new(Value::Bool(x)));
        let clarity_value = Value::Optional(OptionalData { data });
        let json_response = serde_json::json!({
            "okay": true,
            "result": format!("0x{}", clarity_value.serialize_to_hex().unwrap()),
        });
        let raw_json_response = serde_json::to_string(&json_response).unwrap();

        // Setup our mock server
        // POST /v2/contracts/call-read/<contract-principal>/sbtc-registry/get-deposit-status
        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("POST", "/v2/contracts/call-read/ST000000000000000000002AMW42H/sbtc-registry/get-deposit-status?tip=latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&raw_json_response)
            .expect(1)
            .create();

        let client =
            StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();

        // Make the request to the mock server
        let response = client
            .is_deposit_completed(
                &StacksAddress::burn_address(false),
                &bitcoin::OutPoint::null(),
            )
            .await
            .unwrap();

        assert_eq!(response, expected_response.unwrap_or(false));
        mock.assert();
    }

    #[test_case(Some(true); "accepted-withdrawal")]
    #[test_case(Some(false); "rejected-withdrawal")]
    #[test_case(None; "incomplete-withdrawal")]
    #[tokio::test]
    async fn is_withdrawal_completed_works(expected_response: Option<bool>) {
        // Create our simulated response JSON.
        let data = expected_response.map(|x| Box::new(Value::Bool(x)));
        let clarity_value = Value::Optional(OptionalData { data });
        let json_response = serde_json::json!({
            "data": format!("0x{}", clarity_value.serialize_to_hex().unwrap()),
        });
        let raw_json_response = serde_json::to_string(&json_response).unwrap();

        // Setup our mock server
        // POST /v2/map_entry/<contract-principal>/sbtc-registry/withdrawal-status
        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("POST", "/v2/map_entry/ST000000000000000000002AMW42H/sbtc-registry/withdrawal-status?proof=0")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&raw_json_response)
            .expect(1)
            .create();

        let client =
            StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();

        // Make the request to the mock server
        let response = client
            .is_withdrawal_completed(&StacksAddress::burn_address(false), 1)
            .await
            .unwrap();

        assert_eq!(response, expected_response.is_some());
        mock.assert();
    }

    // Check that if we don't get valid responses from the Stacks node for both
    // the transaction and STX transfer fee estimation requests, we fallback to
    // estimating the fee based on the size of the transaction payload.
    #[test_case(15, 11)]
    #[tokio::test]
    async fn estimate_fees_fallback_works(num_keys: u16, signatures_required: u16) {
        let wallet = generate_wallet(num_keys, signatures_required);
        let mut stacks_node_server = mockito::Server::new_async().await;

        // Setup a mock which will fail both the transaction and STX transfer
        // estimation request attempts.
        let mock = stacks_node_server
            .mock("POST", "/v2/fees/transaction")
            .with_status(400)
            .expect(2)
            .create();

        // Setup our Stacks client. We use a regular client here because we're
        // testing the `get_fee_estimate` method.
        let client =
            StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();

        let expected_fee = get_full_tx_size(&*DUMMY_STX_TRANSFER_PAYLOAD, &wallet).unwrap()
            * TX_FEE_TX_SIZE_MULTIPLIER;

        let resp = client
            .estimate_fees(&wallet, &*DUMMY_STX_TRANSFER_PAYLOAD, FeePriority::High)
            .await
            .unwrap();

        assert_eq!(resp, expected_fee);

        mock.assert();
    }

    /// Check that everything works as expected in the happy path case.
    #[tokio::test]
    async fn get_fee_estimate_works() {
        let wallet = generate_wallet(1, 1);
        // The following was taken from a locally running stacks node for
        // the cost of a contract deploy.
        let raw_json_response = r#"{
            "estimated_cost":{
                "write_length":3893,
                "write_count":3,
                "read_length":94,
                "read_count":3,
                "runtime":157792
            },
            "estimated_cost_scalar":44,
            "estimations":[
                {"fee_rate":156.45435901001113,"fee":7679},
                {"fee_rate":174.56585442157953,"fee":7680},
                {"fee_rate":579.6667045875889,"fee":25505}
            ],
            "cost_scalar_change_by_byte":0.00476837158203125
        }"#;

        let mut stacks_node_server = mockito::Server::new_async().await;
        let first_mock = stacks_node_server
            .mock("POST", "/v2/fees/transaction")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(4)
            .create();

        // Setup our Stacks client. We use a regular client here because we're
        // testing the `get_fee_estimate` method.
        let client =
            StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();
        let resp = client
            .get_fee_estimate(&*DUMMY_STX_TRANSFER_PAYLOAD, None)
            .await
            .unwrap();
        let expected: RPCFeeEstimateResponse = serde_json::from_str(raw_json_response).unwrap();

        assert_eq!(resp, expected);

        // Now lets check that the interface function returns the requested
        // priority fees.
        let fee = client
            .estimate_fees(&wallet, &*DUMMY_STX_TRANSFER_PAYLOAD, FeePriority::Low)
            .await
            .unwrap();
        assert_eq!(fee, 7679);

        let fee = client
            .estimate_fees(&wallet, &*DUMMY_STX_TRANSFER_PAYLOAD, FeePriority::Medium)
            .await
            .unwrap();
        assert_eq!(fee, 7680);

        let fee = client
            .estimate_fees(&wallet, &*DUMMY_STX_TRANSFER_PAYLOAD, FeePriority::High)
            .await
            .unwrap();
        assert_eq!(fee, 25505);

        first_mock.assert();
    }

    #[tokio::test]
    async fn get_pox_info_works() {
        let raw_json_response =
            include_str!("../../tests/fixtures/stacksapi-get-pox-info-test-data.json");

        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("GET", "/v2/pox")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(1)
            .create();

        // Setup our Stacks client. We use a regular client here because we're
        // testing the `get_pox_info` method.
        let client =
            StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();
        let resp = client.get_pox_info().await.unwrap();
        let expected: PoxResponse = serde_json::from_str(raw_json_response).unwrap();

        assert_eq!(resp, expected);
        mock.assert();
    }

    #[tokio::test]
    async fn get_epoch_info_works_with_full_response_body() {
        let raw_json_response =
            include_str!("../../tests/fixtures/stacksapi-get-pox-info-test-data.json");

        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("GET", "/v2/pox")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(1)
            .create();

        let client =
            StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();
        let resp = client.get_epoch_status().await.unwrap();

        assert_matches!(resp, StacksEpochStatus::PostNakamoto { nakamoto_start_height }
            if nakamoto_start_height == BitcoinBlockHeight::from(232u64)
        );

        mock.assert();
    }

    #[tokio::test]
    async fn get_epoch_info_errors_when_epoch30_missing() {
        let raw_json_response = r#"{
            "current_burnchain_block_height": 1000,
            "epochs": [
                { "epoch_id": "Epoch10", "start_height": 0 },
                { "epoch_id": "Epoch20", "start_height": 500 }
            ]
        }"#;

        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("GET", "/v2/pox")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(1)
            .create();

        let client = StacksClient::new(stacks_node_server.url().parse().unwrap()).unwrap();
        let err = client.get_epoch_status().await.unwrap_err();
        assert_matches!(err, Error::MissingNakamotoStartHeight);
        mock.assert();
    }

    #[tokio::test]
    async fn get_epoch_info_pre_nakamoto() {
        // current < Epoch30 start -> PreNakamoto
        let raw_json_response = r#"{
            "current_burnchain_block_height": 1999,
            "epochs": [
                { "epoch_id": "Epoch10", "start_height": 0 },
                { "epoch_id": "Epoch30", "start_height": 2000 }
            ]
        }"#;

        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("GET", "/v2/pox")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(1)
            .create();

        let client = StacksClient::new(stacks_node_server.url().parse().unwrap()).unwrap();
        let resp = client.get_epoch_status().await.unwrap();

        assert_matches!(resp, StacksEpochStatus::PreNakamoto { reported_bitcoin_height, nakamoto_start_height }
            if reported_bitcoin_height == BitcoinBlockHeight::from(1999u64)
            && nakamoto_start_height == BitcoinBlockHeight::from(2000u64)
        );

        mock.assert();
    }

    #[tokio::test]
    async fn get_epoch_info_post_nakamoto() {
        // current >= Epoch30 start -> PostNakamoto
        let raw_json_response = r#"{
            "current_burnchain_block_height": 2000,
            "epochs": [
                { "epoch_id": "Epoch10", "start_height": 0 },
                { "epoch_id": "Epoch30", "start_height": 2000 }
            ]
        }"#;

        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("GET", "/v2/pox")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(1)
            .create();

        let client = StacksClient::new(stacks_node_server.url().parse().unwrap()).unwrap();
        let resp = client.get_epoch_status().await.unwrap();

        assert_matches!(
            resp,
            StacksEpochStatus::PostNakamoto { nakamoto_start_height }
                if nakamoto_start_height == BitcoinBlockHeight::from(2000u64)
        );

        mock.assert();
    }

    #[tokio::test]
    async fn get_epoch_info_ignores_unknown_epochs_after_epoch30() {
        // Unknown epochs (strings) after Epoch30 should not break parsing.
        let raw_json_response = r#"{
            "current_burnchain_block_height": 2500,
            "epochs": [
                { "epoch_id": "Epoch10", "start_height": 0 },
                { "epoch_id": "Epoch11", "start_height": 232 },
                { "epoch_id": "Epoch12", "start_height": 1456 },
                { "epoch_id": "Epoch30", "start_height": 2000 },
                { "epoch_id": "Epoch9999", "start_height": 3000 },
                { "epoch_id": "SomeFutureEpoch", "start_height": 4000 }
            ]
        }"#;

        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("GET", "/v2/pox")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(1)
            .create();

        let client = StacksClient::new(stacks_node_server.url().parse().unwrap()).unwrap();
        let resp = client.get_epoch_status().await.unwrap();

        assert_matches!(
            resp,
            StacksEpochStatus::PostNakamoto { nakamoto_start_height }
                if nakamoto_start_height == BitcoinBlockHeight::from(2000u64)
        );

        mock.assert();
    }

    #[tokio::test]
    async fn get_node_info_works() {
        let raw_json_response =
            include_str!("../../tests/fixtures/stacksapi-get-node-info-test-data.json");

        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("GET", "/v2/info")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(1)
            .create();

        // Setup our Stacks client. We use a regular client here because we're
        // testing the `get_node_info` method.
        let client =
            StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();
        let resp = client.get_node_info().await.unwrap();
        let expected: GetNodeInfoResponse = serde_json::from_str(raw_json_response).unwrap();

        assert_eq!(resp, expected);
        mock.assert();
    }

    #[tokio::test]
    #[ignore = "This is an integration test that hasn't been setup for CI yet"]
    async fn fetching_last_tenure_blocks_works() {
        let settings = Settings::new_from_default_config().unwrap();
        // We use the fallback client here because the CI test reads from the config
        // which provides a list of endpoints.
        let client: ApiFallbackClient<StacksClient> = TryFrom::try_from(&settings).unwrap();
        let storage = Store::new_shared();

        let info = client.get_tenure_info().await.unwrap();
        let btc_info = client
            .get_sortition_info(&info.consensus_hash)
            .await
            .unwrap();
        update_db_with_unknown_ancestors(&client, &storage, btc_info.burn_block_height.into())
            .await
            .unwrap();
    }

    #[test_case("0x1A3B5C7D9E", 112665066910; "uppercase-112665066910")]
    #[test_case("0x1a3b5c7d9e", 112665066910; "lowercase-112665066910")]
    #[test_case("1a3b5c7d9e", 112665066910; "no-prefix-lowercase-112665066910")]
    #[test_case("0xF0", 240; "uppercase-240")]
    #[test_case("f0", 240; "no-prefix-lowercase-240")]
    fn parsing_integers(hex: &str, expected: u128) {
        let actual = parse_hex_u128(hex).unwrap();
        assert_eq!(actual, expected);
    }

    #[test_case(""; "empty-string")]
    #[test_case("0x"; "almost-empty-string")]
    #[test_case("ZZZ"; "invalid hex")]
    fn parsing_integers_bad_input(hex: &str) {
        assert!(parse_hex_u128(hex).is_err());
    }

    #[tokio::test]
    #[ignore = "This is an integration test that hasn't been setup for CI yet"]
    async fn fetching_account_information_works() {
        let settings = Settings::new_from_default_config().unwrap();
        // We use the fallback client here because the CI test reads from the config
        // which provides a list of endpoints.
        let client: ApiFallbackClient<StacksClient> = TryFrom::try_from(&settings).unwrap();

        let address = StacksAddress::burn_address(false);
        let account = client.get_account(&address).await.unwrap();
        assert_eq!(account.nonce, 0);
    }

    // I don't think we really need this test, just for wip.
    // This is just to show that new function indeed returns same as the old one
    #[tokio::test]
    async fn get_tenure_headers() {
        let url = url::Url::parse("https://api.hiro.so/").unwrap();
        let client = StacksClient::new(url).unwrap();

        let tenure_headers = client.get_tenure_headers(900_000u32.into()).await.unwrap();

        let old_headers = client
            .get_tenure_headers_raw(
                &StacksBlockHash::from_hex(
                    "e8ab147057dc77f10063199e56b4110b3aff637d27337762c0415ac692f9db27",
                )
                .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(old_headers.len(), 37);
        assert_eq!(tenure_headers.headers.len(), 39);

        for header in old_headers {
            assert!(tenure_headers.headers.contains(&header));
        }
    }
}
