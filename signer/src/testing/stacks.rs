//! Test utilities from the stacks module
//!

use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
use blockstack_lib::net::api::getsortition::SortitionInfo;
use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::SortitionId;

use crate::error::Error;
use crate::stacks::api::GetNodeInfoResponse;
use crate::stacks::api::StacksBlockHeader;
use crate::stacks::api::TenureBlockHeaders;
use crate::storage::model::BitcoinBlockHeight;
use crate::storage::model::BitcoinBlockRef;
use crate::storage::model::StacksBlockHeight;
use crate::storage::postgres::PgStore;

/// Some dummy sortition info
pub const DUMMY_SORTITION_INFO: SortitionInfo = SortitionInfo {
    burn_block_hash: BurnchainHeaderHash([0; 32]),
    burn_block_height: 0,
    burn_header_timestamp: 0,
    sortition_id: SortitionId([0; 32]),
    parent_sortition_id: SortitionId([0; 32]),
    consensus_hash: blockstack_lib::chainstate::burn::ConsensusHash([0; 20]),
    was_sortition: false,
    miner_pk_hash160: None,
    stacks_parent_ch: Some(blockstack_lib::chainstate::burn::ConsensusHash([1; 20])),
    last_sortition_ch: Some(blockstack_lib::chainstate::burn::ConsensusHash([2; 20])),
    committed_block_hash: None,
    vrf_seed: None,
};

/// Some dummy node info
pub const DUMMY_NODE_INFO: GetNodeInfoResponse = GetNodeInfoResponse {
    burn_block_height: BitcoinBlockHeight::new(0),
    server_version: String::new(),
    stacks_tip_consensus_hash: crate::storage::model::ConsensusHash::new([1; 20]),
    stacks_tip_height: StacksBlockHeight::new(0),
    stacks_tip: BlockHeaderHash([0; 32]),
};

impl TenureBlockHeaders {
    /// Create a TenureBlockHeaders struct that is basically empty.
    pub fn nearly_empty() -> Result<Self, Error> {
        let header = NakamotoBlockHeader::empty().into();
        let mut sortition_info = DUMMY_SORTITION_INFO;
        sortition_info.burn_block_height = 300;
        Self::try_new(vec![header], sortition_info)
    }

    /// Create TenureBlockHeaders with some dummy sortition info.
    pub fn from_headers(headers: Vec<StacksBlockHeader>) -> Result<Self, Error> {
        Self::try_new(headers, DUMMY_SORTITION_INFO)
    }

    /// Create TenureBlockHeaders with a given anchor block.
    ///
    /// # Notes
    ///
    /// We do not set the bitcoin block height in any of these testing
    /// functions, because our tests often need the stacks anchor height to
    /// be before the nakamoto start height. This is because our Stacks
    /// block update logic stops at the nakamoto start height.
    pub fn from_anchor<T>(anchor: T) -> Self
    where
        T: Into<BitcoinBlockRef>,
    {
        let header = NakamotoBlockHeader::empty().into();

        let anchor = anchor.into();
        let mut sortition_info = DUMMY_SORTITION_INFO.clone();
        sortition_info.burn_block_hash = anchor.block_hash.into();
        sortition_info.burn_block_height = *anchor.block_height;

        Self::try_new(vec![header], sortition_info).unwrap()
    }
}

impl From<&bitcoincore_rpc_json::GetChainTipsResultTip> for BitcoinBlockRef {
    fn from(value: &bitcoincore_rpc_json::GetChainTipsResultTip) -> Self {
        Self {
            block_hash: value.hash.into(),
            block_height: value.height.into(),
        }
    }
}

/// Asserts that given [`storage`] contains stacks blocks with all heights in range [from;to]
/// and no other stacks blocks
pub async fn assert_db_contains_stacks_headers(storage: &PgStore, from: u64, to: u64) {
    let (min_block_height, max_block_height, count) = sqlx::query_as::<_, (i64, i64, i64)>(
        r#"SELECT 
             MIN(block_height) as min_block_height
           , MAX(block_height) as max_block_height
           , COUNT(DISTINCT block_hash) as count
         FROM sbtc_signer.stacks_blocks"#,
    )
    .fetch_one(storage.pool())
    .await
    .unwrap();

    assert_eq!(min_block_height as u64, from);
    assert_eq!(max_block_height as u64, to);
    assert_eq!(count as u64, to - from + 1);
}
