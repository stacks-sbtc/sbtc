//! Test utilities from the stacks module
//!

use std::sync::LazyLock;

use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
use blockstack_lib::net::api::getsortition::SortitionInfo;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::SortitionId;
use stacks_common::types::chainstate::StacksBlockId;

use crate::error::Error;
use crate::stacks::api::GetTenureInfoResponse;
use crate::stacks::api::StacksBlockHeader;
use crate::stacks::api::TenureBlockHeaders;
use crate::storage::model::BitcoinBlockRef;
use crate::storage::model::ConsensusHash;
use crate::storage::model::StacksBlockHash;
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

/// Dummy tenure info whose tip matches [`NakamotoBlockHeader::empty`], which is
/// what [`TenureBlockHeaders::nearly_empty`] / [`TenureBlockHeaders::from_anchor`]
/// write into the database.
pub static DUMMY_TENURE_INFO: LazyLock<GetTenureInfoResponse> = LazyLock::new(|| {
    let header = NakamotoBlockHeader::empty();
    let tip_block_id = StacksBlockHash::from(header.block_id());
    GetTenureInfoResponse {
        consensus_hash: ConsensusHash::from(header.consensus_hash.clone()),
        tenure_start_block_id: tip_block_id,
        parent_consensus_hash: ConsensusHash::new([0; 20]),
        parent_tenure_start_block_id: StacksBlockHash::from(StacksBlockId::first_mined()),
        tip_block_id,
        tip_height: StacksBlockHeight::from(header.chain_length),
        reward_cycle: 0,
    }
});

impl TenureBlockHeaders {
    /// Create a TenureBlockHeaders struct that is basically empty.
    pub fn nearly_empty() -> Result<Self, Error> {
        let header = NakamotoBlockHeader::empty().into();
        Self::try_new(vec![header], DUMMY_SORTITION_INFO)
    }

    /// Create TenureBlockHeaders with some dummy sortition info.
    pub fn from_headers(headers: Vec<StacksBlockHeader>) -> Result<Self, Error> {
        Self::try_new(headers, DUMMY_SORTITION_INFO)
    }

    /// Create TenureBlockHeaders with a given anchor block.
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

/// Asserts that the given [`storage`] contains Stacks blocks with all
/// heights in range [from;to] and no other Stacks blocks.
pub async fn assert_db_contains_stacks_headers(storage: &PgStore, from: u64, to: u64) {
    let (min_block_height, max_block_height, count) = sqlx::query_as::<_, (i64, i64, i64)>(
        r#"SELECT 
             MIN(block_height) as min_block_height
           , MAX(block_height) as max_block_height
           , COUNT(*) as count
         FROM sbtc_signer.stacks_blocks"#,
    )
    .fetch_one(storage.pool())
    .await
    .unwrap();

    assert_eq!(min_block_height as u64, from);
    assert_eq!(max_block_height as u64, to);
    assert_eq!(count as u64, to - from + 1);
}
