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
use crate::storage::model::StacksBlockHeight;

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
    stacks_parent_ch: None,
    last_sortition_ch: None,
    committed_block_hash: None,
    vrf_seed: None,
};

/// Some dummy node info
pub const DUMMY_NODE_INFO: GetNodeInfoResponse = GetNodeInfoResponse {
    burn_block_height: BitcoinBlockHeight::new(0),
    server_version: String::new(),
    stacks_tip_consensus_hash: crate::storage::model::ConsensusHash::new([0; 20]),
    stacks_tip_height: StacksBlockHeight::new(0),
    stacks_tip: BlockHeaderHash([0; 32]),
};

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
}
