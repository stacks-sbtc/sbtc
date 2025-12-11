//! Test utilities from the stacks module
//!

use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
use blockstack_lib::net::api::getsortition::SortitionInfo;
use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::SortitionId;

use crate::error::Error;
use crate::stacks::api::GetNodeInfoResponse;
use crate::stacks::api::GetTenureInfoResponse;
use crate::stacks::api::StacksBlockHeader;
use crate::stacks::api::TenureBlockHeaders;
use crate::storage::model::BitcoinBlockHeight;
use crate::storage::model::ConsensusHash;
use crate::storage::model::StacksBlockHash;
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

/// Dummy node info
pub const DUMMY_NODE_INFO: GetNodeInfoResponse = GetNodeInfoResponse {
    burn_block_height: BitcoinBlockHeight::new(0u64),
    server_version: String::new(),
    stacks_tip_consensus_hash: ConsensusHash::new([0; 20]),
    stacks_tip_height: StacksBlockHeight::new(0u64),
    stacks_tip: BlockHeaderHash([0; 32]),
};

/// Some dummy tenure info
pub const DUMMY_TENURE_INFO: GetTenureInfoResponse = GetTenureInfoResponse {
    consensus_hash: ConsensusHash::new([0; 20]),
    tenure_start_block_id: StacksBlockHash::new([0; 32]),
    parent_consensus_hash: ConsensusHash::new([0; 20]),
    // The following bytes are the ones returned by StacksBlockId::first_mined()
    parent_tenure_start_block_id: StacksBlockHash::new([
        0x55, 0xc9, 0x86, 0x1b, 0xe5, 0xcf, 0xf9, 0x84, 0xa2, 0x0c, 0xe6, 0xd9, 0x9d, 0x4a, 0xa6,
        0x59, 0x41, 0x41, 0x28, 0x89, 0xbd, 0xc6, 0x65, 0x09, 0x41, 0x36, 0x42, 0x9b, 0x84, 0xf8,
        0xc2, 0xee,
    ]),
    tip_block_id: StacksBlockHash::new([0; 32]),
    tip_height: StacksBlockHeight::new(0u64),
    reward_cycle: 0,
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
