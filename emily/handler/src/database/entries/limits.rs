//! Entries into the limit table.

use std::hash::Hash;

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::api::models::limits::Limits;

use super::{EntryTrait, KeyTrait, PrimaryIndex, PrimaryIndexTrait};

// Limit entry ---------------------------------------------------------------

/// Limit entry type, representing information about if entry is manually created
/// or via throttle mode triggering
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u64)]
pub enum LimitEntryType {
    /// Standard limits entry, manually setted.
    #[default]
    Standard = 0,
    /// Throttle limits entry, setted via triggering throttle mode.
    Throttled = 1,
}

impl std::fmt::Display for LimitEntryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Standard => write!(f, "0"),
            Self::Throttled => write!(f, "1"),
        }
    }
}

/// Limit table entry key. This is the primary index key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LimitEntryKey {
    /// Type of the entry, representing if this entry is throttle mode entry or not.
    pub entry_type: LimitEntryType,
    /// The timestamp of the given update.
    pub timestamp: u64,
}

/// Limit table entry key. This is the primary index key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LimitEntry {
    /// Limit entry key.
    #[serde(flatten)]
    pub key: LimitEntryKey,
    /// Represents the current sBTC limits.
    pub peg_cap: Option<u64>,
    /// Per deposit minimum. If none then there is no minimum.
    pub per_deposit_minimum: Option<u64>,
    /// Per deposit cap. If none then the cap is the same as the global per deposit cap.
    pub per_deposit_cap: Option<u64>,
    /// Per withdrawal cap. If none then the cap is the same as the global per withdrawal cap.
    pub per_withdrawal_cap: Option<u64>,
    /// Number of blocks that define the rolling withdrawal window.
    pub rolling_withdrawal_blocks: Option<u64>,
    /// Maximum total sBTC that can be withdrawn within the rolling withdrawal window.
    pub rolling_withdrawal_cap: Option<u64>,
    /// Throttle key initiated throttle mode
    pub throttle_mode_initiator: Option<String>,
}

impl From<Limits> for LimitEntry {
    fn from(limits: Limits) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("SystemTime::now() returned time earlier then UNIX_EPOCH")
            .as_secs();

        Self {
            key: LimitEntryKey {
                entry_type: LimitEntryType::Standard,
                timestamp,
            },
            peg_cap: limits.peg_cap,
            per_deposit_minimum: limits.per_deposit_minimum,
            per_deposit_cap: limits.per_deposit_cap,
            per_withdrawal_cap: limits.per_withdrawal_cap,
            rolling_withdrawal_blocks: limits.rolling_withdrawal_blocks,
            rolling_withdrawal_cap: limits.rolling_withdrawal_cap,
            throttle_mode_initiator: limits.throttle_mode_initiator,
        }
    }
}

impl LimitEntry {
    /// Returns true if the limit entry has no limits set.
    pub fn is_empty(&self) -> bool {
        self.peg_cap.is_none()
            && self.per_deposit_cap.is_none()
            && self.per_withdrawal_cap.is_none()
    }
}

/// Implements the key trait for the deposit entry key.
impl KeyTrait for LimitEntryKey {
    /// The type of the partition key.
    type PartitionKey = u64;
    /// the type of the sort key.
    type SortKey = u64;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "EntryType";
    /// The table field name of the sort key.
    const SORT_KEY_NAME: &'static str = "Timestamp";
}

/// Implements the entry trait for the deposit entry.
impl EntryTrait for LimitEntry {
    /// The type of the key for this entry type.
    type Key = LimitEntryKey;
    /// Extract the key from the deposit entry.
    fn key(&self) -> Self::Key {
        self.key.clone()
    }
}

/// Primary index struct.
pub struct LimitTablePrimaryIndexInner;
/// Withdrawal table primary index type.
pub type LimitTablePrimaryIndex = PrimaryIndex<LimitTablePrimaryIndexInner>;
/// Definition of Primary index trait.
impl PrimaryIndexTrait for LimitTablePrimaryIndexInner {
    type Entry = LimitEntry;
    fn table_name(settings: &crate::context::Settings) -> &str {
        &settings.limit_table_name
    }
}
