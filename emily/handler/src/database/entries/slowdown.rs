//! Entries into the slowdown keys table.

use std::hash::Hash;

use serde::{Deserialize, Serialize};

use super::{EntryTrait, KeyTrait, PrimaryIndex, PrimaryIndexTrait};

/// Limit table entry key. This is the primary index key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SlowdownKeyEntryKey {
    /// Name of the key
    pub key_name: String,
    /// Hash of the secret.
    pub hash: String,
}

/// Limit table entry key. This is the primary index key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SlowdownKeyEntry {
    /// Limit entry key.
    #[serde(flatten)]
    pub key: SlowdownKeyEntryKey,
    /// If the key is eligible to start slow mode.
    pub is_active: bool,
}

/// Implements the key trait for the deposit entry key.
impl KeyTrait for SlowdownKeyEntryKey {
    /// The type of the partition key.
    type PartitionKey = String;
    /// the type of the sort key.
    type SortKey = u64;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "KeyName";
    /// The table field name of the sort key.
    const SORT_KEY_NAME: &'static str = "Hash";
}

/// Implements the entry trait for the deposit entry.
impl EntryTrait for SlowdownKeyEntry {
    /// The type of the key for this entry type.
    type Key = SlowdownKeyEntryKey;
    /// Extract the key from the deposit entry.
    fn key(&self) -> Self::Key {
        self.key.clone()
    }
}

/// Primary index struct.
pub struct SlowdownTablePrimaryIndexInner;
/// Withdrawal table primary index type.
pub type SlowdownTablePrimaryIndex = PrimaryIndex<SlowdownTablePrimaryIndexInner>;
/// Definition of Primary index trait.
impl PrimaryIndexTrait for SlowdownTablePrimaryIndexInner {
    type Entry = SlowdownKeyEntry;
    fn table_name(settings: &crate::context::Settings) -> &str {
        &settings.slowdown_table_name
    }
}
