//! Entries into the throttle keys table.

use std::hash::Hash;

use serde::{Deserialize, Serialize};

use super::{EntryTrait, KeyTrait, PrimaryIndex, PrimaryIndexTrait};

/// Limit table entry key. This is the primary index key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ThrottleKeyEntryKey {
    /// Hash of the secret
    pub hash: String,
    /// The timestamp of key creation, in seconds from UNIX epoch
    pub created_at: u64,
}

/// Limit table entry key. This is the primary index key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ThrottleKeyEntry {
    /// Limit entry key.
    #[serde(flatten)]
    pub key: ThrottleKeyEntryKey,
    /// If the key is eligible to start throttle mode.
    pub is_active: bool,
    /// Name of the key.
    pub name: String,
}

/// Implements the key trait for the deposit entry key.
impl KeyTrait for ThrottleKeyEntryKey {
    /// The type of the partition key.
    type PartitionKey = String;
    /// the type of the sort key.
    type SortKey = u64;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "Hash";
    /// The table field name of the sort key.
    const SORT_KEY_NAME: &'static str = "CreatedAt";
}

/// Implements the entry trait for the deposit entry.
impl EntryTrait for ThrottleKeyEntry {
    /// The type of the key for this entry type.
    type Key = ThrottleKeyEntryKey;
    /// Extract the key from the deposit entry.
    fn key(&self) -> Self::Key {
        self.key.clone()
    }
}

/// Primary index struct.
pub struct ThrottleTablePrimaryIndexInner;
/// Withdrawal table primary index type.
pub type ThrottleTablePrimaryIndex = PrimaryIndex<ThrottleTablePrimaryIndexInner>;
/// Definition of Primary index trait.
impl PrimaryIndexTrait for ThrottleTablePrimaryIndexInner {
    type Entry = ThrottleKeyEntry;
    fn table_name(settings: &crate::context::Settings) -> &str {
        &settings.throttle_table_name
    }
}
