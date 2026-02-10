//! In-memory storage module for testing.

#![allow(clippy::unwrap_in_result, clippy::unwrap_used, clippy::expect_used)]

mod read;
mod store;
mod write;

#[cfg(test)]
mod tests;

pub use store::InMemoryTransaction;
pub use store::SharedStore;
pub use store::Store;

/// Errors specific to the in-memory storage implementation.
#[derive(Debug, thiserror::Error)]
pub enum MemoryStoreError {
    /// Occurs when an optimistic concurrency violation occurs when trying to commit a transaction.
    #[error(
        "Optimistic concurrency violation: actual version {actual_version} does not match expected version {expected_version}"
    )]
    OptimisticConcurrency {
        /// The actual version of the underlying store.
        actual_version: usize,
        /// The transaction's expected version.
        expected_version: usize,
    },
}
