//! In-memory storage module for testing.

mod read;
mod store;
mod transaction;
mod write;

pub use store::SharedStore;
pub use store::Store;
pub use transaction::InMemoryTransaction;
