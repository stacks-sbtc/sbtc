//! In-memory storage module for testing.

mod memory;
mod transaction;

pub use memory::SharedStore;
pub use memory::Store;
pub use transaction::InMemoryTransaction;
