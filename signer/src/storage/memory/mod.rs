//! In-memory storage module for testing.

mod read;
mod store;
mod write;

#[cfg(test)]
mod tests;

pub use store::InMemoryTransaction;
pub use store::SharedStore;
pub use store::Store;
