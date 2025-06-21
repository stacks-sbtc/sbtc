//! All testing utility functions.
pub mod deposits;
pub mod regtest;

/// A trait that provides an implementation for a type to be converted into
/// satoshis (which are represented as `u64`).
pub trait AsSatoshis {
    /// Convert the value into satoshis.
    #[track_caller]
    fn as_satoshis(&self) -> u64;
}

impl AsSatoshis for bitcoin::Amount {
    fn as_satoshis(&self) -> u64 {
        self.to_sat()
    }
}

impl AsSatoshis for u64 {
    fn as_satoshis(&self) -> u64 {
        *self
    }
}
