//! Emily deposit reconciliation using Bitcoin and Stacks API data.

pub mod config;
pub mod error;
pub mod logging;
pub mod model;
pub mod processor;

#[cfg(test)]
mod tests;
