//! Emily deposit reconciliation using Bitcoin and Stacks API data.
//!
//! The binary schedules cycles; [`processor::Processor`] performs each cycle.

pub mod config;
pub mod error;
pub mod logging;
pub mod model;
pub mod processor;
