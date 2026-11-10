//! Postgres storage implementation.

mod read;
mod store;
mod write;

#[cfg(any(test, feature = "testing"))]
/// The SQL query used to measure withdrawal-finality lookup performance.
pub const GET_WITHDRAWAL_FINALITY_HEIGHT_QUERY: &str =
    read::PgRead::GET_WITHDRAWAL_FINALITY_HEIGHT_QUERY;
pub use store::PgStore;
pub use store::PgTransaction;

/// All migration scripts from the `signer/migrations` directory.
pub static PGSQL_MIGRATIONS: include_dir::Dir =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/migrations");
