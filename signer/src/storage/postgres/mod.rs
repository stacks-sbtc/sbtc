//! Postgres storage implementation.

mod read;
mod store;
mod write;

pub use store::PgStore;
pub use store::PgTransaction;

/// All migration scripts from the `signer/migrations` directory.
static PGSQL_MIGRATIONS: include_dir::Dir =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/migrations");
