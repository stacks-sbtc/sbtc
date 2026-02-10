#[cfg(any(test, feature = "testing"))]
use crate::storage::model::{StacksBlockHash, StacksBlockHeight};
use crate::storage::{Transactable, TransactionHandle};
use crate::{error::Error, storage::postgres::PGSQL_MIGRATIONS};
use sqlx::Executor as _;
use sqlx::pool::PoolConnection;
use sqlx::{PgExecutor, postgres::PgPoolOptions};
use tokio::sync::Mutex;

/// A wrapper around a [`sqlx::PgPool`] which implements
/// [`crate::storage::DbRead`] and [`crate::storage::DbWrite`].
#[derive(Debug, Clone)]
pub struct PgStore(sqlx::PgPool);

impl PgStore {
    /// Connect to the Postgres database at `url`.
    pub async fn connect(url: &str) -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .after_connect(|conn, _meta| Box::pin(async move {
                conn.execute("SET application_name = 'sbtc-signer'; SET search_path = sbtc_signer,public;")
                    .await?;
                Ok(())
            }))
            .connect(url)
            .await
            .map_err(Error::SqlxConnect)?;

        Ok(Self(pool))
    }

    /// Apply the migrations to the database.
    pub async fn apply_migrations(&self) -> Result<(), Error> {
        // Note 1: This could be generalized and moved up to the `storage` module, but
        // left that for a future exercise if we need to support other databases.
        //
        // Note 2: The `sqlx` "migration" feature results in dependency conflicts
        // with sqlite from the clarity crate.
        //
        // Note 3: The migration code paths have no explicit integration tests, but are
        // implicitly tested by all integration tests using `new_test_database()`.
        tracing::info!("Preparing to run database migrations");

        sqlx::raw_sql(
            r#"
                CREATE TABLE IF NOT EXISTS public.__sbtc_migrations (
                    key TEXT PRIMARY KEY
                );
            "#,
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxMigrate)?;

        let mut trx = self
            .pool()
            .begin()
            .await
            .map_err(Error::SqlxBeginTransaction)?;

        // Collect all migration scripts and sort them by filename. It is important
        // that the migration scripts are named in a way that they are executed in
        // the correct order, i.e. the current naming of `0001__`, `0002__`, etc.
        let mut migrations = PGSQL_MIGRATIONS.files().collect::<Vec<_>>();
        migrations.sort_by_key(|file| file.path().file_name());
        for migration in migrations {
            let key = migration
                .path()
                .file_name()
                .expect("failed to get filename from migration script path")
                .to_string_lossy();

            // Just in-case we end up with a README.md or some other non-SQL file
            // in the migrations directory.
            if !key.ends_with(".sql") {
                tracing::debug!(migration = %key, "Skipping non-SQL migration file");
            }

            // Check if the migration has already been applied. If so, we should
            // be able to safely skip it.
            if self.check_migration_existence(&mut *trx, &key).await? {
                tracing::debug!(migration = %key, "Database migration already applied");
                continue;
            }

            // Attempt to apply the migration. If we encounter an error, we abort
            // the entire migration process.
            if let Some(script) = migration.contents_utf8() {
                tracing::info!(migration = %key, "Applying database migration");

                // Execute the migration.
                sqlx::raw_sql(script)
                    .execute(&mut *trx)
                    .await
                    .map_err(Error::SqlxMigrate)?;

                // Save the migration as applied.
                self.insert_migration(&mut *trx, &key).await?;
            } else {
                // The trx should be rolled back on drop but let's be explicit.
                trx.rollback()
                    .await
                    .map_err(Error::SqlxRollbackTransaction)?;

                // We failed to read the migration script as valid UTF-8. This
                // shouldn't happen since it's our own migration scripts, but
                // just in case...
                return Err(Error::ReadSqlMigration(
                    migration.path().as_os_str().to_string_lossy(),
                ));
            }
        }

        trx.commit().await.map_err(Error::SqlxCommitTransaction)?;

        Ok(())
    }

    /// Check if a migration with the given `key` exists.
    async fn check_migration_existence(
        &self,
        executor: impl PgExecutor<'_>,
        key: &str,
    ) -> Result<bool, Error> {
        let result = sqlx::query_scalar::<_, i64>(
            // Note: db_name + key are PK so we can only get max 1 row.
            r#"
            SELECT COUNT(*) FROM public.__sbtc_migrations
                WHERE
                    key = $1
            ;
            "#,
        )
        .bind(key)
        .fetch_one(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(result > 0)
    }

    /// Insert a migration with the given `key`.
    async fn insert_migration(
        &self,
        executor: impl PgExecutor<'_>,
        key: &str,
    ) -> Result<(), Error> {
        sqlx::query(
            r#"
            INSERT INTO public.__sbtc_migrations (key)
                VALUES ($1)
            "#,
        )
        .bind(key)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    /// Get a reference to the underlying pool.
    pub fn pool(&self) -> &sqlx::PgPool {
        &self.0
    }

    /// Get a connection from the pool.
    pub async fn get_connection(&self) -> Result<PoolConnection<sqlx::Postgres>, Error> {
        self.0.acquire().await.map_err(Error::SqlxAcquireConnection)
    }

    /// Check whether the given block hash is a part of the stacks
    /// blockchain identified by the given chain-tip. Used by tests which use
    /// a `PgStore` directly. Included here due to `PgRead` being an internal
    /// concern of the `pgsql` module and not available in the public API.
    #[cfg(any(test, feature = "testing"))]
    pub async fn in_canonical_stacks_blockchain(
        &self,
        chain_tip: &StacksBlockHash,
        block_hash: &StacksBlockHash,
        block_height: StacksBlockHeight,
    ) -> Result<bool, Error> {
        super::read::PgRead::in_canonical_stacks_blockchain(
            self.get_connection().await?.as_mut(),
            chain_tip,
            block_hash,
            block_height,
        )
        .await
    }
}

impl From<sqlx::PgPool> for PgStore {
    fn from(value: sqlx::PgPool) -> Self {
        Self(value)
    }
}

impl Transactable for PgStore {
    type Tx<'a> = PgTransaction<'a>;

    async fn begin_transaction(&self) -> Result<Self::Tx<'_>, Error> {
        let tx = self
            .pool()
            .begin()
            .await
            .map_err(Error::SqlxBeginTransaction)?;
        Ok(PgTransaction::new(tx))
    }
}

/// Represents an active PostgreSQL transaction.
/// Implements DbRead and DbWrite to allow operations within the transaction.
pub struct PgTransaction<'a> {
    /// The underlying transaction.
    pub tx: Mutex<sqlx::PgTransaction<'a>>,
}

impl<'a> PgTransaction<'a> {
    pub(super) fn new(tx: sqlx::Transaction<'a, sqlx::Postgres>) -> Self {
        Self { tx: Mutex::new(tx) }
    }
}

impl TransactionHandle for PgTransaction<'_> {
    async fn commit(self) -> Result<(), Error> {
        let tx = self.tx.into_inner();

        tx.commit().await.map_err(Error::SqlxCommitTransaction)?;

        Ok(())
    }

    async fn rollback(self) -> Result<(), Error> {
        let tx = self.tx.into_inner();

        tx.rollback()
            .await
            .map_err(Error::SqlxRollbackTransaction)?;

        Ok(())
    }
}
