use std::sync::Arc;

use madhouse::{State, TestContext};
use signer::{
    storage::{model::EncryptedDkgShares, postgres::PgStore},
    testing::storage::new_test_database,
};
use tokio::runtime::Runtime;

#[derive(Clone, Debug)]
pub struct Ctx {
    db: PgStore,
    runtime: Arc<Runtime>,
}

impl Ctx {
    pub fn new() -> Self {
        let runtime = Arc::new(Runtime::new().unwrap());
        let db = runtime.block_on(async { new_test_database().await });

        Self { db, runtime }
    }

    pub fn db(&self) -> &PgStore {
        &self.db
    }

    pub fn runtime_handle(&self) -> Arc<Runtime> {
        self.runtime.clone()
    }
}

impl TestContext for Ctx {}

#[derive(Debug, Default)]
pub struct TestState {
    pub shares: Option<EncryptedDkgShares>,
}

impl State for TestState {}
