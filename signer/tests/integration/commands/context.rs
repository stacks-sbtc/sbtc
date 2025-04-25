use madhouse::{State, TestContext};

#[derive(Clone, Debug)]
pub struct Ctx {
    db: signer::storage::postgres::PgStore,
    runtime: std::sync::Arc<tokio::runtime::Runtime>,
}

impl Ctx {
    pub fn new() -> Self {
        let runtime = std::sync::Arc::new(tokio::runtime::Runtime::new().unwrap());
        let db = runtime.block_on(async { signer::testing::storage::new_test_database().await });

        Self { db, runtime }
    }

    pub fn db(&self) -> &signer::storage::postgres::PgStore {
        &self.db
    }

    pub fn runtime_handle(&self) -> std::sync::Arc<tokio::runtime::Runtime> {
        self.runtime.clone()
    }
}

impl TestContext for Ctx {}

#[derive(Debug, Default)]
pub struct TestState {
    pub shares: Option<signer::storage::model::EncryptedDkgShares>,
}

impl State for TestState {}
