use madhouse::{State, TestContext};

#[derive(Clone, Debug)]
pub struct Ctx {
    runtime: std::sync::Arc<tokio::runtime::Runtime>,
}

impl Ctx {
    pub fn new() -> Self {
        let runtime = std::sync::Arc::new(tokio::runtime::Runtime::new().unwrap());
        Self { runtime }
    }

    pub fn runtime_handle(&self) -> std::sync::Arc<tokio::runtime::Runtime> {
        self.runtime.clone()
    }
}

impl TestContext for Ctx {}

#[derive(Debug, Default)]
pub struct TestState {
    pub db: Option<signer::storage::postgres::PgStore>,
    pub shares: Option<signer::storage::model::EncryptedDkgShares>,
}

impl State for TestState {}
