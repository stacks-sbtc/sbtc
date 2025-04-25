use madhouse::{State, TestContext};

#[derive(Clone, Debug)]
pub struct Ctx;

impl TestContext for Ctx {}

#[derive(Debug, Default)]
pub struct TestState {
    pub db: Option<signer::storage::postgres::PgStore>,
    pub runtime: Option<tokio::runtime::Runtime>,
    pub shares: Option<signer::storage::model::EncryptedDkgShares>,
}

impl State for TestState {}
