use madhouse::{State, TestContext};

#[derive(Clone, Debug)]
pub struct Ctx;

impl TestContext for Ctx {}

#[derive(Debug, Default)]
pub struct TestState {
    pub db: Option<signer::storage::postgres::PgStore>,
}

impl State for TestState {}
