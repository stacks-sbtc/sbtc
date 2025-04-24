use madhouse::{State, TestContext};
use signer::storage::model::EncryptedDkgShares;

#[derive(Clone, Debug)]
pub struct Ctx;

impl TestContext for Ctx {}

#[derive(Debug, Default)]
pub struct TestState {
    pub db: Option<signer::storage::postgres::PgStore>,
    pub shares: Option<EncryptedDkgShares>,
}

impl State for TestState {}
