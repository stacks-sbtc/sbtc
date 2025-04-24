use madhouse::{Command, CommandWrapper};
use proptest::prelude::Strategy;
use signer::storage::DbWrite;

use super::{Ctx, TestState};

pub struct NewTestDatabase;

impl Command<TestState, Ctx> for NewTestDatabase {
    fn check(&self, state: &TestState) -> bool {
        state.db.is_none()
    }

    fn apply(&self, state: &mut TestState) {
        let runtime = state.runtime.as_ref().unwrap();
        let db = runtime.block_on(async { signer::testing::storage::new_test_database().await });

        state.db = Some(db);
    }

    fn label(&self) -> String {
        "NEW_TEST_DATABASE".to_string()
    }

    fn build(_ctx: std::sync::Arc<Ctx>) -> impl Strategy<Value = CommandWrapper<TestState, Ctx>> {
        proptest::prelude::Just(CommandWrapper::new(NewTestDatabase))
    }
}

pub struct WriteDkgShares;

impl Command<TestState, Ctx> for WriteDkgShares {
    fn check(&self, state: &TestState) -> bool {
        state.db.is_some() && state.shares.is_some()
    }

    fn apply(&self, state: &mut TestState) {
        let runtime = state.runtime.as_ref().unwrap();
        let db = state.db.as_ref().unwrap();
        let shares = state.shares.as_ref().unwrap();

        runtime.block_on(async {
            match db.write_encrypted_dkg_shares(shares).await {
                Ok(db_result) => db_result,
                Err(e) => {
                    panic!("Failed to write DKG shares: {}", e);
                }
            };
        });
    }

    fn label(&self) -> String {
        "WRITE_DKG_SHARES".to_string()
    }

    fn build(_ctx: std::sync::Arc<Ctx>) -> impl Strategy<Value = CommandWrapper<TestState, Ctx>> {
        proptest::prelude::Just(CommandWrapper::new(WriteDkgShares))
    }
}
