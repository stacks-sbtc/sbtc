use madhouse::{Command, CommandWrapper};
use proptest::prelude::Strategy;

use super::{Ctx, TestState};

pub struct NewTestDatabase;

impl Command<TestState, Ctx> for NewTestDatabase {
    fn check(&self, state: &TestState) -> bool {
        state.db.is_none()
    }

    fn apply(&self, state: &mut TestState) {
        let runtime = state.runtime.as_ref().unwrap();
        let db = runtime.block_on(async {
            signer::testing::storage::new_test_database().await
        });

        state.db = Some(db);
    }

    fn label(&self) -> String {
        "NEW_TEST_DATABASE".to_string()
    }

    fn build(_ctx: std::sync::Arc<Ctx>) -> impl Strategy<Value = CommandWrapper<TestState, Ctx>> {
        proptest::prelude::Just(CommandWrapper::new(NewTestDatabase))
    }
}
