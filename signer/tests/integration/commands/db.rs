use madhouse::{Command, CommandWrapper};
use proptest::prelude::Strategy;

use super::{Ctx, TestState};

pub struct NewTestDatabase;

impl Command<TestState, Ctx> for NewTestDatabase {
    fn check(&self, state: &TestState) -> bool {
        state.db.is_none()
    }

    fn apply(&self, state: &mut TestState) {
        // Create a Tokio runtime just for this operation
        let rt = tokio::runtime::Runtime::new().unwrap();

        // Use the Tokio runtime to run the async function
        let db = rt.block_on(signer::testing::storage::new_test_database());
        state.db = Some(db);
    }

    fn label(&self) -> String {
        "NEW_TEST_DATABASE".to_string()
    }

    fn build(_ctx: std::sync::Arc<Ctx>) -> impl Strategy<Value = CommandWrapper<TestState, Ctx>> {
        proptest::prelude::Just(CommandWrapper::new(NewTestDatabase))
    }
}
