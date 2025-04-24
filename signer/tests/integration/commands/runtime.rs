use madhouse::{Command, CommandWrapper};
use proptest::prelude::Strategy;

use super::{Ctx, TestState};

pub struct InitializeRuntime;

impl Command<TestState, Ctx> for InitializeRuntime {
    fn check(&self, state: &TestState) -> bool {
        state.runtime.is_none()
    }

    fn apply(&self, state: &mut TestState) {
        state.runtime = Some(tokio::runtime::Runtime::new().unwrap());
    }

    fn label(&self) -> String {
        "INITIALIZE_RUNTIME".to_string()
    }

    fn build(_ctx: std::sync::Arc<Ctx>) -> impl Strategy<Value = CommandWrapper<TestState, Ctx>> {
        proptest::prelude::Just(CommandWrapper::new(InitializeRuntime))
    }
}
