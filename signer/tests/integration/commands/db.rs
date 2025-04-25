use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::Strategy;
use signer::storage::DbWrite;

use super::{Ctx, TestState};

pub struct WriteDkgShares {
    ctx: Arc<Ctx>,
}

impl WriteDkgShares {
    pub fn new(ctx: Arc<Ctx>) -> Self {
        Self { ctx }
    }
}

impl Command<TestState, Ctx> for WriteDkgShares {
    fn check(&self, state: &TestState) -> bool {
        state.shares.is_some()
    }

    fn apply(&self, state: &mut TestState) {
        let shares = state.shares.as_ref().unwrap();

        self.ctx.runtime_handle().block_on(async {
            match self.ctx.db().write_encrypted_dkg_shares(shares).await {
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

    fn build(ctx: std::sync::Arc<Ctx>) -> impl Strategy<Value = CommandWrapper<TestState, Ctx>> {
        proptest::prelude::Just(CommandWrapper::new(WriteDkgShares::new(ctx.clone())))
    }
}
