use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};
use signer::{error::Error, keys::PublicKeyXOnly, storage::model::DkgSharesStatus};

use crate::transaction_signer::validate_dkg_verification_message::TestParams;

use super::{Ctx, TestState};

pub struct VerifyDkgVerificationFailed {
    ctx: Arc<Ctx>,
}

impl VerifyDkgVerificationFailed {
    pub fn new(ctx: Arc<Ctx>) -> Self {
        Self { ctx }
    }
}

impl Command<TestState, Ctx> for VerifyDkgVerificationFailed {
    fn check(&self, state: &TestState) -> bool {
        state.shares.is_some()
            && state.shares.as_ref().unwrap().dkg_shares_status == DkgSharesStatus::Failed
    }

    fn apply(&self, state: &mut TestState) {
        let aggregate_key = state.shares.as_ref().unwrap().aggregate_key.clone();
        let aggregate_key_x_only: PublicKeyXOnly = aggregate_key.into();
        let params = TestParams::new(aggregate_key_x_only);

        let result = self
            .ctx
            .runtime_handle()
            .block_on(async { params.execute(self.ctx.db()).await.unwrap_err() });

        assert!(matches!(
            result,
            Error::DkgVerificationFailed(key) if aggregate_key_x_only == key
        ))
    }

    fn label(&self) -> String {
        "VERIFY_DKG_VERIFICATION_FAILED".to_string()
    }

    fn build(ctx: std::sync::Arc<Ctx>) -> impl Strategy<Value = CommandWrapper<TestState, Ctx>> {
        Just(CommandWrapper::new(VerifyDkgVerificationFailed::new(
            ctx.clone(),
        )))
    }
}
