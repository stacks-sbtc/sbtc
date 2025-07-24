use std::sync::Arc;

use fake::Fake as _;
use fake::Faker;
use madhouse::{Command, CommandWrapper};
use proptest::prelude::Just;
use proptest::prelude::Strategy;
use proptest::prelude::any;
use rand::SeedableRng;
use secp256k1::{Keypair, rand::rngs::StdRng};
use signer::storage::DbWrite as _;
use signer::{
    keys::PublicKey,
    storage::model::{DkgSharesStatus, EncryptedDkgShares},
};

use super::{Ctx, TestState};

pub struct CreateFailedDkgShares {
    seed: u64,
}

impl CreateFailedDkgShares {
    fn new(seed: u64) -> Self {
        Self { seed }
    }
}

impl Command<TestState, Ctx> for CreateFailedDkgShares {
    fn check(&self, _state: &TestState) -> bool {
        true
    }

    fn apply(&self, state: &mut TestState) {
        let mut rng = StdRng::seed_from_u64(self.seed);
        let aggregate_key: PublicKey = Keypair::new_global(&mut rng).public_key().into();
        let shares = EncryptedDkgShares {
            aggregate_key,
            dkg_shares_status: DkgSharesStatus::Failed,
            started_at_bitcoin_block_height: 0u64.into(),
            ..Faker.fake_with_rng(&mut rng)
        };

        state.shares = Some(shares);
    }

    fn label(&self) -> String {
        "CREATE_FAILED_DKG_SHARES".to_string()
    }

    fn build(_ctx: Arc<Ctx>) -> impl Strategy<Value = CommandWrapper<TestState, Ctx>> {
        any::<u64>().prop_map(|seed| CommandWrapper::new(CreateFailedDkgShares::new(seed)))
    }
}

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

    fn build(ctx: Arc<Ctx>) -> impl Strategy<Value = CommandWrapper<TestState, Ctx>> {
        Just(CommandWrapper::new(WriteDkgShares::new(ctx.clone())))
    }
}
