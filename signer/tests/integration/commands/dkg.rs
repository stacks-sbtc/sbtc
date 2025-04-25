use fake::Fake as _;
use fake::Faker;
use madhouse::{Command, CommandWrapper};
use proptest::prelude::Strategy;
use proptest::prelude::any;
use rand::SeedableRng;
use secp256k1::{Keypair, rand::rngs::StdRng};
use signer::{
    keys::PublicKey,
    storage::model::{DkgSharesStatus, EncryptedDkgShares},
};

use super::{Ctx, TestState};

pub struct CreateDkgShares {
    seed: u64,
}

impl CreateDkgShares {
    fn with_seed(seed: u64) -> Self {
        Self { seed }
    }
}

impl Command<TestState, Ctx> for CreateDkgShares {
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
            ..Faker.fake()
        };

        state.shares = Some(shares);
    }

    fn label(&self) -> String {
        "CREATE_DKG_SHARES".to_string()
    }

    fn build(_ctx: std::sync::Arc<Ctx>) -> impl Strategy<Value = CommandWrapper<TestState, Ctx>> {
        any::<u64>().prop_map(|seed| CommandWrapper::new(CreateDkgShares::with_seed(seed)))
    }
}
