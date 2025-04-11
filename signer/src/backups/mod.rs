//! Module handling backups of the signer state.

mod backup;
mod restore;

pub use backup::BackupError;
pub use restore::RestoreError;

#[allow(unused)]
const BACKUP_FILE_VERSION: u32 = 1;

#[cfg(test)]
mod testing {
    use crate::{
        bitcoin::MockBitcoinInteract,
        emily_client::MockEmilyInteract,
        keys::PrivateKey,
        stacks::api::MockStacksInteract,
        storage::{
            DbWrite,
            in_memory::{SharedStore, Store},
            model,
        },
        testing::context::*,
    };

    pub type MockedContext = TestContext<
        SharedStore,
        WrappedMock<MockBitcoinInteract>,
        WrappedMock<MockStacksInteract>,
        WrappedMock<MockEmilyInteract>,
    >;

    // Helper context setup
    pub async fn setup_test_context(
        signer_private_key: PrivateKey,
        shares: Vec<model::EncryptedDkgShares>,
    ) -> MockedContext {
        // Assuming TestContext takes Arc<Store>
        let store = Store::new_shared();
        for share in shares {
            store.write_encrypted_dkg_shares(&share).await.unwrap();
        }

        TestContext::builder()
            .with_storage(store)
            .with_mocked_clients()
            .modify_settings(|config| {
                config.signer.private_key = signer_private_key;
            })
            .build()
    }
}
