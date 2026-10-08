use blockstack_lib::types::chainstate::StacksAddress;
use rand::rngs::OsRng;

use sbtc::testing::regtest;
use signer::context::Context as _;
use signer::error::Error;
use signer::keys::PublicKey;
use signer::keys::SignerScriptPubKey as _;
use signer::stacks::api::SignerSetInfo;
use signer::stacks::contracts::AsContractCall as _;
use signer::stacks::contracts::ReqContext;
use signer::stacks::contracts::RotateKeysErrorMsg;
use signer::stacks::contracts::RotateKeysV1;
use signer::stacks::wallet::SignerWallet;
use signer::storage::DbRead as _;
use signer::storage::DbWrite as _;
use signer::storage::model::BitcoinBlock;
use signer::storage::model::DkgSharesStatus;
use signer::storage::model::EncryptedDkgShares;
use signer::storage::model::KeyRotationEvent;
use signer::storage::model::StacksBlockHash;
use signer::storage::model::StacksPrincipal;
use signer::storage::model::StacksTxId;
use signer::storage::postgres::PgStore;
use signer::testing;
use signer::testing::context::*;
use signer::testing::get_rng;

use fake::Fake as _;
use signer::testing::storage::model::TestData;

use crate::setup::set_verification_status;

struct TestRotateKeySetup {
    /// The signer object. It's public key represents the group of signers'
    /// public keys, allowing us to abstract away the fact that there are
    /// many signers needed to sign a transaction.
    pub aggregated_signer: regtest::Recipient,
    /// The public keys of the signer set. It is effectively controlled by
    /// the above signer's private key.
    pub signer_keys: Vec<PublicKey>,
    /// This value affects whether a request is considered "accepted".
    pub signatures_required: u16,
    /// The transaction ID
    pub txid: StacksTxId,
    // The block hash of the block that confirmed the transaction.
    pub block_hash: StacksBlockHash,
    /// Signers wallet
    pub wallet: SignerWallet,
    /// Bitcoin chain tip used when generating current setup
    pub chain_tip: BitcoinBlock,
}

impl TestRotateKeySetup {
    pub async fn new<R>(
        db: &PgStore,
        signatures_required: u16,
        num_signers: usize,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng,
    {
        let aggregated_signer = regtest::Recipient::new(bitcoin::AddressType::P2tr);
        let signer_keys =
            signer::testing::wallet::create_signers_keys(rng, &aggregated_signer, num_signers);

        let wallet = SignerWallet::new(
            &signer_keys,
            signatures_required,
            signer::config::NetworkKind::Regtest,
            0,
        )
        .unwrap();

        // Create the transaction as if included in the current stacks chain tip
        let bitcoin_chain_tip = db
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("failed to get bitcoin chain tip")
            .expect("no bitcoin chain tip");
        let bitcoin_chain_tip_block = db
            .get_bitcoin_block(&bitcoin_chain_tip)
            .await
            .expect("failed to get bitcoin chain tip block")
            .expect("no bitcoin chain tip block");
        let stacks_chain_tip = db
            .get_stacks_chain_tip(&bitcoin_chain_tip)
            .await
            .expect("failed to get stacks chain tip")
            .expect("no stacks chain tip");

        TestRotateKeySetup {
            aggregated_signer,
            signer_keys,
            signatures_required,
            txid: fake::Faker.fake_with_rng(rng),
            block_hash: stacks_chain_tip.block_hash,
            wallet,
            chain_tip: bitcoin_chain_tip_block,
        }
    }

    /// Get setup aggregate key
    pub fn aggregate_key(&self) -> PublicKey {
        self.aggregated_signer.keypair.public_key().into()
    }

    /// Store mocked shares in dkg_shares table.
    pub async fn store_dkg_shares(&self, db: &PgStore) {
        let aggregate_key: PublicKey = self.aggregate_key();

        let shares = EncryptedDkgShares {
            script_pubkey: aggregate_key.signers_script_pubkey().into(),
            tweaked_aggregate_key: aggregate_key.signers_tweaked_pubkey().unwrap(),
            encrypted_private_shares: Vec::new(),
            public_shares: Vec::new(),
            aggregate_key,
            signer_set_public_keys: self.signer_keys.clone(),
            signature_share_threshold: self.signatures_required,
            dkg_shares_status: DkgSharesStatus::Verified,
            started_at_bitcoin_block_hash: self.chain_tip.block_hash,
            started_at_bitcoin_block_height: self.chain_tip.block_height,
        };
        db.write_encrypted_dkg_shares(&shares).await.unwrap();
    }

    /// Store rotate key tx.
    pub async fn store_rotate_keys(&self, db: &PgStore) {
        let aggregate_key: PublicKey = self.aggregate_key();
        let address = StacksPrincipal::from(clarity::vm::types::PrincipalData::from(
            self.wallet.address().clone(),
        ));
        let rotate_key_tx = KeyRotationEvent {
            address,
            block_hash: self.block_hash,
            txid: self.txid,
            aggregate_key: aggregate_key.into(),
            signer_set: self.signer_keys.clone(),
            signatures_required: self.signatures_required,
        };
        db.write_rotate_keys_transaction(&rotate_key_tx)
            .await
            .unwrap();
    }
}

fn make_rotate_key(setup: &TestRotateKeySetup) -> (RotateKeysV1, ReqContext) {
    let rotate_key = RotateKeysV1::new(
        &setup.wallet,
        StacksAddress::burn_address(false),
        &setup.aggregate_key(),
    );

    // This is what the current signer thinks is the state of things.
    let req_ctx = ReqContext {
        chain_tip: setup.chain_tip.clone().into(),
        // This is not used for rotate-key tests.
        stacks_chain_tip: setup.block_hash,
        context_window: 10,
        origin: fake::Faker.fake_with_rng(&mut OsRng),
        signatures_required: setup.signatures_required,
        deployer: StacksAddress::burn_address(false),
    };

    (rotate_key, req_ctx)
}

/// Assert that rotate-keys validation failed for the expected policy reason.
fn assert_rotate_keys_error(error: Error, expected: RotateKeysErrorMsg) {
    match error {
        Error::RotateKeysValidation(error) => assert_eq!(error.error, expected),
        error => panic!("unexpected error during validation: {error}"),
    }
}

#[tokio::test]
async fn rotate_key_validation_switches_to_v2_checks_at_activation() {
    let db = testing::storage::new_test_database().await;
    let mut rng = get_rng();
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };
    TestData::generate(&mut rng, &[], &test_model_params)
        .write_to(&db)
        .await;

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;
    let activation_height = setup.chain_tip.block_height;
    let configured_signers = setup.signer_keys.iter().copied().collect();
    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .modify_settings(|settings| {
            settings.signer.v2_signing_block_height = Some(activation_height);
            settings.signer.dkg_disable_block_height = Some(activation_height);
            settings.signer.bootstrap_signing_set = configured_signers;
            settings.signer.bootstrap_signatures_required = setup.signatures_required;
            settings.signer.deployer = StacksAddress::burn_address(false);
        })
        .build();

    let (_, mut req_ctx) = make_rotate_key(&setup);
    let rotate_keys = RotateKeysV1::load(&ctx, &req_ctx.chain_tip).await.unwrap();
    assert_eq!(
        rotate_keys.aggregate_key,
        req_ctx.chain_tip.block_hash.into()
    );

    // Immediately below activation validation still follows the v1 path and
    // therefore requires DKG shares.
    req_ctx.chain_tip.block_height = activation_height.saturating_sub(1_u64);
    std::assert_matches!(
        rotate_keys.validate(&ctx, &req_ctx).await,
        Err(Error::NoDkgShares)
    );

    // At the activation height, the configured signer set is authoritative
    // and no DKG row is needed.
    req_ctx.chain_tip.block_height = activation_height;
    rotate_keys.validate(&ctx, &req_ctx).await.unwrap();

    let mut wrong_signer_set = rotate_keys.clone();
    let removed_key = *wrong_signer_set.new_keys.first().unwrap();
    wrong_signer_set.new_keys.remove(&removed_key);
    assert_rotate_keys_error(
        wrong_signer_set.validate(&ctx, &req_ctx).await.unwrap_err(),
        RotateKeysErrorMsg::SignerSetMismatch,
    );

    let mut wrong_registry_key = rotate_keys.clone();
    wrong_registry_key.aggregate_key = setup.aggregate_key().into();
    assert_rotate_keys_error(
        wrong_registry_key
            .validate(&ctx, &req_ctx)
            .await
            .unwrap_err(),
        RotateKeysErrorMsg::AggregateKeyMismatch,
    );

    let mut wrong_threshold = rotate_keys.clone();
    wrong_threshold.signatures_required += 1;
    assert_rotate_keys_error(
        wrong_threshold.validate(&ctx, &req_ctx).await.unwrap_err(),
        RotateKeysErrorMsg::SignaturesRequiredMismatch,
    );

    testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn rotate_keys_continue_to_use_dkg_after_v2_signing_activation() {
    let db = testing::storage::new_test_database().await;
    let mut rng = get_rng();
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };
    TestData::generate(&mut rng, &[], &test_model_params)
        .write_to(&db)
        .await;

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;
    setup.store_dkg_shares(&db).await;
    let activation_height = setup.chain_tip.block_height;
    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .modify_settings(|settings| {
            settings.signer.v2_signing_block_height = Some(activation_height);
            settings.signer.dkg_disable_block_height = Some(u64::MAX.into());
            settings.signer.deployer = StacksAddress::burn_address(false);
        })
        .build();

    let (_, req_ctx) = make_rotate_key(&setup);
    let rotate_keys = RotateKeysV1::load(&ctx, &req_ctx.chain_tip).await.unwrap();

    assert_eq!(rotate_keys.aggregate_key, setup.aggregate_key().into());
    assert_eq!(rotate_keys.new_keys, setup.wallet.public_keys().clone());
    assert_eq!(rotate_keys.signatures_required, setup.signatures_required);
    rotate_keys.validate(&ctx, &req_ctx).await.unwrap();

    testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn rotate_key_validation_v2_rejects_registry_up_to_date() {
    let db = testing::storage::new_test_database().await;
    let mut rng = get_rng();
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };
    TestData::generate(&mut rng, &[], &test_model_params)
        .write_to(&db)
        .await;

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;
    let activation_height = setup.chain_tip.block_height;
    let configured_signers = setup.signer_keys.iter().copied().collect();
    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .modify_settings(|settings| {
            settings.signer.v2_signing_block_height = Some(activation_height);
            settings.signer.dkg_disable_block_height = Some(activation_height);
            settings.signer.bootstrap_signing_set = configured_signers;
            settings.signer.bootstrap_signatures_required = setup.signatures_required;
            settings.signer.deployer = StacksAddress::burn_address(false);
        })
        .build();

    let (_, req_ctx) = make_rotate_key(&setup);
    let rotate_keys = RotateKeysV1::load(&ctx, &req_ctx.chain_tip).await.unwrap();

    // A different threshold means the registry is not yet up to date, even
    // when it already contains the configured signer set.
    ctx.state().update_registry_signer_set_info(SignerSetInfo {
        aggregate_key: setup.aggregate_key().into(),
        signer_set: rotate_keys.new_keys.clone(),
        signatures_required: rotate_keys.signatures_required + 1,
    });
    rotate_keys.validate(&ctx, &req_ctx).await.unwrap();

    // The registry-key bytes are deliberately from the old v1 rotation. The
    // no-op check is based on signer set and threshold because each v2
    // rotation uses a fresh block-hash identifier.
    ctx.state().update_registry_signer_set_info(SignerSetInfo {
        aggregate_key: setup.aggregate_key().into(),
        signer_set: rotate_keys.new_keys.clone(),
        signatures_required: rotate_keys.signatures_required,
    });

    assert_rotate_keys_error(
        rotate_keys.validate(&ctx, &req_ctx).await.unwrap_err(),
        RotateKeysErrorMsg::RegistryUpToDate,
    );

    testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn rotate_key_validation_happy_path() {
    // Normal: preamble
    let db = testing::storage::new_test_database().await;
    let mut rng = get_rng();

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&db).await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;

    // Normal: we store setup dkg shares
    setup.store_dkg_shares(&db).await;

    // Normal: we get the rotate key from the setup
    let (rotate_key_tx, req_ctx) = make_rotate_key(&setup);

    // Check to see if validation passes.
    rotate_key_tx.validate(&ctx, &req_ctx).await.unwrap();

    // Check that, if we run another dkg, the new tx pass validation
    let setup_other = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;
    let (rotate_key_tx_other, _) = make_rotate_key(&setup_other);

    // No DKG yet
    rotate_key_tx_other
        .validate(&ctx, &req_ctx)
        .await
        .unwrap_err();

    setup_other.store_dkg_shares(&db).await;
    // Now we have the new DKG in db
    rotate_key_tx_other.validate(&ctx, &req_ctx).await.unwrap();

    testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn rotate_key_validation_no_dkg() {
    // Normal: preamble
    let db = testing::storage::new_test_database().await;
    let mut rng = get_rng();

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&db).await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;

    // Differnt: we do NOT store setup dkg shares

    // Normal: we get the rotate key from the setup
    let (rotate_key_tx, req_ctx) = make_rotate_key(&setup);

    let validate_future = rotate_key_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::NoDkgShares => {}
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn rotate_key_validation_wrong_deployer() {
    // Normal: preamble
    let db = testing::storage::new_test_database().await;
    let mut rng = get_rng();

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&db).await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;

    // Normal: we store setup dkg shares
    setup.store_dkg_shares(&db).await;

    // Normal: we get the rotate key from the setup
    let (rotate_key_tx, mut req_ctx) = make_rotate_key(&setup);

    // Different: use a different (expected) deployer
    req_ctx.deployer = StacksAddress::p2pkh(false, &setup.signer_keys[0].into());

    let validate_future = rotate_key_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::RotateKeysValidation(ref err) => {
            assert_eq!(err.error, RotateKeysErrorMsg::DeployerMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn rotate_key_validation_wrong_signing_set() {
    // Normal: preamble
    let db = testing::storage::new_test_database().await;
    let mut rng = get_rng();

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&db).await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;

    // Normal: we store setup dkg shares
    setup.store_dkg_shares(&db).await;

    // Normal: we get the rotate key from the setup
    let (rotate_key_tx, req_ctx) = make_rotate_key(&setup);

    // Different: create another setup, resulting in different public keys, and try to use
    // those as public keys in rotate keys tx
    let setup_other = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;
    let rotate_key_tx_other = RotateKeysV1::new(
        &setup_other.wallet,
        rotate_key_tx.deployer_address().clone(),
        &setup.aggregate_key(),
    );

    let validate_future = rotate_key_tx_other.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::RotateKeysValidation(ref err) => {
            assert_eq!(err.error, RotateKeysErrorMsg::SignerSetMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn rotate_key_validation_wrong_aggregate_key() {
    // Normal: preamble
    let db = testing::storage::new_test_database().await;
    let mut rng = get_rng();

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&db).await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;

    // Normal: we store setup dkg shares
    setup.store_dkg_shares(&db).await;

    // Normal: we get the rotate key from the setup
    let (rotate_key_tx, req_ctx) = make_rotate_key(&setup);

    // Different: create another setup, resulting in different aggregate key, and try to use
    // that as aggregate key in rotate keys tx
    let setup_other = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;
    let rotate_key_tx_other = RotateKeysV1::new(
        &setup.wallet,
        rotate_key_tx.deployer_address().clone(),
        &setup_other.aggregate_key(),
    );

    let validate_future = rotate_key_tx_other.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::RotateKeysValidation(ref err) => {
            assert_eq!(err.error, RotateKeysErrorMsg::AggregateKeyMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn rotate_key_validation_wrong_signatures_required() {
    // Normal: preamble
    let db = testing::storage::new_test_database().await;
    let mut rng = get_rng();

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&db).await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;

    // Normal: we store setup dkg shares
    setup.store_dkg_shares(&db).await;

    // Normal: we get the rotate key from the setup
    let (rotate_key_tx, req_ctx) = make_rotate_key(&setup);

    // Different: we change the signature threshold
    let wallet_other = SignerWallet::new(
        setup.wallet.public_keys(),
        setup.wallet.signatures_required() + 1,
        signer::config::NetworkKind::Regtest,
        0,
    )
    .unwrap();
    let rotate_key_tx_other = RotateKeysV1::new(
        &wallet_other,
        rotate_key_tx.deployer_address().clone(),
        &setup.aggregate_key(),
    );

    let validate_future = rotate_key_tx_other.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::RotateKeysValidation(ref err) => {
            assert_eq!(err.error, RotateKeysErrorMsg::SignaturesRequiredMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn rotate_key_validation_replay() {
    // Normal: preamble
    let db = testing::storage::new_test_database().await;
    let mut rng = get_rng();

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&db).await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;

    // Normal: we store setup dkg shares
    setup.store_dkg_shares(&db).await;

    // Normal: we get the rotate key from the setup
    let (rotate_key_tx, req_ctx) = make_rotate_key(&setup);

    // Check to see if validation passes.
    rotate_key_tx.validate(&ctx, &req_ctx).await.unwrap();

    // Different: store the rotate key tx
    setup.store_rotate_keys(&db).await;

    let validate_future = rotate_key_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::RotateKeysValidation(ref err) => {
            assert_eq!(err.error, RotateKeysErrorMsg::KeyRotationExists)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    // Check that, if we exclude the rotate key from the canonical chain, validation passes
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 2,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&db).await;

    let mut req_ctx_fork = req_ctx;
    req_ctx_fork.chain_tip.block_hash = test_data.bitcoin_blocks[0].block_hash;
    req_ctx_fork.chain_tip.block_height = test_data.bitcoin_blocks[0].block_height;
    req_ctx_fork.stacks_chain_tip = test_data.stacks_blocks.last().unwrap().block_hash;

    rotate_key_tx.validate(&ctx, &req_ctx_fork).await.unwrap();

    testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn rotate_key_validation_not_verfied() {
    // Normal: preamble
    let db = testing::storage::new_test_database().await;
    let mut rng = get_rng();

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&db).await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;

    // Normal: we store setup dkg shares
    setup.store_dkg_shares(&db).await;

    // Different: mark the shares as failed.
    set_verification_status(&db, setup.aggregate_key(), DkgSharesStatus::Failed).await;

    // Normal: we get the rotate key from the setup
    let (rotate_key_tx, req_ctx) = make_rotate_key(&setup);

    let validate_future = rotate_key_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::RotateKeysValidation(ref err) => {
            assert_eq!(err.error, RotateKeysErrorMsg::DkgSharesNotVerified)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    // Different: mark the shares as unverified.
    set_verification_status(&db, setup.aggregate_key(), DkgSharesStatus::Unverified).await;

    let validate_future = rotate_key_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::RotateKeysValidation(ref err) => {
            assert_eq!(err.error, RotateKeysErrorMsg::DkgSharesNotVerified)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    // Well this is the regular happy path. Everything should validate now.
    set_verification_status(&db, setup.aggregate_key(), DkgSharesStatus::Verified).await;

    rotate_key_tx.validate(&ctx, &req_ctx).await.unwrap();

    testing::storage::drop_db(db).await;
}
