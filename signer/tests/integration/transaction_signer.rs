use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::time::Duration;

use bitcoin::OutPoint;
use bitcoin::hashes::Hash as _;
use bitcoincore_rpc::RpcApi as _;
use fake::Fake as _;
use fake::Faker;
use lru::LruCache;
use rand::rngs::OsRng;
use sbtc::testing::containers::TestContainersBuilder;
use signer::bitcoin::MockBitcoinInteract;
use signer::bitcoin::rpc::BitcoinCoreClient;
use signer::emily_client::MockEmilyInteract;
use signer::message::Payload;
use signer::network::in_memory2::SignerNetworkInstance;
use signer::stacks::api::MockStacksInteract;
use signer::stacks::api::SignerSetInfo;
use signer::stacks::wallet::MultisigTx;
use signer::stacks::wallet::SignerWallet;
use signer::storage::DbRead as _;
use signer::storage::DbWrite as _;
use signer::storage::postgres::PgStore;
use signer::testing::btc::get_canonical_chain_tip;
use signer::transaction_signer::BITCOIN_SIGN_REQUEST_LRU_SIZE;
use signer::transaction_signer::STACKS_SIGN_REQUEST_LRU_SIZE;
use test_case::test_case;

use signer::bitcoin::utxo::RequestRef;
use signer::bitcoin::utxo::Requests;
use signer::bitcoin::utxo::SignerUtxoKeySet;
use signer::bitcoin::utxo::UnsignedTransaction;
use signer::bitcoin::validation::TxRequestIds;
use signer::context::Context as _;
use signer::context::SbtcLimits;
use signer::error::Error;
use signer::keys::PrivateKey;
use signer::keys::PublicKey;
use signer::keys::PublicKeyXOnly;
use signer::message::BitcoinPreSignRequest;
use signer::message::StacksTransactionSignRequest;
use signer::message::WstsMessage;
use signer::message::WstsMessageId;
use signer::network::InMemoryNetwork;
use signer::network::MessageTransfer as _;
use signer::network::in_memory2::WanNetwork;
use signer::stacks::contracts::ContractCall;
use signer::storage::model;
use signer::storage::model::BitcoinBlockHash;
use signer::storage::model::BitcoinBlockRef;
use signer::storage::model::BitcoinTxId;
use signer::storage::model::BitcoinTxSigHash;
use signer::storage::model::DkgSharesStatus;
use signer::storage::model::SigHash;
use signer::storage::model::StacksBlockHash;
use signer::storage::model::StacksTxId;
use signer::testing;
use signer::testing::context::*;
use signer::testing::get_rng;
use signer::transaction_signer::ChainTipStatus;
use signer::transaction_signer::MsgChainTipReport;
use signer::transaction_signer::TxSignerEventLoop;
use signer::wsts_state_machine::StateMachineId;
use wsts::net::DkgBegin;
use wsts::net::Message as WstsNetMessage;
use wsts::net::NonceRequest;

use crate::containers::BitcoinContainerExt as _;
use crate::setup::SweepAmounts;
use crate::setup::TestSignerSet;
use crate::setup::TestSweepSetup;
use crate::setup::TestSweepSetup2;
use crate::setup::backfill_bitcoin_blocks;
use crate::setup::fetch_canonical_bitcoin_blockchain;
use crate::setup::fill_signers_utxo;
use crate::setup::set_deposit_incomplete;
use crate::setup::set_verification_status;

type MockedTxSigner = TxSignerEventLoop<
    TestContext<
        PgStore,
        WrappedMock<MockBitcoinInteract>,
        WrappedMock<MockStacksInteract>,
        WrappedMock<MockEmilyInteract>,
    >,
    SignerNetworkInstance,
>;

/// Test that [`TxSignerEventLoop::assert_valid_stacks_tx_sign_request`]
/// errors when the signer is not in the signer set.
#[tokio::test]
async fn signing_set_validation_check_for_stacks_transactions() {
    let db = testing::storage::new_test_database().await;

    let mut rng = get_rng();

    let stack = TestContainersBuilder::start_bitcoin().await;
    let bitcoin = stack.bitcoin().await;
    let rpc = bitcoin.rpc();
    let faucet = &bitcoin.get_faucet();

    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_bitcoin_client(bitcoin.get_client())
        .with_mocked_emily_client()
        .with_mocked_stacks_client()
        .modify_settings(|settings| {
            settings.signer.bootstrap_signatures_required = 2;
        })
        .build();

    // This confirms a deposit transaction, and has a nice helper function
    // for storing a real deposit.
    let mut setup = TestSweepSetup::new_setup(bitcoin.get_client(), faucet, 10000, &mut rng);

    // Let's get the blockchain data into the database.
    let chain_tip = BitcoinBlockRef {
        block_hash: setup.sweep_block_hash.into(),
        block_height: setup.sweep_block_height,
    };
    backfill_bitcoin_blocks(&db, rpc, &chain_tip.block_hash).await;

    // This is all normal things that need to happen in order to pass
    // validation.
    setup.store_happy_path_data(&db).await;

    let stacks_chain_tip = db
        .get_stacks_chain_tip(&chain_tip.block_hash)
        .await
        .unwrap()
        .unwrap();
    ctx.state().set_stacks_chain_tip(stacks_chain_tip.into());

    let (mut req, _) = crate::complete_deposit::make_complete_deposit(&setup);

    req.deployer = ctx.config().signer.deployer.clone();
    let network = InMemoryNetwork::new();
    let mut tx_signer = TxSignerEventLoop {
        network: network.connect(),
        context: ctx.clone(),
        context_window: 10000,
        wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
        signer_private_key: setup.aggregated_signer.keypair.secret_key().into(),
        last_presign_block: None,
        dkg_begin_pause: None,
        dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
        stacks_sign_request: LruCache::new(STACKS_SIGN_REQUEST_LRU_SIZE),
        bitcoin_sign_request: LruCache::new(BITCOIN_SIGN_REQUEST_LRU_SIZE),
    };

    // Let's create a proper sign request.
    let request = StacksTransactionSignRequest {
        contract_tx: ContractCall::CompleteDepositV1(Box::new(req)).into(),
        // The nonce and tx_fee aren't really validated against anything at
        // the moment.
        nonce: 1,
        tx_fee: 100_000,
        txid: Faker.fake_with_rng::<StacksTxId, _>(&mut rng),
    };

    // We need this or the contract call will fail validation with an
    // unrelated error, since we mock reaching out to the stacks node.
    set_deposit_incomplete(&mut ctx).await;

    // We can sign a transaction generated by a coordinator who is not in
    // the signer set, so the origin doesn't matter much for this function
    // call.
    let origin_public_key: PublicKey = Faker.fake_with_rng(&mut rng);
    // This is all happy path, there shouldn't be any errors here
    tx_signer
        .assert_valid_stacks_tx_sign_request(&request, &chain_tip, &origin_public_key)
        .await
        .unwrap();

    // Now we make sure that the current signer is not in the current
    // signing set.
    tx_signer.signer_private_key = PrivateKey::new(&mut rng);

    // Okay now that we have changed the fact that we are not in the
    // signing set, we should get an error now.
    let validation = tx_signer
        .assert_valid_stacks_tx_sign_request(&request, &chain_tip, &origin_public_key)
        .await
        .unwrap_err();
    assert!(matches!(validation, Error::ValidationSignerSet(_)));

    testing::storage::drop_db(db).await;
}

#[test_case(1, false ; "fee-too-high")]
#[test_case(0, true ; "fee-okay")]
#[tokio::test]
async fn signer_rejects_stacks_txns_with_too_high_a_fee(
    fee_relative_to_configured_limit: u64,
    should_accept: bool,
) {
    let db = testing::storage::new_test_database().await;

    let mut rng = get_rng();

    let stack = TestContainersBuilder::start_bitcoin().await;
    let bitcoin = stack.bitcoin().await;
    let rpc = bitcoin.rpc();
    let faucet = &bitcoin.get_faucet();

    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_bitcoin_client(bitcoin.get_client())
        .with_mocked_emily_client()
        .with_mocked_stacks_client()
        .modify_settings(|settings| {
            settings.signer.bootstrap_signatures_required = 2;
        })
        .build();

    // We need this or the contract call will fail validation with an
    // unrelated error, since we mock reaching out to the stacks node.
    set_deposit_incomplete(&mut ctx).await;

    // This confirms a deposit transaction, and has a nice helper function
    // for storing a real deposit.
    let mut setup = TestSweepSetup::new_setup(bitcoin.get_client(), faucet, 10000, &mut rng);

    // Let's get the blockchain data into the database.
    let chain_tip = BitcoinBlockRef {
        block_hash: setup.sweep_block_hash.into(),
        block_height: setup.sweep_block_height,
    };
    backfill_bitcoin_blocks(&db, rpc, &chain_tip.block_hash).await;

    // This is all normal things that need to happen in order to pass
    // validation.
    setup.store_happy_path_data(&db).await;

    let stacks_chain_tip = db
        .get_stacks_chain_tip(&chain_tip.block_hash)
        .await
        .unwrap()
        .unwrap();
    ctx.state().set_stacks_chain_tip(stacks_chain_tip.into());

    let (mut req, _) = crate::complete_deposit::make_complete_deposit(&setup);

    req.deployer = ctx.config().signer.deployer.clone();
    let network = InMemoryNetwork::new();
    let mut tx_signer = TxSignerEventLoop {
        network: network.connect(),
        context: ctx.clone(),
        context_window: 10000,
        wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
        signer_private_key: setup.aggregated_signer.keypair.secret_key().into(),
        last_presign_block: None,
        dkg_begin_pause: None,
        dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
        stacks_sign_request: LruCache::new(STACKS_SIGN_REQUEST_LRU_SIZE),
        bitcoin_sign_request: LruCache::new(BITCOIN_SIGN_REQUEST_LRU_SIZE),
    };

    // Setup the transaction fee to be the maximum fee configured plus one, so that it
    // exceeds the configured value.
    let stacks_fees_max_ustx = ctx.config().signer.stacks_fees_max_ustx;
    let tx_fee = stacks_fees_max_ustx.get() + fee_relative_to_configured_limit;

    // Let's create a proper sign request.
    let request = StacksTransactionSignRequest {
        contract_tx: ContractCall::CompleteDepositV1(Box::new(req)).into(),
        // The nonce isn't really validated against anything at the moment.
        nonce: 1,
        tx_fee,
        txid: Faker.fake_with_rng::<StacksTxId, _>(&mut rng),
    };

    // We can sign a transaction generated by a coordinator who is not in
    // the signer set, so the origin doesn't matter much for this function
    // call.
    let origin_public_key: PublicKey = Faker.fake_with_rng(&mut rng);
    let result = tx_signer
        .assert_valid_stacks_tx_sign_request(&request, &chain_tip, &origin_public_key)
        .await;

    if should_accept {
        assert!(matches!(result, Ok(())));
    } else {
        // We cannot enable partial eq for the error type because it contains many
        // internal types that don't implement it, so we have to match on the error
        // and ensure that it is the correct one.
        assert!(matches!(result, Err(Error::StacksFeeLimitExceeded(_, _))));
    }

    testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn signer_rejects_multiple_attempts_in_tenure() {
    let db = testing::storage::new_test_database().await;

    let mut rng = get_rng();

    let stack = TestContainersBuilder::start_bitcoin().await;
    let bitcoin = stack.bitcoin().await;
    let rpc = bitcoin.rpc();
    let faucet = &bitcoin.get_faucet();

    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_bitcoin_client(bitcoin.get_client())
        .with_mocked_emily_client()
        .with_mocked_stacks_client()
        .modify_settings(|settings| {
            settings.signer.bootstrap_signatures_required = 2;
        })
        .build();

    // We need this or the contract call will fail validation with an
    // unrelated error, since we mock reaching out to the stacks node.
    set_deposit_incomplete(&mut ctx).await;

    // This confirms a deposit transaction, and has a nice helper function
    // for storing a real deposit.
    let mut setup = TestSweepSetup::new_setup(bitcoin.get_client(), faucet, 10000, &mut rng);

    // Let's get the blockchain data into the database.
    let chain_tip = BitcoinBlockRef {
        block_hash: setup.sweep_block_hash.into(),
        block_height: setup.sweep_block_height,
    };
    backfill_bitcoin_blocks(&db, rpc, &chain_tip.block_hash).await;

    // This is all normal things that need to happen in order to pass
    // validation.
    setup.store_happy_path_data(&db).await;

    let stacks_chain_tip = db
        .get_stacks_chain_tip(&chain_tip.block_hash)
        .await
        .unwrap()
        .unwrap();
    ctx.state().set_stacks_chain_tip(stacks_chain_tip.into());

    let (mut req, _) = crate::complete_deposit::make_complete_deposit(&setup);

    req.deployer = ctx.config().signer.deployer.clone();
    let network = InMemoryNetwork::new();
    let mut tx_signer = TxSignerEventLoop {
        network: network.connect(),
        context: ctx.clone(),
        context_window: 10000,
        wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
        signer_private_key: setup.aggregated_signer.keypair.secret_key().into(),
        last_presign_block: None,
        dkg_begin_pause: None,
        dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
        stacks_sign_request: LruCache::new(STACKS_SIGN_REQUEST_LRU_SIZE),
        bitcoin_sign_request: LruCache::new(BITCOIN_SIGN_REQUEST_LRU_SIZE),
    };

    // We need this so that there is a live "network". Otherwise will error when
    // trying to send a message at the end.
    let _rec = ctx.get_signal_receiver();

    // We need the wallet to get the real txid to pass the final checks
    let wallet = SignerWallet::load(&ctx).await.unwrap();

    // We can sign a transaction generated by a coordinator who is not in
    // the signer set, so the origin doesn't matter much for this function
    // call.
    let origin_public_key: PublicKey = Faker.fake_with_rng(&mut rng);

    // Let's create a proper sign request.
    let mut request = StacksTransactionSignRequest {
        contract_tx: ContractCall::CompleteDepositV1(Box::new(req.clone())).into(),
        nonce: 1,
        tx_fee: 100_000,
        txid: Faker.fake_with_rng::<StacksTxId, _>(&mut rng),
    };
    wallet.set_nonce(request.nonce);
    request.txid = MultisigTx::new_tx(&request.contract_tx, &wallet, request.tx_fee)
        .tx()
        .txid()
        .into();

    // Try to sign the sign request for the first time in this tenure
    let result = tx_signer
        .handle_stacks_transaction_sign_request(&request, &chain_tip, &origin_public_key)
        .await;
    assert!(result.is_ok());

    // Now create a different sign request for the same deposit
    let mut new_request = StacksTransactionSignRequest {
        contract_tx: ContractCall::CompleteDepositV1(Box::new(req)).into(),
        nonce: 2,
        tx_fee: 123_000,
        txid: Faker.fake_with_rng::<StacksTxId, _>(&mut rng),
    };
    wallet.set_nonce(new_request.nonce);
    new_request.txid = MultisigTx::new_tx(&new_request.contract_tx, &wallet, new_request.tx_fee)
        .tx()
        .txid()
        .into();

    assert_ne!(new_request.tx_fee, request.tx_fee);
    assert_ne!(new_request.nonce, request.nonce);
    assert_ne!(new_request.txid, request.txid);

    // And try to sign it in the same tenure as the previous attempt
    let result = tx_signer
        .handle_stacks_transaction_sign_request(&new_request, &chain_tip, &origin_public_key)
        .await;
    assert!(matches!(
        result,
        Err(Error::StacksRequestAlreadySigned(_, _))
    ));

    // Now generate a new block and backfill
    faucet.generate_block();
    fetch_canonical_bitcoin_blockchain(&db, rpc).await;
    let new_chain_tip = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .unwrap()
        .unwrap();
    assert_ne!(new_chain_tip, chain_tip);

    // Then try to sign it again in a new tenure
    let result = tx_signer
        .handle_stacks_transaction_sign_request(&new_request, &new_chain_tip, &origin_public_key)
        .await;
    assert!(result.is_ok());

    testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn assert_should_be_able_to_handle_sbtc_requests() {
    let db = testing::storage::new_test_database().await;

    let mut rng = get_rng();
    let fee_rate = 1.3;

    let stack = TestContainersBuilder::start_bitcoin().await;
    let bitcoin = stack.bitcoin().await;
    let rpc = bitcoin.rpc();
    let faucet = &bitcoin.get_faucet();

    // Create a test setup with a confirmed deposit transaction
    let setup = TestSweepSetup::new_setup(bitcoin.get_client(), faucet, 10000, &mut rng);

    // Build the test context with mocked clients. The signer is the
    // setup's aggregated signer, whose votes the setup stores.
    let signer_private_key = setup.aggregated_signer.keypair.secret_key().into();
    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .modify_settings(|settings| {
            settings.signer.bootstrap_signatures_required = 2;
            settings.signer.private_key = signer_private_key;
        })
        .build();
    ctx.state().update_current_limits(SbtcLimits::unlimited());
    // Backfill the blockchain data into the database
    let chain_tip = BitcoinBlockRef {
        block_hash: setup.sweep_block_hash.into(),
        block_height: setup.sweep_block_height,
    };
    backfill_bitcoin_blocks(&db, rpc, &chain_tip.block_hash).await;
    let bitcoin_block = db.get_bitcoin_block(&chain_tip.block_hash).await.unwrap();

    let public_aggregate_key = setup.aggregated_signer.keypair.public_key().into();

    // // Fill the signer's UTXO in the database
    fill_signers_utxo(&db, bitcoin_block.unwrap(), &public_aggregate_key, &mut rng).await;

    // Store the necessary data for passing validation
    setup.store_stacks_genesis_block(&db).await;
    setup.store_deposit_tx(&db).await;
    setup.store_dkg_shares(&db).await;
    setup.store_rotate_keys_event(&db).await;
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    let shares = db.get_latest_encrypted_dkg_shares().await.unwrap().unwrap();
    let signer_set_info = SignerSetInfo::from(shares);
    let stacks_chain_tip = db
        .get_stacks_chain_tip(&chain_tip.block_hash)
        .await
        .unwrap()
        .unwrap();

    let state = ctx.state();
    state.update_current_signer_set(signer_set_info.signer_set.clone());
    state.update_registry_signer_set_info(signer_set_info);
    state.set_stacks_chain_tip(stacks_chain_tip.into());

    // Initialize the transaction signer event loop
    let network = WanNetwork::default();

    let net = network.connect(&ctx);
    let mut tx_signer = TxSignerEventLoop {
        network: net.spawn(),
        context: ctx.clone(),
        context_window: 10000,
        wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
        signer_private_key: setup.aggregated_signer.keypair.secret_key().into(),
        last_presign_block: None,
        dkg_begin_pause: None,
        dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
        stacks_sign_request: LruCache::new(STACKS_SIGN_REQUEST_LRU_SIZE),
        bitcoin_sign_request: LruCache::new(BITCOIN_SIGN_REQUEST_LRU_SIZE),
    };

    let sbtc_requests: TxRequestIds = TxRequestIds {
        deposits: vec![setup.deposit_request.outpoint],
        withdrawals: vec![],
    };

    let sbtc_context = BitcoinPreSignRequest {
        request_package: vec![sbtc_requests],
        fee_rate,
        last_fees: None,
    };

    let sbtc_state = signer::bitcoin::utxo::SignerBtcState {
        output_key_set: SignerUtxoKeySet::V1(setup.aggregated_signer.keypair.public_key().into()),
        utxo: ctx
            .get_storage()
            .get_signer_utxo(&chain_tip.block_hash)
            .await
            .unwrap()
            .unwrap(),
        fee_rate,
        last_fees: None,
        magic_bytes: *b"T3",
    };

    // Create an unsigned transaction with the deposit request
    // to obtain the sighashes and corresponding txid that should
    // be stored in the database
    let unsigned_tx = UnsignedTransaction::new(
        Requests::new(vec![RequestRef::Deposit(&setup.deposit_request)]),
        &sbtc_state,
    )
    .unwrap();

    let digests = unsigned_tx.construct_digests().unwrap();
    let signer_digest = digests.signer_sighash();
    let deposit_digest = digests.deposit_sighashes();
    assert_eq!(deposit_digest.len(), 1);
    let deposit_digest = deposit_digest[0];

    let mut handle = network.connect(&ctx).spawn();

    tx_signer
        .handle_bitcoin_pre_sign_request(&sbtc_context, &chain_tip)
        .await
        .unwrap();

    // Check if we are receiving an Ack from the signer
    tokio::time::timeout(Duration::from_secs(2), async move {
        handle.receive().await.unwrap();
    })
    .await
    .unwrap();

    // Check that the intentions to sign the requests sighashes
    // are stored in the database
    let signing_info = db
        .will_sign_bitcoin_tx_sighash(&signer_digest.sighash.into(), &chain_tip.block_hash)
        .await
        .expect("query to check if signer sighash is stored failed")
        .expect("signer sighash not stored");

    assert!(signing_info.will_sign);
    let signing_info = db
        .will_sign_bitcoin_tx_sighash(&deposit_digest.sighash.into(), &chain_tip.block_hash)
        .await
        .expect("query to check if deposit sighash is stored failed")
        .expect("deposit sighash not stored");

    assert!(signing_info.will_sign);

    // The approvals only apply to the chain tip of the pre-sign request.
    let other_chain_tip: BitcoinBlockHash = Faker.fake_with_rng(&mut rng);
    let result = db
        .will_sign_bitcoin_tx_sighash(&signer_digest.sighash.into(), &other_chain_tip)
        .await
        .expect("query to check if signer sighash is stored failed");
    assert!(result.is_none());

    testing::storage::drop_db(db).await;
}

#[test_case(DkgSharesStatus::Verified, true ; "verified-shares-okay")]
#[test_case(DkgSharesStatus::Unverified, false ; "unverified-shares-not-okay")]
#[test_case(DkgSharesStatus::Failed, false ; "failed-shares-not-okay")]
#[tokio::test]
async fn presign_requests_with_dkg_shares_status(status: DkgSharesStatus, is_ok: bool) {
    let db = testing::storage::new_test_database().await;

    let mut rng = get_rng();
    // Build the test context with mocked clients
    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .modify_settings(|settings| {
            settings.signer.bootstrap_signatures_required = 2;
        })
        .build();

    let stack = TestContainersBuilder::start_bitcoin().await;
    let bitcoin = stack.bitcoin().await;
    let rpc = bitcoin.rpc();
    let faucet = &bitcoin.get_faucet();

    let signers = TestSignerSet::new(&mut rng);
    // Create a test setup object so that we can easily create proper DKG
    // shares in the database. Note that calling TestSweepSetup2::new_setup
    // creates two bitcoin blocks.
    let amounts = SweepAmounts {
        amount: 100000,
        max_fee: 10000,
        is_deposit: true,
    };
    let setup = TestSweepSetup2::new_setup(signers, bitcoin.get_client(), faucet, &[amounts]);

    let block_header = rpc
        .get_block_header_info(&setup.deposit_block_hash)
        .unwrap();
    let chain_tip = BitcoinBlockRef {
        block_hash: block_header.hash.into(),
        block_height: block_header.height.into(),
    };

    // Store the necessary data for passing validation
    let aggregate_key = setup.signers.aggregate_key();

    backfill_bitcoin_blocks(&db, rpc, &setup.deposit_block_hash).await;

    setup.store_stacks_genesis_block(&db).await;
    setup.store_dkg_shares(&db).await;
    setup.store_rotate_keys_event(&db).await;
    setup.store_donation(&db).await;
    setup.store_deposit_txs(&db).await;
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    set_verification_status(&db, aggregate_key, status).await;

    let shares = db.get_latest_encrypted_dkg_shares().await.unwrap().unwrap();
    let signer_set_info = SignerSetInfo::from(shares);
    let stacks_chain_tip = db
        .get_stacks_chain_tip(&chain_tip.block_hash)
        .await
        .unwrap()
        .unwrap();

    ctx.state().update_registry_signer_set_info(signer_set_info);
    ctx.state().update_current_limits(SbtcLimits::unlimited());
    ctx.state().set_stacks_chain_tip(stacks_chain_tip.into());

    // Initialize the transaction signer event loop
    let network = WanNetwork::default();

    let net = network.connect(&ctx);
    let mut tx_signer = TxSignerEventLoop {
        network: net.spawn(),
        context: ctx.clone(),
        context_window: 10000,
        wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
        // We use this private key because it needs to be associated with
        // one of the public keys that we stored in the DKG shares table.
        signer_private_key: setup.signers.private_key(),
        last_presign_block: None,
        dkg_begin_pause: None,
        dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
        stacks_sign_request: LruCache::new(STACKS_SIGN_REQUEST_LRU_SIZE),
        bitcoin_sign_request: LruCache::new(BITCOIN_SIGN_REQUEST_LRU_SIZE),
    };

    let sbtc_requests: TxRequestIds = TxRequestIds {
        deposits: setup.deposit_outpoints(),
        withdrawals: vec![],
    };

    let sbtc_context = BitcoinPreSignRequest {
        request_package: vec![sbtc_requests],
        fee_rate: 2.0,
        last_fees: None,
    };

    let result = tx_signer
        .handle_bitcoin_pre_sign_request(&sbtc_context, &chain_tip)
        .await;

    match result {
        Ok(()) => assert!(is_ok),
        Err(Error::NoVerifiedDkgShares) => assert!(!is_ok),
        Err(error) => panic!("{error}, got an unexpected result"),
    }

    testing::storage::drop_db(db).await;
}

#[tokio::test]
pub async fn presign_request_ignore_request_if_already_processed_this_block() {
    let db = testing::storage::new_test_database().await;

    let mut rng = get_rng();
    // Build the test context with mocked clients
    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let stack = TestContainersBuilder::start_bitcoin().await;
    let bitcoin = stack.bitcoin().await;
    let rpc = bitcoin.rpc();
    let faucet = &bitcoin.get_faucet();

    let signers = TestSignerSet::new(&mut rng);
    // Create a test setup object so that we can easily create proper DKG
    // shares in the database. Note that calling TestSweepSetup2::new_setup
    // creates two bitcoin blocks.
    let amounts = SweepAmounts {
        amount: 100000,
        max_fee: 10000,
        is_deposit: true,
    };
    let setup = TestSweepSetup2::new_setup(signers, bitcoin.get_client(), faucet, &[amounts]);

    let block_header = rpc
        .get_block_header_info(&setup.deposit_block_hash)
        .unwrap();
    let chain_tip = BitcoinBlockRef {
        block_hash: block_header.hash.into(),
        block_height: block_header.height.into(),
    };

    // Store the necessary data for passing validation
    let aggregate_key = setup.signers.aggregate_key();

    backfill_bitcoin_blocks(&db, rpc, &setup.deposit_block_hash).await;

    setup.store_stacks_genesis_block(&db).await;
    setup.store_dkg_shares(&db).await;
    setup.store_rotate_keys_event(&db).await;
    setup.store_donation(&db).await;
    setup.store_deposit_txs(&db).await;
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    set_verification_status(&db, aggregate_key, DkgSharesStatus::Verified).await;

    let shares = db.get_latest_encrypted_dkg_shares().await.unwrap().unwrap();
    let signer_set_info = SignerSetInfo::from(shares);
    let stacks_chain_tip = db
        .get_stacks_chain_tip(&chain_tip.block_hash)
        .await
        .unwrap()
        .unwrap();

    ctx.state().update_registry_signer_set_info(signer_set_info);
    ctx.state().update_current_limits(SbtcLimits::unlimited());
    ctx.state().set_stacks_chain_tip(stacks_chain_tip.into());

    // Initialize the transaction signer event loop
    let network = WanNetwork::default();

    let net = network.connect(&ctx);
    let mut tx_signer = TxSignerEventLoop {
        network: net.spawn(),
        context: ctx.clone(),
        context_window: 10000,
        wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
        // We use this private key because it needs to be associated with
        // one of the public keys that we stored in the DKG shares table.
        signer_private_key: setup.signers.private_key(),
        last_presign_block: None,
        dkg_begin_pause: None,
        dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
        stacks_sign_request: LruCache::new(STACKS_SIGN_REQUEST_LRU_SIZE),
        bitcoin_sign_request: LruCache::new(BITCOIN_SIGN_REQUEST_LRU_SIZE),
    };

    let sbtc_requests: TxRequestIds = TxRequestIds {
        deposits: setup.deposit_outpoints(),
        withdrawals: vec![],
    };

    let sbtc_context = BitcoinPreSignRequest {
        request_package: vec![sbtc_requests],
        fee_rate: 2.0,
        last_fees: None,
    };

    let result = tx_signer
        .handle_bitcoin_pre_sign_request(&sbtc_context, &chain_tip)
        .await;

    // We are processing this block with verified shares and thus it should be ok.
    assert!(result.is_ok());

    // Check that we store information that we processed this block
    assert_eq!(tx_signer.last_presign_block, Some(chain_tip.block_hash));

    // Now we will try to process the same block again, but since we already
    // processed it, we should get an error.
    let result = tx_signer
        .handle_bitcoin_pre_sign_request(&sbtc_context, &chain_tip)
        .await;

    let err = result.unwrap_err();
    match err {
        Error::InvalidPresignRequest(hash) => {
            assert_eq!(hash, chain_tip.block_hash)
        }
        _ => panic!("Expected InvalidPresignRequest error, got: {err}"),
    }

    // Sanity check: if we clear information about already processed blocks this is ok again

    tx_signer.last_presign_block = None;
    let result = tx_signer
        .handle_bitcoin_pre_sign_request(&sbtc_context, &chain_tip)
        .await;

    assert!(result.is_ok());

    testing::storage::drop_db(db).await;
}

/// The number of valid and invalid requests serviced by one transaction
/// in a pre-sign package.
#[derive(Debug, Default)]
struct TxRequestCounts {
    /// Deposits with a max fee that covers their assessed fee.
    valid_deposits: usize,
    /// Deposits with a max fee below their assessed fee.
    invalid_deposits: usize,
    /// Withdrawals with a max fee that covers their assessed fee.
    valid_withdrawals: usize,
    /// Withdrawals with a max fee below their assessed fee.
    invalid_withdrawals: usize,
}

impl TxRequestCounts {
    /// Whether every request in the transaction passes validation.
    fn is_valid(&self) -> bool {
        self.invalid_deposits == 0 && self.invalid_withdrawals == 0
    }
}

/// Check that a signer only writes pre-sign rows for the transactions in
/// the package that come before the first one that fails validation.
///
/// Each case gives the number of valid and invalid deposits and
/// withdrawals in each transaction of the package. A request is invalid
/// when its max fee is less than the fee it is assessed in its
/// transaction, and a single invalid request makes its transaction
/// invalid. At the 2 sats per vbyte used here, each request is assessed
/// well over 10 sats and well under 10,000 sats, so we use those as the
/// max fees of invalid and valid requests.
///
/// We check both the sighash rows and the withdrawal output rows. The
/// withdrawal output rows feed the checks for whether a withdrawal may be
/// rejected, so rows for an invalid transaction would let a coordinator
/// delay or confuse those checks.
#[test_case(vec![
    TxRequestCounts { valid_deposits: 2, valid_withdrawals: 1, ..Default::default() },
    TxRequestCounts { valid_withdrawals: 2, ..Default::default() },
    TxRequestCounts { valid_deposits: 1, ..Default::default() },
] ; "all-transactions-valid")]
#[test_case(vec![
    TxRequestCounts { valid_deposits: 1, invalid_deposits: 1, valid_withdrawals: 1, ..Default::default() },
    TxRequestCounts { valid_deposits: 1, ..Default::default() },
] ; "first-transaction-invalid-deposit")]
#[test_case(vec![
    TxRequestCounts { invalid_withdrawals: 1, ..Default::default() },
    TxRequestCounts { valid_deposits: 1, valid_withdrawals: 1, ..Default::default() },
] ; "first-transaction-invalid-withdrawal")]
#[test_case(vec![
    TxRequestCounts { valid_deposits: 1, valid_withdrawals: 1, ..Default::default() },
    TxRequestCounts { valid_withdrawals: 1, invalid_withdrawals: 1, ..Default::default() },
    TxRequestCounts { valid_deposits: 1, valid_withdrawals: 1, ..Default::default() },
] ; "middle-transaction-invalid-withdrawal")]
#[test_case(vec![
    TxRequestCounts { valid_withdrawals: 1, ..Default::default() },
    TxRequestCounts { invalid_deposits: 1, ..Default::default() },
] ; "last-transaction-invalid-deposit")]
#[tokio::test]
async fn presign_rows_only_written_for_valid_transactions(request_counts: Vec<TxRequestCounts>) {
    /// The max fee of a request that passes validation, in sats.
    const VALID_MAX_FEE: u64 = 10_000;
    /// The max fee of a request that fails validation, in sats.
    const INVALID_MAX_FEE: u64 = 10;

    // The number of transactions at the start of the package that we
    // expect rows for.
    let expected_valid_txs = request_counts.iter().take_while(|tx| tx.is_valid()).count();
    let db = testing::storage::new_test_database().await;

    let mut rng = get_rng();

    // The signer reads its public key from the config when validating
    // pre-sign requests, and the deposit votes are stored under the test
    // signer set's key, so the two need to match.
    let signers = TestSignerSet::new(&mut rng);
    let signer_private_key = signers.private_key();
    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .modify_settings(|settings| {
            settings.signer.bootstrap_signatures_required = 2;
            settings.signer.private_key = signer_private_key;
        })
        .build();

    let stack = TestContainersBuilder::start_bitcoin().await;
    let bitcoin = stack.bitcoin().await;
    let rpc = bitcoin.rpc();
    let faucet = &bitcoin.get_faucet();

    // The setup keeps deposits in the order that we give them, so we list
    // them in package order, with each transaction's valid deposits before
    // its invalid ones.
    let deposits = request_counts
        .iter()
        .flat_map(|tx| {
            let valid = std::iter::repeat_n(VALID_MAX_FEE, tx.valid_deposits);
            let invalid = std::iter::repeat_n(INVALID_MAX_FEE, tx.invalid_deposits);
            valid.chain(invalid)
        })
        .map(|max_fee| SweepAmounts {
            amount: 100_000,
            max_fee,
            is_deposit: true,
        });
    let withdrawals = request_counts
        .iter()
        .flat_map(|tx| {
            let valid = std::iter::repeat_n(VALID_MAX_FEE, tx.valid_withdrawals);
            let invalid = std::iter::repeat_n(INVALID_MAX_FEE, tx.invalid_withdrawals);
            valid.chain(invalid)
        })
        .map(|max_fee| SweepAmounts {
            amount: 30_000,
            max_fee,
            is_deposit: false,
        });
    let sweep_amounts: Vec<SweepAmounts> = deposits.chain(withdrawals).collect();
    let setup = TestSweepSetup2::new_setup(signers, bitcoin.get_client(), faucet, &sweep_amounts);

    let block_header = rpc
        .get_block_header_info(&setup.deposit_block_hash)
        .unwrap();
    let chain_tip = BitcoinBlockRef {
        block_hash: block_header.hash.into(),
        block_height: block_header.height.into(),
    };

    let aggregate_key = setup.signers.aggregate_key();

    backfill_bitcoin_blocks(&db, rpc, &setup.deposit_block_hash).await;

    setup.store_stacks_genesis_block(&db).await;
    setup.store_dkg_shares(&db).await;
    setup.store_rotate_keys_event(&db).await;
    setup.store_donation(&db).await;
    setup.store_deposit_txs(&db).await;
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;
    setup.store_withdrawal_requests(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    set_verification_status(&db, aggregate_key, DkgSharesStatus::Verified).await;

    let shares = db.get_latest_encrypted_dkg_shares().await.unwrap().unwrap();
    let signer_set_info = SignerSetInfo::from(shares);
    let stacks_chain_tip = db
        .get_stacks_chain_tip(&chain_tip.block_hash)
        .await
        .unwrap()
        .unwrap();

    ctx.state().update_registry_signer_set_info(signer_set_info);
    ctx.state().update_current_limits(SbtcLimits::unlimited());
    ctx.state().set_stacks_chain_tip(stacks_chain_tip.into());
    // The withdrawal requests are confirmed in the chain tip block, so
    // they are final if the finality height is just above it.
    ctx.state()
        .set_withdrawal_finality_height(Some(chain_tip.block_height.saturating_add(1u64)));

    let network = WanNetwork::default();

    let net = network.connect(&ctx);
    let mut tx_signer = TxSignerEventLoop {
        network: net.spawn(),
        context: ctx.clone(),
        context_window: 10000,
        wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
        // We use this private key because it needs to be associated with
        // one of the public keys that we stored in the DKG shares table.
        signer_private_key: setup.signers.private_key(),
        last_presign_block: None,
        dkg_begin_pause: None,
        dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
        stacks_sign_request: LruCache::new(STACKS_SIGN_REQUEST_LRU_SIZE),
        bitcoin_sign_request: LruCache::new(BITCOIN_SIGN_REQUEST_LRU_SIZE),
    };

    // Build the package from the requests that the setup created. The
    // deposits are in package order. The setup sorts withdrawals by
    // request ID, so we split them by max fee and take them as needed;
    // withdrawals with the same max fee are interchangeable.
    let mut deposits = setup.deposits.iter().map(|(info, _, _)| info.outpoint);
    let (valid_withdrawals, invalid_withdrawals): (Vec<_>, Vec<_>) = setup
        .withdrawals
        .iter()
        .map(|w| &w.request)
        .partition(|req| req.max_fee == VALID_MAX_FEE);
    let mut valid_withdrawals = valid_withdrawals.into_iter().map(|req| req.qualified_id());
    let mut invalid_withdrawals = invalid_withdrawals
        .into_iter()
        .map(|req| req.qualified_id());

    let request_package: Vec<TxRequestIds> = request_counts
        .iter()
        .map(|tx| {
            let deposit_count = tx.valid_deposits + tx.invalid_deposits;
            let valid = valid_withdrawals.by_ref().take(tx.valid_withdrawals);
            let invalid = invalid_withdrawals.by_ref().take(tx.invalid_withdrawals);
            TxRequestIds {
                deposits: deposits.by_ref().take(deposit_count).collect(),
                withdrawals: valid.chain(invalid).collect(),
            }
        })
        .collect();

    let valid_txs = request_package[..expected_valid_txs].to_vec();

    let presign_request = BitcoinPreSignRequest {
        request_package,
        fee_rate: 2.0,
        last_fees: None,
    };

    // Start with empty tables, so that every row we find below was
    // written by the pre-sign request.
    sqlx::query(
        "TRUNCATE sbtc_signer.bitcoin_tx_sighashes, sbtc_signer.bitcoin_withdrawals_outputs",
    )
    .execute(db.pool())
    .await
    .unwrap();

    let mut handle = network.connect(&ctx).spawn();

    tx_signer
        .handle_bitcoin_pre_sign_request(&presign_request, &chain_tip)
        .await
        .unwrap();

    // The signer still acknowledges the request, whatever the outcome of
    // validation.
    tokio::time::timeout(Duration::from_secs(2), async move {
        handle.receive().await.unwrap();
    })
    .await
    .unwrap();

    #[derive(sqlx::FromRow, Debug)]
    struct TxSighashRow {
        txid: BitcoinTxId,
        prevout_txid: BitcoinTxId,
        prevout_output_index: i32,
        prevout_type: model::TxPrevoutType,
        is_valid_tx: bool,
    }

    let rows = sqlx::query_as::<_, TxSighashRow>(
        r#"
        SELECT
            txid
          , prevout_txid
          , prevout_output_index
          , prevout_type
          , is_valid_tx
        FROM sbtc_signer.bitcoin_tx_sighashes
        "#,
    )
    .fetch_all(db.pool())
    .await
    .unwrap();

    let expected_deposits: HashSet<OutPoint> = valid_txs
        .iter()
        .flat_map(|tx| tx.deposits.iter().copied())
        .collect();

    // Each recorded transaction has one row for the signers' input and
    // one row for each of its deposits, and every recorded row is for a
    // valid transaction.
    assert_eq!(rows.len(), expected_valid_txs + expected_deposits.len());
    assert!(rows.iter().all(|row| row.is_valid_tx));

    let recorded_txids: HashSet<BitcoinTxId> = rows.iter().map(|row| row.txid).collect();
    assert_eq!(recorded_txids.len(), expected_valid_txs);

    let recorded_deposits: HashSet<OutPoint> = rows
        .iter()
        .filter(|row| row.prevout_type == model::TxPrevoutType::Deposit)
        .map(|row| OutPoint::new(row.prevout_txid.into(), row.prevout_output_index as u32))
        .collect();

    assert_eq!(recorded_deposits, expected_deposits);

    #[derive(sqlx::FromRow, Debug)]
    struct WithdrawalOutputRow {
        bitcoin_txid: BitcoinTxId,
        output_index: i32,
        request_id: i64,
        stacks_block_hash: StacksBlockHash,
        is_valid_tx: bool,
    }

    let withdrawal_rows = sqlx::query_as::<_, WithdrawalOutputRow>(
        r#"
        SELECT
            bitcoin_txid
          , output_index
          , request_id
          , stacks_block_hash
          , is_valid_tx
        FROM sbtc_signer.bitcoin_withdrawals_outputs
        "#,
    )
    .fetch_all(db.pool())
    .await
    .unwrap();

    let expected_withdrawals: HashSet<(u64, StacksBlockHash)> = valid_txs
        .iter()
        .flat_map(|tx| &tx.withdrawals)
        .map(|id| (id.request_id, id.block_hash))
        .collect();

    // There is one withdrawal output row for each withdrawal in a
    // recorded transaction. Each row is for an output after the signers'
    // output and the OP_RETURN output, and for a transaction that we
    // recorded sighashes for. No row exists for the first invalid
    // transaction or for any transaction after it.
    assert_eq!(withdrawal_rows.len(), expected_withdrawals.len());
    assert!(withdrawal_rows.iter().all(|row| row.is_valid_tx));
    assert!(withdrawal_rows.iter().all(|row| row.output_index >= 2));
    assert!(
        withdrawal_rows
            .iter()
            .all(|row| recorded_txids.contains(&row.bitcoin_txid))
    );

    let recorded_withdrawals: HashSet<(u64, StacksBlockHash)> = withdrawal_rows
        .iter()
        .map(|row| (row.request_id as u64, row.stacks_block_hash))
        .collect();

    assert_eq!(recorded_withdrawals, expected_withdrawals);

    testing::storage::drop_db(db).await;
}

mod serial {
    use super::*;

    #[test_log::test(tokio::test)]
    async fn new_state_machine_per_valid_sighash() {
        let db = testing::storage::new_test_database().await;

        let mut rng = get_rng();
        // Build the test context with mocked clients
        let ctx = TestContext::builder()
            .with_storage(db.clone())
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.bootstrap_signatures_required = 2;
            })
            .build();

        let (_, faucet) = sbtc::testing::regtest::initialize_blockchain();

        let mut signers = TestSignerSet::new(&mut rng);
        // This test drives one transaction signer, so store a one-party WSTS
        // fixture whose key ownership matches the production one-key-per-signer
        // mapping. TestSignerSet normally models its one private key as owning
        // every synthetic signer key, which is intentionally rejected by the
        // nonce-response ownership check.
        signers.keys = vec![signers.aggregate_key()];
        // Create a test setup object so that we can easily create proper DKG
        // shares in the database. Note that calling TestSweepSetup2::new_setup
        // creates two bitcoin blocks.
        let mut setup =
            TestSweepSetup2::new_setup(signers, BitcoinCoreClient::new_regtest(), faucet, &[]);
        setup.signatures_required = 1;

        setup.store_dkg_shares(&db).await;

        // Initialize the transaction signer event loop
        let network = WanNetwork::default();

        let net = network.connect(&ctx);
        let mut tx_signer = TxSignerEventLoop {
            network: net.spawn(),
            context: ctx.clone(),
            context_window: 10000,
            wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
            // We use this private key because it needs to be associated with
            // one of the public keys that we stored in the DKG shares table.
            signer_private_key: setup.signers.private_key(),
            last_presign_block: None,
            dkg_begin_pause: None,
            dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
            stacks_sign_request: LruCache::new(STACKS_SIGN_REQUEST_LRU_SIZE),
            bitcoin_sign_request: LruCache::new(BITCOIN_SIGN_REQUEST_LRU_SIZE),
        };

        // We need to convince the signer event loop that it should accept the
        // message that we are going to send it.
        let report = MsgChainTipReport {
            sender_is_coordinator: true,
            chain_tip_status: ChainTipStatus::Canonical,
            chain_tip: BitcoinBlockRef {
                block_hash: BitcoinBlockHash::from([0; 32]),
                block_height: 0u64.into(),
            },
        };

        // The message that we will send is for the following sighash. We'll
        // need to make sure that it is in our database first
        let txid: BitcoinTxId = Faker.fake_with_rng(&mut rng);
        let sighash: SigHash = Faker.fake_with_rng(&mut rng);

        let row = BitcoinTxSigHash {
            txid,
            chain_tip: BitcoinBlockHash::from([0; 32]),
            prevout_txid: BitcoinTxId::from([0; 32]),
            prevout_output_index: 0,
            sighash,
            prevout_type: model::TxPrevoutType::Deposit,
            validation_result: signer::bitcoin::validation::InputValidationResult::Ok,
            is_valid_tx: true,
            will_sign: true,
            key_set_id: PublicKeyXOnly::from(PublicKey::from_private_key(
                &tx_signer.signer_private_key,
            ))
            .into(),
        };

        db.write_bitcoin_txs_sighashes(&[row]).await.unwrap();

        // Now for the nonce request message
        let mut nonce_request_msg = WstsMessage {
            id: WstsMessageId::Sweep(*txid),
            inner: wsts::net::Message::NonceRequest(NonceRequest {
                dkg_id: 1,
                sign_id: 1,
                sign_iter_id: 1,
                message: sighash.to_byte_array().to_vec(),
                signature_type: wsts::net::SignatureType::Schnorr,
            }),
        };
        let msg_public_key = PublicKey::from_private_key(&PrivateKey::new(&mut rng));

        // Sanity check, the state machines cache should be empty.
        assert!(tx_signer.wsts_state_machines.is_empty());

        tx_signer
            .handle_wsts_message(&nonce_request_msg, msg_public_key, &report)
            .await
            .unwrap();

        // We should have a state machine associated with the sighash nonce
        // request message that we just received.
        let id1 = StateMachineId::BitcoinSign(sighash, report.chain_tip);
        assert!(tx_signer.wsts_state_machines.contains(&id1));
        assert_eq!(tx_signer.wsts_state_machines.len(), 1);

        let other_chain_tip = BitcoinBlockRef {
            block_hash: BitcoinBlockHash::from([1; 32]),
            block_height: 1u64.into(),
        };
        let id_at_other_chain_tip = StateMachineId::BitcoinSign(sighash, other_chain_tip);
        assert!(
            !tx_signer
                .wsts_state_machines
                .contains(&id_at_other_chain_tip)
        );

        // Now let's see what happens when we receive a nonce request message
        // for a sighash that we do not know about. Since the nonce request is
        // not in the database we should return an error, and the state machine
        // should not be in the local cache.
        let random_sighash: SigHash = Faker.fake_with_rng(&mut rng);
        match &mut nonce_request_msg.inner {
            wsts::net::Message::NonceRequest(NonceRequest { message, .. }) => {
                *message = random_sighash.as_byte_array().to_vec();
            }
            _ => panic!("You forgot to update the variant"),
        };

        let response = tx_signer
            .handle_wsts_message(&nonce_request_msg, msg_public_key, &report)
            .await;

        let id2 = StateMachineId::BitcoinSign(random_sighash, report.chain_tip);
        assert!(response.is_err());
        assert!(tx_signer.wsts_state_machines.contains(&id1));
        assert!(!tx_signer.wsts_state_machines.contains(&id2));
        assert_eq!(tx_signer.wsts_state_machines.len(), 1);

        testing::storage::drop_db(db).await;
    }

    /// Check that an approved sighash can start only one signing round.
    #[test_log::test(tokio::test)]
    async fn bitcoin_signing_round_is_one_shot_per_sighash() {
        let db = testing::storage::new_test_database().await;

        let mut rng = get_rng();
        // Build the test context with mocked clients
        let ctx = TestContext::builder()
            .with_storage(db.clone())
            .with_mocked_clients()
            .build();

        let (_, faucet) = sbtc::testing::regtest::initialize_blockchain();

        let mut signers = TestSignerSet::new(&mut rng);
        // This test drives one transaction signer, so store a one-party WSTS
        // fixture whose key ownership matches the production one-key-per-signer
        // mapping. TestSignerSet normally models its one private key as owning
        // every synthetic signer key, which is intentionally rejected by the
        // nonce-response ownership check.
        signers.keys = vec![signers.aggregate_key()];
        // Create a test setup object so that we can simply create proper DKG
        // shares in the database. Note that calling TestSweepSetup2::new_setup
        // creates two bitcoin blocks.
        let mut setup =
            TestSweepSetup2::new_setup(signers, BitcoinCoreClient::new_regtest(), faucet, &[]);
        setup.signatures_required = 1;

        setup.store_dkg_shares(&db).await;

        // Initialize the transaction signer event loop
        let network = WanNetwork::default();

        let net = network.connect(&ctx);
        let mut tx_signer = TxSignerEventLoop {
            network: net.spawn(),
            context: ctx.clone(),
            context_window: 10000,
            wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
            // We use this private key because it needs to be associated with
            // one of the public keys that we stored in the DKG shares table.
            signer_private_key: setup.signers.private_key(),
            dkg_begin_pause: None,
            last_presign_block: None,
            dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
            stacks_sign_request: LruCache::new(STACKS_SIGN_REQUEST_LRU_SIZE),
            bitcoin_sign_request: LruCache::new(BITCOIN_SIGN_REQUEST_LRU_SIZE),
        };

        // We need to convince the signer event loop that it should accept the
        // message that we are going to send it.
        let report = MsgChainTipReport {
            sender_is_coordinator: true,
            chain_tip_status: ChainTipStatus::Canonical,
            chain_tip: BitcoinBlockRef {
                block_hash: BitcoinBlockHash::from([0; 32]),
                block_height: 0u64.into(),
            },
        };

        // The message that we will send is for the following sighash. We'll
        // need to make sure that it is in our database first
        let txid: BitcoinTxId = Faker.fake_with_rng(&mut rng);
        let sighash: SigHash = Faker.fake_with_rng(&mut rng);

        let row = BitcoinTxSigHash {
            txid,
            chain_tip: BitcoinBlockHash::from([0; 32]),
            prevout_txid: BitcoinTxId::from([0; 32]),
            prevout_output_index: 0,
            sighash,
            prevout_type: model::TxPrevoutType::Deposit,
            validation_result: signer::bitcoin::validation::InputValidationResult::Ok,
            is_valid_tx: true,
            will_sign: true,
            key_set_id: PublicKeyXOnly::from(PublicKey::from_private_key(
                &tx_signer.signer_private_key,
            ))
            .into(),
        };

        db.write_bitcoin_txs_sighashes(&[row]).await.unwrap();

        // Now for the nonce request message
        let mut nonce_request_msg = WstsMessage {
            id: WstsMessageId::Sweep(*txid),
            inner: wsts::net::Message::NonceRequest(NonceRequest {
                dkg_id: 1,
                sign_id: 1,
                sign_iter_id: 1,
                message: sighash.to_byte_array().to_vec(),
                signature_type: wsts::net::SignatureType::Schnorr,
            }),
        };
        let msg_public_key = PublicKey::from_private_key(&PrivateKey::new(&mut rng));

        // Sanity check, the state machines cache should be empty.
        assert!(tx_signer.wsts_state_machines.is_empty());

        // This function listens for WSTS NonceResponse messages broadcast from
        // the TxSignerEventLoop and returns them.
        let func = |mut handle: SignerNetworkInstance| async move {
            let signed_message = handle.receive().await.unwrap();
            let Payload::WstsMessage(WstsMessage {
                inner: WstsNetMessage::NonceResponse(response),
                ..
            }) = signed_message.inner.payload
            else {
                panic!("incorrect payload, test creator error");
            };

            response
        };

        // Let's create a handle to listen to any messages generated during the
        // handle_wsts_message call.
        let handle = network.connect(&ctx).spawn();

        tx_signer
            .handle_wsts_message(&nonce_request_msg, msg_public_key, &report)
            .await
            .unwrap();

        // Let's listen for the nonce response.
        tokio::time::timeout(Duration::from_secs(2), func(handle))
            .await
            .unwrap();

        // Even an exact retransmission is rejected. The signer must never
        // emit a second nonce response for this authorization.
        let result = tx_signer
            .handle_wsts_message(&nonce_request_msg, msg_public_key, &report)
            .await;
        assert!(matches!(
            result,
            Err(Error::BitcoinSigningRoundAlreadyStarted(
                error_sighash,
                error_chain_tip,
            )) if error_sighash == sighash && error_chain_tip == report.chain_tip.block_hash
        ));

        // A different iteration would cause WSTS to generate fresh nonces for
        // the same approved sighash, so reject it even while the original
        // state machine is active.
        let WstsNetMessage::NonceRequest(request) = &mut nonce_request_msg.inner else {
            panic!("expected a NonceRequest")
        };
        request.sign_iter_id += 1;

        let result = tx_signer
            .handle_wsts_message(&nonce_request_msg, msg_public_key, &report)
            .await;
        assert!(matches!(
            result,
            Err(Error::BitcoinSigningRoundAlreadyStarted(
                error_sighash,
                error_chain_tip,
            )) if error_sighash == sighash && error_chain_tip == report.chain_tip.block_hash
        ));

        // Sweep signature-share handling removes its state machine after the
        // signer produces a share. Simulate that completed lifecycle here;
        // this fixture intentionally only contains enough DKG material to
        // exercise nonce generation.
        tx_signer.wsts_state_machines.clear();
        assert!(tx_signer.wsts_state_machines.is_empty());

        // Replaying even the exact original request after completion must not
        // load a fresh state machine and generate another nonce response.
        let WstsNetMessage::NonceRequest(request) = &mut nonce_request_msg.inner else {
            panic!("expected a NonceRequest")
        };
        request.sign_iter_id -= 1;
        let result = tx_signer
            .handle_wsts_message(&nonce_request_msg, msg_public_key, &report)
            .await;
        assert!(matches!(
            result,
            Err(Error::BitcoinSigningRoundAlreadyStarted(
                error_sighash,
                error_chain_tip,
            )) if error_sighash == sighash && error_chain_tip == report.chain_tip.block_hash
        ));

        testing::storage::drop_db(db).await;
    }
}

#[tokio::test]
async fn max_one_state_machine_per_bitcoin_block_hash_for_dkg() {
    let db = testing::storage::new_test_database().await;

    let mut rng = get_rng();
    // Build the test context with mocked clients
    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .modify_settings(|settings| {
            settings.signer.bootstrap_signatures_required = 2;
        })
        .build();

    // Let's make sure that the database has the chain tip.
    let stack = TestContainersBuilder::start_bitcoin().await;
    let bitcoin = stack.bitcoin().await;
    let rpc = bitcoin.rpc();

    let headers = &get_canonical_chain_tip(rpc);
    let chain_tip = BitcoinBlockRef {
        block_hash: headers.hash.into(),
        block_height: headers.height.into(),
    };
    backfill_bitcoin_blocks(&db, rpc, &chain_tip.block_hash).await;

    let signer_set_public_keys = ctx.config().signer.bootstrap_signing_set.clone();

    ctx.state()
        .update_current_signer_set(signer_set_public_keys);

    // Initialize the transaction signer event loop
    let network = WanNetwork::default();
    let net = network.connect(&ctx);
    let mut tx_signer = TxSignerEventLoop {
        network: net.spawn(),
        context: ctx.clone(),
        context_window: 10000,
        wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
        signer_private_key: ctx.config().signer.private_key,
        last_presign_block: None,
        dkg_begin_pause: None,
        dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
        stacks_sign_request: LruCache::new(STACKS_SIGN_REQUEST_LRU_SIZE),
        bitcoin_sign_request: LruCache::new(BITCOIN_SIGN_REQUEST_LRU_SIZE),
    };

    // We need to convince the signer event loop that it should accept the
    // message that we are going to send it. DkgBegin messages are only
    // accepted from the coordinator on the canonical chain tip.
    let mut report = MsgChainTipReport {
        sender_is_coordinator: true,
        chain_tip_status: ChainTipStatus::Canonical,
        chain_tip,
    };

    // Now for the DKG begin message. We pick an arbitrary dkg_id, and an
    // arbitrary transaction ID.
    let dkg_id = 2;
    let dkg_begin_msg = WstsMessage {
        id: bitcoin::Txid::all_zeros().into(),
        inner: wsts::net::Message::DkgBegin(DkgBegin { dkg_id }),
    };
    let msg_public_key = PublicKey::from_private_key(&PrivateKey::new(&mut rng));

    // Sanity check, the state machines cache should be empty.
    assert!(tx_signer.wsts_state_machines.is_empty());

    tx_signer
        .handle_wsts_message(&dkg_begin_msg, msg_public_key, &report)
        .await
        .unwrap();

    // We should have a state machine associated with the current chain tip
    // request message that we just received.
    let id1 = StateMachineId::from(&chain_tip);
    let state_machine = tx_signer.wsts_state_machines.get(&id1).unwrap();
    assert_eq!(state_machine.dkg_id(), dkg_id);
    assert_eq!(tx_signer.wsts_state_machines.len(), 1);

    // Now let's see what happens when we receive another dkg message with
    // a different `dkg_id`. The expected behavior is that a new state
    // machine gets created, overwriting any existing one.
    let dkg_id = 1234;
    let dkg_begin_msg = WstsMessage {
        id: bitcoin::Txid::from_byte_array(Faker.fake_with_rng(&mut rng)).into(),
        inner: wsts::net::Message::DkgBegin(DkgBegin { dkg_id }),
    };

    tx_signer
        .handle_wsts_message(&dkg_begin_msg, msg_public_key, &report)
        .await
        .unwrap();

    let state_machine = tx_signer.wsts_state_machines.get(&id1).unwrap();
    assert_eq!(state_machine.dkg_id(), dkg_id);
    assert_eq!(tx_signer.wsts_state_machines.len(), 1);

    // If we say the current chain tip is something else, a new state
    // machine will be created associated with that chain tip. We keep the
    // height, since DKG does not run at or after the v2 activation height.
    report.chain_tip = BitcoinBlockRef {
        block_hash: Faker.fake_with_rng(&mut rng),
        block_height: chain_tip.block_height,
    };

    tx_signer
        .handle_wsts_message(&dkg_begin_msg, msg_public_key, &report)
        .await
        .unwrap();

    let id2 = StateMachineId::from(&report.chain_tip);
    let state_machine = tx_signer.wsts_state_machines.get(&id2).unwrap();
    assert_eq!(state_machine.dkg_id(), dkg_id);
    assert_eq!(tx_signer.wsts_state_machines.len(), 2);

    testing::storage::drop_db(db).await;
}

/// Module containing tests for the
/// [`MockedTxSigner::validate_dkg_verification_message`] function. See
/// [`MockedTxSigner`] for information on the validations that these tests
/// are asserting.
mod validate_dkg_verification_message {
    use secp256k1::Keypair;

    use signer::{
        bitcoin::utxo::UnsignedMockTransaction, keys::PublicKeyXOnly,
        storage::model::EncryptedDkgShares,
    };

    use super::*;

    /// Helper struct for testing
    /// [`MockedTxSigner::validate_dkg_verification_message`].
    struct TestParams {
        pub new_aggregate_key: PublicKeyXOnly,
        pub dkg_verification_window: u16,
        pub bitcoin_chain_tip: BitcoinBlockRef,
        pub message: Option<Vec<u8>>,
        pub signature_type: Option<wsts::net::SignatureType>,
    }

    impl Default for TestParams {
        fn default() -> Self {
            let new_aggregate_key = Keypair::new_global(&mut OsRng).x_only_public_key().into();
            Self {
                new_aggregate_key,
                dkg_verification_window: 0,
                bitcoin_chain_tip: BitcoinBlockRef {
                    block_hash: BitcoinBlockHash::from([0; 32]),
                    block_height: 0u64.into(),
                },
                message: None,
                signature_type: None,
            }
        }
    }

    impl TestParams {
        fn new(new_aggregate_key: PublicKeyXOnly) -> Self {
            Self {
                new_aggregate_key,
                ..Self::default()
            }
        }
        /// Executes [`MockedTxSigner::validate_dkg_verification_message`] with
        /// the values in this [`TestParams`] instance.
        async fn execute(&self, db: &PgStore) -> Result<(), Error> {
            MockedTxSigner::validate_dkg_verification_message::<PgStore>(
                db,
                &self.new_aggregate_key,
                self.message.as_deref(),
                self.signature_type,
                self.dkg_verification_window,
                &self.bitcoin_chain_tip,
            )
            .await
        }
    }

    #[tokio::test]
    async fn no_dkg_shares() {
        let db = testing::storage::new_test_database().await;

        // Just use default since we don't even have stored shares.
        let params = TestParams::default();

        let result = params.execute(&db).await.unwrap_err();
        assert!(matches!(result, Error::NoDkgShares));

        testing::storage::drop_db(db).await;
    }

    #[tokio::test]
    async fn latest_key_mismatch() {
        let mut rng = get_rng();
        let db = testing::storage::new_test_database().await;
        let latest_aggregate_key = Keypair::new_global(&mut rng).public_key().into();
        let new_aggregate_key = Keypair::new_global(&mut rng).x_only_public_key().into();

        // Create new DKG shares and store them in the database. We expect the
        // aggregate keys to not match, so we set them to values we explicitly
        // know won't match.
        let shares = EncryptedDkgShares {
            aggregate_key: latest_aggregate_key,
            ..Faker.fake()
        };
        db.write_encrypted_dkg_shares(&shares).await.unwrap();

        // Just to show that these two aren't equal.
        assert_ne!(new_aggregate_key, shares.aggregate_key.into());

        // New params with the new aggregate key which won't match.
        let params = TestParams::new(new_aggregate_key);

        let result = params.execute(&db).await.unwrap_err();

        if let Error::AggregateKeyMismatch { actual, expected } = result {
            let actual = *actual;
            let expected = *expected;

            assert_eq!(actual, latest_aggregate_key.into());
            assert_eq!(expected, new_aggregate_key);
            assert_ne!(actual, expected);
        } else {
            panic!("Expected an AggregateKeyMismatch error, got: {result:?}");
        }

        testing::storage::drop_db(db).await;
    }

    #[tokio::test]
    async fn latest_key_in_failed_state() {
        let db = testing::storage::new_test_database().await;
        let aggregate_key: PublicKey = Keypair::new_global(&mut OsRng).public_key().into();
        let aggregate_key_x_only = aggregate_key.into();

        // Create new DKG shares and store them in the database. We expect the
        // aggregate keys to match but validation to fail due to the latest shares
        // being marked as `Failed`.
        let shares = EncryptedDkgShares {
            aggregate_key,
            dkg_shares_status: DkgSharesStatus::Failed,
            ..Faker.fake()
        };
        db.write_encrypted_dkg_shares(&shares).await.unwrap();

        // Setup the test parameters.
        let params = TestParams::new(aggregate_key_x_only);

        let result = params.execute(&db).await.unwrap_err();

        assert!(matches!(
            result,
            Error::DkgVerificationFailed(key) if aggregate_key_x_only == key
        ));

        testing::storage::drop_db(db).await;
    }

    #[tokio::test]
    async fn verification_window_elapsed() {
        let db = testing::storage::new_test_database().await;
        let aggregate_key: PublicKey = Keypair::new_global(&mut OsRng).public_key().into();

        // Create new DKG shares and store them in the database. We expect the
        // aggregate keys to match and the status to be allowed. We use 0 as the
        // starting block.
        let shares = EncryptedDkgShares {
            aggregate_key,
            dkg_shares_status: DkgSharesStatus::Unverified,
            started_at_bitcoin_block_height: 0u64.into(),
            ..Faker.fake()
        };
        db.write_encrypted_dkg_shares(&shares).await.unwrap();

        // Setup the test parameters with a verification window of 10 blocks and
        // the actual time elapsed being 11 blocks.
        let params = TestParams {
            new_aggregate_key: aggregate_key.into(),
            dkg_verification_window: 10,
            bitcoin_chain_tip: BitcoinBlockRef {
                block_hash: BitcoinBlockHash::from([0; 32]),
                block_height: 11u64.into(),
            },
            ..Default::default()
        };

        let result = params.execute(&db).await.unwrap_err();

        assert!(matches!(
            result,
            Error::DkgVerificationWindowElapsed(key) if aggregate_key == key
        ));

        testing::storage::drop_db(db).await;
    }

    #[tokio::test]
    async fn verification_window_is_inclusive() {
        let db = testing::storage::new_test_database().await;
        let aggregate_key: PublicKey = Keypair::new_global(&mut OsRng).public_key().into();

        // Create new DKG shares and store them in the database. We expect the
        // aggregate keys to match and the status to be allowed. We use 0 as the
        // starting block.
        let shares = EncryptedDkgShares {
            aggregate_key,
            dkg_shares_status: DkgSharesStatus::Unverified,
            started_at_bitcoin_block_height: 0u64.into(),
            ..Faker.fake()
        };
        db.write_encrypted_dkg_shares(&shares).await.unwrap();

        // Setup the test parameters with a verification window of 10 blocks and
        // the actual time elapsed being 10 blocks. Tests that the verification
        // window is inclusive.
        let params = TestParams {
            new_aggregate_key: aggregate_key.into(),
            dkg_verification_window: 10,
            bitcoin_chain_tip: BitcoinBlockRef {
                block_hash: BitcoinBlockHash::from([0; 32]),
                block_height: 10u64.into(),
            },
            ..Default::default()
        };

        params.execute(&db).await.unwrap();

        testing::storage::drop_db(db).await;
    }

    #[tokio::test]
    async fn expected_sighash_succeeds() {
        let db = testing::storage::new_test_database().await;
        let aggregate_key: PublicKey = Keypair::new_global(&mut OsRng).public_key().into();

        // Create new DKG shares and store them in the database. We expect
        // all other verifications to succeed.
        let shares = EncryptedDkgShares {
            aggregate_key,
            dkg_shares_status: DkgSharesStatus::Unverified,
            started_at_bitcoin_block_height: 0u64.into(),
            ..Faker.fake()
        };
        db.write_encrypted_dkg_shares(&shares).await.unwrap();

        let sighash = UnsignedMockTransaction::new(aggregate_key.into())
            .compute_sighash()
            .unwrap();

        // Setup the test parameters using the expected sighash.
        let params = TestParams {
            new_aggregate_key: aggregate_key.into(),
            message: Some(sighash.as_byte_array().to_vec()),
            ..Default::default()
        };

        params.execute(&db).await.unwrap();

        testing::storage::drop_db(db).await;
    }

    #[tokio::test]
    async fn non_taproot_signature_type_fails() {
        let db = testing::storage::new_test_database().await;
        let aggregate_key: PublicKey = Keypair::new_global(&mut OsRng).public_key().into();

        let shares = EncryptedDkgShares {
            aggregate_key,
            dkg_shares_status: DkgSharesStatus::Unverified,
            started_at_bitcoin_block_height: 0u64.into(),
            ..Faker.fake()
        };
        db.write_encrypted_dkg_shares(&shares).await.unwrap();

        let sighash = UnsignedMockTransaction::new(aggregate_key.into())
            .compute_sighash()
            .unwrap();
        for signature_type in [
            wsts::net::SignatureType::Schnorr,
            wsts::net::SignatureType::Frost,
        ] {
            let params = TestParams {
                new_aggregate_key: aggregate_key.into(),
                message: Some(sighash.as_byte_array().to_vec()),
                signature_type: Some(signature_type),
                ..Default::default()
            };

            let result = params.execute(&db).await.unwrap_err();
            assert!(matches!(
                result,
                Error::InvalidDkgVerificationSignatureType(rejected)
                    if rejected == signature_type
            ));
        }

        testing::storage::drop_db(db).await;
    }

    #[tokio::test]
    async fn taproot_signature_type_succeeds() {
        let db = testing::storage::new_test_database().await;
        let aggregate_key: PublicKey = Keypair::new_global(&mut OsRng).public_key().into();

        let shares = EncryptedDkgShares {
            aggregate_key,
            dkg_shares_status: DkgSharesStatus::Unverified,
            started_at_bitcoin_block_height: 0u64.into(),
            ..Faker.fake()
        };
        db.write_encrypted_dkg_shares(&shares).await.unwrap();

        let sighash = UnsignedMockTransaction::new(aggregate_key.into())
            .compute_sighash()
            .unwrap();
        let params = TestParams {
            new_aggregate_key: aggregate_key.into(),
            message: Some(sighash.as_byte_array().to_vec()),
            signature_type: Some(wsts::net::SignatureType::Taproot),
            ..Default::default()
        };

        params.execute(&db).await.unwrap();

        testing::storage::drop_db(db).await;
    }

    #[tokio::test]
    async fn unexpected_sighash_fails() {
        let db = testing::storage::new_test_database().await;
        let aggregate_key: PublicKey = Keypair::new_global(&mut OsRng).public_key().into();

        // Create new DKG shares and store them in the database. We expect
        // all other verifications to succeed.
        let shares = EncryptedDkgShares {
            aggregate_key,
            dkg_shares_status: DkgSharesStatus::Unverified,
            started_at_bitcoin_block_height: 0u64.into(),
            ..Faker.fake()
        };
        db.write_encrypted_dkg_shares(&shares).await.unwrap();

        // Setup the test parameters using a random sighash, which we expect
        // to fail validation.
        let params = TestParams {
            new_aggregate_key: aggregate_key.into(),
            dkg_verification_window: 10,
            bitcoin_chain_tip: BitcoinBlockRef {
                block_hash: BitcoinBlockHash::from([0; 32]),
                block_height: 10u64.into(),
            },
            message: Some(Faker.fake()),
            signature_type: None,
        };

        let result = params.execute(&db).await.unwrap_err();

        std::assert_matches!(result, Error::InvalidSigHash(_, _));

        testing::storage::drop_db(db).await;
    }
}
