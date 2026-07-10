use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bitcoin::Address;
use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoincore_rpc::RpcApi as _;
use clarity::vm::types::PrincipalData;
use clarity::vm::types::StandardPrincipalData;
use fake::Fake as _;
use lru::LruCache;
use sbtc::testing::containers::TestContainersBuilder;
use sbtc::testing::regtest::Recipient;
use secp256k1::Keypair;
use signer::block_observer::BlockObserver;
use signer::context::Context as _;
use signer::context::SignerEvent;
use signer::context::SignerSignal;
use signer::context::TxCoordinatorEvent;
use signer::ecdsa::SignEcdsa as _;
use signer::keys::PrivateKey;
use signer::keys::SignerScriptPubKey as _;
use signer::message::Payload;
use signer::network::in_memory2::SignerNetwork;
use signer::network::in_memory2::SignerNetworkInstance;
use signer::network::in_memory2::WanNetwork;
use signer::network::{MessageTransfer, Msg};
use signer::request_decider::RequestDeciderEventLoop;
use signer::storage::DbRead as _;
use signer::storage::DbWrite as _;
use signer::storage::model::BitcoinBlockHash;
use signer::storage::model::KeyRotationEvent;
use signer::storage::model::StacksTxId;
use signer::storage::model::WithdrawalRequest;
use signer::storage::model::WithdrawalSigner;
use signer::storage::postgres::PgStore;
use signer::testing::FuturesIterExt as _;
use signer::testing::btc::get_canonical_chain_tip;
use signer::testing::context::*;
use signer::testing::get_rng;
use signer::testing::storage;
use signer::testing::storage::DbReadTestExt as _;
use signer::testing::wallet;
use signer::transaction_coordinator::TxCoordinatorEventLoop;
use signer::transaction_signer::STACKS_SIGN_REQUEST_LRU_SIZE;
use signer::transaction_signer::TxSignerEventLoop;
use signer::util::Sleep;
use testing_emily_client::apis::chainstate_api;
use testing_emily_client::apis::withdrawal_api;
use testing_emily_client::models::Chainstate;
use tokio::sync::broadcast::Sender;
use tokio_stream::wrappers::BroadcastStream;
use wsts::net::Message as WstsNetMessage;

use crate::containers::BitcoinContainerExt as _;

use super::setup::*;

// Imports for mock_stacks_core
use bitcoincore_rpc_json::GetChainTipsResultTip;
use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::net::api::getsortition::SortitionInfo;
use signer::bitcoin::rpc::BitcoinCoreClient;
use signer::emily_client::EmilyClient;
use signer::stacks::api::AccountInfo;
use signer::stacks::api::MockStacksInteract;
use signer::stacks::api::SignerSetInfo;
use signer::stacks::api::StacksEpochStatus;
use signer::stacks::api::StacksInteract;
use signer::stacks::api::SubmitTxResponse;
use signer::stacks::api::TenureBlockHeaders;
use signer::storage::model;
use signer::storage::model::BitcoinBlockHeight;
use signer::testing::stacks::DUMMY_TENURE_INFO;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::types::chainstate::SortitionId;

type IntegrationTestContext<Stacks> = TestContext<PgStore, BitcoinCoreClient, Stacks, EmilyClient>;

/// A network wrapper that intercepts and corrupts WSTS SignatureShareResponse messages.
#[derive(Clone)]
struct MaliciousNetwork {
    inner: SignerNetworkInstance,
    private_key: PrivateKey,
    /// When false, behaves honestly (needed for DKG to complete).
    /// When true, corrupts signature shares.
    attack_active: Arc<AtomicBool>,
}

impl MessageTransfer for MaliciousNetwork {
    async fn broadcast(&mut self, mut msg: Msg) -> Result<(), signer::error::Error> {
        let mut signer_msg = msg.inner.clone();

        // INTERCEPT AND CORRUPT:
        // If this is a SignatureShareResponse (which contains the WSTS share),
        // we replace the share with a random value.
        // This simulates a signer sending an invalid share.

        if self.attack_active.load(Ordering::SeqCst)
            && let Payload::WstsMessage(ref mut wsts_msg) = signer_msg.payload
            && let WstsNetMessage::SignatureShareResponse(ref mut share) = wsts_msg.inner
        {
            // Corrupt the shares
            // We don't need to be subtle. Just invalidating it is enough to cause
            // the aggregator to fail verification and the round to timeout.
            if !share.signature_shares.is_empty() {
                // Fuzz the first share's scalar by creating a random one
                let random_bytes: [u8; 32] = rand::random();
                share.signature_shares[0].z_i = p256k1::scalar::Scalar::from(random_bytes);
            }
            // Re-sign the message with the attacker's private key
            // This ensures the message is "authentic" (from the signer) but "malicious" (invalid payload)
            msg = signer_msg.sign_ecdsa(&self.private_key);
        }

        self.inner.broadcast(msg).await
    }

    async fn receive(&mut self) -> Result<Msg, signer::error::Error> {
        self.inner.receive().await
    }
}

/// Enum-based network dispatch to avoid dyn-compatibility issues with MessageTransfer.
/// MessageTransfer requires Clone (Self: Sized), so Box<dyn MessageTransfer> won't work.
#[derive(Clone)]
enum TestNetwork {
    Honest(SignerNetworkInstance),
    Malicious(MaliciousNetwork),
}

impl MessageTransfer for TestNetwork {
    async fn broadcast(&mut self, msg: Msg) -> Result<(), signer::error::Error> {
        match self {
            TestNetwork::Honest(n) => n.broadcast(msg).await,
            TestNetwork::Malicious(n) => n.broadcast(msg).await,
        }
    }

    async fn receive(&mut self) -> Result<Msg, signer::error::Error> {
        match self {
            TestNetwork::Honest(n) => n.receive().await,
            TestNetwork::Malicious(n) => n.receive().await,
        }
    }
}

const WITHDRAWAL_MIN_CONFIRMATIONS: u64 = 6;

/// Full WSTS Censorship Attack: Proves single malicious signer can block withdrawals
///
/// Demonstrates:
/// 1. Database determinism enables targeted censorship
/// 2. Invalid signature share causes signing round timeout
/// 3. Head-of-line blocking prevents processing of subsequent requests
/// 4. No penalty mechanism for malicious behavior
#[tokio::test]
#[ignore = "requires docker (postgres, bitcoind, emily)"]
async fn test_wsts_censorship_full_signing_round() {
    let (_, signer_key_pairs): (_, [Keypair; 3]) = wallet::regtest_bootstrap_wallet();

    let stack = TestContainersBuilder::start_bitcoin().await;
    let bitcoin = stack.bitcoin().await;
    let rpc = bitcoin.rpc();
    let faucet = &bitcoin.get_faucet();

    let mut rng = get_rng();

    let (emily_client, _emily_tables) = new_emily_setup().await;
    let emily_config = emily_client.config().as_testing();

    let base_network = WanNetwork::default();
    let attack_active = Arc::new(AtomicBool::new(false));

    faucet.generate_fee_data();

    let chain_tip_info = get_canonical_chain_tip(rpc);

    // =========================================================================
    // Step 1: Create 3 signers with databases and contexts
    // =========================================================================
    let mut signers = Vec::new();
    for (i, kp) in signer_key_pairs.iter().enumerate() {
        let db = storage::new_test_database().await;
        let ctx = TestContext::builder()
            .with_storage(db.clone())
            .with_bitcoin_client(bitcoin.get_client())
            .with_emily_client(emily_client.clone())
            .with_mocked_stacks_client()
            .modify_settings(|config| {
                config.signer.is_malicious = Some(i == 0);
                config.signer.private_key = kp.secret_key().into();
            })
            .build();

        backfill_bitcoin_blocks(&db, rpc, &chain_tip_info.hash).await;

        signers.push(ctx);
    }

    // =========================================================================
    // Step 2: Setup Stacks client mocks
    // =========================================================================
    let (broadcast_stacks_tx, rx) = tokio::sync::broadcast::channel(10);
    let _stacks_tx_stream = BroadcastStream::new(rx);

    for ctx in signers.iter_mut() {
        let broadcast_stacks_tx = broadcast_stacks_tx.clone();
        let db = ctx.storage.clone();

        mock_stacks_core(ctx, chain_tip_info.clone(), db, broadcast_stacks_tx).await;
    }

    // =========================================================================
    // Step 3: Start event loops for all signers
    // =========================================================================
    let start_count = Arc::new(AtomicU8::new(0));
    let bitcoin_chain_tip_poller = bitcoin.start_chain_tip_poller().await;

    for ctx in signers.iter() {
        ctx.state().set_sbtc_contracts_deployed();

        let attack_flag = attack_active.clone();
        let spawn_network = |net: &SignerNetwork,
                             mal: bool,
                             private_key: PrivateKey,
                             flag: &Arc<AtomicBool>|
         -> TestNetwork {
            if mal {
                TestNetwork::Malicious(MaliciousNetwork {
                    inner: net.spawn(),
                    private_key,
                    attack_active: flag.clone(),
                })
            } else {
                TestNetwork::Honest(net.spawn())
            }
        };
        // Store the SignerNetwork for each signer; malicious wrapping happens at spawn time
        let network = base_network.connect(ctx);

        // Coordinator
        let is_malicious = ctx.config().signer.is_malicious.unwrap_or(false);
        let private_key = ctx.config().signer.private_key;
        let ev = TxCoordinatorEventLoop {
            network: spawn_network(&network, is_malicious, private_key, &attack_flag),
            context: ctx.clone(),
            context_window: 10000,
            private_key,
            signing_round_max_duration: Duration::from_secs(10),
            bitcoin_presign_request_max_duration: Duration::from_secs(10),
            dkg_max_duration: Duration::from_secs(10),
            is_epoch3: true,
        };
        let counter = start_count.clone();
        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            ev.run().await
        });

        // Signer
        let ev = TxSignerEventLoop {
            network: spawn_network(&network, is_malicious, private_key, &attack_flag),
            context: ctx.clone(),
            context_window: 10000,
            wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
            signer_private_key: private_key,
            last_presign_block: None,
            dkg_begin_pause: None,
            dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
            stacks_sign_request: LruCache::new(STACKS_SIGN_REQUEST_LRU_SIZE),
        };
        let counter = start_count.clone();
        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            ev.run().await
        });

        // Request Decider
        let ev = RequestDeciderEventLoop {
            network: spawn_network(&network, is_malicious, private_key, &attack_flag),
            context: ctx.clone(),
            context_window: 10000,
            deposit_decisions_retry_window: 1,
            withdrawal_decisions_retry_window: 1,
            blocklist_checker: Some(()),
            signer_private_key: private_key,
        };
        let counter = start_count.clone();
        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            ev.run().await
        });

        // Block Observer
        let block_observer = BlockObserver {
            context: ctx.clone(),
            bitcoin_block_source: bitcoin_chain_tip_poller.clone(),
        };
        let counter = start_count.clone();
        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            block_observer.run().await
        });
    }

    // Wait for all event loops to start (12 total: 4 per signer * 3 signers)
    while start_count.load(Ordering::SeqCst) < 12 {
        Sleep::for_millis(10).await;
    }

    // =========================================================================
    // Step 4: Wait for DKG to complete
    // =========================================================================
    // Generate blocks until DKG is verified
    let ctx = signers.first().unwrap();
    let db = ctx.storage.clone();
    for _ in 0..5 {
        let chain_tip = faucet.generate_block().into();
        wait_for_signers(&signers, chain_tip).await;

        // Check if DKG shares are verified
        if db.get_latest_verified_dkg_shares().await.unwrap().is_some() {
            break;
        }
    }

    // Get chain tips to use for key rotation and withdrawal requests
    let (bitcoin_chain_tip, stacks_chain_tip) = db.get_chain_tips().await;

    // NOW activate the attack - DKG is done, start corrupting signature shares
    attack_active.store(true, Ordering::SeqCst);

    // Populate DKG shares and key rotation event
    for ctx in signers.iter() {
        let db = ctx.storage.clone();
        let shares = db
            .get_latest_verified_dkg_shares()
            .await
            .unwrap()
            .expect("DKG shares should be verified");

        let event = KeyRotationEvent {
            txid: fake::Faker.fake_with_rng(&mut rng),
            block_hash: stacks_chain_tip,
            aggregate_key: shares.aggregate_key,
            signer_set: shares.signer_set_public_keys.clone(),
            signatures_required: shares.signature_share_threshold,
            address: PrincipalData::from(ctx.config().signer.deployer.clone()).into(),
        };
        db.write_rotate_keys_transaction(&event).await.unwrap();
    }

    let shares = db.get_latest_encrypted_dkg_shares().await.unwrap().unwrap();

    // =========================================================================
    // Step 5: Fund the signers' aggregate key
    // =========================================================================
    let script_pub_key = shares.aggregate_key.signers_script_pubkey();
    let network_type = bitcoin::Network::Regtest;
    let address = Address::from_script(&script_pub_key, network_type).unwrap();

    faucet.send_to(100_000_000, &address);

    // =========================================================================
    // Step 6: Create 5 withdrawal requests (OUT OF ORDER)
    // =========================================================================

    let withdrawal_requests: Vec<(u64, u64)> = vec![
        (103, 300_000),
        (101, 100_000), // TARGET: This will be censored
        (102, 200_000),
        (105, 50_000),
        (104, 400_000),
    ];

    for (request_id, amount) in withdrawal_requests.iter() {
        let withdrawal_recipient = Recipient::new(AddressType::P2tr);

        let withdrawal_request = WithdrawalRequest {
            request_id: *request_id,
            bitcoin_block_height: bitcoin_chain_tip.block_height,
            amount: *amount,
            block_hash: stacks_chain_tip,
            recipient: withdrawal_recipient.script_pubkey.clone().into(),
            max_fee: 10_000,
            txid: StacksTxId::from([(*request_id as u8); 32]),
            sender_address: PrincipalData::from(StandardPrincipalData::transient()).into(),
        };

        // Write to all signer databases
        for ctx in signers.iter() {
            let db = ctx.storage.clone();
            db.write_withdrawal_request(&withdrawal_request)
                .await
                .unwrap();
        }

        // Write to Emily
        let stacks_tip_height = db
            .get_stacks_block(&stacks_chain_tip)
            .await
            .unwrap()
            .unwrap()
            .block_height;

        chainstate_api::set_chainstate(
            &emily_config,
            Chainstate {
                stacks_block_hash: stacks_chain_tip.to_string(),
                stacks_block_height: *stacks_tip_height,
                bitcoin_block_height: Some(Some(0)),
            },
        )
        .await
        .expect("Failed to set chainstate");

        let request_body = testing_emily_client::models::CreateWithdrawalRequestBody {
            amount: withdrawal_request.amount,
            parameters: Box::new(testing_emily_client::models::WithdrawalParameters {
                max_fee: withdrawal_request.max_fee,
            }),
            recipient: withdrawal_request.recipient.to_string(),
            request_id: withdrawal_request.request_id,
            sender: withdrawal_request.sender_address.to_string(),
            stacks_block_hash: withdrawal_request.block_hash.to_string(),
            stacks_block_height: *stacks_tip_height,
            txid: withdrawal_request.txid.to_string(),
        };
        withdrawal_api::create_withdrawal(&emily_config, request_body)
            .await
            .unwrap();

        // Accept by all signers
        for ctx in signers.iter() {
            let db = ctx.storage.clone();
            for _ in 0..3 {
                let decision = WithdrawalSigner {
                    request_id: *request_id,
                    block_hash: stacks_chain_tip,
                    txid: withdrawal_request.txid,
                    signer_pub_key: fake::Faker.fake(),
                    is_accepted: true,
                };
                db.write_withdrawal_signer_decision(&decision)
                    .await
                    .unwrap();
            }
        }
    }

    // =========================================================================
    // Step 7: Verify deterministic ordering
    // =========================================================================
    let pending = db
        .get_pending_accepted_withdrawal_requests(
            bitcoin_chain_tip.as_ref(),
            &stacks_chain_tip,
            0u64.into(),
            2, // 2-of-3 threshold
        )
        .await
        .unwrap();

    assert_eq!(
        pending[0].request_id, 101,
        "Database should return request 101 first"
    );
    assert_eq!(pending.len(), 5, "All 5 requests should be pending");

    // =========================================================================
    // Step 8: Process withdrawal confirmations
    // =========================================================================
    for _ in 0..WITHDRAWAL_MIN_CONFIRMATIONS - 1 {
        let chain_tip = faucet.generate_block().into();
        wait_for_signers(&signers, chain_tip).await;

        let txids = ctx.bitcoin_client.inner_client().get_raw_mempool().unwrap();
        assert!(txids.is_empty(), "No transactions should be broadcast yet");
    }

    let chain_tip = faucet.generate_block().into();
    wait_for_signers(&signers, chain_tip).await;

    // =========================================================================
    // Step 9: Wait for signing round to complete or timeout
    // =========================================================================
    // In normal operation, the coordinator would broadcast a sweep transaction
    // However, if a malicious signer sends invalid shares, the signing round
    // will timeout after signing_round_max_duration (10 seconds)

    Sleep::for_secs(15).await; // Wait for timeout + buffer

    // =========================================================================
    // Step 10: Verify withdrawal blocking
    // =========================================================================
    let pending_after = db
        .get_pending_accepted_withdrawal_requests(
            bitcoin_chain_tip.as_ref(),
            &stacks_chain_tip,
            0u64.into(),
            2,
        )
        .await
        .unwrap();

    // If signing succeeded, pending would be empty or reduced
    // If signing failed (timeout), all requests remain pending
    assert_eq!(
        pending_after.len(),
        5,
        "All requests should still be pending after signing round timeout"
    );
    assert_eq!(
        pending_after[0].request_id, 101,
        "Request 101 should still be at head of queue (HOL blocking)"
    );

    // Cleanup
    for ctx in signers.iter() {
        storage::drop_db(ctx.storage.clone()).await;
    }
}

/// Mock the stacks client to return dummy data for the given context.
async fn mock_stacks_core<D, B, E>(
    ctx: &mut TestContext<D, B, WrappedMock<MockStacksInteract>, E>,
    chain_tip_info: GetChainTipsResultTip,
    db: PgStore,
    broadcast_stacks_tx: Sender<StacksTransaction>,
) {
    ctx.with_stacks_client(|client| {
        client
            .expect_get_tenure_info()
            .returning(move || Box::pin(std::future::ready(Ok(DUMMY_TENURE_INFO.clone()))));

        client.expect_get_block().returning(|_| {
            let response = Ok(NakamotoBlock {
                header: NakamotoBlockHeader::empty(),
                txs: vec![],
            });
            Box::pin(std::future::ready(response))
        });

        let chain_tip = model::BitcoinBlockHash::from(chain_tip_info.hash);
        client.expect_get_tenure_headers().returning(move |_| {
            let mut tenure = TenureBlockHeaders::nearly_empty().unwrap();
            tenure.anchor_block_hash = chain_tip;
            Box::pin(std::future::ready(Ok(tenure)))
        });

        client.expect_get_epoch_status().returning(|| {
            Box::pin(std::future::ready(Ok(StacksEpochStatus::PostNakamoto {
                nakamoto_start_height: BitcoinBlockHeight::from(232_u32),
            })))
        });

        client
            .expect_estimate_fees()
            .returning(|_, _, _| Box::pin(std::future::ready(Ok(25))));

        // The coordinator will try to further process the deposit to submit
        // the stacks tx, but we are not interested (for the current test iteration).
        client.expect_get_account().returning(|_| {
            let response = Ok(AccountInfo {
                balance: 0,
                locked: 0,
                unlock_height: 0u64.into(),
                // this is the only part used to create the Stacks transaction.
                nonce: 12,
            });
            Box::pin(std::future::ready(response))
        });
        client.expect_get_sortition_info().returning(move |_| {
            let response = Ok(SortitionInfo {
                burn_block_hash: BurnchainHeaderHash::from(chain_tip),
                burn_block_height: chain_tip_info.height,
                burn_header_timestamp: 0,
                sortition_id: SortitionId([0; 32]),
                parent_sortition_id: SortitionId([0; 32]),
                consensus_hash: ConsensusHash([0; 20]),
                was_sortition: true,
                miner_pk_hash160: None,
                stacks_parent_ch: None,
                last_sortition_ch: None,
                committed_block_hash: None,
                vrf_seed: None,
            });
            Box::pin(std::future::ready(response))
        });

        // The coordinator broadcasts a rotate keys transaction if it
        // is not up-to-date with their view of the current aggregate
        // key. The response of here means that the stacks node has a
        // record of a rotate keys contract call being executed once we
        // have verified shares.
        client
            .expect_get_current_signer_set_info()
            .returning(move |_| {
                let db = db.clone();
                Box::pin(async move {
                    let shares = db.get_latest_verified_dkg_shares().await?;
                    Ok(shares.map(SignerSetInfo::from))
                })
            });

        // Only the client that corresponds to the coordinator will
        // submit a transaction, so we don't make explicit the
        // expectation here.
        client.expect_submit_tx().returning(move |tx| {
            let tx = tx.clone();
            let txid = tx.txid().into();
            let broadcast_stacks_tx = broadcast_stacks_tx.clone();
            Box::pin(async move {
                broadcast_stacks_tx.send(tx).unwrap();
                Ok(SubmitTxResponse::Acceptance(txid))
            })
        });
        // The coordinator will get the total supply of sBTC to
        // determine the amount of mintable sBTC.
        client
            .expect_get_sbtc_total_supply()
            .returning(move |_| Box::pin(async move { Ok(Amount::ZERO) }));

        client
            .expect_is_deposit_completed()
            .returning(move |_, _| Box::pin(async move { Ok(false) }));

        // We use this during validation to check if the withdrawal
        // request completed in the smart contract.
        client
            .expect_is_withdrawal_completed()
            .returning(|_, _| Box::pin(std::future::ready(Ok(false))));
    })
    .await;
}

async fn wait_for_signers<S>(signers: &[IntegrationTestContext<S>], chain_tip: BitcoinBlockHash)
where
    S: StacksInteract + Clone + Send + Sync + 'static,
{
    let wait_duration = Duration::from_secs(15);

    signers
        .iter()
        .map(|ctx| async {
            ctx.wait_for_signal(wait_duration, |signal| match signal {
                SignerSignal::Event(SignerEvent::TxCoordinator(
                    TxCoordinatorEvent::TenureCompleted(block_ref),
                )) => block_ref.block_hash == chain_tip,
                _ => false,
            })
            .await
            .unwrap();
        })
        .join_all()
        .await;

    // It's not entirely clear why this sleep is helpful, but it appears to
    // be necessary in CI.
    Sleep::for_secs(2).await;
}
