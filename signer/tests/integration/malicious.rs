use std::num::NonZero;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::consensus::encode::serialize_hex;
use bitcoincore_rpc::RpcApi;
use bitcoincore_rpc_json::Utxo;
use clarity::vm::types::PrincipalData;
use clarity::vm::types::StacksAddressExtensions as _;
use emily_client::apis::deposit_api;
use emily_client::models::CreateDepositRequestBody;
use futures::stream::StreamExt as _;
use lru::LruCache;
use rand::rngs::OsRng;
use sbtc::testing::containers::TestContainersBuilder;
use sbtc::testing::regtest::BITCOIN_CORE_FALLBACK_FEE;
use sbtc::testing::regtest::Recipient;
use secp256k1::Keypair;
use signer::bitcoin::BitcoinBlockHashStreamProvider as _;
use signer::bitcoin::poller::BitcoinChainTipPoller;
use signer::bitcoin::rpc::BitcoinCoreClient;
use signer::block_observer::BlockObserver;
use signer::config::NetworkKind;
use signer::context::Context as _;
use signer::emily_client::EmilyClient;
use signer::keys::PublicKey;
use signer::keys::SignerScriptPubKey as _;
use signer::message::Payload;
use signer::message::WstsMessageId;
use signer::network::MessageTransfer;
use signer::network::Msg;
use signer::network::in_memory2::SignerNetwork;
use signer::network::in_memory2::SignerNetworkInstance;
use signer::network::in_memory2::WanNetwork;
use signer::request_decider::RequestDeciderEventLoop;
use signer::stacks::api::StacksClient;
use signer::stacks::api::StacksInteract as _;
use signer::stacks::wallet::SignerWallet;
use signer::storage::DbRead as _;
use signer::storage::model::BitcoinBlockHeight;
use signer::storage::model::DkgSharesStatus;
use signer::testing;
use signer::testing::context::*;
use signer::transaction_coordinator::TxCoordinatorEventLoop;
use signer::transaction_coordinator::coordinator_public_key;
use signer::transaction_signer::STACKS_SIGN_REQUEST_LRU_SIZE;
use signer::transaction_signer::TxSignerEventLoop;
use signer::util::FutureExt as _;
use signer::util::Sleep;
use wsts::net::Message as WstsNetMessage;

use crate::containers::BitcoinContainerExt as _;
use crate::containers::StacksContainerExt as _;
use crate::setup::clean_emily_setup;
use crate::setup::new_emily_setup;
use crate::stacks::fund_stx;
use crate::stacks::wait_for_new_nonce;
use crate::stacks::wait_for_stx_balance;
use crate::transaction_coordinator::IntegrationTestContext;
use crate::transaction_coordinator::wait_for_tenure_completed;
use crate::utxo_construction::make_deposit_request_to;

#[derive(Clone)]
struct MaliciousDkgControl {
    /// Enables the malicious behavior once the test has completed the honest
    /// first DKG and first deposit sweep.
    attack_active: Arc<AtomicBool>,
    /// The signer selected to withhold DKG verification responses. This is set
    /// after the second-DKG trigger block is mined so the test can avoid
    /// targeting that block's coordinator.
    malicious_signer: Arc<Mutex<Option<PublicKey>>>,
    /// Count of DKG verification response messages intentionally dropped by
    /// the selected malicious signer.
    dropped_dkg_verification_responses: Arc<AtomicUsize>,
}

/// A network wrapper that makes one signer stop participating in DKG
/// verification rounds while leaving DKG itself and ordinary sweep signing
/// untouched.
#[derive(Clone)]
struct MaliciousNetwork {
    /// The honest in-memory network instance that actually sends and receives
    /// messages for one signer component.
    inner: SignerNetworkInstance,
    /// The public key of the signer whose component owns this network wrapper.
    signer_public_key: PublicKey,
    /// The shared state that controls when, and for which signer, messages are
    /// dropped.
    malicious_dkg: MaliciousDkgControl,
}

impl MessageTransfer for MaliciousNetwork {
    async fn broadcast(&mut self, msg: Msg) -> Result<(), signer::error::Error> {
        let is_malicious_signer = self
            .malicious_dkg
            .malicious_signer
            .lock()
            .expect("malicious signer mutex poisoned")
            .is_some_and(|public_key| public_key == self.signer_public_key);

        if self.malicious_dkg.attack_active.load(Ordering::SeqCst)
            && is_malicious_signer
            && let Payload::WstsMessage(wsts_msg) = &msg.inner.payload
            && matches!(wsts_msg.id, WstsMessageId::DkgVerification(_))
            && matches!(
                &wsts_msg.inner,
                WstsNetMessage::NonceResponse(_) | WstsNetMessage::SignatureShareResponse(_)
            )
        {
            self.malicious_dkg
                .dropped_dkg_verification_responses
                .fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }

        self.inner.broadcast(msg).await
    }

    async fn receive(&mut self) -> Result<Msg, signer::error::Error> {
        self.inner.receive().await
    }
}

struct SignerClients<'a> {
    /// The Bitcoin Core client copied into each signer context.
    bitcoin_client: &'a BitcoinCoreClient,
    /// The block poller shared by every block observer event loop.
    bitcoin_chain_tip_poller: &'a BitcoinChainTipPoller,
    /// The Stacks node client copied into each signer context.
    stacks_client: &'a StacksClient,
    /// The Emily client copied into each signer context.
    emily_client: &'a EmilyClient,
    /// The in-memory WAN used to connect all signer components.
    network: &'a WanNetwork,
}

#[derive(Clone, Copy)]
struct SignerSetConfig {
    /// Number of signer contexts to create.
    num_signers: usize,
    /// Signing threshold for the generated signer set.
    signatures_required: u16,
    /// Bitcoin block height at which the signers are allowed to run DKG.
    dkg_min_bitcoin_block_height: BitcoinBlockHeight,
}

/// This struct is a container for most of the parameters that are needed
/// to create a deposit transaction. The missing parameters are around the
/// reclaim script.
#[derive(Clone)]
struct DepositParameters {
    /// Amount, in satoshis, locked by the deposit.
    amount: u64,
    /// Maximum fee, in satoshis, that the depositor allows the sweep to spend.
    max_fee: u64,
    /// Aggregate key that controls the sBTC deposit script.
    aggregate_key: PublicKey,
    /// Stacks principal that receives the minted sBTC.
    recipient: PrincipalData,
}

struct DepositSubmission<'a> {
    /// The Bitcoin wallet making the deposit.
    depositor: &'a Recipient,
    /// The UTXO that funds this deposit output.
    fund_outpoint: OutPoint,
    /// The value, in sats, of the funding UTXO.
    fund_amount: u64,
    /// Deposit script, amount, fee, and recipient parameters.
    parameters: DepositParameters,
}

/// Create the signer contexts, connect every signer to the shared in-memory
/// WAN, and start the coordinator, signer, request-decider, and block-observer
/// event loops for each signer.
///
/// All signer networks must be connected before any event loop starts, because
/// `WanNetwork::connect` subscribes that signer to the broadcast channel and
/// early DKG messages are not replayed to later subscribers.
async fn start_signers(
    clients: SignerClients<'_>,
    signer_set: SignerSetConfig,
    malicious_dkg: MaliciousDkgControl,
) -> Vec<IntegrationTestContext<StacksClient>> {
    let keypairs = std::iter::repeat_with(|| Keypair::new_global(&mut OsRng))
        .take(signer_set.num_signers)
        .collect::<Vec<_>>();

    let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public_key().into()).collect();
    let wallet = SignerWallet::new(
        &public_keys,
        signer_set.signatures_required,
        NetworkKind::Testnet,
        0,
    )
    .unwrap();

    let tx = fund_stx(
        clients.stacks_client,
        &wallet.address().to_account_principal(),
        100 * 1_000_000,
    )
    .await;
    clients
        .stacks_client
        .submit_tx(&tx)
        .await
        .expect("failed to send stacks transaction");

    wait_for_stx_balance(clients.stacks_client, wallet.address(), |ustx| ustx > 0).await;

    // Let the poller observe the current chain tip before we start producing
    // blocks for the test scenario.
    let mut stream = clients.bitcoin_chain_tip_poller.get_block_hash_stream();
    let polling_fut = async {
        loop {
            let _ = stream.next().with_timeout(Duration::from_millis(100)).await;
        }
    };
    let _ = polling_fut.with_timeout(Duration::from_millis(500)).await;

    let mut signers = Vec::new();
    let mut networks = Vec::new();
    for kp in keypairs.iter() {
        let db = testing::storage::new_test_database().await;
        let ctx = TestContext::builder()
            .with_storage(db.clone())
            .with_bitcoin_client(clients.bitcoin_client.clone())
            .with_emily_client(clients.emily_client.clone())
            .with_stacks_client(clients.stacks_client.clone())
            .modify_settings(|settings| {
                settings.signer.private_key = kp.secret_key().into();
                settings.signer.bootstrap_signing_set = public_keys.iter().cloned().collect();
                settings.signer.bootstrap_signatures_required = signer_set.signatures_required;
                settings.signer.bitcoin_processing_delay = Duration::from_millis(500);
                settings.signer.deployer = wallet.address().clone();
                settings.signer.dkg_min_bitcoin_block_height =
                    Some(signer_set.dkg_min_bitcoin_block_height);
                settings.signer.stacks_fees_max_ustx = NonZero::new(1_000_000).unwrap();
            })
            .build();

        // Note: we create all networks here because all of them need to
        // exist and be connected before any of the event loops are
        // started.
        networks.push(clients.network.connect(&ctx));
        signers.push(ctx);
    }

    let start_count = Arc::new(AtomicUsize::new(0));
    for (ctx, network) in signers.iter().zip(networks.iter()) {
        let private_key = ctx.config().signer.private_key;
        let signer_public_key = PublicKey::from_private_key(&private_key);
        let spawn_network = |network: &SignerNetwork| MaliciousNetwork {
            inner: network.spawn(),
            signer_public_key,
            malicious_dkg: malicious_dkg.clone(),
        };

        let ev = TxCoordinatorEventLoop {
            network: spawn_network(network),
            context: ctx.clone(),
            context_window: 10000,
            private_key,
            signing_round_max_duration: Duration::from_secs(3),
            bitcoin_presign_request_max_duration: Duration::from_secs(10),
            dkg_max_duration: Duration::from_secs(10),
            is_epoch3: true,
        };
        let counter = start_count.clone();
        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            ev.run().await
        });

        let ev = TxSignerEventLoop {
            network: spawn_network(network),
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

        let ev = RequestDeciderEventLoop {
            network: spawn_network(network),
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

        let block_observer = BlockObserver {
            context: ctx.clone(),
            bitcoin_block_source: clients.bitcoin_chain_tip_poller.clone(),
        };
        let counter = start_count.clone();
        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            block_observer.run().await
        });
    }

    while start_count.load(Ordering::SeqCst) < 4 * signer_set.num_signers {
        Sleep::for_millis(10).await;
    }

    signers
}

/// Build a deposit transaction for `depositor`, submit it to Bitcoin Core, and
/// register the matching request with Emily.
///
/// Returns the deposit outpoint so callers can later assert that a sweep
/// transaction spends it.
async fn submit_deposit<R>(
    rpc: &R,
    emily: &EmilyClient,
    submission: DepositSubmission<'_>,
) -> OutPoint
where
    R: RpcApi,
{
    let depositor_utxo = Utxo {
        txid: submission.fund_outpoint.txid,
        vout: submission.fund_outpoint.vout,
        script_pub_key: submission.depositor.address.script_pubkey(),
        descriptor: String::new(),
        amount: Amount::from_sat(submission.fund_amount),
        height: 0,
    };
    let (deposit_tx, deposit_request, deposit_info) = make_deposit_request_to(
        submission.depositor,
        submission.parameters.amount,
        depositor_utxo,
        submission.parameters.max_fee,
        submission.parameters.aggregate_key.into(),
        submission.parameters.recipient,
    );

    rpc.send_raw_transaction(&deposit_tx)
        .expect("cannot submit deposit tx");

    let emily_request = CreateDepositRequestBody {
        bitcoin_tx_output_index: deposit_request.outpoint.vout,
        bitcoin_txid: deposit_request.outpoint.txid.to_string(),
        deposit_script: deposit_request.deposit_script.to_hex_string(),
        reclaim_script: deposit_info.reclaim_script.to_hex_string(),
        transaction_hex: serialize_hex(&deposit_tx),
    };

    deposit_api::create_deposit(emily.config(), emily_request)
        .await
        .expect("cannot create emily deposit");

    deposit_request.outpoint
}

/// After the first DKG has been verified and rotated on-chain, a later
/// `dkg_min_bitcoin_block_height` forces a second DKG. If one signer stops
/// participating in the second DKG's verification round, the coordinator should
/// skip rotate-key submission but still complete the rest of the tenure, which
/// includes sweeping Emily's pending deposit.
#[test_log::test(tokio::test)]
async fn dkg_verification_failure_does_not_block_deposit_sweep() {
    let stack = TestContainersBuilder::start_stacks().await;
    let bitcoin = stack.bitcoin().await;
    let stacks = stack.stacks().await;

    let rpc = bitcoin.rpc();
    let faucet = &bitcoin.get_faucet();
    let stacks_client = stacks.get_client();

    let (emily_client, emily_tables) = new_emily_setup().await;
    let network = WanNetwork::default();

    faucet.generate_fee_data();
    let initial_tip = rpc.get_blockchain_info().unwrap();
    let dkg_min_bitcoin_block_height = BitcoinBlockHeight::from(initial_tip.blocks + 5);

    let malicious_dkg = MaliciousDkgControl {
        attack_active: Arc::new(AtomicBool::new(false)),
        malicious_signer: Arc::new(Mutex::new(None)),
        dropped_dkg_verification_responses: Arc::new(AtomicUsize::new(0)),
    };
    let signer_set = SignerSetConfig {
        num_signers: 3,
        signatures_required: 3,
        dkg_min_bitcoin_block_height,
    };
    let bitcoin_client = bitcoin.get_client();
    let bitcoin_chain_tip_poller = bitcoin.start_chain_tip_poller().await;

    let signers = start_signers(
        SignerClients {
            bitcoin_client: &bitcoin_client,
            bitcoin_chain_tip_poller: &bitcoin_chain_tip_poller,
            stacks_client: &stacks_client,
            emily_client: &emily_client,
            network: &network,
        },
        signer_set,
        malicious_dkg.clone(),
    )
    .await;

    let deployer = signers[0].config().signer.deployer.clone();

    let old_nonce = stacks_client.get_account(&deployer).await.unwrap().nonce;
    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;
    wait_for_new_nonce(&stacks_client, &deployer, old_nonce).await;

    let old_nonce = stacks_client.get_account(&deployer).await.unwrap().nonce;
    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;
    wait_for_new_nonce(&stacks_client, &deployer, old_nonce).await;

    let first_aggregate_key = stacks_client
        .get_current_signers_aggregate_key(&deployer)
        .await
        .unwrap()
        .expect("no aggregate key in contract after first rotate-key");

    let verified_dkg = signers[0]
        .storage
        .get_latest_verified_dkg_shares()
        .await
        .unwrap()
        .expect("first DKG should be verified before the attack starts");
    assert_eq!(verified_dkg.aggregate_key, first_aggregate_key);

    // The signers need an initial UTXO, and the depositor needs spendable
    // UTXOs, before Emily can hold pending deposits.
    faucet.send_to_script(10_000, first_aggregate_key.signers_script_pubkey());

    let depositor = Recipient::new(AddressType::P2tr);
    let deposit_parameters = DepositParameters {
        amount: 100_000,
        max_fee: 20_000,
        aggregate_key: first_aggregate_key,
        recipient: depositor.stacks_address().to_account_principal(),
    };

    let depositor_fund_amount = deposit_parameters.amount + BITCOIN_CORE_FALLBACK_FEE.to_sat();
    let first_depositor_fund_outpoint = faucet.send_to(depositor_fund_amount, &depositor.address);
    let second_depositor_fund_outpoint = faucet.send_to(depositor_fund_amount, &depositor.address);

    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;

    let first_deposit_outpoint = submit_deposit(
        rpc,
        &emily_client,
        DepositSubmission {
            depositor: &depositor,
            fund_outpoint: first_depositor_fund_outpoint,
            fund_amount: depositor_fund_amount,
            parameters: deposit_parameters.clone(),
        },
    )
    .await;

    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;

    let ctx = signers.first().unwrap();
    let txids = ctx.bitcoin_client.inner_client().get_raw_mempool().unwrap();
    assert!(
        txids.iter().any(|txid| {
            let tx = ctx.bitcoin_client.get_tx(txid).unwrap().unwrap();
            tx.tx
                .input
                .iter()
                .any(|input| input.previous_output == first_deposit_outpoint)
        }),
        "coordinator should sweep the first deposit before the malicious second DKG"
    );

    malicious_dkg.attack_active.store(true, Ordering::SeqCst);
    let second_deposit_outpoint = submit_deposit(
        rpc,
        &emily_client,
        DepositSubmission {
            depositor: &depositor,
            fund_outpoint: second_depositor_fund_outpoint,
            fund_amount: depositor_fund_amount,
            parameters: deposit_parameters,
        },
    )
    .await;

    let chain_tip = faucet.generate_block().into();
    let coordinator = coordinator_public_key(
        &chain_tip,
        &signers[0].config().signer.bootstrap_signing_set,
    )
    .expect("could not determine coordinator for second-DKG block");
    let target = signers[0]
        .config()
        .signer
        .bootstrap_signing_set
        .iter()
        .copied()
        .find(|public_key| *public_key != coordinator)
        .expect("there should be a non-coordinator signer to target");
    *malicious_dkg
        .malicious_signer
        .lock()
        .expect("malicious signer mutex poisoned") = Some(target);

    wait_for_tenure_completed(&signers, chain_tip).await;

    assert!(
        malicious_dkg
            .dropped_dkg_verification_responses
            .load(Ordering::SeqCst)
            > 0,
        "malicious signer should have withheld DKG verification participation"
    );

    let latest_dkg = signers[0]
        .storage
        .get_latest_encrypted_dkg_shares()
        .await
        .unwrap()
        .expect("second DKG should have written shares");
    assert_eq!(
        latest_dkg.started_at_bitcoin_block_height,
        dkg_min_bitcoin_block_height
    );
    assert_eq!(latest_dkg.dkg_shares_status, DkgSharesStatus::Unverified);
    assert_ne!(latest_dkg.aggregate_key, first_aggregate_key);
    assert_eq!(
        stacks_client
            .get_current_signers_aggregate_key(&deployer)
            .await
            .unwrap(),
        Some(first_aggregate_key),
        "failed DKG verification should not rotate the registry key"
    );

    let ctx = signers.first().unwrap();
    let txids = ctx.bitcoin_client.inner_client().get_raw_mempool().unwrap();
    let sweep_txid = txids
        .iter()
        .find(|txid| {
            let tx = ctx.bitcoin_client.get_tx(txid).unwrap().unwrap();
            tx.tx
                .input
                .iter()
                .any(|input| input.previous_output == second_deposit_outpoint)
        })
        .expect("coordinator should still broadcast a sweep for the pending deposit");

    tracing::info!(%sweep_txid, "found deposit sweep after failed DKG verification");

    for ctx in signers {
        testing::storage::drop_db(ctx.storage).await;
    }
    clean_emily_setup(emily_tables).await;
}
