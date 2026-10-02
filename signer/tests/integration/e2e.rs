use std::{
    num::{NonZero, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use bitcoin::{AddressType, Amount, consensus::encode::serialize_hex};
use bitcoincore_rpc::RpcApi as _;
use bitcoincore_rpc_json::Utxo;
use clarity::{
    types::chainstate::StacksAddress,
    vm::{
        Value,
        types::{PrincipalData, StacksAddressExtensions as _},
    },
};
use emily_client::{apis::deposit_api, models::CreateDepositRequestBody};
use futures::stream::StreamExt as _;
use lru::LruCache;
use more_asserts::{assert_ge, assert_le};
use rand::rngs::OsRng;
use sbtc::testing::{
    containers::TestContainersBuilder,
    regtest::{BITCOIN_CORE_FALLBACK_FEE, Recipient},
};
use secp256k1::Keypair;
use signer::{
    bitcoin::{
        BitcoinBlockHashStreamProvider as _, poller::BitcoinChainTipPoller, rpc::BitcoinCoreClient,
    },
    block_observer::BlockObserver,
    config::NetworkKind,
    context::Context as _,
    emily_client::EmilyClient,
    error::Error,
    keys::{PublicKey, SignerScriptPubKey as _},
    network::in_memory2::WanNetwork,
    request_decider::RequestDeciderEventLoop,
    stacks::{
        api::{ClarityName, StacksClient, StacksInteract as _},
        contracts::SmartContract,
        wallet::SignerWallet,
    },
    storage::{DbRead as _, DbWrite as _, model, postgres::PgStore},
    testing::{self, context::*},
    transaction_coordinator::TxCoordinatorEventLoop,
    transaction_signer::{STACKS_SIGN_REQUEST_LRU_SIZE, TxSignerEventLoop},
    util::{FutureExt as _, Sleep},
};

use crate::{
    containers::{BitcoinContainerExt as _, StacksContainerExt as _},
    setup::{clean_emily_setup, new_emily_setup},
    stacks::{fund_stx, wait_for_new_nonce, wait_for_stx_balance},
    transaction_coordinator::{IntegrationTestContext, wait_for_tenure_completed},
    utxo_construction::make_deposit_request_to,
};

#[allow(clippy::too_many_arguments)]
pub async fn start_signers(
    bitcoin_client: &BitcoinCoreClient,
    bitcoin_chain_tip_poller: &BitcoinChainTipPoller,
    stacks_client: &StacksClient,
    emily_client: &EmilyClient,
    network: &WanNetwork,
    num_signers: usize,
    signatures_required: u16,
    v2_signing_block_height: Option<u64>,
    bitcoin_processing_delay: Duration,
) -> Vec<(
    IntegrationTestContext<StacksClient>,
    PgStore,
    Keypair,
    signer::network::in_memory2::SignerNetwork,
)> {
    let keypairs = std::iter::repeat_with(|| Keypair::new_global(&mut OsRng))
        .take(num_signers)
        .collect::<Vec<_>>();

    let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public_key().into()).collect();
    let wallet =
        SignerWallet::new(&public_keys, signatures_required, NetworkKind::Testnet, 0).unwrap();

    let tx = fund_stx(
        stacks_client,
        &wallet.address().to_account_principal(),
        100 * 1_000_000,
    )
    .await;
    stacks_client
        .submit_tx(&tx)
        .await
        .expect("failed to send stacks transaction");

    wait_for_stx_balance(stacks_client, wallet.address(), |ustx| ustx > 0).await;

    // We fetch for a period longer than the poller interval so it sets the last
    // seen block to current chain tip and will not notify the signers yet.
    let mut stream = bitcoin_chain_tip_poller.get_block_hash_stream();
    let polling_fut = async {
        loop {
            let _ = stream.next().with_timeout(Duration::from_millis(100)).await;
        }
    };
    let _ = polling_fut.with_timeout(Duration::from_millis(500)).await;

    let mut signers = Vec::new();
    for kp in keypairs.iter() {
        let db = testing::storage::new_test_database().await;
        let ctx = TestContext::builder()
            .with_storage(db.clone())
            .with_bitcoin_client(bitcoin_client.clone())
            .with_emily_client(emily_client.clone())
            .with_stacks_client(stacks_client.clone())
            .modify_settings(|settings| {
                settings.signer.private_key = kp.secret_key().into();
                settings.signer.bootstrap_signing_set = public_keys.iter().cloned().collect();
                settings.signer.bootstrap_signatures_required = signatures_required;
                // Without an explicit height we keep the configured one;
                // overriding it with None would fall back to the testnet
                // activation height, which the regtest chain is already past.
                if let Some(height) = v2_signing_block_height {
                    settings.signer.v2_signing_block_height = Some(height.into());
                }
                settings.signer.bitcoin_processing_delay = bitcoin_processing_delay;
                settings.signer.deployer = wallet.address().clone();
                settings.signer.stacks_fees_max_ustx = NonZero::new(1_000_000).unwrap();
            })
            .build();

        let key_set = ctx.config().signer.v2_signer_key_set().unwrap();
        db.write_signer_key_set(&model::SignerKeySet::from(key_set))
            .await
            .unwrap();

        let network = network.connect(&ctx);

        signers.push((ctx, db, *kp, network));
    }

    let start_count = Arc::new(AtomicU8::new(0));
    for (ctx, _, kp, network) in signers.iter() {
        let ev = TxCoordinatorEventLoop {
            network: network.spawn(),
            context: ctx.clone(),
            context_window: 10000,
            private_key: kp.secret_key().into(),
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

        let ev = TxSignerEventLoop {
            network: network.spawn(),
            context: ctx.clone(),
            context_window: 10000,
            wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
            signer_private_key: kp.secret_key().into(),
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
            network: network.spawn(),
            context: ctx.clone(),
            context_window: 10000,
            deposit_decisions_retry_window: 1,
            withdrawal_decisions_retry_window: 1,
            blocklist_checker: Some(()),
            signer_private_key: kp.secret_key().into(),
        };
        let counter = start_count.clone();
        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            ev.run().await
        });

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

    while start_count.load(Ordering::SeqCst) < 4 * num_signers as u8 {
        Sleep::for_millis(10).await;
    }

    signers
}

async fn get_sbtc_balance(
    stacks_client: &StacksClient,
    deployer: &StacksAddress,
    address: &PrincipalData,
) -> Result<Amount, Error> {
    let result = stacks_client
        .call_read(
            deployer,
            SmartContract::SbtcToken,
            ClarityName("get-balance"),
            deployer,
            &[Value::Principal(address.clone())],
        )
        .await?;

    match result {
        Value::Response(response) => match *response.data {
            Value::UInt(total_supply) => Ok(Amount::from_sat(
                u64::try_from(total_supply)
                    .map_err(|_| Error::InvalidStacksResponse("invalid u64"))?,
            )),
            _ => Err(Error::InvalidStacksResponse(
                "expected a uint but got something else",
            )),
        },
        _ => Err(Error::InvalidStacksResponse(
            "expected a response but got something else",
        )),
    }
}

/// DKG remains available after the v2 signer-output activation height until
/// the separately configured DKG disable height is reached.
#[tokio::test]
async fn dkg_runs_after_v2_signing_activation() {
    let stack = TestContainersBuilder::start_stacks().await;
    let bitcoin = stack.bitcoin().await;
    let stacks = stack.stacks().await;

    let rpc = bitcoin.rpc();
    let faucet = bitcoin.get_faucet();
    let stacks_client = stacks.get_client();
    let (emily_client, emily_tables) = new_emily_setup().await;
    let network = WanNetwork::default();

    faucet.generate_fee_data();

    // V2 is already active when the signers observe their first new block.
    // DKG remains enabled because its disable height retains the u64::MAX
    // default.
    let v2_signing_block_height = rpc.get_block_count().unwrap();
    let bitcoin_chain_tip_poller = bitcoin.start_chain_tip_poller().await;
    let signers = start_signers(
        &bitcoin.get_client(),
        &bitcoin_chain_tip_poller,
        &stacks_client,
        &emily_client,
        &network,
        3,
        2,
        Some(v2_signing_block_height),
        Duration::from_millis(500),
    )
    .await;

    // Check that no shares have been written yet.
    for (_, db, _, _) in &signers {
        let shares = db
            .get_latest_encrypted_dkg_shares()
            .await
            .unwrap();

        assert!(shares.is_none());
    }

    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;

    let mut aggregate_key = None;
    for (context, db, _, _) in &signers {
        let bitcoin_chain_tip = db
            .get_bitcoin_canonical_chain_tip_ref()
            .await
            .unwrap()
            .expect("signer did not persist the Bitcoin chain tip");

        let is_v2_signing_active = context
            .config()
            .signer
            .is_v2_signing_active(bitcoin_chain_tip.block_height);
        let is_dkg_disabled = context
            .config()
            .signer
            .is_dkg_disabled(bitcoin_chain_tip.block_height);

        assert!(is_v2_signing_active);
        assert!(!is_dkg_disabled);

        let shares = db
            .get_latest_encrypted_dkg_shares()
            .await
            .unwrap()
            .expect("DKG should write shares after v2 signing activation");
        assert_eq!(shares.started_at_bitcoin_block_hash, chain_tip);

        // Check that all signers have the same aggregate key. Meaning that
        // DKG has been run.
        match aggregate_key {
            Some(expected) => assert_eq!(shares.aggregate_key, expected),
            None => aggregate_key = Some(shares.aggregate_key),
        }
    }

    for (_, db, _, _) in signers {
        testing::storage::drop_db(db).await;
    }
    clean_emily_setup(emily_tables).await;
}

/// End to end test for deposits: after the sBTC bootstrap a deposit is created
/// on Emily, the signers do their magic (with a controlled chain progression)
/// and we get sBTC minted.
#[test_log::test(tokio::test)]
async fn deposit() {
    let stack = TestContainersBuilder::start_stacks().await;
    let bitcoin = stack.bitcoin().await;
    let stacks = stack.stacks().await;

    let rpc = bitcoin.rpc();
    let faucet = &bitcoin.get_faucet();

    let stacks_client = stacks.get_client();

    let (emily_client, emily_tables) = new_emily_setup().await;

    let network = WanNetwork::default();

    // Ensure we can estimate fees
    faucet.generate_fee_data();

    let num_signers = 3;
    let signatures_required = 2;

    let bitcoin_chain_tip_poller = bitcoin.start_chain_tip_poller().await;

    let signers = start_signers(
        &bitcoin.get_client(),
        &bitcoin_chain_tip_poller,
        &stacks_client,
        &emily_client,
        &network,
        num_signers,
        signatures_required,
        None,
        Duration::from_millis(500),
    )
    .await;

    let deployer = signers[0].0.config().signer.deployer.clone();

    let old_nonce = stacks_client.get_account(&deployer).await.unwrap().nonce;
    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;
    wait_for_new_nonce(&stacks_client, &deployer, old_nonce).await;
    // Now we should have contracts deployed

    let old_nonce = stacks_client.get_account(&deployer).await.unwrap().nonce;
    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;
    wait_for_new_nonce(&stacks_client, &deployer, old_nonce).await;
    // Now we should have a key rotation

    let aggregate_key = stacks_client
        .get_current_signers_aggregate_key(&deployer)
        .await
        .unwrap()
        .expect("no aggregate key in contract")
        .v1_public_key()
        .expect("test requires a v1 signer key");

    // Signers require a donation
    faucet.send_to_script(10_000, aggregate_key.signers_script_pubkey());

    let depositor = Recipient::new(AddressType::P2tr);
    let deposit_amount = 100_000;

    let tx_fee = BITCOIN_CORE_FALLBACK_FEE.to_sat();
    let max_fee = deposit_amount / 2;
    let depositor_fund_amount = deposit_amount + tx_fee;
    let depositor_fund_outpoint = faucet.send_to(depositor_fund_amount, &depositor.address);

    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;
    // Now the funding txs should be confirmed, we can submit the deposit

    let recipient = depositor.stacks_address().to_account_principal();

    // Check that recipient doesn't hold any sBTC yet
    let sbtc_balance = get_sbtc_balance(&stacks_client, &deployer, &recipient)
        .await
        .expect("cannot get sbtc balance");
    assert_eq!(sbtc_balance, Amount::ZERO);

    let depositor_utxo = Utxo {
        txid: depositor_fund_outpoint.txid,
        vout: depositor_fund_outpoint.vout,
        script_pub_key: depositor.address.script_pubkey(),
        descriptor: "".to_string(),
        amount: Amount::from_sat(depositor_fund_amount),
        height: 0,
    };
    let (deposit_tx, deposit_request, deposit_info) = make_deposit_request_to(
        &depositor,
        deposit_amount,
        depositor_utxo.clone(),
        max_fee,
        aggregate_key.into(),
        recipient.clone(),
    );
    rpc.send_raw_transaction(&deposit_tx)
        .expect("cannot submit deposit tx");

    let emily_request = CreateDepositRequestBody {
        bitcoin_tx_output_index: deposit_request.outpoint.vout,
        bitcoin_txid: deposit_request.outpoint.txid.to_string(),
        deposit_script: deposit_request.deposit_script.to_hex_string(),
        reclaim_script: deposit_info.reclaim_script.to_hex_string(),
        transaction_hex: serialize_hex(&deposit_tx),
        recipient: None,
        max_fee: None,
    };

    deposit_api::create_deposit(emily_client.config(), emily_request.clone())
        .await
        .expect("cannot create emily deposit");

    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;
    // Now we should have a sweep transaction submitted

    let old_nonce = stacks_client.get_account(&deployer).await.unwrap().nonce;
    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;
    wait_for_new_nonce(&stacks_client, &deployer, old_nonce).await;
    // Now we should have sBTC minted

    let sbtc_balance = get_sbtc_balance(&stacks_client, &deployer, &recipient)
        .await
        .expect("cannot get sbtc balance");

    assert_ge!(sbtc_balance.to_sat(), deposit_amount - max_fee);
    assert_le!(sbtc_balance.to_sat(), deposit_amount);

    for (_, db, _, _) in signers {
        testing::storage::drop_db(db).await;
    }
    clean_emily_setup(emily_tables).await;
}
