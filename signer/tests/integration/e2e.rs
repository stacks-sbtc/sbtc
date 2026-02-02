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
    storage::postgres::PgStore,
    testing::{self, context::*},
    transaction_coordinator::TxCoordinatorEventLoop,
    transaction_signer::{STACKS_SIGN_REQUEST_LRU_SIZE, TxSignerEventLoop},
    util::{FutureExt as _, Sleep},
};

use crate::{
    containers::{BitcoinContainerExt as _, StacksContainerExt as _},
    setup::{clean_emily_setup, new_emily_setup},
    stacks::{fund_stx, wait_for_new_nonce, wait_for_stx_balance},
    transaction_coordinator::{IntegrationTestContext, wait_for_signers},
    utxo_construction::make_deposit_request_to,
};

async fn start_signers(
    bitcoin_client: &BitcoinCoreClient,
    bitcoin_chain_tip_poller: &BitcoinChainTipPoller,
    stacks_client: &StacksClient,
    emily_client: &EmilyClient,
    network: &WanNetwork,
    num_signers: usize,
    signatures_required: u16,
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
                settings.signer.bootstrap_signing_set = public_keys.iter().cloned().collect();
                settings.signer.bootstrap_signatures_required = signatures_required;
                settings.signer.bitcoin_processing_delay = Duration::from_millis(500);
                settings.signer.deployer = wallet.address().clone();
                settings.signer.stacks_fees_max_ustx = NonZero::new(1_000_000).unwrap();
            })
            .build();

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
    faucet.generate_fee_data_timed(Duration::from_secs(1)).await;

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
    )
    .await;

    let deployer = signers[0].0.config().signer.deployer.clone();

    let old_nonce = stacks_client.get_account(&deployer).await.unwrap().nonce;
    faucet.generate_block();
    wait_for_signers(&signers).await;
    wait_for_new_nonce(&stacks_client, &deployer, old_nonce).await;
    // Now we should have contracts deployed

    let old_nonce = stacks_client.get_account(&deployer).await.unwrap().nonce;
    faucet.generate_block();
    wait_for_signers(&signers).await;
    wait_for_new_nonce(&stacks_client, &deployer, old_nonce).await;
    // Now we should have a key rotation

    let aggregate_key = stacks_client
        .get_current_signers_aggregate_key(&deployer)
        .await
        .unwrap()
        .expect("no aggregate key in contract");

    // Signers require a donation
    faucet.send_to_script(10_000, aggregate_key.signers_script_pubkey());

    let depositor = Recipient::new(AddressType::P2tr);
    let deposit_amount = 100_000;

    let tx_fee = BITCOIN_CORE_FALLBACK_FEE.to_sat();
    let max_fee = deposit_amount / 2;
    let depositor_fund_amount = deposit_amount + tx_fee;
    let depositor_fund_outpoint = faucet.send_to(depositor_fund_amount, &depositor.address);

    faucet.generate_block();
    wait_for_signers(&signers).await;
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
    };

    deposit_api::create_deposit(emily_client.config(), emily_request.clone())
        .await
        .expect("cannot create emily deposit");

    faucet.generate_block();
    wait_for_signers(&signers).await;
    // Now we should have a sweep transaction submitted

    let old_nonce = stacks_client.get_account(&deployer).await.unwrap().nonce;
    faucet.generate_block();
    wait_for_signers(&signers).await;
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
