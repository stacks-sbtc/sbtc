use emily_client::apis::deposit_api;
use rand::RngCore;
use sbtc::testing::regtest::Faucet;
use signer::emily_client::EmilyClient;
use signer::storage::model;
use signer::testing::TestUtilityError;
use signer::testing::get_rng;
use std::borrow::Borrow;
use std::collections::HashSet;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use test_case::test_case;
use url::Url;

use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use bitcoin::XOnlyPublicKey;
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoincore_rpc::RpcApi as _;
use bitvec::array::BitArray;
use clarity::vm::types::PrincipalData;
use fake::Fake;
use rand::Rng as _;
use rand::distributions::Uniform;
use rand::rngs::OsRng;
use sbtc::deposits::CreateDepositRequest;
use sbtc::deposits::DepositInfo;
use sbtc::deposits::DepositScriptInputs;
use sbtc::deposits::ReclaimScriptInputs;
use signer::DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX;
use signer::bitcoin::rpc::BitcoinCoreClient;
use signer::bitcoin::utxo::DepositRequest;
use signer::bitcoin::utxo::SbtcRequests;
use signer::bitcoin::utxo::SignerBtcState;
use signer::bitcoin::utxo::SignerUtxo;
use signer::bitcoin::utxo::TxDeconstructor;
use signer::bitcoin::utxo::WithdrawalRequest;
use signer::config::Settings;
use signer::context::SbtcLimits;
use signer::keys::SignerScriptPubKey;
use signer::storage::model::TaprootScriptHash;
use stacks_common::types::chainstate::StacksAddress;

use regtest::Recipient;
use sbtc::testing::AsSatoshis;
use sbtc::testing::regtest;
use sbtc::testing::regtest::AsUtxo;

pub static REQUEST_IDS: AtomicU64 = AtomicU64::new(0);

pub fn generate_withdrawal() -> (WithdrawalRequest, Recipient) {
    let amount = OsRng.sample(Uniform::new(200_000, 250_000));
    make_withdrawal(amount, amount / 2)
}

pub fn make_withdrawal(amount: u64, max_fee: u64) -> (WithdrawalRequest, Recipient) {
    let recipient = Recipient::new(AddressType::P2tr);

    let req = WithdrawalRequest {
        amount,
        max_fee,
        script_pubkey: recipient.script_pubkey.clone().into(),
        signer_bitmap: BitArray::ZERO,
        request_id: REQUEST_IDS.fetch_add(1, Ordering::Relaxed),
        txid: fake::Faker.fake_with_rng(&mut OsRng),
        block_hash: fake::Faker.fake_with_rng(&mut OsRng),
    };

    (req, recipient)
}

/// Creates a single deposit request and the corresponding Bitcoin transaction,
/// submitting them to Emily and the Bitcoin node respectively.
pub fn make_deposit_request<U>(
    depositor: &Recipient,
    amount: u64,
    utxo: U,
    max_fee: u64,
    signers_public_key: XOnlyPublicKey,
) -> (Transaction, DepositRequest, DepositInfo)
where
    U: AsUtxo,
{
    let fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();
    let deposit_inputs = DepositScriptInputs {
        signers_public_key,
        max_fee,
        recipient: PrincipalData::from(StacksAddress::burn_address(false)),
    };
    let reclaim_inputs = ReclaimScriptInputs::try_new(50, ScriptBuf::new()).unwrap();

    let deposit_script = deposit_inputs.deposit_script();
    let reclaim_script = reclaim_inputs.reclaim_script();

    let mut deposit_tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(utxo.txid(), utxo.vout()),
            sequence: Sequence::ZERO,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: sbtc::deposits::to_script_pubkey(
                    deposit_script.clone(),
                    reclaim_script.clone(),
                ),
            },
            TxOut {
                value: utxo.amount() - Amount::from_sat(amount + fee),
                script_pubkey: depositor.address.script_pubkey(),
            },
        ],
    };

    regtest::p2tr_sign_transaction(&mut deposit_tx, 0, &[utxo], &depositor.keypair);

    let create_req = CreateDepositRequest {
        outpoint: OutPoint::new(deposit_tx.compute_txid(), 0),
        deposit_script,
        reclaim_script,
    };

    let dep = create_req.validate_tx(&deposit_tx, false).unwrap();

    let req = DepositRequest {
        outpoint: dep.outpoint,
        max_fee: dep.max_fee,
        signer_bitmap: BitArray::ZERO,
        amount: dep.amount,
        deposit_script: dep.deposit_script.clone(),
        reclaim_script: dep.reclaim_script.clone(),
        reclaim_script_hash: Some(TaprootScriptHash::from(&dep.reclaim_script)),
        signers_public_key: dep.signers_public_key,
    };
    (deposit_tx, req, dep)
}

/// Creates multiple deposit requests, one for each amount in the `amounts` slice.
/// The deposit requests are submitted to Emily, and a single Bitcoin transaction
/// containing all deposits is submitted to the Bitcoin node.
pub fn make_deposit_requests<U>(
    depositor: &Recipient,
    amounts: &[u64],
    utxo: U,
    max_fee: u64,
    signers_public_key: bitcoin::XOnlyPublicKey,
) -> (Transaction, Vec<DepositRequest>)
where
    U: regtest::AsUtxo,
{
    let deposit_inputs = DepositScriptInputs {
        signers_public_key,
        max_fee,
        recipient: PrincipalData::from(StacksAddress::burn_address(false)),
    };
    let reclaim_inputs = ReclaimScriptInputs::try_new(50, bitcoin::ScriptBuf::new()).unwrap();

    let deposit_script = deposit_inputs.deposit_script();
    let reclaim_script = reclaim_inputs.reclaim_script();

    let mut outputs = vec![];
    for amount in amounts {
        outputs.push(bitcoin::TxOut {
            value: Amount::from_sat(*amount),
            script_pubkey: sbtc::deposits::to_script_pubkey(
                deposit_script.clone(),
                reclaim_script.clone(),
            ),
        })
    }

    let fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();
    outputs.push(bitcoin::TxOut {
        value: utxo.amount() - Amount::from_sat(amounts.iter().sum::<u64>() + fee),
        script_pubkey: depositor.address.script_pubkey(),
    });

    let mut deposit_tx = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::new(utxo.txid(), utxo.vout()),
            sequence: bitcoin::Sequence::ZERO,
            script_sig: bitcoin::ScriptBuf::new(),
            witness: bitcoin::Witness::new(),
        }],
        output: outputs,
    };

    regtest::p2tr_sign_transaction(&mut deposit_tx, 0, &[utxo], &depositor.keypair);

    let mut requests = vec![];
    for (index, amount) in amounts.iter().enumerate() {
        let req = CreateDepositRequest {
            outpoint: bitcoin::OutPoint::new(deposit_tx.compute_txid(), index as u32),
            deposit_script: deposit_script.clone(),
            reclaim_script: reclaim_script.clone(),
        };

        requests.push(DepositRequest {
            outpoint: req.outpoint,
            max_fee,
            signer_bitmap: BitArray::ZERO,
            amount: *amount,
            deposit_script: deposit_script.clone(),
            reclaim_script: reclaim_script.clone(),
            reclaim_script_hash: Some(model::TaprootScriptHash::from(&reclaim_script)),
            signers_public_key,
        });
    }

    (deposit_tx, requests)
}

/// A simple helper struct representing a deposit/withdrawal request amount and
/// max fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReqAmounts<TxAmt, FeeAmt> {
    pub amount: TxAmt,
    pub max_fee: FeeAmt,
}

/// Provides a constructor for [`ReqAmounts`] with the specified amount and max
/// fee which must implement [`AsSatoshis`], allowing amounts to be provided as
/// e.g. `u64`, `bitcoin::Amount`, etc.
impl<TxAmt, FeeAmt> ReqAmounts<TxAmt, FeeAmt>
where
    TxAmt: AsSatoshis,
    FeeAmt: AsSatoshis,
{
    /// Creates a new `ReqAmounts` instance with the specified amount and max fee.
    pub fn new(amount: TxAmt, max_fee: FeeAmt) -> Self {
        Self { amount, max_fee }
    }
}

/// Represents a submitted deposit.
pub struct SubmittedDeposit {
    pub tx: Transaction,
    pub request: DepositRequest,
    pub info: DepositInfo,
}

/// A helper struct for submitting deposits to the Bitcoin network and Emily from
/// a given depositor.
///
/// This helper uses typestate to provide differing functionality based on the
/// types of `Bitcoin`, `Emily`, and `Depositor` used.
pub struct DepositHelper<'a, Bitcoin, Emily = (), Depositor = ()> {
    bitcoin: &'a Bitcoin,
    emily: &'a Emily,
    depositor: Depositor,
}

/// Provides constructors for creating a `DepositHelper` instance with types
/// which implement `Borrow<bitcoincore_rpc::Client>` and a [`Recipient`].
impl<'a, Bitcoin> DepositHelper<'a, Bitcoin, (), Recipient>
where
    Bitcoin: Borrow<bitcoincore_rpc::Client>,
{
    /// Creates a new `DepositHelper` instance with the specified Bitcoin client and depositor.
    pub fn with_depositor(bitcoin: &'a Bitcoin, depositor: Recipient) -> Self {
        Self { bitcoin, emily: &(), depositor }
    }

    /// Creates a new `DepositHelper` instance with a new depositor generated using the provided RNG.
    pub fn with_new_depositor<R>(bitcoin: &'a Bitcoin, rng: &mut R) -> Self
    where
        R: RngCore,
    {
        let depositor = Recipient::new_with_rng(AddressType::P2tr, rng);
        Self { bitcoin, emily: &(), depositor }
    }
}

/// Provides specialized functionality for `DepositHelper` when:
/// * the `Bitcoin` type is a [`Faucet`],
/// * the `Emily` type is any type,
/// * and the `depositor` is a type that implements `Borrow<bitcoin::Address>`.
impl<Emily, Depositor> DepositHelper<'_, Faucet, Emily, Depositor>
where
    Depositor: Borrow<bitcoin::Address>,
{
    /// Funds the inner `Depositor` from the faucet with the specified amount.
    pub fn fund<Amt>(&self, amount: Amt)
    where
        Amt: AsSatoshis,
    {
        self.bitcoin
            .send_to(amount.as_satoshis(), self.depositor.borrow());
    }
}

/// Provides specialized functionality for `DepositHelper` when:
/// * the `Bitcoin` and `Depositor` types are any type,
/// * and the `Emily` type is unset/default (`()`).
impl<'a, Bitcoin, Depositor> DepositHelper<'a, Bitcoin, (), Depositor> {
    /// Sets the Emily client for this `DepositHelper`, enabling deposit submission to Emily.
    /// Consumes this instance and returns a new one with the Emily client set.
    pub fn with_emily_client(
        self,
        emily: &'a EmilyClient,
    ) -> DepositHelper<'a, Bitcoin, EmilyClient, Depositor> {
        DepositHelper {
            bitcoin: self.bitcoin,
            emily,
            depositor: self.depositor,
        }
    }
}

/// Provides specialized functionality for `DepositHelper` when:
/// * the `Bitcoin` and `Emily` types are any type,
/// * the `Depositor` type implements `Borrow<bitcoin::Address>`, for example a [`bitcoin::Address`] or [`Recipient`].
impl<Bitcoin, Emily, Depositor> DepositHelper<'_, Bitcoin, Emily, Depositor>
where
    Depositor: Borrow<bitcoin::Address>,
{
    /// Gets the [`bitcoin::Address`] for the inner [`Recipient`] (depositor).
    pub fn address(&self) -> &bitcoin::Address {
        self.depositor.borrow()
    }

    /// Funds the inner [`Recipient`] from the faucet with the specified amount.
    /// This does not implicitly create a bitcoin block, so the funding is not
    /// immediately visible on the blockchain. You need to generate a block to
    /// confirm the funding and thus make the new UTXO available.
    pub fn fund_from<Amt>(&self, faucet: &Faucet, amount: Amt)
    where
        Amt: AsSatoshis,
    {
        faucet.send_to(amount.as_satoshis(), self.address());
    }
}

/// Provides specialized functionality for `DepositHelper` when:
/// * the `Bitcoin` type implements `Borrow<bitcoincore_rpc::Client>`,
/// * the `Emily` type is any type,
/// * and the `depositor` is a [`Recipient`].
impl<Bitcoin, Emily> DepositHelper<'_, Bitcoin, Emily, Recipient>
where
    Bitcoin: Borrow<bitcoincore_rpc::Client>,
{
    /// Returns a reference to the inner [`Recipient`] (depositor).
    pub fn depositor(&self) -> &Recipient {
        &self.depositor
    }

    /// Gets the balance of the inner [`Recipient`] (depositor) as a [`bitcoin::Amount`].
    pub fn get_balance(&self) -> Amount {
        self.depositor.get_balance(self.bitcoin.borrow())
    }

    /// Finds a suitable UTXO for the depositor that covers the specified amount.
    fn find_suitable_utxo<Amt>(&self, amount: Amt) -> Result<impl AsUtxo, TestUtilityError>
    where
        Amt: AsSatoshis,
    {
        let amount_sats = amount.as_satoshis();

        // Get the UTXOs for the depositor and filter them to find one that covers the amount.
        // If no suitable UTXO is found, return an error.
        let utxo = self
            .depositor
            .get_utxos(self.bitcoin.borrow(), Some(amount_sats))
            .pop()
            .ok_or_else(|| {
                format!(
                    "No UTXO found for depositor '{address}' covering {amount_sats} satoshis",
                    address = self.depositor.address
                )
            })?;

        Ok(utxo)
    }

    /// Creates and submits a deposit transaction to the Bitcoin node, returning
    /// a [`SubmittedDeposit`] containing the deposit request and Bitcoin
    /// transaction,
    pub fn submit_deposit_transaction<TxAmt, FeeAmt>(
        &self,
        amount: TxAmt,
        max_fee: FeeAmt,
        aggregate_key: impl Into<XOnlyPublicKey>,
    ) -> Result<SubmittedDeposit, TestUtilityError>
    where
        TxAmt: AsSatoshis,
        FeeAmt: AsSatoshis,
    {
        let aggregate_key = aggregate_key.into();
        let amount_sats = amount.as_satoshis();
        let max_fee_sats = max_fee.as_satoshis();
        let total_sats = amount_sats + max_fee_sats;

        let utxo = self.find_suitable_utxo(total_sats)?;

        let (tx, request, info) = make_deposit_request(
            &self.depositor,
            amount_sats,
            utxo,
            max_fee_sats,
            aggregate_key,
        );

        self.bitcoin
            .borrow()
            .send_raw_transaction(&tx)
            .map_err(|e| format!("Failed to submit raw transaction to Bitcoin node: {e}"))?;

        Ok(SubmittedDeposit { tx, request, info })
    }
}

/// Provides specialized functionality for `DepositHelper` when:
/// * the `Bitcoin` type implements `Borrow<Client>`,
/// * the Emily client is a concrete [`EmilyClient`],
/// * and the recipient is a [`Recipient`].
impl<Bitcoin> DepositHelper<'_, Bitcoin, EmilyClient, Recipient>
where
    Bitcoin: Borrow<bitcoincore_rpc::Client>,
{
    /// For each provided [`DepReq`], creates a deposit request and bitcoin transaction,
    /// submitting them to Emily and the Bitcoin node respectively.
    #[allow(unused)] // TODO: Remove when other tests use this
    pub async fn submit_deposits<I, K, TxAmt, FeeAmt>(
        &self,
        requests: I,
        aggregate_key: K,
    ) -> Result<Vec<SubmittedDeposit>, TestUtilityError>
    where
        K: Into<XOnlyPublicKey>,
        TxAmt: AsSatoshis,
        FeeAmt: AsSatoshis,
        I: IntoIterator<Item = ReqAmounts<TxAmt, FeeAmt>>,
    {
        let aggregate_key = aggregate_key.into();
        let mut submitted_deposits = Vec::new();

        for req in requests {
            let deposit = self.submit_deposit(req, aggregate_key).await?;
            submitted_deposits.push(deposit);
        }

        Ok(submitted_deposits)
    }

    /// Creates a deposit request and bitcoin transaction containing the deposit,
    /// submitting them to Emily and the Bitcoin node respectively.
    pub async fn submit_deposit<K, TxAmt, FeeAmt>(
        &self,
        req: ReqAmounts<TxAmt, FeeAmt>,
        aggregate_key: K,
    ) -> Result<SubmittedDeposit, TestUtilityError>
    where
        K: Into<XOnlyPublicKey>,
        TxAmt: AsSatoshis,
        FeeAmt: AsSatoshis,
    {
        let deposit = self.submit_deposit_transaction(req.amount, req.max_fee, aggregate_key)?;

        let emily_request_body = deposit.request.as_emily_request(&deposit.tx);
        deposit_api::create_deposit(self.emily.config(), emily_request_body)
            .await
            .map_err(|e| format!("Failed to submit deposit to Emily: {e}"))?;

        Ok(deposit)
    }
}

/// Allows `DepositHelper` to be borrowed as a `bitcoin::Address` if the `depositor`
/// field implements `Borrow<bitcoin::Address>` (e.g. a [`Recipient`]).
impl<Bitcoin, Emily, Addr> Borrow<bitcoin::Address> for &DepositHelper<'_, Bitcoin, Emily, Addr>
where
    Addr: Borrow<bitcoin::Address>,
{
    fn borrow(&self) -> &bitcoin::Address {
        self.depositor.borrow()
    }
}

/// Verifies that the `DepositHelper` correctly creates, submits, and reports a deposit.
#[tokio::test]
async fn deposit_helper_submits_deposit_successfully() {
    let rng = &mut get_rng();
    let (rpc, faucet) = regtest::initialize_blockchain();

    let emily_client = EmilyClient::try_new(
        &Url::parse("http://testApiKey@localhost:3031").unwrap(),
        Duration::from_secs(1),
        None,
    )
    .expect("Failed to create EmilyClient");

    let signer_for_agg_key = Recipient::new(AddressType::P2tr);
    let depositor = DepositHelper::with_new_depositor(faucet, rng).with_emily_client(&emily_client);

    let initial_depositor_balance_sats = 100_000_000; // 1 BTC
    depositor.fund(initial_depositor_balance_sats);

    // Confirm the funding transactions
    faucet.generate_block();

    assert_eq!(
        depositor.get_balance().to_sat(),
        initial_depositor_balance_sats,
        "Initial depositor balance mismatch"
    );
    // Define deposit parameters
    let deposit_amount_sats = 5_000_000; // 0.05 BTC
    let sbtc_max_fee_sats = 10_000; // 0.0001 BTC
    let aggregate_key = signer_for_agg_key.keypair.x_only_public_key().0;

    // Call submit_deposit
    let submitted_deposit = depositor
        .submit_deposit(
            ReqAmounts::new(deposit_amount_sats, sbtc_max_fee_sats),
            aggregate_key,
        )
        .await
        .expect("Failed to submit deposit");

    // Verify mempool contents before mining
    let mempool = rpc.get_raw_mempool().expect("Failed to get mempool");
    assert_eq!(
        mempool.len(),
        1,
        "Mempool should contain exactly one transaction (the deposit)"
    );
    assert_eq!(
        mempool[0],
        submitted_deposit.tx.compute_txid(),
        "Transaction ID in mempool does not match submitted deposit transaction ID"
    );

    // Mine a block to confirm the Bitcoin transaction
    faucet.generate_block();

    // Check depositor's balance
    // The Bitcoin transaction fee is handled by `make_deposit_request` using `regtest::BITCOIN_CORE_FALLBACK_FEE`.
    let bitcoin_tx_fee_sats = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();
    let expected_depositor_balance_sats =
        initial_depositor_balance_sats - deposit_amount_sats - bitcoin_tx_fee_sats;
    let final_depositor_balance_sats = depositor.get_balance().to_sat();

    assert_eq!(
        final_depositor_balance_sats, expected_depositor_balance_sats,
        "Depositor balance mismatch after deposit. Expected {}, got {}",
        expected_depositor_balance_sats, final_depositor_balance_sats
    );

    // Verify returned data (basic checks)
    assert_eq!(
        submitted_deposit.tx.output[0].value.to_sat(),
        deposit_amount_sats,
        "Deposit transaction output amount mismatch"
    );
    assert_eq!(
        submitted_deposit.request.amount, deposit_amount_sats,
        "DepositRequest amount mismatch"
    );
    assert_eq!(
        submitted_deposit.request.max_fee, sbtc_max_fee_sats,
        "DepositRequest max_fee mismatch"
    );
    assert_eq!(
        submitted_deposit.request.signers_public_key, aggregate_key,
        "DepositRequest signers_public_key mismatch"
    );

    assert_eq!(
        submitted_deposit.info.amount, deposit_amount_sats,
        "DepositInfo amount mismatch"
    );
    assert_eq!(
        submitted_deposit.info.max_fee, sbtc_max_fee_sats,
        "DepositInfo max_fee mismatch"
    );
    assert_eq!(
        submitted_deposit.info.signers_public_key, aggregate_key,
        "DepositInfo signers_public_key mismatch"
    );
    assert_eq!(
        submitted_deposit.info.outpoint.txid,
        submitted_deposit.tx.compute_txid(),
        "DepositInfo outpoint txid mismatch"
    );
    assert_eq!(
        submitted_deposit.info.outpoint.vout, 0,
        "DepositInfo outpoint vout mismatch (expected 0)"
    );
}

/// This test just checks that many of the methods on the Recipient struct
/// work as advertised.
#[test]
fn helper_struct_methods_work() {
    let (rpc, faucet) = regtest::initialize_blockchain();
    let signer = Recipient::new(AddressType::P2tr);

    // Newly created "recipients" do not have any UTXOs associated with
    // their address.
    let balance = signer.get_balance(rpc);
    assert_eq!(balance.to_sat(), 0);

    // Okay now we send coins to an address from the one address that
    // coins have been mined to.
    faucet.send_to(500_000, &signer.address);
    faucet.generate_blocks(1);

    // Now the balance should be updated, and the amount sent should be
    // adjusted too.
    let balance = signer.get_balance(rpc);
    assert_eq!(balance.to_sat(), 500_000);

    // Now let's have a third address get some coin from our signer address.
    let withdrawal_recipient = Recipient::new(AddressType::P2wpkh);

    // Again, this third address doesn't have any UTXOs associated with it.
    let balance = withdrawal_recipient.get_balance(rpc);
    assert_eq!(balance.to_sat(), 0);

    // Now we check that get_utxos do what we want
    let mut utxos = signer.get_utxos(rpc, None);
    assert_eq!(utxos.len(), 1);
    let utxo = utxos.pop().unwrap();

    assert_eq!(utxo.amount.to_sat(), 500_000);
}

/// Check that deposits, when sent with the expected format, are
/// spent using the transactions generated in the utxo module.
#[test]
fn deposits_add_to_controlled_amounts() {
    let rng = &mut get_rng();
    let (rpc, faucet) = regtest::initialize_blockchain();
    let fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();

    let signer = Recipient::new(AddressType::P2tr);
    let depositor = DepositHelper::with_new_depositor(faucet, rng);
    let signers_public_key = signer.keypair.x_only_public_key().0;

    // Start off with some initial UTXOs to work with.
    faucet.send_to(100_000_000, &signer.address);
    depositor.fund(50_000_000);
    faucet.generate_block();

    assert_eq!(signer.get_balance(rpc).to_sat(), 100_000_000);
    assert_eq!(depositor.get_balance().to_sat(), 50_000_000);

    // Now lets make a deposit transaction and submit it
    let deposit_amount = 25_000_000;
    let max_fee = deposit_amount / 2;
    let deposit = depositor
        .submit_deposit_transaction(deposit_amount, max_fee, signers_public_key)
        .unwrap();
    faucet.generate_block();

    // The depositor's balance should be updated now.
    let depositor_balance = depositor.get_balance();
    assert_eq!(depositor_balance.to_sat(), 50_000_000 - 25_000_000 - fee);
    // We deposited the transaction to the signer, but it's not clear to the
    // wallet tracking the signer's address that the deposit is associated
    // with the signer since it's hidden within the merkle tree.
    assert_eq!(signer.get_balance(rpc).to_sat(), 100_000_000);

    // Okay now we try to peg-in the deposit by making a transaction. Let's
    // start by getting the signer's sole UTXO.
    let signer_utxo = signer.get_utxos(rpc, None).pop().unwrap();

    // Now build the struct with the outstanding peg-in and peg-out requests.
    let requests = SbtcRequests {
        deposits: vec![deposit.request],
        withdrawals: Vec::new(),
        signer_state: SignerBtcState {
            utxo: SignerUtxo {
                outpoint: OutPoint::new(signer_utxo.txid, signer_utxo.vout),
                amount: signer_utxo.amount.to_sat(),
                public_key: signers_public_key,
            },
            fee_rate: 10.0,
            public_key: signers_public_key,
            last_fees: None,
            magic_bytes: [b'T', b'3'],
        },
        accept_threshold: 4,
        num_signers: 7,
        sbtc_limits: SbtcLimits::unlimited(),
        max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
    };

    // There should only be one transaction here since there is only one
    // deposit request and no withdrawal requests.
    let mut transactions = requests.construct_transactions().unwrap();
    assert_eq!(transactions.len(), 1);
    let mut unsigned = transactions.pop().unwrap();

    // Add the signature and/or other required information to the witness data.
    signer::testing::set_witness_data(&mut unsigned, signer.keypair);

    // The moment of truth, does the network accept the transaction?
    rpc.send_raw_transaction(&unsigned.tx).unwrap();
    faucet.generate_block();

    // The signer's balance should now reflect the deposit.
    let signers_balance = signer.get_balance(rpc);

    more_asserts::assert_gt!(signers_balance.to_sat(), 124_000_000);
    more_asserts::assert_lt!(signers_balance.to_sat(), 125_000_000);
}

#[test]
fn withdrawals_reduce_to_signers_amounts() {
    const FEE_RATE: f64 = 10.0;

    let (rpc, faucet) = regtest::initialize_blockchain();
    let fallback_fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();
    let signer = Recipient::new(AddressType::P2tr);
    let signers_public_key = signer.keypair.x_only_public_key().0;

    // Start off with some initial UTXOs to work with.
    faucet.send_to(100_000_000, &signer.address);
    faucet.generate_block();

    assert_eq!(signer.get_balance(rpc).to_sat(), 100_000_000);

    // Now lets make a withdrawal request. This recipient shouldn't
    // have any coins to their name.
    let (withdrawal_request, recipient) = generate_withdrawal();
    assert_eq!(recipient.get_balance(rpc).to_sat(), 0);

    // Okay now we try to peg-out the withdrawal by making a transaction. Let's
    // start by getting the signer's sole UTXO.
    let signer_utxo = signer.get_utxos(rpc, None).pop().unwrap();

    // Now build the struct with the outstanding peg-in and peg-out requests.
    let requests = SbtcRequests {
        deposits: Vec::new(),
        withdrawals: vec![withdrawal_request.clone()],
        signer_state: SignerBtcState {
            utxo: SignerUtxo {
                outpoint: OutPoint::new(signer_utxo.txid, signer_utxo.vout),
                amount: signer_utxo.amount.to_sat(),
                public_key: signers_public_key,
            },
            fee_rate: FEE_RATE,
            public_key: signers_public_key,
            last_fees: None,
            magic_bytes: [b'T', b'3'],
        },
        accept_threshold: 4,
        num_signers: 7,
        sbtc_limits: SbtcLimits::unlimited(),
        max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
    };

    // There should only be one transaction here since there is only one
    // withdrawal request and no deposit requests.
    let mut transactions = requests.construct_transactions().unwrap();
    assert_eq!(transactions.len(), 1);
    let mut unsigned = transactions.pop().unwrap();

    // Add the signature and/or other required information to the witness data.
    signer::testing::set_witness_data(&mut unsigned, signer.keypair);

    // Ship it
    rpc.send_raw_transaction(&unsigned.tx).unwrap();
    faucet.generate_blocks(1);

    // The signer's balance should now reflect the withdrawal.
    // Note that the signer started with 1 BTC.
    let signers_balance = signer.get_balance(rpc).to_sat();

    assert_eq!(
        signers_balance,
        100_000_000 - withdrawal_request.amount - unsigned.tx_fee
    );

    let withdrawal_fee = unsigned.input_amounts() - unsigned.output_amounts();
    let recipient_balance = recipient.get_balance(rpc).to_sat();
    assert_eq!(recipient_balance, withdrawal_request.amount);

    // Let's check that we have the right fee rate too.
    let fee_rate = withdrawal_fee as f64 / unsigned.tx.vsize() as f64;
    more_asserts::assert_ge!(fee_rate, FEE_RATE);
    more_asserts::assert_lt!(fee_rate, FEE_RATE + 1.0);

    // Now we construct another transaction where the withdrawing
    // recipient pays to someone else.
    let another_recipient = Recipient::new(AddressType::P2wpkh);
    let another_recipient_balance = another_recipient.get_balance(rpc).to_sat();
    assert_eq!(another_recipient_balance, 0);

    // Get the UTXO that the signer sent to the withdrawing user.
    let withdrawal_utxo = recipient.get_utxos(rpc, None).pop().unwrap();
    let mut tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(withdrawal_utxo.txid, withdrawal_utxo.vout),
            sequence: Sequence::ZERO,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: another_recipient.address.script_pubkey(),
            },
            TxOut {
                value: withdrawal_utxo.amount() - Amount::from_sat(50_000 + fallback_fee),
                script_pubkey: recipient.address.script_pubkey(),
            },
        ],
    };
    regtest::p2tr_sign_transaction(&mut tx, 0, &[withdrawal_utxo], &recipient.keypair);

    // Ship it
    rpc.send_raw_transaction(&tx).unwrap();
    faucet.generate_block();

    // Let's make sure their ending balances are correct. We start with the
    // Withdrawal recipient.
    let recipient_balance = recipient.get_balance(rpc).to_sat();
    assert_eq!(
        recipient_balance,
        withdrawal_request.amount - 50_000 - fallback_fee
    );

    // And what about the person that they just sent coins to?
    let another_recipient_balance = another_recipient.get_balance(rpc).to_sat();
    assert_eq!(another_recipient_balance, 50_000);
}

#[test_case(0; "no withdrawals")]
#[test_case(1; "single withdrawals")]
#[test_case(11; "multiple withdrawals")]
fn parse_withdrawal_ids(withdrawal_numbers: u64) {
    const FEE_RATE: f64 = 10.0;
    let rng = &mut get_rng();

    let (rpc, faucet) = regtest::initialize_blockchain();
    let signer = Recipient::new(AddressType::P2tr);
    let signers_public_key = signer.keypair.x_only_public_key().0;
    let depositor = DepositHelper::with_new_depositor(faucet, rng);

    // Start off with some initial UTXOs to work with.
    let signers_funds = 100_000_000 * (1 + withdrawal_numbers);
    faucet.send_to(signers_funds, &signer.address);
    depositor.fund(50_000_000);
    faucet.generate_block();

    // Now lets make a deposit transaction and submit it. We do this to ensure
    // we can create a transaction with zero withdrawals
    let deposit_amount = 25_000_000;
    let max_fee = deposit_amount / 2;
    let deposit = depositor
        .submit_deposit_transaction(deposit_amount, max_fee, signers_public_key)
        .unwrap();
    faucet.generate_block();

    let signer_utxo = signer.get_utxos(rpc, None).pop().unwrap();

    // Now lets make some withdrawal requests
    let mut withdrawal_requests = vec![];
    for i in 0..withdrawal_numbers {
        let (withdrawal_request, _) = generate_withdrawal();
        withdrawal_requests.push(withdrawal_request);
        // Add some gaps in the request ids
        if i % 2 == 1 {
            REQUEST_IDS.fetch_add(i, Ordering::Relaxed);
        }
    }

    // Now build the struct with the outstanding peg-in and peg-out requests.
    let requests = SbtcRequests {
        deposits: vec![deposit.request],
        withdrawals: withdrawal_requests.clone(),
        signer_state: SignerBtcState {
            utxo: SignerUtxo {
                outpoint: OutPoint::new(signer_utxo.txid, signer_utxo.vout),
                amount: signer_utxo.amount.to_sat(),
                public_key: signers_public_key,
            },
            fee_rate: FEE_RATE,
            public_key: signers_public_key,
            last_fees: None,
            magic_bytes: [b'T', b'3'],
        },
        accept_threshold: 4,
        num_signers: 7,
        sbtc_limits: SbtcLimits::unlimited(),
        max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
    };

    // There should only be one transaction here since there are only
    // withdrawal requests and no deposit requests.
    let mut transactions = requests.construct_transactions().unwrap();
    assert_eq!(transactions.len(), 1);
    let mut unsigned = transactions.pop().unwrap();

    // Add the signature and/or other required information to the witness data.
    signer::testing::set_witness_data(&mut unsigned, signer.keypair);

    // Ship it
    rpc.send_raw_transaction(&unsigned.tx).unwrap();
    let sweep_block_hash = faucet.generate_block();

    // The signer's balance should now reflect the withdrawal.
    let signers_balance = signer.get_balance(rpc).to_sat();
    assert_eq!(
        signers_balance,
        signers_funds
            - withdrawal_requests
                .iter()
                .map(|req| req.amount)
                .sum::<u64>()
            - unsigned.tx_fee
            + deposit_amount
    );

    // Let's check we correctly parse the withdrawal IDs
    let settings = Settings::new_from_default_config().unwrap();
    let client = BitcoinCoreClient::try_from(&settings.bitcoin.rpc_endpoints[0]).unwrap();
    let tx_info = client
        .get_tx_info(&unsigned.tx.compute_txid(), &sweep_block_hash)
        .unwrap()
        .unwrap();

    let signer_script_pubkeys = HashSet::from([signers_public_key.signers_script_pubkey()]);
    let (_, withdrawal_outputs) = tx_info.to_outputs(&signer_script_pubkeys).unwrap();

    // Sanity check: we got a output for each request
    assert_eq!(withdrawal_requests.len(), withdrawal_outputs.len());
    assert_eq!(
        withdrawal_requests.len(),
        withdrawal_outputs
            .iter()
            .map(|out| out.request_id)
            .collect::<HashSet<_>>()
            .len()
    );

    for output in withdrawal_outputs {
        assert_eq!(output.txid, tx_info.compute_txid().into());
        let request = withdrawal_requests
            .iter()
            .find(|req| req.request_id == output.request_id)
            .unwrap();

        let amount = tx_info.tx.output[output.output_index as usize].value;
        assert_eq!(amount.to_sat(), request.amount);
    }
}
