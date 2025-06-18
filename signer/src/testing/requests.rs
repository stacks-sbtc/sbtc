//! Helpers for requests

use std::{
    borrow::Borrow,
    sync::atomic::{AtomicU64, Ordering},
};

use bitcoin::Txid as BitcoinTxid;
use bitcoin::{
    AddressType, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    XOnlyPublicKey, absolute::LockTime, transaction::Version,
};
use bitcoincore_rpc::RpcApi;
use bitcoincore_rpc_json::Utxo;
use bitvec::array::BitArray;
use clarity::{types::chainstate::StacksAddress, vm::types::PrincipalData};
use emily_client::apis::deposit_api;
use emily_client::models::Deposit as EmilyDepositModel;
use fake::Fake;
use rand::{Rng, RngCore, distributions::Uniform, rngs::OsRng};
use sbtc::{
    deposits::{CreateDepositRequest, DepositInfo, DepositScriptInputs, ReclaimScriptInputs},
    testing::{
        AsSatoshis,
        regtest::{self, AsUtxo, Faucet, Recipient},
    },
};

use crate::{
    bitcoin::utxo::{DepositRequest, WithdrawalRequest},
    emily_client::EmilyClient,
    storage::model::TaprootScriptHash,
    testing::TestUtilityError,
};

/// A static counter for generating unique request IDs for withdrawals.
pub static REQUEST_IDS: AtomicU64 = AtomicU64::new(0);

/// Generates a random withdrawal request with a random amount and max fee.
pub fn generate_withdrawal() -> (WithdrawalRequest, Recipient) {
    let amount = OsRng.sample(Uniform::new(200_000, 250_000));
    make_withdrawal(amount, amount / 2)
}

/// Creates a withdrawal request with the specified amount and max fee,
/// returning the request and a recipient with a new P2TR address.
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

/// Creates multiple deposit requests, one for each amount in the `amounts` slice.
/// The deposit requests are submitted to Emily, and a single Bitcoin transaction
/// containing all deposits is submitted to the Bitcoin node.
pub fn make_deposit_requests<U, TxAmt, FeeAmt>(
    depositor: &Recipient,
    amounts: &[TxAmt],
    utxo: U,
    max_fee: FeeAmt,
    signers_public_key: bitcoin::XOnlyPublicKey,
) -> (Transaction, Vec<DepositRequest>)
where
    U: regtest::AsUtxo,
    TxAmt: AsSatoshis,
    FeeAmt: AsSatoshis,
{
    let amounts_sats = amounts.iter().map(|a| a.as_satoshis()).collect::<Vec<_>>();
    let max_fee_sats = max_fee.as_satoshis();

    let deposit_inputs = DepositScriptInputs {
        signers_public_key,
        max_fee: max_fee_sats,
        recipient: PrincipalData::from(StacksAddress::burn_address(false)),
    };
    let reclaim_inputs = ReclaimScriptInputs::try_new(50, bitcoin::ScriptBuf::new()).unwrap();

    let deposit_script = deposit_inputs.deposit_script();
    let reclaim_script = reclaim_inputs.reclaim_script();

    let mut outputs = vec![];
    for amount in amounts {
        outputs.push(bitcoin::TxOut {
            value: Amount::from_sat(amount.as_satoshis()),
            script_pubkey: sbtc::deposits::to_script_pubkey(
                deposit_script.clone(),
                reclaim_script.clone(),
            ),
        })
    }

    let fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();
    outputs.push(bitcoin::TxOut {
        value: utxo.amount() - Amount::from_sat(amounts_sats.iter().sum::<u64>() + fee),
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
    for (index, &amount) in amounts_sats.iter().enumerate() {
        let req = CreateDepositRequest {
            outpoint: bitcoin::OutPoint::new(deposit_tx.compute_txid(), index as u32),
            deposit_script: deposit_script.clone(),
            reclaim_script: reclaim_script.clone(),
        };

        requests.push(DepositRequest {
            outpoint: req.outpoint,
            max_fee: max_fee_sats,
            signer_bitmap: BitArray::ZERO,
            amount,
            deposit_script: deposit_script.clone(),
            reclaim_script: reclaim_script.clone(),
            reclaim_script_hash: Some(TaprootScriptHash::from(&reclaim_script)),
            signers_public_key,
        });
    }

    (deposit_tx, requests)
}

/// A simple helper struct representing a deposit/withdrawal request amount and
/// max fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmountSpec<TxAmt, FeeAmt> {
    /// The amount to be deposited or withdrawn.
    pub amount: TxAmt,
    /// The maximum fee that can be paid for the transaction.
    pub max_fee: FeeAmt,
}

/// Provides a constructor for [`AmountSpec`] with the specified amount and max
/// fee which must implement [`AsSatoshis`], allowing amounts to be provided as
/// e.g. `u64`, `bitcoin::Amount`, etc.
impl<TxAmt, FeeAmt> AmountSpec<TxAmt, FeeAmt>
where
    TxAmt: AsSatoshis,
    FeeAmt: AsSatoshis,
{
    /// Creates a new `AmountSpec` instance with the specified amount and max
    /// fee.
    pub fn new(amount: TxAmt, max_fee: FeeAmt) -> Self {
        Self { amount, max_fee }
    }
}

impl<TxAmt> AmountSpec<TxAmt, u64>
where
    TxAmt: AsSatoshis,
{
    /// Creates a new `AmountSpec` instance with the specified amount and a
    /// max fee derived from the amount using the specified fraction.
    pub fn with_derived_max_fee(amount: TxAmt, fraction: f32) -> AmountSpec<TxAmt, u64> {
        let max_fee: u64 = (amount.as_satoshis() as f32 * fraction) as u64;
        AmountSpec { amount, max_fee }
    }
}

/// Represents a prepared deposit which is ready to be submitted.
pub struct PreparedDeposit<'a, Bitcoin, Emily, BitcoinTxid = (), EmilyDeposit = ()> {
    /// The Bitcoin transaction that was submitted for the deposit.
    pub tx: Transaction,
    /// The deposit request that was created for the deposit.
    pub request: DepositRequest,
    /// The deposit information.
    pub info: DepositInfo,

    bitcoin: &'a Bitcoin,
    emily: &'a Emily,

    _bitcoin_txid: BitcoinTxid,
    _emily_deposit: EmilyDeposit,
}

/// Provides specialized functionality for `PreparedDeposit` when the Bitcoin
/// transaction has not yet been submitted to the Bitcoin node, and the Emily
/// deposit has not yet been created.
///
/// This is identified by the `BitcoinTxid` type parameter being `()`.
impl<'a, Bitcoin, Emily, EmilyDeposit> PreparedDeposit<'a, Bitcoin, Emily, (), EmilyDeposit>
where
    Bitcoin: Borrow<bitcoincore_rpc::Client>,
{
    /// Submits the deposit transaction to the Bitcoin node.
    #[track_caller]
    pub fn submit_to_bitcoin(
        self,
    ) -> PreparedDeposit<'a, Bitcoin, Emily, BitcoinTxid, EmilyDeposit> {
        let txid = self
            .bitcoin
            .borrow()
            .send_raw_transaction(&self.tx)
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to submit raw transaction with txid '{}' to Bitcoin node: {e}",
                    self.tx.compute_txid()
                )
            });

        assert_eq!(txid, self.request.outpoint.txid);

        PreparedDeposit {
            tx: self.tx,
            request: self.request,
            info: self.info,
            bitcoin: self.bitcoin,
            emily: self.emily,
            _bitcoin_txid: txid,
            _emily_deposit: self._emily_deposit,
        }
    }
}

/// Provides specialized functionality for `PreparedDeposit` when the Bitcoin
/// transaction has been submitted to the Bitcoin node, but not yet to Emily.
///
/// This is identified by the `BitcoinTxid` type parameter being a
/// [`bitcoin::Txid`] and the `EmilyDeposit` type parameter being `()`.
impl<'a, Bitcoin> PreparedDeposit<'a, Bitcoin, EmilyClient, BitcoinTxid, ()> {
    /// Submits the deposit request to Emily.
    pub async fn submit_to_emily(
        self,
    ) -> Result<
        PreparedDeposit<'a, Bitcoin, EmilyClient, BitcoinTxid, EmilyDepositModel>,
        TestUtilityError,
    > {
        let emily_request_body = self.request.as_emily_request(&self.tx);
        let response = deposit_api::create_deposit(self.emily.config(), emily_request_body)
            .await
            .map_err(|e| format!("Failed to submit deposit to Emily: {e}"))?;

        Ok(PreparedDeposit {
            tx: self.tx,
            request: self.request,
            info: self.info,
            bitcoin: self.bitcoin,
            emily: self.emily,
            _bitcoin_txid: self._bitcoin_txid,
            _emily_deposit: response,
        })
    }
}

/// A helper struct for submitting deposits to the Bitcoin network and Emily
/// from a given depositor.
///
/// This helper uses typestate to provide differing functionality based on the
/// types of `Bitcoin`, `Emily`, and `Depositor` used.
pub struct DepositHelper<'a, Bitcoin, Emily = (), Depositor = ()> {
    bitcoin: &'a Bitcoin,
    emily: &'a Emily,
    depositor: Depositor,
}

/// Provides constructors for creating a `DepositHelper` instance with a
/// [`Recipient`].
impl<'a> DepositHelper<'a, (), (), Recipient> {
    /// Creates a new `DepositHelper` instance with the specified Bitcoin client
    /// and depositor.
    pub fn with_depositor(depositor: Recipient) -> Self {
        Self {
            bitcoin: &(),
            emily: &(),
            depositor,
        }
    }

    /// Creates a new `DepositHelper` instance with a new depositor generated
    /// using the provided RNG.
    pub fn new_depositor<R>(rng: &mut R) -> Self
    where
        R: RngCore,
    {
        let depositor = Recipient::new_with_rng(AddressType::P2tr, rng);
        Self {
            bitcoin: &(),
            emily: &(),
            depositor,
        }
    }
}

/// Provides specialized functionality for `DepositHelper` when:
/// * `Bitcoin` and `Depositor` are any type,
/// * `Emily` is unset/default (`()`).
impl<'a, Bitcoin, Depositor> DepositHelper<'a, Bitcoin, (), Depositor> {
    /// Sets the Emily client for this `DepositHelper`, enabling deposit
    /// submission to Emily. Consumes this instance and returns a new one with
    /// the Emily client set.
    pub fn with_emily(
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
/// * `Bitcoin` is unset/default (`()`),
/// * `Emily` and `Depositor` are any type,
impl<'a, Emily, Depositor> DepositHelper<'a, (), Emily, Depositor> {
    /// Sets the Bitcoin client for this `DepositHelper`, enabling deposit
    /// submission to Bitcoin. Consumes this instance and returns a new one with
    /// the Bitcoin client set.
    pub fn with_bitcoin<B>(self, bitcoin: &'a B) -> DepositHelper<'a, B, Emily, Depositor>
    where
        B: Borrow<bitcoincore_rpc::Client>,
    {
        DepositHelper {
            bitcoin,
            emily: self.emily,
            depositor: self.depositor,
        }
    }
}

/// Provides specialized functionality for `DepositHelper` when:
/// * `Bitcoin` and `Emily` are any type,
/// * `Depositor` implements `Borrow<bitcoin::Address>`, for example a
///   [`bitcoin::Address`] or [`Recipient`].
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
/// * `Bitcoin` and `Emilty` are any type,
/// * `Depositor` is a [`Recipient`].
impl<'a, Bitcoin, Emily> DepositHelper<'a, Bitcoin, Emily, Recipient> {
    /// Prepares a deposit request for the specified UTXO, amount, and max fee,
    /// returning the Bitcoin transaction, deposit request, and deposit info.
    pub fn prepare_deposit_transaction_with_utxo<K, TxAmt, FeeAmt>(
        &self,
        utxo: impl AsUtxo,
        amount_spec: AmountSpec<TxAmt, FeeAmt>,
        signers_public_key: K,
    ) -> PreparedDeposit<'a, Bitcoin, Emily, (), ()>
    where
        K: Into<XOnlyPublicKey>,
        TxAmt: AsSatoshis,
        FeeAmt: AsSatoshis,
    {
        let signers_public_key = signers_public_key.into();
        let amount_sats = amount_spec.amount.as_satoshis();
        let max_fee_sats = amount_spec.max_fee.as_satoshis();

        let fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();
        let deposit_inputs = DepositScriptInputs {
            signers_public_key,
            max_fee: max_fee_sats,
            recipient: PrincipalData::from(StacksAddress::burn_address(false)),
        };
        let reclaim_inputs = ReclaimScriptInputs::try_new(50, ScriptBuf::new()).unwrap();

        let deposit_script = deposit_inputs.deposit_script();
        let reclaim_script = reclaim_inputs.reclaim_script();

        let mut tx = Transaction {
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
                    value: Amount::from_sat(amount_sats),
                    script_pubkey: sbtc::deposits::to_script_pubkey(
                        deposit_script.clone(),
                        reclaim_script.clone(),
                    ),
                },
                TxOut {
                    value: utxo.amount() - Amount::from_sat(amount_sats + fee),
                    script_pubkey: self.depositor.address.script_pubkey(),
                },
            ],
        };

        regtest::p2tr_sign_transaction(&mut tx, 0, &[utxo], &self.depositor.keypair);

        let create_req = CreateDepositRequest {
            outpoint: OutPoint::new(tx.compute_txid(), 0),
            deposit_script,
            reclaim_script,
        };

        let info = create_req.validate_tx(&tx, false).unwrap();

        let request = DepositRequest {
            outpoint: info.outpoint,
            max_fee: info.max_fee,
            signer_bitmap: BitArray::ZERO,
            amount: info.amount,
            deposit_script: info.deposit_script.clone(),
            reclaim_script: info.reclaim_script.clone(),
            reclaim_script_hash: Some(TaprootScriptHash::from(&info.reclaim_script)),
            signers_public_key: info.signers_public_key,
        };

        assert_eq!(tx.compute_txid(), request.outpoint.txid);

        PreparedDeposit {
            tx,
            request,
            info,
            bitcoin: self.bitcoin,
            emily: self.emily,
            _bitcoin_txid: (),
            _emily_deposit: (),
        }
    }
}

/// Provides specialized functionality for `DepositHelper` when:
/// * `Bitcoin` is a [`Faucet`],
/// * `Emily` is any type,
/// * `Depositor` is any type that implements `Borrow<bitcoin::Address>`.
impl<Emily, Depositor> DepositHelper<'_, Faucet, Emily, Depositor>
where
    Depositor: Borrow<bitcoin::Address>,
{
    /// Funds the inner `Depositor` from the faucet with the specified amount.
    pub fn fund<Amt>(&self, amount: Amt) -> OutPoint
    where
        Amt: AsSatoshis,
    {
        self.bitcoin
            .send_to(amount.as_satoshis(), self.depositor.borrow())
    }
}

/// Provides specialized functionality for `DepositHelper` when:
/// * `Bitcoin` implements `Borrow<bitcoincore_rpc::Client>`,
/// * `Emily` is any type,
/// * `Depositor` is a [`Recipient`].
impl<'a, Bitcoin, Emily> DepositHelper<'a, Bitcoin, Emily, Recipient>
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

    /// Finds a suitable UTXO for the depositor that covers the specified
    /// amount.
    fn find_suitable_utxo<TxAmt, FeeAmt>(
        &self,
        amount_spec: &AmountSpec<TxAmt, FeeAmt>,
    ) -> Result<Utxo, TestUtilityError>
    where
        TxAmt: AsSatoshis,
        FeeAmt: AsSatoshis,
    {
        let amount_sats = amount_spec.amount.as_satoshis();
        let max_fee_sats = amount_spec.max_fee.as_satoshis();
        let total_sats = amount_sats + max_fee_sats;

        // Get the UTXOs for the depositor and filter them to find one that
        // covers the amount. If no suitable UTXO is found, return an error.
        let utxo = self
            .depositor
            .get_utxos(self.bitcoin.borrow(), Some(total_sats))
            .pop()
            .ok_or_else(|| {
                format!(
                    "No UTXO found for depositor '{address}' covering {total_sats} satoshis",
                    address = self.depositor.address
                )
            })?;

        Ok(utxo)
    }

    /// Prepares a deposit transaction for the specified amount and max fee,
    /// using a suitable UTXO from the inner [`Recipient`] (depositor).
    ///
    /// ## Panics
    ///
    /// This function will panic if no suitable UTXO is found for the specified
    /// amount and max fee.
    #[track_caller]
    pub fn prepare_deposit_transaction<AggKey, TxAmt, FeeAmt>(
        &self,
        amount_spec: AmountSpec<TxAmt, FeeAmt>,
        aggregate_key: AggKey,
    ) -> PreparedDeposit<'a, Bitcoin, Emily, (), ()>
    where
        AggKey: Into<XOnlyPublicKey>,
        TxAmt: AsSatoshis,
        FeeAmt: AsSatoshis,
    {
        // Find a suitable UTXO for the specified amount and max fee.
        let utxo = self.find_suitable_utxo(&amount_spec).unwrap();

        // Prepare the deposit transaction using the found UTXO.
        self.prepare_deposit_transaction_with_utxo(utxo, amount_spec, aggregate_key)
    }
}

/// Allows `DepositHelper` to be borrowed as a `bitcoin::Address` if the
/// `depositor` field implements `Borrow<bitcoin::Address>` (e.g. a
/// [`Recipient`]).
impl<Bitcoin, Emily, Addr> Borrow<bitcoin::Address> for DepositHelper<'_, Bitcoin, Emily, Addr>
where
    Addr: Borrow<bitcoin::Address>,
{
    fn borrow(&self) -> &bitcoin::Address {
        self.depositor.borrow()
    }
}
