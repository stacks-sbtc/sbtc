//! validation of bitcoin transactions.

use std::collections::HashMap;
use std::collections::HashSet;

use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;
use bitcoin::relative::LockTime;

use crate::BITCOIN_FEE_RATE_RANGE;
use crate::DEPOSIT_DUST_LIMIT;
use crate::DEPOSIT_LOCKTIME_BLOCK_BUFFER;
use crate::WITHDRAWAL_BLOCKS_EXPIRY;
use crate::bitcoin::rpc::assess_mempool_sweep_transaction_fees;
use crate::bitcoin::utxo::FeeAssessment;
use crate::bitcoin::utxo::SignerBtcState;
use crate::context::Context;
use crate::context::SbtcLimits;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::message::BitcoinPreSignRequest;
use crate::storage::DbRead as _;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinBlockHeight;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::BitcoinTxRef;
use crate::storage::model::BitcoinTxSigHash;
use crate::storage::model::BitcoinWithdrawalOutput;
use crate::storage::model::DkgSharesStatus;
use crate::storage::model::QualifiedRequestId;
use crate::storage::model::SignerVotes;
use crate::storage::model::TaprootScriptHash;
use sbtc::WITHDRAWAL_MIN_CONFIRMATIONS;

use super::utxo::DepositRequest;
use super::utxo::RequestRef;
use super::utxo::Requests;
use super::utxo::SignatureHash;
use super::utxo::UnsignedTransaction;
use super::utxo::WithdrawalRequest;

/// Cached validation data to avoid repeated DB queries
#[derive(Default)]
struct ValidationCache<'a> {
    deposit_reports: HashMap<&'a OutPoint, (DepositRequestReport, SignerVotes)>,
    withdrawal_reports: HashMap<&'a QualifiedRequestId, (WithdrawalRequestReport, SignerVotes)>,
}

/// The necessary information for validating a bitcoin transaction.
#[derive(Debug, Clone)]
pub struct BitcoinTxContext {
    /// This signer's current view of the chain tip of the canonical
    /// bitcoin blockchain. It is the block hash of the block on the
    /// bitcoin blockchain with the greatest height. On ties, we sort by
    /// the block hash descending and take the first one.
    pub chain_tip: BitcoinBlockHash,
    /// The block height of the bitcoin chain tip identified by the
    /// `chain_tip` field.
    pub chain_tip_height: BitcoinBlockHeight,
    /// This signer's public key.
    pub signer_public_key: PublicKey,
    /// The current aggregate key that was the output of DKG. The DKG
    /// shares associated with this aggregate key must have passed
    /// verification.
    pub aggregate_key: PublicKey,
}

/// This type is a container for all deposits and withdrawals that are part
/// of a transaction package.
#[derive(Debug, Clone, PartialEq)]
pub struct TxRequestIds {
    /// The deposit requests associated with the inputs in the transaction.
    pub deposits: Vec<OutPoint>,
    /// The withdrawal requests associated with the outputs in the current
    /// transaction.
    pub withdrawals: Vec<QualifiedRequestId>,
}

impl std::fmt::Display for TxRequestIds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TxRequestIds(deposits=[")?;
        for (i, value) in self.deposits.iter().enumerate() {
            if i > 0 {
                write!(f, ",")?;
            }
            write!(f, "{value}")?;
        }
        write!(f, "], withdrawals=[")?;
        for (i, value) in self.withdrawals.iter().enumerate() {
            if i > 0 {
                write!(f, ",")?;
            }
            write!(f, "{value}")?;
        }
        write!(f, "])")
    }
}

impl From<&Requests<'_>> for TxRequestIds {
    fn from(requests: &Requests) -> Self {
        let mut deposits = Vec::new();
        let mut withdrawals = Vec::new();
        for request in requests.iter() {
            match request {
                RequestRef::Deposit(deposit) => deposits.push(deposit.outpoint),
                RequestRef::Withdrawal(withdrawal) => withdrawals.push(withdrawal.qualified_id()),
            }
        }
        TxRequestIds { deposits, withdrawals }
    }
}

/// Check that this does not contain duplicate deposits or withdrawals.
pub fn is_unique(package: &[TxRequestIds]) -> bool {
    let mut deposits_set = HashSet::new();
    let mut withdrawal_request_id_set = HashSet::new();

    package.iter().all(|reqs| {
        let deposits = reqs.deposits.iter().all(|out| deposits_set.insert(out));
        let withdrawal_requests = reqs
            .withdrawals
            .iter()
            .all(|id| withdrawal_request_id_set.insert(id.request_id));

        deposits && withdrawal_requests
    })
}

impl BitcoinPreSignRequest {
    /// Check that the request object is valid
    // TODO: Have the type system do these checks. Perhaps TxRequestIds
    // should really be a wrapper around something like a (frozen)
    // NonEmptySet<Either<OutPoint, QualifiedRequestId>> with the
    // `request_package` field being a NonEmptySlice<TxRequestIds>.
    fn pre_validation(&self) -> Result<(), Error> {
        let no_requests = self
            .request_package
            .iter()
            .any(|x| x.deposits.is_empty() && x.withdrawals.is_empty());

        if no_requests || self.request_package.is_empty() {
            return Err(Error::PreSignContainsNoRequests);
        }

        if !is_unique(&self.request_package) {
            return Err(Error::DuplicateRequests);
        }

        if !BITCOIN_FEE_RATE_RANGE.contains(&self.fee_rate) {
            return Err(Error::PreSignInvalidFeeRate(self.fee_rate));
        }

        Ok(())
    }

    async fn fetch_all_reports<C>(
        &self,
        ctx: &C,
        btc_ctx: &BitcoinTxContext,
    ) -> Result<ValidationCache<'_>, Error>
    where
        C: Context + Send + Sync,
    {
        let db = ctx.get_storage();
        let mut cache = ValidationCache::default();
        let bitcoin_chain_tip = &btc_ctx.chain_tip;

        let maybe_stacks_chain_tip = ctx.state().stacks_chain_tip();
        let sbtc_limits = ctx.state().get_current_limits();
        let Some(stacks_chain_tip) = maybe_stacks_chain_tip.map(|b| b.block_hash) else {
            return Err(Error::NoStacksChainTip);
        };

        for requests in &self.request_package {
            // Fetch all deposit reports and votes
            for outpoint in &requests.deposits {
                let txid = outpoint.txid.into();
                let output_index = outpoint.vout;

                let report_future = db.get_deposit_request_report(
                    bitcoin_chain_tip,
                    &txid,
                    output_index,
                    &btc_ctx.signer_public_key,
                );
                let Some(report) = report_future.await? else {
                    return Err(InputValidationResult::Unknown.into_error(*outpoint));
                };

                report
                    .validate_without_fee(btc_ctx.chain_tip_height, &sbtc_limits)
                    .map_err(|result| result.into_error(*outpoint))?;

                let votes = db
                    .get_deposit_request_signer_votes(&txid, output_index, &btc_ctx.aggregate_key)
                    .await?;

                cache.deposit_reports.insert(outpoint, (report, votes));
            }

            // Fetch all withdrawal reports and votes
            for qualified_id in &requests.withdrawals {
                let report = db.get_withdrawal_request_report(
                    bitcoin_chain_tip,
                    &stacks_chain_tip,
                    qualified_id,
                    &btc_ctx.signer_public_key,
                );
                let Some(report) = report.await? else {
                    let id = qualified_id.clone();
                    return Err(WithdrawalValidationResult::Unknown.into_error(id));
                };

                report
                    .validate_without_fee(btc_ctx.chain_tip_height, &sbtc_limits)
                    .map_err(|result| result.into_error(qualified_id.clone()))?;

                let votes = db
                    .get_withdrawal_request_signer_votes(qualified_id, &btc_ctx.aggregate_key)
                    .await?;

                cache
                    .withdrawal_reports
                    .insert(qualified_id, (report, votes));
            }
        }
        Ok(cache)
    }

    fn assert_request_amount_limits(
        cache: &ValidationCache<'_>,
        limits: &SbtcLimits,
    ) -> Result<(), Error> {
        let max_mintable = limits.max_mintable_cap().to_sat();

        cache
            .deposit_reports
            .values()
            .try_fold(0u64, |acc, (report, _)| {
                acc.checked_add(report.amount)
                    .ok_or(Error::ExceedsSbtcSupplyCap {
                        total_amount: u64::MAX,
                        max_mintable,
                    })
                    .and_then(|sum| {
                        if sum > max_mintable {
                            Err(Error::ExceedsSbtcSupplyCap {
                                total_amount: sum,
                                max_mintable,
                            })
                        } else {
                            Ok(sum)
                        }
                    })
            })?;

        let rolling_limits = limits.rolling_withdrawal_limits();
        let withdrawn_total = rolling_limits.withdrawn_total;

        cache
            .withdrawal_reports
            .values()
            .try_fold(withdrawn_total, |acc, (report, _)| {
                let sum = acc.saturating_add(report.amount);
                if sum > rolling_limits.cap {
                    return Err(Error::ExceedsWithdrawalCap(WithdrawalCapContext {
                        amounts: sum,
                        cap: rolling_limits.cap,
                        cap_blocks: rolling_limits.blocks,
                        withdrawn_total,
                    }));
                }
                Ok(sum)
            })?;

        Ok(())
    }

    /// Construct the reports for each request that this transaction will
    /// service.
    pub async fn construct_package_sighashes<C>(
        &self,
        ctx: &C,
        btc_ctx: &BitcoinTxContext,
    ) -> Result<Vec<BitcoinTxValidationData>, Error>
    where
        C: Context + Send + Sync,
    {
        // Let's do basic validation of the request object itself.
        self.pre_validation()?;
        let db = ctx.get_storage();
        let cache = self.fetch_all_reports(ctx, btc_ctx).await?;

        // We now check that the withdrawal amounts adhere to the rolling
        // limits. We check the individual withdrawal caps later.
        let limits = ctx.state().get_current_limits();
        Self::assert_request_amount_limits(&cache, &limits)?;

        let signer_utxo = db
            .get_signer_utxo(&btc_ctx.chain_tip)
            .await?
            .ok_or(Error::MissingSignerUtxo)?;

        let bitcoin_client = ctx.get_bitcoin_client();
        let last_fees =
            assess_mempool_sweep_transaction_fees(&bitcoin_client, &signer_utxo).await?;

        let mut signer_state = SignerBtcState {
            fee_rate: self.fee_rate,
            utxo: signer_utxo,
            public_key: bitcoin::XOnlyPublicKey::from(btc_ctx.aggregate_key),
            last_fees,
            magic_bytes: [b'T', b'3'], //TODO(#472): Use the correct magic bytes.
        };
        let mut outputs = Vec::new();

        for requests in self.request_package.iter() {
            let (output, new_signer_state) = self
                .construct_tx_sighashes(ctx, btc_ctx, requests, signer_state, &cache)
                .await?;
            signer_state = new_signer_state;
            outputs.push(output);
        }

        Ok(outputs)
    }

    /// Construct the validation for each request that this transaction
    /// will service.
    ///
    /// This function returns the new signer bitcoin state if we were to
    /// sign and confirmed the bitcoin transaction created using the given
    /// inputs and outputs.
    async fn construct_tx_sighashes<'a, C>(
        &self,
        ctx: &C,
        btc_ctx: &BitcoinTxContext,
        requests: &'a TxRequestIds,
        signer_state: SignerBtcState,
        cache: &ValidationCache<'a>,
    ) -> Result<(BitcoinTxValidationData, SignerBtcState), Error>
    where
        C: Context + Send + Sync,
    {
        let mut deposits = Vec::with_capacity(requests.deposits.len());
        let mut withdrawals = Vec::with_capacity(requests.withdrawals.len());

        for outpoint in requests.deposits.iter() {
            let (report, votes) = cache
                .deposit_reports
                .get(outpoint)
                // This should never happen because we have already validated that we have all the reports.
                .ok_or_else(|| InputValidationResult::Unknown.into_error(*outpoint))?;
            deposits.push((report.to_deposit_request(votes), report.clone()));
        }

        for id in requests.withdrawals.iter() {
            let (report, votes) = cache
                .withdrawal_reports
                .get(id)
                // This should never happen because we have already validated that we have all the reports.
                .ok_or_else(|| WithdrawalValidationResult::Unknown.into_error(id.clone()))?;
            withdrawals.push((report.to_withdrawal_request(votes), report.clone()));
        }

        deposits.sort_by_key(|(request, _)| request.outpoint);
        withdrawals.sort_by_key(|(_, report)| report.id.clone());
        let reports = SbtcReports {
            deposits,
            withdrawals,
            signer_state,
        };
        let mut signer_state = signer_state;
        let tx = reports.create_transaction()?;
        let sighashes = tx.construct_digests()?;

        signer_state.utxo = tx.new_signer_utxo();
        // The first transaction is the only one whose input UTXOs that
        // have all been confirmed. Moreover, the fees that it sets aside
        // are enough to make up for the remaining transactions in the
        // transaction package. With that in mind, we do not need to bump
        // their fees anymore in order for them to be accepted by the
        // network.
        signer_state.last_fees = None;
        let out = BitcoinTxValidationData {
            signer_sighash: sighashes.signer_sighash(),
            deposit_sighashes: sighashes.deposit_sighashes(),
            chain_tip: btc_ctx.chain_tip,
            tx: tx.tx.clone(),
            tx_fee: Amount::from_sat(tx.tx_fee),
            reports,
            chain_tip_height: btc_ctx.chain_tip_height,
            sbtc_limits: ctx.state().get_current_limits(),
        };

        out.validate()?;

        Ok((out, signer_state))
    }
}

/// Whether this signer will sign a particular sighash, and the reason if
/// not. This is narrower than [`InputValidationResult`]: by the time we
/// build a [`BitcoinTxSigHash`], the request has already passed
/// validation, so the only remaining question is signability.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub enum WillSign {
    /// The signer will sign the sighash.
    Yes,
    /// The signer is not part of the signing set that controls the
    /// aggregate key locking the deposit funds.
    CannotSignUtxo,
    /// The DKG shares associated with the aggregate key locking the
    /// deposit have not yet been verified.
    DkgSharesUnverified,
    /// The DKG shares associated with the aggregate key locking the
    /// deposit failed verification.
    DkgSharesVerifyFailed,
}

impl std::fmt::Display for WillSign {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WillSign::Yes => write!(f, "will sign"),
            WillSign::CannotSignUtxo => write!(f, "cannot sign utxo"),
            WillSign::DkgSharesUnverified => write!(f, "dkg shares unverified"),
            WillSign::DkgSharesVerifyFailed => write!(f, "dkg shares verify failed"),
        }
    }
}

/// An intermediate struct to aid in computing validation of deposits and
/// withdrawals and transforming the computed sighash into a
/// [`BitcoinTxSigHash`].
#[derive(Debug)]
pub struct BitcoinTxValidationData {
    /// The sighash of the signers' prevout
    pub signer_sighash: SignatureHash,
    /// The sighash of each of the deposit request prevout
    pub deposit_sighashes: Vec<SignatureHash>,
    /// The computed deposits and withdrawals reports.
    pub reports: SbtcReports,
    /// The chain tip at the time that this signer received the sign
    /// request.
    pub chain_tip: BitcoinBlockHash,
    /// The transaction that we are (implicitly) requested to help sign.
    pub tx: bitcoin::Transaction,
    /// the transaction fee in sats
    pub tx_fee: Amount,
    /// the chain tip height.
    pub chain_tip_height: BitcoinBlockHeight,
    /// The current sBTC limits.
    pub sbtc_limits: SbtcLimits,
}

impl BitcoinTxValidationData {
    /// Construct the sighashes for the inputs of the associated
    /// transaction.
    ///
    /// This function coalesces the information contained in this struct
    /// into a list of sighashes that we will sign for. Signing a sighash
    /// depends on
    /// 1. The entire transaction passing an "aggregate" validation. This
    ///    means that each input and output is unfulfilled, and doesn't
    ///    violate protocol rules, such as max fees, lock-time rules, and
    ///    so on.
    /// 2. That this signer has not rejected/blocked any of the deposits or
    ///    withdrawals in the transaction.
    /// 3. That this signer is a party to signing set that controls the
    ///    public key locking the transaction output.
    pub fn to_input_rows(&self) -> Vec<BitcoinTxSigHash> {
        // If the transaction is invalid we won't sign anything, so skip
        // it entirely.
        if !self.is_valid_tx() {
            return Vec::new();
        }

        // just a sanity check
        debug_assert_eq!(self.deposit_sighashes.len(), self.reports.deposits.len());

        // We might not be able to sign for some of the deposit inputs, and
        // we only want to write rows to the database if we will sign for
        // the input. So we filter out the inputs that we cannot sign for
        let deposit_sighashes = self
            .deposit_sighashes
            .iter()
            .zip(self.reports.deposits.iter())
            .filter_map(|(sighash, (_, report))| match report.will_sign() {
                WillSign::Yes => Some(sighash),
                reason => {
                    tracing::warn!(
                        outpoint = %sighash.outpoint,
                        %reason,
                        "skipping deposit input: this signer will not sign for it"
                    );
                    None
                }
            });

        // The signers' input is always signable — it's our own UTXO,
        // unspent and locked by the signers' aggregate key.
        std::iter::once(&self.signer_sighash)
            .chain(deposit_sighashes)
            .map(|sighash| BitcoinTxSigHash {
                txid: sighash.txid.into(),
                sighash: sighash.sighash.into(),
                chain_tip: self.chain_tip,
                aggregate_key: sighash.aggregate_key.into(),
                prevout_txid: sighash.outpoint.txid.into(),
                prevout_output_index: sighash.outpoint.vout,
                prevout_type: sighash.prevout_type,
            })
            .collect()
    }

    /// Construct objects with withdrawal output identifiers for each
    /// withdrawal serviced by this transaction. Returns an empty vec if
    /// the transaction is invalid (and so we will not sign).
    pub fn to_withdrawal_rows(&self) -> Vec<BitcoinWithdrawalOutput> {
        if !self.is_valid_tx() {
            return Vec::new();
        }

        let bitcoin_txid = self.tx.compute_txid().into();

        // If we ever construct a transaction with more than u32::MAX then
        // we are dealing with a very different Bitcoin and Stacks than we
        // started with, and there are other things that we need to change
        // first.
        self.reports
            .withdrawals
            .iter()
            .enumerate()
            .map(|(output_index, (_, report))| BitcoinWithdrawalOutput {
                bitcoin_txid,
                bitcoin_chain_tip: self.chain_tip,
                output_index: output_index as u32 + 2,
                request_id: report.id.request_id,
                stacks_txid: report.id.txid,
                stacks_block_hash: report.id.block_hash,
            })
            .collect()
    }

    /// Check whether the transaction is valid. This determines whether
    /// this signer will participate in the signing rounds for this
    /// transaction at all.
    ///
    /// A transaction is invalid if any request fails core validation
    /// (status, amounts, votes, lock-time, expiry) or if any input/output
    /// fails the fee check. Signability of individual inputs (a separate
    /// concern handled by [`DepositRequestReport::will_sign`]) does NOT
    /// affect tx validity — unsignable inputs are still part of the tx;
    /// they're just skipped (and logged) by `to_input_rows`, so the row
    /// is never persisted and this signer doesn't commit to signing it.
    pub fn is_valid_tx(&self) -> bool {
        self.validate().is_ok()
    }

    /// Validate the transaction and return an error if it is invalid.
    fn validate(&self) -> Result<(), Error> {
        // A transaction is invalid if it is not servicing any deposit or
        // withdrawal requests. Doing so costs fees and the signers do not
        // gain anything by permitting such a transaction.
        if self.reports.deposits.is_empty() && self.reports.withdrawals.is_empty() {
            let inner = BitcoinValidationError::NoRequests;
            return Err(Error::BitcoinValidation(Box::new(inner)));
        }

        let chain_tip_height = self.chain_tip_height;
        let tx = &self.tx;
        let tx_fee = self.tx_fee;
        let sbtc_limits = &self.sbtc_limits;

        for (_, report) in self.reports.deposits.iter() {
            if let Err(error) = report.validate(chain_tip_height, tx, tx_fee, sbtc_limits) {
                return Err(error.into_error(report.outpoint));
            }
        }

        for (index, (_, report)) in self.reports.withdrawals.iter().enumerate() {
            let output_index = index + 2;
            if let Err(error) =
                report.validate(chain_tip_height, output_index, tx, tx_fee, sbtc_limits)
            {
                return Err(error.into_error(report.id.clone()));
            }
        }

        Ok(())
    }
}

/// The set of sBTC requests with additional relevant
/// information used to construct the next transaction package.
#[derive(Debug)]
pub struct SbtcReports {
    /// Deposit requests with how the signers voted for them.
    pub deposits: Vec<(DepositRequest, DepositRequestReport)>,
    /// Withdrawal requests with how the signers voted for them.
    pub withdrawals: Vec<(WithdrawalRequest, WithdrawalRequestReport)>,
    /// Summary of the Signers' UTXO and information necessary for
    /// constructing their next UTXO.
    pub signer_state: SignerBtcState,
}

impl SbtcReports {
    /// Create the transaction with witness data using the requests.
    pub fn create_transaction(&self) -> Result<UnsignedTransaction<'_>, Error> {
        let deposits = self
            .deposits
            .iter()
            .map(|(request, _)| RequestRef::Deposit(request));
        let withdrawals = self
            .withdrawals
            .iter()
            .map(|(request, _)| RequestRef::Withdrawal(request));

        let state = &self.signer_state;
        let requests = Requests::new(deposits.chain(withdrawals).collect());

        UnsignedTransaction::new_stub(requests, state)
    }
}

/// The responses for validation of a sweep transaction on bitcoin.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub enum InputValidationResult {
    /// The deposit request amount is below the allowed per-deposit minimum.
    #[error("amount too low")]
    AmountTooLow,
    /// The deposit request amount, less the fees, would be rejected from
    /// the smart contract during the complete-deposit contract call.
    #[error("mint amount below dust limit")]
    MintAmountBelowDustLimit,
    /// The deposit request amount exceeds the allowed per-deposit cap.
    #[error("amount too high")]
    AmountTooHigh,
    /// The assessed fee exceeds the max-fee in the deposit request.
    #[error("fee too high")]
    FeeTooHigh,
    /// The deposit transaction has been confirmed on a bitcoin block
    /// that is not part of the canonical bitcoin blockchain.
    #[error("transaction not on best chain")]
    TxNotOnBestChain,
    /// The deposit UTXO has already been spent.
    #[error("deposit utxo spent")]
    DepositUtxoSpent,
    /// Given the current time and block height, it would be imprudent to
    /// attempt to sweep in a deposit request with the given lock-time.
    #[error("lock time expiry")]
    LockTimeExpiry,
    /// The signer does not have a record of their vote on the deposit
    /// request in their database.
    #[error("no vote")]
    NoVote,
    /// The signer has rejected the deposit request.
    #[error("we have rejected the request")]
    RejectedRequest,
    /// The signer does not have a record of the deposit request in their
    /// database.
    #[error("unknown deposit request")]
    Unknown,
    /// The locktime in the reclaim script is in time units and that is not
    /// supported. This shouldn't happen, since we will not put it in our
    /// database is this is the case.
    #[error("unsupported lock time type")]
    UnsupportedLockTime,
}

impl InputValidationResult {
    fn into_error(self, outpoint: OutPoint) -> Error {
        Error::BitcoinValidation(Box::new(BitcoinValidationError::Deposit(self, outpoint)))
    }
}

/// The responses for validation of the outputs of a sweep transaction on
/// bitcoin.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub enum WithdrawalValidationResult {
    /// The withdrawal request amount exceeds the allowed per-withdrawal cap
    #[error("amount too high")]
    AmountTooHigh,
    /// The withdrawal request amount is below the bitcoin dust amount.
    #[error("the withdrawal request amount is below the dust amount limit")]
    AmountIsDust,
    /// The assessed fee exceeds the max-fee in the withdrawal request.
    #[error("the assessed fee exceeds the max-fee in the withdrawal request")]
    FeeTooHigh,
    /// The signer does not have a record of their vote on the withdrawal
    /// request in their database.
    #[error("no vote")]
    NoVote,
    /// The withdrawal request has expired. This means that too many
    /// bitcoin blocks have been observed since observing the Stacks
    /// block that confirmed the transaction creating the withdrawal
    /// request.
    #[error("the withdrawal request has expired")]
    RequestExpired,
    /// The withdrawal request has already been fulfilled by a sweep
    /// transaction that has been confirmed on the canonical bitcoin
    /// blockchain.
    #[error("the withdrawal request has already been fulfilled by a sweep transaction")]
    RequestFulfilled,
    /// The withdrawal request is not deemed final. This means that not
    /// enough bitcoin blocks have been observed since observing the Stacks
    /// block that confirmed the transaction creating the withdrawal
    /// request.
    #[error("the withdrawal request is not deemed final")]
    RequestNotFinal,
    /// The signer has rejected the withdrawal request.
    #[error("we have rejected the request")]
    RequestRejected,
    /// The transaction that created the withdrawal request has been
    /// confirmed by a stacks block that is not part of the canonical
    /// Stacks blockchain.
    #[error("this withdrawal request is not on the canonical Stacks blockchain")]
    TxNotOnBestChain,
    /// The signer does not have a record of the withdrawal request in
    /// their database.
    #[error("unknown withdrawal request")]
    Unknown,
}

/// A struct containing context information for when a collection of
/// withdrawals exceeds the rolling withdrawal limits.
#[derive(Debug, PartialEq, Eq)]
pub struct WithdrawalCapContext {
    /// The new withdrawal amount, including the currently withdrawn total,
    /// if some of the proposed withdrawals would be swept. This amount is
    /// in sats.
    pub amounts: u64,
    /// The rolling withdrawal maximum in sats.
    pub cap: u64,
    /// The number of bitcoin blocks that are used in the rolling
    /// withdrawal cap.
    pub cap_blocks: u16,
    /// The currently withdrawal total over the last N bitcoin blocks in
    /// sats.
    pub withdrawn_total: u64,
}

impl WithdrawalValidationResult {
    /// Make into a crate error
    pub fn into_error(self, qualified_id: QualifiedRequestId) -> Error {
        let inner = BitcoinValidationError::Withdrawal(self, qualified_id);
        Error::BitcoinValidation(Box::new(inner))
    }
}

/// The responses for validation of a sweep transaction on bitcoin.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum BitcoinValidationError {
    /// The transaction does not service any deposit or withdrawal requests.
    #[error("no requests")]
    NoRequests,
    /// The error has something to do with the inputs.
    #[error("deposit error for outpoint {1}: {0}")]
    Deposit(InputValidationResult, OutPoint),
    /// The error has something to do with the outputs.
    #[error("withdrawal error for request {1}: {0}")]
    Withdrawal(WithdrawalValidationResult, QualifiedRequestId),
}

/// An enum for the confirmation status of a deposit request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositConfirmationStatus {
    /// We have a record of the deposit request transaction, and it has
    /// been confirmed on the canonical bitcoin blockchain. We have not
    /// spent these funds. The integer is the height of the block
    /// confirming the deposit request.
    Confirmed(BitcoinBlockHeight, BitcoinBlockHash),
    /// We have a record of the deposit request being included as an input
    /// in another bitcoin transaction that has been confirmed on the
    /// canonical bitcoin blockchain.
    Spent(BitcoinTxId),
    /// We have a record of the deposit request transaction, and it has not
    /// been confirmed on the canonical bitcoin blockchain.
    ///
    /// Usually we will almost certainly have a record of a deposit
    /// request, and we require that the deposit transaction be confirmed
    /// before we write it to our database. But the deposit transaction can
    /// be affected by a bitcoin reorg, where it is no longer confirmed on
    /// the canonical bitcoin blockchain. If this happens when we query for
    /// the status then it will come back as unconfirmed.
    Unconfirmed,
}

/// A struct for the status report summary of a deposit request for use
/// in validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositRequestReport {
    /// The deposit UTXO outpoint that uniquely identifies the deposit.
    pub outpoint: OutPoint,
    /// The confirmation status of the deposit request transaction.
    pub status: DepositConfirmationStatus,
    /// Whether this signer was part of the signing set associated with the
    /// deposited funds. If the signer is not part of the signing set, then
    /// we do not do a check of whether we will accept it otherwise.
    ///
    /// This will only be `None` if we do not have a record of the deposit
    /// request.
    pub can_sign: Option<bool>,
    /// Whether this signers' blocklist client accepted the deposit request
    /// or not. This should only be `None` if we do not have a record of
    /// the deposit request.
    pub can_accept: Option<bool>,
    /// The deposit amount
    pub amount: u64,
    /// The max fee embedded in the deposit request.
    pub max_fee: u64,
    /// The lock_time in the reclaim script
    pub lock_time: LockTime,
    /// The deposit script used so that the signers' can spend funds.
    pub deposit_script: ScriptBuf,
    /// The reclaim script hash for the deposit.
    pub reclaim_script_hash: TaprootScriptHash,
    /// The public key used in the deposit script.
    pub signers_public_key: XOnlyPublicKey,
    /// The status of the DKG shares associated with the above
    /// `signers_public_key`.
    pub dkg_shares_status: Option<DkgSharesStatus>,
}

impl DepositRequestReport {
    /// Validate the deposit request without reference to a sweep
    /// transaction. This covers the request's confirmation status, lock
    /// time, votes, DKG shares, and per-deposit amount caps.
    fn validate_without_fee(
        &self,
        chain_tip_height: BitcoinBlockHeight,
        sbtc_limits: &SbtcLimits,
    ) -> Result<(), InputValidationResult> {
        let confirmed_block_height = match self.status {
            // Deposit requests are only written to the database after they
            // have been confirmed, so this means that we have a record of
            // the request, but it has not been confirmed on the canonical
            // bitcoin blockchain.
            DepositConfirmationStatus::Unconfirmed => {
                return Err(InputValidationResult::TxNotOnBestChain);
            }
            // This means that we have a record of the deposit UTXO being
            // spent in a sweep transaction that has been confirmed on the
            // canonical bitcoin blockchain.
            DepositConfirmationStatus::Spent(_) => {
                return Err(InputValidationResult::DepositUtxoSpent);
            }
            // The deposit has been confirmed on the canonical bitcoin
            // blockchain and remains unspent by us.
            DepositConfirmationStatus::Confirmed(block_height, _) => block_height,
        };

        if self.amount < sbtc_limits.per_deposit_minimum().to_sat() {
            return Err(InputValidationResult::AmountTooLow);
        }

        if self.amount > sbtc_limits.per_deposit_cap().to_sat() {
            return Err(InputValidationResult::AmountTooHigh);
        }

        // We only sweep a deposit if the depositor cannot reclaim the
        // deposit within the next DEPOSIT_LOCKTIME_BLOCK_BUFFER blocks.
        let deposit_age = chain_tip_height.saturating_sub(confirmed_block_height);

        match self.lock_time {
            LockTime::Blocks(height) => {
                let max_age = height
                    .value()
                    .saturating_sub(DEPOSIT_LOCKTIME_BLOCK_BUFFER)
                    .into();
                if deposit_age >= max_age {
                    return Err(InputValidationResult::LockTimeExpiry);
                }
            }
            LockTime::Time(_) => {
                return Err(InputValidationResult::UnsupportedLockTime);
            }
        }

        // Let's check whether we rejected this deposit.
        match self.can_accept {
            Some(true) => (),
            // If we are here, we know that we have a record for the
            // deposit request, but we have not voted on it yet, so we do
            // not know if we can sign for it.
            None => return Err(InputValidationResult::NoVote),
            Some(false) => return Err(InputValidationResult::RejectedRequest),
        }

        if self.can_sign.is_none() {
            // We shouldn't ever get here, since `can_accept` and
            // `can_sign` are written together for each signer's vote.
            // Still, we treat it defensively as a "no vote" where the rest
            // of the signability check are done by `will_sign`.
            return Err(InputValidationResult::NoVote);
        }

        Ok(())
    }

    /// Validate the assessed fee for this deposit input within a
    /// constructed sweep transaction.
    fn validate_assessed_fee<F>(&self, tx: &F, tx_fee: Amount) -> Result<(), InputValidationResult>
    where
        F: FeeAssessment,
    {
        let Some(assessed_fee) = tx.assess_input_fee(&self.outpoint, tx_fee) else {
            return Err(InputValidationResult::Unknown);
        };

        if assessed_fee.to_sat() > self.max_fee.min(self.amount) {
            return Err(InputValidationResult::FeeTooHigh);
        }

        if self.amount.saturating_sub(assessed_fee.to_sat()) < DEPOSIT_DUST_LIMIT {
            return Err(InputValidationResult::MintAmountBelowDustLimit);
        }

        Ok(())
    }

    /// Validate that the deposit request is okay given the report.
    fn validate<F>(
        &self,
        chain_tip_height: BitcoinBlockHeight,
        tx: &F,
        tx_fee: Amount,
        sbtc_limits: &SbtcLimits,
    ) -> Result<(), InputValidationResult>
    where
        F: FeeAssessment,
    {
        self.validate_without_fee(chain_tip_height, sbtc_limits)?;
        self.validate_assessed_fee(tx, tx_fee)
    }

    /// Whether this signer will sign for this deposit input, and if not,
    /// why. The request itself is assumed to have already passed
    /// validation — this only inspects the signer-specific state (whether
    /// the signer is part of the signing set, and the verification status
    /// of the DKG shares locking the UTXO).
    pub fn will_sign(&self) -> WillSign {
        // Defensive: if validation hasn't run yet and `can_sign` is None,
        // we don't know enough to sign — treat as not part of the set.
        if self.can_sign != Some(true) {
            return WillSign::CannotSignUtxo;
        }
        match self.dkg_shares_status {
            Some(DkgSharesStatus::Verified) => WillSign::Yes,
            Some(DkgSharesStatus::Unverified) => WillSign::DkgSharesUnverified,
            Some(DkgSharesStatus::Failed) => WillSign::DkgSharesVerifyFailed,
            None => WillSign::CannotSignUtxo,
        }
    }

    /// As deposit request.
    fn to_deposit_request(&self, votes: &SignerVotes) -> DepositRequest {
        DepositRequest {
            outpoint: self.outpoint,
            max_fee: self.max_fee,
            amount: self.amount,
            deposit_script: self.deposit_script.clone(),
            reclaim_script_hash: self.reclaim_script_hash.clone(),
            signers_public_key: self.signers_public_key,
            signer_bitmap: votes.into(),
        }
    }
}

/// An enum for the confirmation status of a withdrawal request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WithdrawalRequestStatus {
    /// We have a record of the withdrawal request transaction, and it is
    /// confirmed by a block on the canonical Stacks blockchain. We have
    /// not fulfilled the request.
    Confirmed,
    /// We have a record of the withdrawal request being included as an
    /// output in another bitcoin transaction that has been confirmed on
    /// the canonical bitcoin blockchain.
    Fulfilled(BitcoinTxRef),
    /// We have a record of the transaction that created the withdrawal
    /// request, but it is not confirmed on the canonical Stacks blockchain
    /// and the withdrawal request has not been fulfilled.
    Unconfirmed,
}

/// A struct for the status report summary of a withdrawal request for use
/// in validation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WithdrawalRequestReport {
    /// The unique identifier for the request. It includes the ID generated
    /// by the smart contract when the `initiate-withdrawal-request` public
    /// function was called along with the transaction ID and Stacks block
    /// ID.
    pub id: QualifiedRequestId,
    /// The confirmation status of the withdrawal request transaction.
    pub status: WithdrawalRequestStatus,
    /// The amount of BTC, in sats, to withdraw.
    pub amount: u64,
    /// The max fee amount to use for the bitcoin transaction sweeping out
    /// the funds.
    pub max_fee: u64,
    /// The script_pubkey of the output.
    pub recipient: ScriptBuf,
    /// Whether this signers' blocklist client accepted the withdrawal
    /// request or not. This should only be `None` if we do not have a
    /// record of the withdrawal request.
    pub is_accepted: Option<bool>,
    /// The height of the bitcoin chain tip during the execution of the
    /// contract call that generated the withdrawal request.
    pub bitcoin_block_height: BitcoinBlockHeight,
}

impl WithdrawalRequestReport {
    /// Validate the withdrawal request without reference to a sweep
    /// transaction. This covers the request's confirmation status, votes,
    /// dust amount, confirmation/expiry windows, and per-withdrawal cap.
    fn validate_without_fee(
        &self,
        chain_tip_height: BitcoinBlockHeight,
        sbtc_limits: &SbtcLimits,
    ) -> Result<(), WithdrawalValidationResult> {
        match self.status {
            WithdrawalRequestStatus::Confirmed => {}
            WithdrawalRequestStatus::Unconfirmed => {
                return Err(WithdrawalValidationResult::TxNotOnBestChain);
            }
            WithdrawalRequestStatus::Fulfilled(_) => {
                return Err(WithdrawalValidationResult::RequestFulfilled);
            }
        }

        match self.is_accepted {
            Some(true) => (),
            None => return Err(WithdrawalValidationResult::NoVote),
            Some(false) => return Err(WithdrawalValidationResult::RequestRejected),
        }

        if self.amount > sbtc_limits.per_withdrawal_cap().to_sat() {
            return Err(WithdrawalValidationResult::AmountTooHigh);
        }

        if self.amount < self.recipient.minimal_non_dust().to_sat() {
            return Err(WithdrawalValidationResult::AmountIsDust);
        }

        let block_wait = *chain_tip_height.saturating_sub(self.bitcoin_block_height);
        if block_wait < WITHDRAWAL_MIN_CONFIRMATIONS {
            return Err(WithdrawalValidationResult::RequestNotFinal);
        }

        if block_wait > WITHDRAWAL_BLOCKS_EXPIRY {
            return Err(WithdrawalValidationResult::RequestExpired);
        }

        Ok(())
    }

    /// Validate the assessed fee for this withdrawal output within a
    /// constructed sweep transaction.
    fn validate_assessed_fee<F>(
        &self,
        output_index: usize,
        tx: &F,
        tx_fee: Amount,
    ) -> Result<(), WithdrawalValidationResult>
    where
        F: FeeAssessment,
    {
        let Some(assessed_fee) = tx.assess_output_fee(output_index, tx_fee) else {
            return Err(WithdrawalValidationResult::Unknown);
        };

        if assessed_fee.to_sat() > self.max_fee {
            return Err(WithdrawalValidationResult::FeeTooHigh);
        }

        Ok(())
    }

    /// Validate that the withdrawal request is okay given the report.
    ///
    /// See https://github.com/stacks-network/sbtc/issues/741 for the
    /// validation rules for withdrawal requests.
    pub fn validate<F>(
        &self,
        bitcoin_chain_tip_height: BitcoinBlockHeight,
        output_index: usize,
        tx: &F,
        tx_fee: Amount,
        sbtc_limits: &SbtcLimits,
    ) -> Result<(), WithdrawalValidationResult>
    where
        F: FeeAssessment,
    {
        self.validate_without_fee(bitcoin_chain_tip_height, sbtc_limits)?;
        self.validate_assessed_fee(output_index, tx, tx_fee)
    }

    fn to_withdrawal_request(&self, votes: &SignerVotes) -> WithdrawalRequest {
        WithdrawalRequest {
            request_id: self.id.request_id,
            txid: self.id.txid,
            block_hash: self.id.block_hash,
            amount: self.amount,
            max_fee: self.max_fee,
            script_pubkey: self.recipient.clone().into(),
            signer_bitmap: votes.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use bitcoin::ScriptBuf;
    use bitcoin::Sequence;
    use bitcoin::TxIn;
    use bitcoin::TxOut;
    use bitcoin::Txid;
    use bitcoin::Witness;
    use bitcoin::hashes::Hash as _;
    use secp256k1::SECP256K1;
    use test_case::test_case;

    use crate::MAX_BITCOIN_FEE_RATE;
    use crate::MIN_BITCOIN_FEE_RATE;
    use crate::context::RollingWithdrawalLimits;
    use crate::context::SbtcLimits;
    use crate::storage::model::BitcoinBlockHeight;
    use crate::storage::model::StacksBlockHash;
    use crate::storage::model::StacksTxId;

    use super::*;

    /// A helper struct to aid in testing of deposit validation.
    #[derive(Debug)]
    struct DepositReportErrorMapping {
        report: DepositRequestReport,
        status: Result<(), InputValidationResult>,
        chain_tip_height: BitcoinBlockHeight,
        limits: SbtcLimits,
    }

    const TX_FEE: Amount = Amount::from_sat(10000);

    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Unconfirmed,
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Err(InputValidationResult::TxNotOnBestChain),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    }; "deposit-reorged")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Spent(BitcoinTxId::from([1; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Err(InputValidationResult::DepositUtxoSpent),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    }; "deposit-spent")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0u64.into(), BitcoinBlockHash::from([0; 32])),
            can_sign: None,
            can_accept: None,
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Err(InputValidationResult::NoVote),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "deposit-no-vote")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0u64.into(), BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(false),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Err(InputValidationResult::RejectedRequest),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "rejected-deposit")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0u64.into(), BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 1),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Err(InputValidationResult::LockTimeExpiry),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "lock-time-expires-soon-1")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0u64.into(), BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 2),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Err(InputValidationResult::LockTimeExpiry),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "lock-time-expires-soon-2")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0u64.into(), BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_512_second_intervals(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Err(InputValidationResult::UnsupportedLockTime),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "lock-time-in-time-units-2")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0u64.into(), BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Ok(()),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "happy-path")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0u64.into(), BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: TX_FEE.to_sat(),
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::new(bitcoin::Txid::from_byte_array([1; 32]), 0),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Err(InputValidationResult::Unknown),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "unknown-prevout")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0u64.into(), BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: TX_FEE.to_sat(),
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Ok(()),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "at-the-border")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0u64.into(), BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: TX_FEE.to_sat() - 1,
            max_fee: TX_FEE.to_sat(),
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Err(InputValidationResult::FeeTooHigh),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "one-sat-too-high-fee-amount")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0u64.into(), BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: TX_FEE.to_sat() + DEPOSIT_DUST_LIMIT - 1,
            max_fee: TX_FEE.to_sat(),
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Err(InputValidationResult::MintAmountBelowDustLimit),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "one-sat-under-dust-amount")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0u64.into(), BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: TX_FEE.to_sat() + DEPOSIT_DUST_LIMIT,
            max_fee: TX_FEE.to_sat(),
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Ok(()),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "at-dust-amount")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0u64.into(), BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: TX_FEE.to_sat() - 1,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Err(InputValidationResult::FeeTooHigh),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "one-sat-too-high-fee")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0u64.into(), BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Err(InputValidationResult::AmountTooHigh),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(0, 99_999_999),
    } ; "amount-too-high")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0u64.into(), BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 99_999_999,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status: Some(DkgSharesStatus::Verified),
        },
        status: Err(InputValidationResult::AmountTooLow),
        chain_tip_height: 2u64.into(),
        limits: SbtcLimits::new_per_deposit(100_000_000, u64::MAX),
    } ; "amount-too-low")]
    fn deposit_report_validation(mapping: DepositReportErrorMapping) {
        let mut tx = crate::testing::btc::base_signer_transaction();
        tx.input.push(TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        });

        let status =
            mapping
                .report
                .validate(mapping.chain_tip_height, &tx, TX_FEE, &mapping.limits);

        assert_eq!(status, mapping.status);
    }

    fn signability_report(
        can_sign: Option<bool>,
        dkg_shares_status: Option<DkgSharesStatus>,
    ) -> DepositRequestReport {
        DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(
                0u64.into(),
                BitcoinBlockHash::from([0; 32]),
            ),
            can_sign,
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script_hash: TaprootScriptHash::zeros(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            dkg_shares_status,
        }
    }

    #[test_case(
        signability_report(Some(true), Some(DkgSharesStatus::Verified)),
        WillSign::Yes;
        "signable"
    )]
    #[test_case(
        signability_report(Some(false), Some(DkgSharesStatus::Verified)),
        WillSign::CannotSignUtxo;
        "not-part-of-signing-set"
    )]
    #[test_case(
        signability_report(Some(true), Some(DkgSharesStatus::Unverified)),
        WillSign::DkgSharesUnverified;
        "dkg-shares-unverified"
    )]
    #[test_case(
        signability_report(Some(true), Some(DkgSharesStatus::Failed)),
        WillSign::DkgSharesVerifyFailed;
        "dkg-shares-failed-verification"
    )]
    #[test_case(
        signability_report(Some(true), None),
        WillSign::CannotSignUtxo;
        "no-dkg-shares-status"
    )]
    #[test_case(
        signability_report(None, Some(DkgSharesStatus::Verified)),
        WillSign::CannotSignUtxo;
        "no-vote-defensive"
    )]
    fn deposit_report_signability(report: DepositRequestReport, expected: WillSign) {
        assert_eq!(report.will_sign(), expected);
    }

    /// A helper struct to aid in testing of deposit validation.
    #[derive(Debug)]
    struct WithdrawalReportErrorMapping {
        report: WithdrawalRequestReport,
        status: Result<(), WithdrawalValidationResult>,
        chain_tip_height: BitcoinBlockHeight,
        limits: SbtcLimits,
    }

    pub static TEST_RECIPIENT: LazyLock<ScriptBuf> =
        LazyLock::new(|| ScriptBuf::new_p2tr(SECP256K1, *sbtc::UNSPENDABLE_TAPROOT_KEY, None));

    #[test_case(WithdrawalReportErrorMapping {
        report: WithdrawalRequestReport {
            // This is the only acceptable status.
            status: WithdrawalRequestStatus::Confirmed,
            // This does not matter during validation.
            id: QualifiedRequestId {
                request_id: 0,
                txid: StacksTxId::from([0; 32]),
                block_hash: StacksBlockHash::from([0; 32]),
            },
            // This is the only acceptable value.
            is_accepted: Some(true),
            // This just needs to be under the sBTC withdrawal maximum in
            // the SbtcLimits.
            amount: Amount::ONE_BTC.to_sat(),
            // The max fee just needs to be greater than or equal to the
            // assessed fee.
            max_fee: TX_FEE.to_sat(),
            // This is used for computing the dust amount during validation.
            recipient: TEST_RECIPIENT.clone(),
            // This needs to be WITHDRAWAL_MIN_CONFIRMATIONS less than the
            // chain_tip_height.
            bitcoin_block_height: 0u64.into(),
        },
        // This is part of sBTC consensus.
        chain_tip_height: WITHDRAWAL_MIN_CONFIRMATIONS.into(),
        // This is set by Emily.
        limits: SbtcLimits::new_per_withdrawal(Amount::ONE_BTC.to_sat()),
        status: Ok(()),
    } ; "happy-path-ok")]
    #[test_case(WithdrawalReportErrorMapping {
        report: WithdrawalRequestReport {
            status: WithdrawalRequestStatus::Confirmed,
            id: QualifiedRequestId {
                request_id: 0,
                txid: StacksTxId::from([0; 32]),
                block_hash: StacksBlockHash::from([0; 32]),
            },
            is_accepted: Some(true),
            amount: Amount::ONE_BTC.to_sat() + 1,
            max_fee: TX_FEE.to_sat(),
            recipient: TEST_RECIPIENT.clone(),
            bitcoin_block_height: 0u64.into(),
        },
        status: Err(WithdrawalValidationResult::AmountTooHigh),
        chain_tip_height: WITHDRAWAL_MIN_CONFIRMATIONS.into(),
        limits: SbtcLimits::new_per_withdrawal(Amount::ONE_BTC.to_sat()),
    } ; "amount-too-high")]
    #[test_case(WithdrawalReportErrorMapping {
        report: WithdrawalRequestReport {
            status: WithdrawalRequestStatus::Confirmed,
            id: QualifiedRequestId {
                request_id: 0,
                txid: StacksTxId::from([0; 32]),
                block_hash: StacksBlockHash::from([0; 32]),
            },
            is_accepted: Some(true),
            amount: TEST_RECIPIENT.minimal_non_dust().to_sat() - 1,
            max_fee: TX_FEE.to_sat(),
            recipient: TEST_RECIPIENT.clone(),
            bitcoin_block_height: 0u64.into(),
        },
        chain_tip_height: WITHDRAWAL_MIN_CONFIRMATIONS.into(),
        limits: SbtcLimits::new_per_withdrawal(Amount::ONE_BTC.to_sat()),
        status: Err(WithdrawalValidationResult::AmountIsDust),
    } ; "amount-is-dust")]
    #[test_case(WithdrawalReportErrorMapping {
        report: WithdrawalRequestReport {
            status: WithdrawalRequestStatus::Confirmed,
            id: QualifiedRequestId {
                request_id: 0,
                txid: StacksTxId::from([0; 32]),
                block_hash: StacksBlockHash::from([0; 32]),
            },
            is_accepted: Some(true),
            amount: TX_FEE.to_sat() - 1,
            max_fee: TX_FEE.to_sat(),
            recipient: TEST_RECIPIENT.clone(),
            bitcoin_block_height: 0u64.into(),
        },
        chain_tip_height: WITHDRAWAL_MIN_CONFIRMATIONS.into(),
        limits: SbtcLimits::new_per_withdrawal(Amount::ONE_BTC.to_sat()),
        status: Ok(()),
    } ; "amount-and-fee-divorced")]
    #[test_case(WithdrawalReportErrorMapping {
        report: WithdrawalRequestReport {
            status: WithdrawalRequestStatus::Confirmed,
            id: QualifiedRequestId {
                request_id: 0,
                txid: StacksTxId::from([0; 32]),
                block_hash: StacksBlockHash::from([0; 32]),
            },
            is_accepted: Some(true),
            amount: Amount::ONE_BTC.to_sat(),
            max_fee: TX_FEE.to_sat() - 1,
            recipient: TEST_RECIPIENT.clone(),
            bitcoin_block_height: 0u64.into(),
        },
        chain_tip_height: WITHDRAWAL_MIN_CONFIRMATIONS.into(),
        limits: SbtcLimits::new_per_withdrawal(Amount::ONE_BTC.to_sat()),
        status: Err(WithdrawalValidationResult::FeeTooHigh) ,
    } ; "fee-too-high")]
    #[test_case(WithdrawalReportErrorMapping {
        report: WithdrawalRequestReport {
            status: WithdrawalRequestStatus::Confirmed,
            id: QualifiedRequestId {
                request_id: 0,
                txid: StacksTxId::from([0; 32]),
                block_hash: StacksBlockHash::from([0; 32]),
            },
            is_accepted: None,
            amount: Amount::ONE_BTC.to_sat(),
            max_fee: TX_FEE.to_sat(),
            recipient: TEST_RECIPIENT.clone(),
            bitcoin_block_height: 0u64.into(),
        },
        chain_tip_height: WITHDRAWAL_MIN_CONFIRMATIONS.into(),
        limits: SbtcLimits::new_per_withdrawal(Amount::ONE_BTC.to_sat()),
        status: Err(WithdrawalValidationResult::NoVote),
    } ; "no-vote")]
    #[test_case(WithdrawalReportErrorMapping {
        report: WithdrawalRequestReport {
            status: WithdrawalRequestStatus::Confirmed,
            id: QualifiedRequestId {
                request_id: 0,
                txid: StacksTxId::from([0; 32]),
                block_hash: StacksBlockHash::from([0; 32]),
            },
            is_accepted: Some(true),
            amount: Amount::ONE_BTC.to_sat(),
            max_fee: TX_FEE.to_sat(),
            recipient: TEST_RECIPIENT.clone(),
            bitcoin_block_height: 0u64.into(),
        },
        chain_tip_height: (WITHDRAWAL_BLOCKS_EXPIRY + 1).into(),
        limits: SbtcLimits::new_per_withdrawal(Amount::ONE_BTC.to_sat()),
        status: Err(WithdrawalValidationResult::RequestExpired),
    } ; "request-expired")]
    #[test_case(WithdrawalReportErrorMapping {
        report: WithdrawalRequestReport {
            status: WithdrawalRequestStatus::Fulfilled(BitcoinTxRef {
                txid: BitcoinTxId::from([0; 32]),
                block_hash: BitcoinBlockHash::from([0; 32]),
            }),
            id: QualifiedRequestId {
                request_id: 0,
                txid: StacksTxId::from([0; 32]),
                block_hash: StacksBlockHash::from([0; 32]),
            },
            is_accepted: Some(true),
            amount: Amount::ONE_BTC.to_sat(),
            max_fee: TX_FEE.to_sat(),
            recipient: TEST_RECIPIENT.clone(),
            bitcoin_block_height: 0u64.into(),
        },
        chain_tip_height: WITHDRAWAL_MIN_CONFIRMATIONS.into(),
        limits: SbtcLimits::new_per_withdrawal(Amount::ONE_BTC.to_sat()),
        status: Err(WithdrawalValidationResult::RequestFulfilled),
    } ; "request-fulfilled")]
    #[test_case(WithdrawalReportErrorMapping {
        report: WithdrawalRequestReport {
            status: WithdrawalRequestStatus::Confirmed,
            id: QualifiedRequestId {
                request_id: 0,
                txid: StacksTxId::from([0; 32]),
                block_hash: StacksBlockHash::from([0; 32]),
            },
            is_accepted: Some(true),
            amount: Amount::ONE_BTC.to_sat(),
            max_fee: TX_FEE.to_sat(),
            recipient: TEST_RECIPIENT.clone(),
            bitcoin_block_height: 0u64.into(),
        },
        chain_tip_height: (WITHDRAWAL_MIN_CONFIRMATIONS - 1).into(),
        limits: SbtcLimits::new_per_withdrawal(Amount::ONE_BTC.to_sat()),
        status: Err(WithdrawalValidationResult::RequestNotFinal),
    } ; "request-not-final")]
    #[test_case(WithdrawalReportErrorMapping {
        report: WithdrawalRequestReport {
            status: WithdrawalRequestStatus::Confirmed,
            id: QualifiedRequestId {
                request_id: 0,
                txid: StacksTxId::from([0; 32]),
                block_hash: StacksBlockHash::from([0; 32]),
            },
            is_accepted: Some(false),
            amount: Amount::ONE_BTC.to_sat(),
            max_fee: TX_FEE.to_sat(),
            recipient: TEST_RECIPIENT.clone(),
            bitcoin_block_height: 0u64.into(),
        },
        chain_tip_height: WITHDRAWAL_MIN_CONFIRMATIONS.into(),
        limits: SbtcLimits::new_per_withdrawal(Amount::ONE_BTC.to_sat()),
        status: Err(WithdrawalValidationResult::RequestRejected),
    } ; "request-rejected")]
    #[test_case(WithdrawalReportErrorMapping {
        report: WithdrawalRequestReport {
            status: WithdrawalRequestStatus::Unconfirmed,
            id: QualifiedRequestId {
                request_id: 0,
                txid: StacksTxId::from([0; 32]),
                block_hash: StacksBlockHash::from([0; 32]),
            },
            is_accepted: Some(true),
            amount: Amount::ONE_BTC.to_sat(),
            max_fee: TX_FEE.to_sat(),
            recipient: TEST_RECIPIENT.clone(),
            bitcoin_block_height: 0u64.into(),
        },
        chain_tip_height: WITHDRAWAL_MIN_CONFIRMATIONS.into(),
        limits: SbtcLimits::new_per_withdrawal(Amount::ONE_BTC.to_sat()),
        status: Err(WithdrawalValidationResult::TxNotOnBestChain),
    } ; "tx-not-on-best-chain")]
    fn withdrawal_report_validation(mapping: WithdrawalReportErrorMapping) {
        let mut tx = crate::testing::btc::base_signer_transaction();
        tx.output.push(TxOut {
            value: Amount::from_sat(mapping.report.amount),
            script_pubkey: mapping.report.recipient.clone(),
        });

        let output_index = tx.output.len() - 1;
        let chain_tip_height = mapping.chain_tip_height;
        let limits = &mapping.limits;

        let status = mapping
            .report
            .validate(chain_tip_height, output_index, &tx, TX_FEE, limits);

        assert_eq!(status, mapping.status);
    }

    #[test]
    fn withdrawal_report_validation_unknown() {
        let report = WithdrawalRequestReport {
            status: WithdrawalRequestStatus::Confirmed,
            id: QualifiedRequestId {
                request_id: 0,
                txid: StacksTxId::from([0; 32]),
                block_hash: StacksBlockHash::from([0; 32]),
            },
            is_accepted: Some(true),
            amount: Amount::ONE_BTC.to_sat(),
            max_fee: u64::MAX,
            recipient: ScriptBuf::new(),
            bitcoin_block_height: 0u64.into(),
        };
        let mut tx = crate::testing::btc::base_signer_transaction();
        tx.output.push(TxOut {
            value: Amount::from_sat(report.amount),
            script_pubkey: report.recipient.clone(),
        });

        // This output_index is out of bounds, and is not the index for the
        // withdrawal output, so we won't know the assessed fee. This
        // should never happen, and is a programming error whenever we
        // observe it.
        let output_index = tx.output.len();
        let bitcoin_chain_tip_height = WITHDRAWAL_MIN_CONFIRMATIONS.into();
        let limits = &SbtcLimits::unlimited();

        let status = report.validate(bitcoin_chain_tip_height, output_index, &tx, TX_FEE, limits);

        assert_eq!(status, Err(WithdrawalValidationResult::Unknown));
    }

    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 0,
                    },
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 1,
                    },
                ],
                withdrawals: vec![
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([1; 32]),
                    },
                    QualifiedRequestId {
                        request_id: 1,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([2; 32]),
                    },
                ],
            }],
            fee_rate: 1.0,
            last_fees: None,
        }, true; "unique-requests")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 0,
                    },
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 1,
                    },
                ],
                withdrawals: vec![
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([1; 32]),
                    },
                    QualifiedRequestId {
                        request_id: 1,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([2; 32]),
                    },
                ],
            }],
            fee_rate: 0.0,
            last_fees: None,
        }, false; "unique-requests-zero-fee-rate")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 0,
                    },
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 1,
                    },
                ],
                withdrawals: vec![
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([1; 32]),
                    },
                    QualifiedRequestId {
                        request_id: 1,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([2; 32]),
                    },
                ],
            }],
            fee_rate: -1.0,
            last_fees: None,
        }, false; "unique-requests-negative-fee-rate")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 0,
                    },
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 0,
                    },
                ],
                withdrawals: vec![
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([1; 32]),
                    },
                    QualifiedRequestId {
                        request_id: 1,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([2; 32]),
                    },
                ],
            }],
            fee_rate: 1.0,
            last_fees: None,
        }, false; "duplicate-deposits-in-same-tx")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 0,
                    },
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 1,
                    },
                ],
                withdrawals: vec![
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([1; 32]),
                    },
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([1; 32]),
                    },
                ],
            }],
            fee_rate: 1.0,
            last_fees: None,
        }, false; "duplicate-withdrawals-in-same-tx")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![
                TxRequestIds {
                    deposits: vec![
                        OutPoint {
                            txid: Txid::from_byte_array([1; 32]),
                            vout: 0,
                        },
                        OutPoint {
                            txid: Txid::from_byte_array([1; 32]),
                            vout: 1,
                        },
                    ],
                    withdrawals: vec![
                        QualifiedRequestId {
                            request_id: 0,
                            txid: StacksTxId::from([1; 32]),
                            block_hash: StacksBlockHash::from([1; 32]),
                        },
                        QualifiedRequestId {
                            request_id: 0,
                            txid: StacksTxId::from([1; 32]),
                            block_hash: StacksBlockHash::from([2; 32]),
                        },
                    ],
                },
            ],
            fee_rate: 1.0,
            last_fees: None,
        }, false; "duplicate-withdrawal-request-ids-in-same-tx")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![
                TxRequestIds {
                    deposits: vec![
                        OutPoint {
                            txid: Txid::from_byte_array([1; 32]),
                            vout: 0,
                        },
                        OutPoint {
                            txid: Txid::from_byte_array([1; 32]),
                            vout: 1,
                        },
                    ],
                    withdrawals: vec![
                        QualifiedRequestId {
                            request_id: 0,
                            txid: StacksTxId::from([1; 32]),
                            block_hash: StacksBlockHash::from([1; 32]),
                        },
                        QualifiedRequestId {
                            request_id: 1,
                            txid: StacksTxId::from([1; 32]),
                            block_hash: StacksBlockHash::from([2; 32]),
                        },
                    ],
                },
                TxRequestIds {
                    deposits: vec![OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 0,
                    }],
                    withdrawals: vec![],
                },
            ],
            fee_rate: 1.0,
            last_fees: None,
        }, false; "duplicate-requests-in-different-txs")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: Vec::new(),
            fee_rate: 1.0,
            last_fees: None,
        }, false; "empty-package_requests")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![
                TxRequestIds {
                    deposits: Vec::new(),
                    withdrawals: Vec::new(),
                },
                TxRequestIds {
                    deposits: Vec::new(),
                    withdrawals: Vec::new(),
                },
            ],
            fee_rate: 1.0,
            last_fees: None,
        }, false; "basically-empty-package_requests")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![
                TxRequestIds {
                    deposits: vec![
                        OutPoint {
                            txid: Txid::from_byte_array([1; 32]),
                            vout: 0,
                        },
                        OutPoint {
                            txid: Txid::from_byte_array([1; 32]),
                            vout: 1,
                        },
                    ],
                    withdrawals: vec![
                        QualifiedRequestId {
                            request_id: 0,
                            txid: StacksTxId::from([1; 32]),
                            block_hash: StacksBlockHash::from([1; 32]),
                        },
                        QualifiedRequestId {
                            request_id: 0,
                            txid: StacksTxId::from([1; 32]),
                            block_hash: StacksBlockHash::from([2; 32]),
                        },
                    ],
                },
                TxRequestIds {
                    deposits: Vec::new(),
                    withdrawals: Vec::new(),
                },
            ],
            fee_rate: 1.0,
            last_fees: None,
        }, false; "contains-empty-tx-requests")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![OutPoint::null()],
                withdrawals: Vec::new(),
            }],
            fee_rate: MAX_BITCOIN_FEE_RATE,
            last_fees: None,
        }, true; "max-fee-rate-request")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![OutPoint::null()],
                withdrawals: Vec::new(),
            }],
            fee_rate: MAX_BITCOIN_FEE_RATE * (1.0 + f64::EPSILON * 2.0),
            last_fees: None,
        }, false; "max-fee-rate-request-plus-epsilon")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![OutPoint::null()],
                withdrawals: Vec::new(),
            }],
            fee_rate: MIN_BITCOIN_FEE_RATE,
            last_fees: None,
        }, true; "min-fee-rate-request")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![OutPoint::null()],
                withdrawals: Vec::new(),
            }],
            fee_rate: MIN_BITCOIN_FEE_RATE - f64::EPSILON,
            last_fees: None,
        }, false; "min-fee-rate-request-minus-epsilon")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![OutPoint::null()],
                withdrawals: Vec::new(),
            }],
            fee_rate: f64::NAN,
            last_fees: None,
        }, false; "unique-requests-nan-fee-rate")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![OutPoint::null()],
                withdrawals: Vec::new(),
            }],
            fee_rate: f64::NEG_INFINITY,
            last_fees: None,
        }, false; "unique-requests-negative-infinity-fee-rate")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![OutPoint::null()],
                withdrawals: Vec::new(),
            }],
            fee_rate: f64::INFINITY,
            last_fees: None,
        }, false; "unique-requests-positive-infinity-fee-rate")]
    fn test_pre_validation(requests: BitcoinPreSignRequest, result: bool) {
        assert_eq!(requests.pre_validation().is_ok(), result);
    }

    fn create_deposit_report(idx: u8, amount: u64) -> (DepositRequestReport, SignerVotes) {
        (
            DepositRequestReport {
                outpoint: OutPoint::new(Txid::from_byte_array([idx; 32]), 0),
                status: DepositConfirmationStatus::Confirmed(
                    0u64.into(),
                    BitcoinBlockHash::from([idx; 32]),
                ),
                can_sign: Some(true),
                can_accept: Some(true),
                amount,
                max_fee: 1000,
                lock_time: LockTime::from_height(100),
                deposit_script: ScriptBuf::new(),
                reclaim_script_hash: TaprootScriptHash::zeros(),
                signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
                dkg_shares_status: Some(DkgSharesStatus::Verified),
            },
            SignerVotes::from(Vec::new()),
        )
    }

    fn create_withdrawal_report(idx: u8, amount: u64) -> (WithdrawalRequestReport, SignerVotes) {
        let report = WithdrawalRequestReport {
            id: QualifiedRequestId {
                txid: StacksTxId::from([0; 32]),
                request_id: idx as u64,
                block_hash: StacksBlockHash::from([0; 32]),
            },
            status: WithdrawalRequestStatus::Confirmed,
            is_accepted: Some(true),
            amount,
            max_fee: 1000,
            recipient: ScriptBuf::new(),
            bitcoin_block_height: 0u64.into(),
        };

        (report, SignerVotes::from(Vec::new()))
    }

    #[test_case(
        vec![1000, 2000, 3000],
        Amount::from_sat(10_000),
        Amount::from_sat(1_000),
        Ok(());
        "should_accept_deposits_under_max_mintable"
    )]
    #[test_case(
        vec![],
        Amount::from_sat(10_000),
        Amount::from_sat(0),
        Ok(());
        "should_accept_empty_deposits"
    )]
    #[test_case(
        vec![10_000],
        Amount::from_sat(10_000),
        Amount::from_sat(0),
        Ok(());
        "should_accept_deposit_equal_to_max_mintable"
    )]
    #[test_case(
        vec![5000, 5001],
        Amount::from_sat(10_000),
        Amount::from_sat(0),
        Err(Error::ExceedsSbtcSupplyCap {
            total_amount: 10_001,
            max_mintable: 10_000
        });
        "should_reject_deposits_over_max_mintable"
    )]
    #[test_case(
        vec![1, 1, Amount::MAX_MONEY.to_sat() - 2],
        Amount::MAX_MONEY,
        Amount::from_sat(1),
        Err(Error::ExceedsSbtcSupplyCap {
            total_amount: Amount::MAX_MONEY.to_sat(),
            max_mintable: Amount::MAX_MONEY.to_sat() - 1
        });
        "filter_out_deposits_over_max_mintable"
    )]
    fn test_validate_max_mintable(
        deposit_amounts: Vec<u64>,
        total_cap: Amount,
        sbtc_supply: Amount,
        expected: Result<(), Error>,
    ) {
        let limits = SbtcLimits::new(
            Some(total_cap),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(total_cap - sbtc_supply),
        );
        // Create cache with test data
        let mut cache = ValidationCache::default();

        let deposit_reports: Vec<(DepositRequestReport, SignerVotes)> = deposit_amounts
            .into_iter()
            .enumerate()
            .map(|(idx, amount)| create_deposit_report(idx as u8, amount))
            .collect();

        cache.deposit_reports = deposit_reports
            .iter()
            .map(|(report, votes)| (&report.outpoint, (report.clone(), votes.clone())))
            .collect();

        // Create request and validate
        let result = BitcoinPreSignRequest::assert_request_amount_limits(&cache, &limits);

        match (result, expected) {
            (Ok(()), Ok(())) => {}
            (
                Err(Error::ExceedsSbtcSupplyCap {
                    total_amount: a1,
                    max_mintable: m1,
                }),
                Err(Error::ExceedsSbtcSupplyCap {
                    total_amount: a2,
                    max_mintable: m2,
                }),
            ) => {
                assert_eq!(a1, a2);
                assert_eq!(m1, m2);
            }
            (result, expected) => panic!("Expected {expected:?} but got {result:?}"),
        };
    }

    /// A helper struct for testing how the code handles withdrawals with
    /// specific limits.
    struct WithdrawalLimitsTestCase {
        /// The withdrawal amounts that are being considered.
        withdrawal_amounts: Vec<u64>,
        /// The rolling withdrawal limits to test.
        rolling_limits: RollingWithdrawalLimits,
        /// The expected outcome after running validation on the withdrawal
        /// requests.
        expected: Result<(), Error>,
    }

    #[test_case(WithdrawalLimitsTestCase {
        withdrawal_amounts: vec![1000, 2000, 3000],
        rolling_limits: RollingWithdrawalLimits {
            cap: 10_000,
            blocks: 150,
            withdrawn_total: 1_000,
        },
        expected: Ok(()),
    }; "should accept withdrawals under rolling cap")]
    #[test_case(WithdrawalLimitsTestCase {
        withdrawal_amounts: vec![],
        rolling_limits: RollingWithdrawalLimits {
            cap: 10_000,
            blocks: 150,
            withdrawn_total: 0,
        },
        expected: Ok(()),
    }; "should accept empty withdrawals")]
    #[test_case(WithdrawalLimitsTestCase {
        withdrawal_amounts: vec![10_000],
        rolling_limits: RollingWithdrawalLimits {
            cap: 10_000,
            blocks: 150,
            withdrawn_total: 0,
        },
        expected: Ok(()),
    }; "should accept withdrawals equal to rolling cap")]
    #[test_case(WithdrawalLimitsTestCase {
        withdrawal_amounts: vec![5000, 5001],
        rolling_limits: RollingWithdrawalLimits {
            cap: 10_000,
            blocks: 150,
            withdrawn_total: 0,
        },
        expected: Err(Error::ExceedsWithdrawalCap(WithdrawalCapContext {
            amounts: 10_001,
            cap: 10_000,
            cap_blocks: 150,
            withdrawn_total: 0,
        })),
    }; "should reject withdrawals over rolling cap")]
    #[test_case(WithdrawalLimitsTestCase {
        withdrawal_amounts: vec![1, 1, Amount::MAX_MONEY.to_sat() - 2],
        rolling_limits: RollingWithdrawalLimits {
            cap: Amount::MAX_MONEY.to_sat(),
            blocks: 150,
            withdrawn_total: 1,
        },
        expected: Err(Error::ExceedsWithdrawalCap(WithdrawalCapContext {
            amounts: Amount::MAX_MONEY.to_sat() + 1,
            cap: Amount::MAX_MONEY.to_sat(),
            cap_blocks: 150,
            withdrawn_total: 1,
        })),
    }; "filter out withdrawals over rolling cap")]
    #[test_case(WithdrawalLimitsTestCase {
        withdrawal_amounts: vec![Amount::MAX_MONEY.to_sat() / 4; 3],
        rolling_limits: RollingWithdrawalLimits::unlimited(Amount::MAX_MONEY.to_sat() / 4),
        expected: Ok(()),
    }; "unlimited filters no withdrawals")]
    #[test_case(WithdrawalLimitsTestCase {
        withdrawal_amounts: vec![1, Amount::MAX_MONEY.to_sat()],
        rolling_limits: RollingWithdrawalLimits::unlimited(0),
        expected: Ok(()),
    }; "unlimited allows more then max money")]
    #[test_case(WithdrawalLimitsTestCase {
        withdrawal_amounts: vec![],
        rolling_limits: RollingWithdrawalLimits::fully_constrained(u64::MAX),
        expected: Ok(()),
    }; "no withdrawals when withdrawals are locked down okay")]
    #[test_case(WithdrawalLimitsTestCase {
        withdrawal_amounts: vec![1],
        rolling_limits: RollingWithdrawalLimits::fully_constrained(0),
        expected: Err(Error::ExceedsWithdrawalCap(WithdrawalCapContext {
            amounts:  1,
            cap: 0,
            cap_blocks: 0,
            withdrawn_total: 0,
        })),
    }; "limits of zero filters all withdrawals")]
    fn test_validate_withdrawal_limits(case: WithdrawalLimitsTestCase) {
        let limits = SbtcLimits::from_withdrawal_limits(u64::MAX, case.rolling_limits);
        // Create cache with test data
        let mut cache = ValidationCache::default();

        let withdrawal_reports: Vec<(WithdrawalRequestReport, SignerVotes)> = case
            .withdrawal_amounts
            .into_iter()
            .enumerate()
            .map(|(idx, amount)| create_withdrawal_report(idx as u8, amount))
            .collect();

        cache.withdrawal_reports = withdrawal_reports
            .iter()
            .map(|(report, votes)| (&report.id, (report.clone(), votes.clone())))
            .collect();

        // Create request and validate
        let result = BitcoinPreSignRequest::assert_request_amount_limits(&cache, &limits);

        match (result, case.expected) {
            (Ok(()), Ok(())) => {}
            (
                Err(Error::ExceedsWithdrawalCap(actual_context)),
                Err(Error::ExceedsWithdrawalCap(expected_context)),
            ) => {
                assert_eq!(actual_context, expected_context);
            }
            (result, expected) => panic!("Expected {expected:?}, got {result:?}"),
        };
    }
}
