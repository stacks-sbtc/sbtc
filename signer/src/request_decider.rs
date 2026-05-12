//! # Request decider event loop
//!
//! This module contains the request decider, which is the component of the sBTC signer
//! responsible for deciding whether to accept or reject a request.
//!
//! For more details, see the [`RequestDeciderEventLoop`] documentation.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::SIGNER_CHANNEL_CAPACITY;
use crate::block_observer::BlockObserver;
use crate::blocklist_client::BlocklistChecker;
use crate::context::Context;
use crate::context::P2PEvent;
use crate::context::RequestDeciderEvent;
use crate::context::SignerCommand;
use crate::context::SignerEvent;
use crate::context::SignerSignal;
use crate::ecdsa::SignEcdsa as _;
use crate::ecdsa::Signed;
use crate::emily_client::EmilyInteract as _;
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::message::Payload;
use crate::message::SignerDepositDecision;
use crate::message::SignerMessage;
use crate::message::SignerWithdrawalDecision;
use crate::network::MessageTransfer;
use crate::storage::DbRead as _;
use crate::storage::DbWrite as _;
use crate::storage::model;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinBlockRef;
use crate::storage::model::DepositSigner;
use crate::storage::model::WithdrawalSigner;

use futures::StreamExt as _;
use futures::TryStreamExt as _;

/// This struct is responsible for deciding whether to accept or reject
/// requests and persisting requests from other signers.
#[derive(Debug)]
pub struct RequestDeciderEventLoop<C, N, B> {
    /// The signer context.
    pub context: C,
    /// Interface to the signer network.
    pub network: N,
    /// Blocklist checker.
    pub blocklist_checker: Option<B>,
    /// Private key of the signer for network communication.
    pub signer_private_key: PrivateKey,
    /// How many bitcoin blocks back from the chain tip the signer will look for requests.
    pub context_window: u16,
    /// How many bitcoin blocks back from the chain tip the signer will look for deposit
    /// decisions to retry to propagate.
    pub deposit_decisions_retry_window: u16,
    /// How many bitcoin blocks back from the chain tip the signer will look for withdrawal
    /// decisions to retry to propagate.
    pub withdrawal_decisions_retry_window: u16,
}

/// This function defines which messages this event loop is interested
/// in.
fn run_loop_message_filter(signal: &SignerSignal) -> bool {
    matches!(
        signal,
        SignerSignal::Command(SignerCommand::Shutdown)
            | SignerSignal::Event(SignerEvent::P2P(P2PEvent::MessageReceived(_)))
            | SignerSignal::Event(SignerEvent::BitcoinBlockObserved(_))
    )
}

impl<C, N, B> RequestDeciderEventLoop<C, N, B>
where
    C: Context + 'static,
    N: MessageTransfer,
    B: BlocklistChecker,
{
    /// Run the request decider event loop
    #[tracing::instrument(
        skip_all,
        fields(public_key = %self.signer_public_key()),
        name = "request-decider"
    )]
    pub async fn run(mut self) -> Result<(), Error> {
        let start_message = RequestDeciderEvent::EventLoopStarted.into();
        if let Err(error) = self.context.signal(start_message) {
            tracing::error!(%error, "error signaling event loop start");
            return Err(error);
        };

        // Channel for processing incoming signer messages off the main
        // signal stream so we can keep draining the signal stream quickly.
        let (msg_tx, msg_rx) = mpsc::channel::<Signed<SignerMessage>>(SIGNER_CHANNEL_CAPACITY);

        // Channel for deposit decisions that require fetching the deposit
        // request from Emily and potentially backfilling bitcoin blocks.
        // This is the slowest path, so it gets its own task.
        let (backfill_tx, backfill_rx) = mpsc::channel::<DepositSigner>(SIGNER_CHANNEL_CAPACITY);

        let ctx = self.context.clone();
        let msg_worker = tokio::spawn(run_message_worker(ctx, msg_rx, backfill_tx));

        let ctx = self.context.clone();
        let backfill_worker = tokio::spawn(run_backfill_worker(ctx, backfill_rx));

        let mut signal_stream = self.context.as_signal_stream(run_loop_message_filter);

        while let Some(message) = signal_stream.next().await {
            match message {
                SignerSignal::Command(SignerCommand::Shutdown) => break,
                SignerSignal::Command(SignerCommand::P2PPublish(_)) => {}
                SignerSignal::Event(event) => match event {
                    SignerEvent::P2P(P2PEvent::MessageReceived(msg)) => {
                        match msg_tx.try_send(*msg) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => tracing::warn!(
                                "message worker channel full; dropping signer message"
                            ),
                            Err(TrySendError::Closed(_)) => {
                                tracing::error!("The worker is closed, stopping the event loop");
                                break;
                            }
                        }
                    }
                    SignerEvent::BitcoinBlockObserved(chain_tip) => {
                        if let Err(error) = self.handle_new_requests(chain_tip).await {
                            tracing::warn!(%error, "error handling new requests; skipping this round");
                        }

                        let message = RequestDeciderEvent::NewRequestsHandled(chain_tip).into();
                        // If there is an error here then the application
                        // is on its way down since
                        // [`SignerContext::signal`] sends a shutdown
                        // signal on error. We've also logged the error
                        // already.
                        if self.context.signal(message).is_err() {
                            break;
                        }
                    }
                    _ => {}
                },
            }
        }

        drop(msg_tx);
        let _ = msg_worker.await;
        let _ = backfill_worker.await;
        tracing::info!("request decider event loop has been stopped");
        Ok(())
    }

    /// Vote on pending deposit requests
    #[tracing::instrument(skip_all, fields(
        bitcoin_tip_hash = %block_ref.block_hash,
        bitcoin_tip_height = %block_ref.block_height,
    ))]
    pub async fn handle_new_requests(&mut self, block_ref: BitcoinBlockRef) -> Result<(), Error> {
        let requests_processing_delay = self.context.config().signer.requests_processing_delay;
        if requests_processing_delay > Duration::ZERO {
            tracing::debug!("sleeping before processing new requests");
            tokio::time::sleep(requests_processing_delay).await;
        }

        let bitcoin_chain_tip = block_ref.block_hash;
        let stacks_chain_tip = self
            .context
            .state()
            .stacks_chain_tip()
            .ok_or(Error::NoStacksChainTip)?
            .block_hash;
        let signer_public_key = self.signer_public_key();
        let db = self.context.get_storage();
        // We retry the deposit decisions because some signers' bitcoin nodes might have
        // been running behind and ignored the previous messages.
        let deposit_decisions_to_retry = db
            .get_deposit_signer_decisions(
                &bitcoin_chain_tip,
                self.deposit_decisions_retry_window,
                &signer_public_key,
            )
            .await?;

        let _ = self
            .handle_deposit_decisions_to_retry(deposit_decisions_to_retry, &bitcoin_chain_tip)
            .await
            .inspect_err(
                |error| tracing::warn!(%error, "error handling deposit decisions to retry"),
            );

        let deposit_requests = db
            .get_pending_deposit_requests(
                &bitcoin_chain_tip,
                self.context_window,
                &signer_public_key,
            )
            .await?;

        for deposit_request in deposit_requests {
            let outpoint = deposit_request.outpoint();
            let _ = self
                .handle_pending_deposit_request(deposit_request, &bitcoin_chain_tip)
                .await
                .inspect_err(|error| {
                    tracing::warn!(
                        %error,
                        %outpoint,
                        "error handling new deposit request"
                    )
                });
        }

        let withdrawal_decisions_to_retry = db
            .get_withdrawal_signer_decisions(
                &bitcoin_chain_tip,
                self.withdrawal_decisions_retry_window,
                &signer_public_key,
            )
            .await?;

        let _ = self
            .handle_withdrawal_decisions_to_retry(withdrawal_decisions_to_retry, &bitcoin_chain_tip)
            .await
            .inspect_err(
                |error| tracing::warn!(%error, "error handling withdrawal decisions to retry"),
            );

        let withdraw_requests = db
            .get_pending_withdrawal_requests(
                &bitcoin_chain_tip,
                &stacks_chain_tip,
                self.context_window,
                &signer_public_key,
            )
            .await?;

        for withdraw_request in withdraw_requests {
            let request_id = withdraw_request.request_id;
            let _ = self
                .handle_pending_withdrawal_request(withdraw_request, &bitcoin_chain_tip)
                .await
                .inspect_err(|error| {
                    tracing::warn!(
                        %error,
                        %request_id,
                        "error handling new withdrawal request"
                    )
                });
        }

        Ok(())
    }

    /// Check whether this signer accepts the deposit request. This
    /// involves:
    ///
    /// 1. Reach out to the blocklist client and find out whether we can
    ///    accept the deposit given all the input `scriptPubKey`s of the
    ///    transaction.
    /// 2. Check if we are a part of the signing set associated with the
    ///    public key locking the funds.
    ///
    /// If the block list client is not configured then the first check
    /// always passes.
    #[tracing::instrument(skip_all)]
    pub async fn handle_pending_deposit_request(
        &mut self,
        request: model::DepositRequest,
        chain_tip: &BitcoinBlockHash,
    ) -> Result<(), Error> {
        let db = self.context.get_storage_mut();

        let signer_public_key = self.signer_public_key();
        // Let's find out whether or not we can even sign for this deposit
        // request. If we cannot then we do not even reach out to the
        // blocklist client.
        //
        // We should have a record for the request because of where this
        // function is in the code path.
        let can_sign = db
            .can_sign_deposit_tx(&request.txid, request.output_index, &signer_public_key)
            .await?
            .unwrap_or(false);

        let can_accept = self.can_accept_deposit_request(&request).await?;

        let msg = SignerDepositDecision {
            txid: request.txid.into(),
            output_index: request.output_index,
            can_accept,
            can_sign,
        };

        let signer_decision = DepositSigner {
            txid: request.txid,
            output_index: request.output_index,
            signer_pub_key: signer_public_key,
            can_accept,
            can_sign,
        };

        db.write_deposit_signer_decision(&signer_decision).await?;

        self.send_message(msg, chain_tip).await?;

        self.context
            .signal(RequestDeciderEvent::PendingDepositRequestRegistered.into())?;

        Ok(())
    }

    /// Send the given withdrawal decisions to the other signers for redundancy.
    #[tracing::instrument(skip_all)]
    pub async fn handle_withdrawal_decisions_to_retry(
        &mut self,
        decisions: Vec<model::WithdrawalSigner>,
        chain_tip: &BitcoinBlockHash,
    ) -> Result<(), Error> {
        for decision in decisions.into_iter().map(SignerWithdrawalDecision::from) {
            let _ = self
                .send_message(decision, chain_tip)
                .await
                .inspect_err(|error| {
                    tracing::warn!(%error, "error sending withdrawal decision to retry, skipping");
                });
        }
        Ok(())
    }

    /// Send the given deposit decisions to the other signers for redundancy.
    #[tracing::instrument(skip_all)]
    pub async fn handle_deposit_decisions_to_retry(
        &mut self,
        decisions: Vec<model::DepositSigner>,
        chain_tip: &BitcoinBlockHash,
    ) -> Result<(), Error> {
        for decision in decisions.into_iter().map(SignerDepositDecision::from) {
            let _ = self
                .send_message(decision, chain_tip)
                .await
                .inspect_err(|error| {
                    tracing::warn!(%error, "error sending deposit decision to retry, skipping");
                });
        }
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn handle_pending_withdrawal_request(
        &mut self,
        withdrawal_request: model::WithdrawalRequest,
        chain_tip: &BitcoinBlockHash,
    ) -> Result<(), Error> {
        // TODO: Do we want to do this on the sender address or the
        // recipient address?
        let is_accepted = self
            .can_accept_withdrawal_request(&withdrawal_request)
            .await?;

        let msg = SignerWithdrawalDecision {
            request_id: withdrawal_request.request_id,
            block_hash: withdrawal_request.block_hash,
            accepted: is_accepted,
            txid: withdrawal_request.txid,
        };

        let signer_decision = WithdrawalSigner {
            request_id: withdrawal_request.request_id,
            block_hash: withdrawal_request.block_hash,
            signer_pub_key: self.signer_public_key(),
            is_accepted,
            txid: withdrawal_request.txid,
        };

        self.context
            .get_storage_mut()
            .write_withdrawal_signer_decision(&signer_decision)
            .await?;

        self.send_message(msg, chain_tip).await?;

        self.context
            .signal(RequestDeciderEvent::PendingWithdrawalRequestRegistered.into())?;

        Ok(())
    }

    async fn can_accept_withdrawal_request(
        &self,
        req: &model::WithdrawalRequest,
    ) -> Result<bool, Error> {
        // If we have not configured a blocklist checker, then we can
        // return early.
        let Some(client) = self.blocklist_checker.as_ref() else {
            return Ok(true);
        };

        let network = bitcoin::Network::from(self.context.config().signer.network);
        let receiver_address = bitcoin::Address::from_script(&req.recipient, network.params())
            .map_err(|err| {
                Error::WithdrawalBitcoinAddressFromScript(err, req.request_id, req.block_hash)
            })?;

        let can_accept = client
            .can_accept(&receiver_address.to_string())
            .await
            .inspect_err(|error| tracing::error!(%error, "blocklist client issue"))?;

        Ok(can_accept)
    }

    async fn can_accept_deposit_request(&self, req: &model::DepositRequest) -> Result<bool, Error> {
        // If we have not configured a blocklist checker, then we can
        // return early.
        let Some(client) = self.blocklist_checker.as_ref() else {
            return Ok(true);
        };

        // We turn all the input scriptPubKeys into addresses and check
        // those with the blocklist client.
        let bitcoin_network = bitcoin::Network::from(self.context.config().signer.network);
        let params = bitcoin_network.params();
        let addresses = req
            .sender_script_pub_keys
            .iter()
            .map(|script_pubkey| bitcoin::Address::from_script(script_pubkey, params))
            .collect::<Result<Vec<bitcoin::Address>, _>>()
            .map_err(|err| Error::DepositBitcoinAddressFromScript(err, req.outpoint()))?;

        let responses = futures::stream::iter(&addresses)
            .then(|address| async { client.can_accept(&address.to_string()).await })
            .inspect_err(|error| tracing::error!(%error, "blocklist client issue"))
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        // If all of the inputs addresses are fine then we pass the deposit
        // request.
        let can_accept = responses.into_iter().all(|res| res);
        Ok(can_accept)
    }

    #[tracing::instrument(skip_all)]
    async fn send_message(
        &mut self,
        msg: impl Into<Payload>,
        chain_tip: &BitcoinBlockHash,
    ) -> Result<(), Error> {
        let payload: Payload = msg.into();
        let msg = payload
            .to_message(*chain_tip)
            .sign_ecdsa(&self.signer_private_key);

        self.network.broadcast(msg).await?;

        Ok(())
    }

    fn signer_public_key(&self) -> PublicKey {
        PublicKey::from_private_key(&self.signer_private_key)
    }
}

/// Processes incoming signer messages from the message channel.
///
/// Decisions for requests we already know about are persisted directly.
/// Deposit decisions for unknown requests are forwarded to the backfill
/// worker. Withdrawal decisions for unknown requests are dropped.
async fn run_message_worker<C: Context>(
    ctx: C,
    mut msg_rx: mpsc::Receiver<Signed<SignerMessage>>,
    backfill_tx: mpsc::Sender<DepositSigner>,
) {
    while let Some(msg) = msg_rx.recv().await {
        tracing::trace!(payload = %msg.inner.payload, "handling message");
        let result = match msg.inner.payload {
            Payload::SignerDepositDecision(decision) => {
                let decision = DepositSigner {
                    txid: decision.txid.into(),
                    output_index: decision.output_index,
                    signer_pub_key: msg.signer_public_key,
                    can_accept: decision.can_accept,
                    can_sign: decision.can_sign,
                };
                persist_received_deposit_decision(&ctx, decision, &backfill_tx).await
            }
            Payload::SignerWithdrawalDecision(decision) => {
                persist_received_withdraw_decision(&ctx, decision, msg.signer_public_key).await
            }
            Payload::StacksTransactionSignRequest(_)
            | Payload::BitcoinPreSignRequest(_)
            | Payload::BitcoinPreSignAck(_)
            | Payload::WstsMessage(_)
            | Payload::StacksTransactionSignature(_) => Ok(()),
        };

        if let Err(error) = result {
            tracing::error!(%error, "error handling signer message");
        }
    }
}

/// Handles deposit decisions that require fetching the deposit request
/// from Emily and potentially backfilling bitcoin blocks. This is the
/// slowest path in message processing.
pub async fn run_backfill_worker<C>(context: C, mut backfill_rx: mpsc::Receiver<DepositSigner>)
where
    C: Context,
{
    while let Some(decision) = backfill_rx.recv().await {
        if let Err(error) = backfill_and_persist_deposit(&context, &decision).await {
            tracing::warn!(
                %error,
                txid = %decision.txid,
                output_index = decision.output_index,
                "failed to backfill deposit decision",
            );
        }
    }
}

/// Fetch an unknown deposit request from Emily, backfill it into the
/// database, and persist the signer decision.
#[tracing::instrument(skip_all, fields(
    txid = %decision.txid,
    output_index = decision.output_index,
    sender = %decision.signer_pub_key,
))]
async fn backfill_and_persist_deposit<C: Context>(
    context: &C,
    decision: &DepositSigner,
) -> Result<(), Error> {
    let txid = decision.txid.clone();
    let output_index = decision.output_index;
    tracing::debug!("backfilling deposit request from emily");

    let processor = BlockObserver {
        context: context.clone(),
        bitcoin_block_source: (),
    };

    let deposit_request = context
        .get_emily_client()
        .get_deposit(&txid, output_index)
        .await?;

    if let Some(request) = deposit_request {
        processor.load_requests(&[request]).await?;
    }

    let db = context.get_storage_mut();

    if !db.deposit_request_exists(&txid, output_index).await? {
        tracing::debug!("we still do not have a record of the deposit request after backfill");
        return Ok(());
    }

    db.write_deposit_signer_decision(&decision).await?;

    context.signal(RequestDeciderEvent::ReceivedDepositDecision.into())?;

    Ok(())
}

/// Save the given deposit decision into the database.
///
/// If we already have a record of the associated deposit request, the
/// decision is persisted directly. Otherwise the decision is forwarded
/// to the backfill worker which fetches it from Emily. This keeps the
/// fast path (known requests) cheap and avoids blocking the message
/// worker on Emily round-trips.
#[tracing::instrument(skip_all, fields(sender = %decision.signer_pub_key))]
pub async fn persist_received_deposit_decision<C: Context>(
    ctx: &C,
    decision: DepositSigner,
    backfill_tx: &mpsc::Sender<DepositSigner>,
) -> Result<(), Error> {
    let txid = decision.txid;
    let output_index = decision.output_index;

    let db = ctx.get_storage_mut();

    if !db.deposit_request_exists(&txid, output_index).await? {
        tracing::debug!(%txid, %output_index, "no record of deposit request, forwarding to backfill worker");
        if let Err(TrySendError::Full(_)) = backfill_tx.try_send(decision) {
            tracing::warn!(%txid, %output_index, "backfill channel full; dropping deposit decision");
        }
        return Ok(());
    }

    db.write_deposit_signer_decision(&decision).await?;

    ctx.signal(RequestDeciderEvent::ReceivedDepositDecision.into())?;

    Ok(())
}

#[tracing::instrument(skip_all, fields(sender = %sender_public_key))]
async fn persist_received_withdraw_decision<C: Context>(
    ctx: &C,
    decision: SignerWithdrawalDecision,
    sender_public_key: PublicKey,
) -> Result<(), Error> {
    let signer_decision = WithdrawalSigner {
        request_id: decision.request_id,
        block_hash: decision.block_hash,
        signer_pub_key: sender_public_key,
        is_accepted: decision.accepted,
        txid: decision.txid,
    };

    ctx.get_storage_mut()
        .write_withdrawal_signer_decision(&signer_decision)
        .await?;

    ctx.signal(RequestDeciderEvent::ReceivedWithdrawalDecision.into())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::bitcoin::MockBitcoinInteract;
    use crate::emily_client::MockEmilyInteract;
    use crate::stacks::api::MockStacksInteract;
    use crate::storage::memory::SharedStore;
    use crate::testing;
    use crate::testing::context::*;

    #[allow(clippy::type_complexity)]
    fn test_environment() -> testing::request_decider::TestEnvironment<
        TestContext<
            SharedStore,
            WrappedMock<MockBitcoinInteract>,
            WrappedMock<MockStacksInteract>,
            WrappedMock<MockEmilyInteract>,
        >,
    > {
        let test_model_parameters = testing::storage::model::Params {
            num_bitcoin_blocks: 20,
            num_stacks_blocks_per_bitcoin_block: 3,
            num_deposit_requests_per_block: 5,
            num_withdraw_requests_per_block: 5,
            num_signers_per_request: 0,
            consecutive_blocks: false,
        };

        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        testing::request_decider::TestEnvironment {
            context,
            context_window: 6,
            deposit_decisions_retry_window: 1,
            withdrawal_decisions_retry_window: 1,
            num_signers: 7,
            signing_threshold: 5,
            test_model_parameters,
        }
    }

    #[tokio::test]
    async fn should_store_decisions_for_pending_deposit_requests() {
        test_environment()
            .assert_should_store_decisions_for_pending_deposit_requests()
            .await;
    }

    #[tokio::test]
    // TODO(#1466): This test is currently using a known-working fixed seed, but is flaky with other seeds.
    async fn should_store_decisions_for_pending_withdrawal_requests() {
        test_environment()
            .assert_should_store_decisions_for_pending_withdrawal_requests()
            .await;
    }

    #[tokio::test]
    async fn should_store_decisions_received_from_other_signers() {
        test_environment()
            .assert_should_store_decisions_received_from_other_signers()
            .await;
    }
}
