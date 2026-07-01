//! LibP2P behaviour that gates connections to peers in the current signer
//! set. Placed first in [`super::swarm::SignerBehavior`] so its denial
//! fires during the connection-upgrade phase, before any other behaviour
//! records per-connection state.
//!
//! Rejecting non-signers here means the connection never enters the swarm
//! pool, never consumes a slot against `connection_limits`, and never
//! causes any other behaviour's state machinery to run for it.
//!
//! The behaviour holds an [`Arc<SignerState>`] — the same handle the rest
//! of the signer shares — and reads the live signer set on each
//! connection. The set is `RwLock`-guarded internally, so updates made
//! anywhere else are observed here without any extra wiring.

use std::sync::Arc;

use libp2p::Multiaddr;
use libp2p::PeerId;
use libp2p::core::Endpoint;
use libp2p::core::transport::PortUse;
use libp2p::swarm::ConnectionDenied;
use libp2p::swarm::ConnectionId;
use libp2p::swarm::FromSwarm;
use libp2p::swarm::NetworkBehaviour;
use libp2p::swarm::THandler;
use libp2p::swarm::THandlerInEvent;
use libp2p::swarm::ToSwarm;
use libp2p::swarm::dummy;

use crate::context::SignerState;

/// Reason returned to libp2p when a peer is rejected. Surfaces in the
/// `ConnectionDenied` cause chain.
#[derive(Debug, thiserror::Error)]
#[error("peer {0} is not in the current signer set")]
pub struct PeerNotInSignerSet(pub PeerId);

/// Behavior for allowing only signers to connect to the signer.
pub struct Behavior {
    /// The signer state to check against.
    pub state: Arc<SignerState>,
}

impl Behavior {
    /// Creates a new [`Behavior`] that admits only peers in the current signer
    /// set of the given shared state.
    pub fn new(state: Arc<SignerState>) -> Self {
        Self { state }
    }

    fn check(&self, peer_id: PeerId) -> Result<(), ConnectionDenied> {
        if self.state.current_signer_set().is_allowed_peer(&peer_id) {
            Ok(())
        } else {
            Err(ConnectionDenied::new(PeerNotInSignerSet(peer_id)))
        }
    }
}

impl NetworkBehaviour for Behavior {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = std::convert::Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer_id: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.check(peer_id)?;
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer_id: PeerId,
        _address: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.check(peer_id)?;
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        _event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
    }

    fn poll(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        std::task::Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use libp2p::core::transport::PortUse;
    use rand::rngs::OsRng;

    use crate::keys::PrivateKey;
    use crate::keys::PublicKey;

    use super::*;

    fn peer_id() -> (PublicKey, PeerId) {
        let public_key = PublicKey::from_private_key(&PrivateKey::new(&mut OsRng));
        (public_key, public_key.into())
    }

    fn behaviour_allowing(public_key: PublicKey) -> Behavior {
        let state = Arc::new(SignerState::default());
        state.current_signer_set().add_signer(public_key);
        Behavior::new(state)
    }

    #[test]
    fn admits_inbound_signer_and_rejects_others() {
        let (allowed_key, allowed_peer) = peer_id();
        let (_, other_peer) = peer_id();
        let mut behaviour = behaviour_allowing(allowed_key);

        let conn = ConnectionId::new_unchecked(0);
        let addr = Multiaddr::empty();

        assert!(
            behaviour
                .handle_established_inbound_connection(conn, allowed_peer, &addr, &addr)
                .is_ok()
        );

        let denied = behaviour
            .handle_established_inbound_connection(conn, other_peer, &addr, &addr)
            .err()
            .expect("a non-signer must be rejected");
        assert!(denied.downcast::<PeerNotInSignerSet>().is_ok());
    }

    #[test]
    fn admits_outbound_signer_and_rejects_others() {
        let (allowed_key, allowed_peer) = peer_id();
        let (_, other_peer) = peer_id();
        let mut behaviour = behaviour_allowing(allowed_key);

        let conn = ConnectionId::new_unchecked(0);
        let addr = Multiaddr::empty();

        assert!(
            behaviour
                .handle_established_outbound_connection(
                    conn,
                    allowed_peer,
                    &addr,
                    Endpoint::Dialer,
                    PortUse::New,
                )
                .is_ok()
        );

        assert!(
            behaviour
                .handle_established_outbound_connection(
                    conn,
                    other_peer,
                    &addr,
                    Endpoint::Dialer,
                    PortUse::New,
                )
                .is_err()
        );
    }

    #[test]
    fn tracks_live_signer_set_updates() {
        let (allowed_key, allowed_peer) = peer_id();
        let state = Arc::new(SignerState::default());
        let mut behaviour = Behavior::new(Arc::clone(&state));

        let conn = ConnectionId::new_unchecked(0);
        let addr = Multiaddr::empty();

        // Initially the set is empty, so the peer is rejected.
        assert!(
            behaviour
                .handle_established_inbound_connection(conn, allowed_peer, &addr, &addr)
                .is_err()
        );

        // Adding the signer to the shared state is observed without rebuilding
        // the behaviour.
        state.current_signer_set().add_signer(allowed_key);
        assert!(
            behaviour
                .handle_established_inbound_connection(conn, allowed_peer, &addr, &addr)
                .is_ok()
        );
    }
}
