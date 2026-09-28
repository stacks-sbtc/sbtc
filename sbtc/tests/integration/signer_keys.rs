//! Test v2 signer key-set scripts against bitcoin-core

use bitcoin::Address;
use bitcoin::Network;
use bitcoin::NetworkKind;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi as _;
use rand::rngs::OsRng;
use sbtc::SignerKeySet;
use sbtc::signer_keys::signer_set_descriptor;
use sbtc::testing::regtest;
use secp256k1::PublicKey;
use secp256k1::SECP256K1;
use secp256k1::SecretKey;
use test_case::test_case;

/// Return the address that bitcoin-core derives from the descriptor.
fn derive_address(rpc: &Client, descriptor: &str) -> Address {
    let descriptor = rpc.get_descriptor_info(descriptor).unwrap().descriptor;
    let addresses = rpc.derive_addresses(&descriptor, None).unwrap();
    let [address] = addresses.as_slice() else {
        panic!("expected one address, got {addresses:?}");
    };
    address.clone().require_network(Network::Regtest).unwrap()
}

/// Check that bitcoin-core agrees with us about the scriptPubKey of a
/// signer UTXO locked by a v2 key set.
///
/// We check two descriptors. The one with the derived signing keys checks
/// the Taproot `multi_a` script, and the one with each signer's master
/// extended public key checks the BIP32 derivation of the signing keys as
/// well, since bitcoin-core does that derivation itself.
#[test_case(1, 1; "1-of-1")]
#[test_case(3, 2; "2-of-3")]
#[test_case(15, 11; "11-of-15")]
#[test_case(16, 16; "16-of-16")]
fn key_set_script_pubkey_matches_bitcoin_core(signer_count: usize, signatures_required: u16) {
    let (rpc, _) = regtest::initialize_blockchain();

    let public_keys: Vec<PublicKey> = (0..signer_count)
        .map(|_| PublicKey::from_secret_key(SECP256K1, &SecretKey::new(&mut OsRng)))
        .collect();
    let key_set = SignerKeySet::derive(public_keys.clone(), signatures_required).unwrap();
    let expected = Address::from_script(&key_set.script_pubkey(), Network::Regtest).unwrap();

    let address = derive_address(rpc, &key_set.descriptor());
    assert_eq!(address, expected);

    let descriptor = signer_set_descriptor(public_keys, signatures_required, NetworkKind::Test);
    let address = derive_address(rpc, &descriptor);
    assert_eq!(address, expected);
}
