//! BIP32-derived Bitcoin signing keys and v2 signer key-set scripts.

use std::collections::BTreeSet;

use bitcoin::NetworkKind;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;
use bitcoin::bip32::ChainCode;
use bitcoin::bip32::ChildNumber;
use bitcoin::bip32::Fingerprint;
use bitcoin::bip32::Xpriv;
use bitcoin::bip32::Xpub;
use bitcoin::hashes::Hash as _;
use bitcoin::hashes::sha256;
use bitcoin::opcodes::all as opcodes;
use bitcoin::script::Instruction;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::NodeInfo;
use bitcoin::taproot::TaprootSpendInfo;
use secp256k1::PublicKey;
use secp256k1::SECP256K1;
use secp256k1::SecretKey;

use crate::MAX_SIGNERS;
use crate::error::Error;

const CHAIN_CODE_DOMAIN: &[u8] = b"sbtc/signer/chain-code/v1";
const SIGNING_PATH: [ChildNumber; 2] = [
    ChildNumber::Normal { index: 0 },
    ChildNumber::Normal { index: 0 },
];

/// Stable identifier for a signer key set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeySetId([u8; 32]);

impl KeySetId {
    /// Return the identifier as a byte array.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for KeySetId {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<KeySetId> for [u8; 32] {
    fn from(value: KeySetId) -> Self {
        value.0
    }
}

impl std::fmt::Display for KeySetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        bitcoin::hex::DisplayHex::as_hex(&self.0).fmt(f)
    }
}

/// Derive the deterministic BIP32 chain code for a configured signer key.
fn chain_code(public_key: PublicKey) -> ChainCode {
    let mut bytes = Vec::with_capacity(CHAIN_CODE_DOMAIN.len() + 33);
    bytes.extend_from_slice(CHAIN_CODE_DOMAIN);
    bytes.extend_from_slice(&public_key.serialize());
    ChainCode::from(sha256::Hash::hash(&bytes).to_byte_array())
}

/// The network recorded in signer extended keys.
///
/// BIP32 child derivation depends only on the key, the chain code and the
/// child index; the network only selects the version bytes used when an
/// extended key is serialized. We never serialize these extended keys, so
/// derived signing keys are the same on every network.
const SIGNER_XKEY_NETWORK: NetworkKind = NetworkKind::Main;

/// Construct the deterministic master xpub for a configured signer key.
fn signer_xpub(public_key: PublicKey) -> Xpub {
    Xpub {
        network: SIGNER_XKEY_NETWORK,
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::Normal { index: 0 },
        public_key,
        chain_code: chain_code(public_key),
    }
}

/// Derive the `/0/0` Bitcoin signing public key for a configured signer key.
pub fn derive_signing_public_key(public_key: PublicKey) -> XOnlyPublicKey {
    signer_xpub(public_key)
        .derive_pub(SECP256K1, &SIGNING_PATH)
        // SAFETY: Xpub::derive_pub returns an error for a hardened child
        // index, for exceeding the maximum depth, or for a tweak that is
        // not a valid scalar or that takes the key to the point at
        // infinity. The path is two unhardened steps from depth zero, and
        // the tweak failures happen with negligible probability, which is
        // why Xpriv::derive_priv treats the same failures as unreachable.
        .expect("fixed public signing-key derivation cannot fail")
        .to_x_only_pub()
}

/// Derive the `[SIGNING_PATH]` Bitcoin signing secret key for a configured
/// signer key.
pub fn derive_signing_secret_key(private_key: SecretKey) -> SecretKey {
    let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);
    Xpriv {
        network: SIGNER_XKEY_NETWORK,
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::Normal { index: 0 },
        private_key,
        chain_code: chain_code(public_key),
    }
    .derive_priv(SECP256K1, &SIGNING_PATH)
    // SAFETY: The Xpriv::derive_priv function is actually infallible
    // because the one "fallible" function called internally cannot produce
    // an error.
    .expect("fixed private signing-key derivation cannot fail")
    .private_key
}

/// A v2 signer key set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignerKeySet {
    /// Sorted, independently signing x-only public keys.
    public_keys: BTreeSet<XOnlyPublicKey>,
    /// The number of signatures required to spend an output.
    signatures_required: u16,
}

impl SignerKeySet {
    /// Construct a key set from already-derived public keys.
    pub fn new<I>(public_keys: I, signatures_required: u16) -> Result<Self, Error>
    where
        I: IntoIterator<Item = XOnlyPublicKey>,
    {
        let public_keys = public_keys.into_iter().collect::<BTreeSet<_>>();
        let signer_count = public_keys.len();

        if signer_count > MAX_SIGNERS {
            return Err(Error::TooManySignerKeys {
                signer_count,
                max_signers: MAX_SIGNERS,
            });
        }

        if signatures_required == 0 || usize::from(signatures_required) > public_keys.len() {
            return Err(Error::InvalidDepositThreshold {
                signatures_required,
                signer_count,
            });
        }
        Ok(Self {
            public_keys,
            signatures_required,
        })
    }

    /// Construct a key set without checking the number of keys or the
    /// threshold.
    ///
    /// This is for key sets that are already known to lock an output, such
    /// as one read back from storage.
    pub fn new_unchecked<I>(public_keys: I, signatures_required: u16) -> Self
    where
        I: IntoIterator<Item = XOnlyPublicKey>,
    {
        Self {
            public_keys: public_keys.into_iter().collect(),
            signatures_required,
        }
    }

    /// Return the, independently signing x-only public keys locking the
    /// signers' UTXO.
    pub fn public_keys(&self) -> &BTreeSet<XOnlyPublicKey> {
        &self.public_keys
    }

    /// Return the number of signatures required to spend an output.
    pub fn signatures_required(&self) -> u16 {
        self.signatures_required
    }

    /// Derive and construct a key set from configured signer public keys.
    pub fn derive<I>(public_keys: I, signatures_required: u16) -> Result<Self, Error>
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let keys = public_keys.into_iter().map(derive_signing_public_key);
        Self::new(keys, signatures_required)
    }

    /// Return the stable identifier of this key set.
    pub fn id(&self) -> KeySetId {
        let mut bytes = self.signatures_required.to_be_bytes().to_vec();
        for key in &self.public_keys {
            bytes.extend(key.serialize());
        }
        sha256::Hash::hash(&bytes).to_byte_array().into()
    }

    /// Parse a canonical v2 signer `multi_a` script.
    pub fn parse(signing_script: &bitcoin::Script) -> Result<Self, Error> {
        let mut instructions = signing_script.instructions_minimal();
        let mut public_keys = BTreeSet::new();

        let signatures_required = loop {
            match instructions
                .next()
                .transpose()
                .map_err(|_| Error::InvalidSignerScript)?
                .ok_or(Error::InvalidSignerScript)?
            {
                Instruction::PushBytes(bytes) if bytes.len() == 32 => {
                    let key = XOnlyPublicKey::from_slice(bytes.as_bytes())
                        .map_err(Error::InvalidXOnlyPublicKey)?;
                    if !public_keys.insert(key) {
                        return Err(Error::InvalidSignerScript);
                    }
                    if public_keys.len() > MAX_SIGNERS {
                        return Err(Error::TooManySignerKeys {
                            signer_count: public_keys.len(),
                            max_signers: MAX_SIGNERS,
                        });
                    }
                    let expected = if public_keys.len() == 1 {
                        opcodes::OP_CHECKSIG
                    } else {
                        opcodes::OP_CHECKSIGADD
                    };
                    match instructions.next().transpose() {
                        Ok(Some(Instruction::Op(opcode))) if opcode == expected => {}
                        _ => return Err(Error::InvalidSignerScript),
                    }
                }
                Instruction::Op(opcode)
                    if (opcodes::OP_PUSHNUM_1.to_u8()..=opcodes::OP_PUSHNUM_16.to_u8())
                        .contains(&opcode.to_u8()) =>
                {
                    break u16::from(opcode.to_u8() - opcodes::OP_PUSHNUM_1.to_u8() + 1);
                }
                _ => return Err(Error::InvalidSignerScript),
            }
        };

        match instructions.next().transpose() {
            Ok(Some(Instruction::Op(opcodes::OP_NUMEQUAL))) => {}
            _ => return Err(Error::InvalidSignerScript),
        }
        if instructions.next().is_some() {
            return Err(Error::InvalidSignerScript);
        }

        let key_set = Self::new(public_keys, signatures_required)?;
        if key_set.signing_script().as_script() != signing_script {
            return Err(Error::InvalidSignerScript);
        }
        Ok(key_set)
    }

    /// Construct the descriptor-compatible `multi_a` tapscript.
    pub fn signing_script(&self) -> ScriptBuf {
        let mut builder = ScriptBuf::builder();
        for (index, key) in self.public_keys.iter().enumerate() {
            builder = builder
                .push_slice(key.serialize())
                .push_opcode(if index == 0 {
                    opcodes::OP_CHECKSIG
                } else {
                    opcodes::OP_CHECKSIGADD
                });
        }
        builder
            .push_int(i64::from(self.signatures_required))
            .push_opcode(opcodes::OP_NUMEQUAL)
            .into_script()
    }

    /// Construct the single-leaf Taproot spend information for the signer UTXO.
    pub fn taproot(&self) -> TaprootSpendInfo {
        let (script, leaf_version) = self.script_and_leaf_version();
        let node = NodeInfo::new_leaf_with_ver(script, leaf_version);
        TaprootSpendInfo::from_node_info(SECP256K1, *crate::V2_UNSPENDABLE_TAPROOT_KEY, node)
    }

    /// Construct the signer UTXO scriptPubKey.
    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.taproot().output_key())
    }

    /// Return the control block for the signer UTXO's sole script leaf.
    pub fn control_block(&self) -> bitcoin::taproot::ControlBlock {
        // SAFETY: The TaprootSpendInfo::control_block function can only
        // fail if the input signing script, leaf version pair is not part
        // of the spend info. However, we know that it is, from the taproot
        // function above.
        self.taproot()
            .control_block(&self.script_and_leaf_version())
            .expect("the signing script is the sole leaf")
    }

    /// Return the signing script and leaf version for the signer UTXO.
    fn script_and_leaf_version(&self) -> (ScriptBuf, LeafVersion) {
        (self.signing_script(), LeafVersion::TapScript)
    }
}

#[cfg(any(test, feature = "testing"))]
impl SignerKeySet {
    /// Return the output descriptor, without a checksum, for the signer
    /// UTXO locked by this key set.
    ///
    /// The descriptor lists the derived signing keys in sorted order, so
    /// its `multi_a` script is exactly [`SignerKeySet::signing_script`].
    pub fn descriptor(&self) -> String {
        let keys = self
            .public_keys
            .iter()
            .map(XOnlyPublicKey::to_string)
            .collect::<Vec<_>>();
        format!(
            "tr({},multi_a({},{}))",
            *crate::V2_UNSPENDABLE_TAPROOT_KEY,
            self.signatures_required,
            keys.join(",")
        )
    }
}

/// Return the output descriptor, without a checksum, for the signer UTXO
/// locked by the key set derived from the given configured signer public
/// keys.
///
/// Unlike [`SignerKeySet::descriptor`], this descriptor lists each
/// signer's extended public key with the signing path, so a wallet that
/// parses it does the BIP32 derivation itself. Wallets only accept
/// extended keys serialized for their network, which is why this takes a
/// network.
#[cfg(any(test, feature = "testing"))]
pub fn signer_set_descriptor<I>(
    public_keys: I,
    signatures_required: u16,
    network: NetworkKind,
) -> String
where
    I: IntoIterator<Item = PublicKey>,
{
    let path = bitcoin::bip32::DerivationPath::from(SIGNING_PATH.as_slice());
    let keys = public_keys
        .into_iter()
        .map(|public_key| {
            let xpub = Xpub {
                network,
                ..signer_xpub(public_key)
            };
            format!("{xpub}/{path}")
        })
        .collect::<Vec<_>>()
        .join(",");

    let nums_keys = *crate::V2_UNSPENDABLE_TAPROOT_KEY;

    format!("tr({nums_keys},sortedmulti_a({signatures_required},{keys}))")
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use secp256k1::PublicKey;
    use secp256k1::SecretKey;
    use test_case::test_case;

    use super::*;

    #[test]
    fn public_and_private_derivation_match() {
        let secret_key = SecretKey::new(&mut OsRng);
        let public_key = PublicKey::from_secret_key(SECP256K1, &secret_key);
        let derived_secret = derive_signing_secret_key(secret_key);
        let from_secret = derived_secret.x_only_public_key(SECP256K1).0;
        let from_public = derive_signing_public_key(public_key);
        assert_eq!(from_secret, from_public);
    }

    #[test]
    fn key_set_is_order_independent() {
        let keys: Vec<_> = (0..4)
            .map(|_| SecretKey::new(&mut OsRng).x_only_public_key(SECP256K1).0)
            .collect();
        let mut reversed = keys.clone();
        reversed.reverse();
        let first = SignerKeySet::new(keys, 3).unwrap();
        let second = SignerKeySet::new(reversed, 3).unwrap();
        assert_eq!(first.id(), second.id());
        assert_eq!(first.signing_script(), second.signing_script());
        assert_eq!(first.script_pubkey(), second.script_pubkey());
    }

    #[test]
    fn key_set_rejects_more_than_sixteen_signers() {
        let keys = (0..17)
            .map(|_| SecretKey::new(&mut OsRng).x_only_public_key(SECP256K1).0)
            .collect::<Vec<_>>();
        std::assert_matches!(
            SignerKeySet::new(keys, 12),
            Err(Error::TooManySignerKeys {
                signer_count: 17,
                max_signers: MAX_SIGNERS,
            })
        );
    }

    /// The bootstrap signing set in the devenv signer config.
    const DEVENV_SIGNER_KEYS: [&str; 3] = [
        "035249137286c077ccee65ecc43e724b9b9e5a588e3d7f51e3b62f9624c2a49e46",
        "031a4d9f4903da97498945a4e01a5023a1d53bc96ad670bfe03adf8a06c52e6380",
        "02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c",
    ];

    /// The bootstrap signing set in the sample testnet signer config.
    const TESTNET_SIGNER_KEYS: [&str; 15] = [
        "03fc6197a1396680f7acc4241ac3935ba4af560deac0224abec45c47c5e73ea638",
        "0390d76b21867e9c5aa25a903423d3ddb0da65604f0470390ed903f2056c5adb4b",
        "03fb16c76ae6773951b2ea957f723dc0f5f4ccd795313793308a38a37a3c4aa582",
        "024681893c76fb2d52bdbcd6341c66f15f14698aed638d6c1a2fc9440948b5f11a",
        "0341a8f3562d805ab240c2ce2dd220313329ef75459f115bd818b250a2ad2df6aa",
        "02a963be44cd7efd07e59e28f02f5d2bafdf28b5b13b3b13b5c2a9e3f4c1b1e5bf",
        "03c4382afb075bf577acbb13196e6130c386a3d8261326402f587fb7c42d0dbd5e",
        "02c2b53974a2b1a05103a7c42a4861c859c9b999ed196c065bcec952438ae8ec9b",
        "034646af6402dab3a265688b2ea67a7aa88d9fc6eca663385a6e92336f7f081c59",
        "02629d043197e659ac45f0332b219760b9542d22499ff6431c113ec64d60e86628",
        "033f3dd6b1e8e4cfff219054dce240d312b6deda10386c3a815459224a2ba0f411",
        "031c7e1267b272d5a11257f46c61e0e5005337ebcebb6f2b71798addfd04e5a38a",
        "02ae3a560f4f67ce8c0f4b2e46d24f51232a768cfc69cf08a02ea02426d77bd64c",
        "026fb0b3c3ea60a3197e94f2dcd37d7f302e6d33c75351f4f5024e9c31ac327c11",
        "0374e256948a14799c2a788960ab6657dc5d322b070abae4ce83b2a0df4df2c727",
    ];

    /// A randomly generated key, for a key set with a single signer.
    const RANDOM_SIGNER_KEYS: [&str; 1] =
        ["027212421e4a9c34e251a7cd523146c4434451e42c230d576b07fe8874f97a694d"];

    /// Signer UTXOs locked by a key set must stay spendable by that key
    /// set, so the scriptPubKey that we derive from the signers' public
    /// keys and threshold must never change.
    ///
    /// Each expected scriptPubKey was checked against Bitcoin Core, which
    /// derives the same address from the descriptor returned by
    /// [`signer_set_descriptor`] with [`NetworkKind::Test`]. Bitcoin Core does the
    /// BIP32 derivation itself, so this also checks our derivation. To
    /// repeat the check, run
    ///
    /// ```text
    /// bitcoin-cli -regtest getdescriptorinfo "<descriptor>"
    /// bitcoin-cli -regtest deriveaddresses "<descriptor with checksum>"
    /// ```
    ///
    /// and compare the result with the regtest address of the expected
    /// scriptPubKey.
    #[test_case(
        DEVENV_SIGNER_KEYS, 2,
        "512044d42c5fdc191818e50ec6591d2103f17ec2771c1a0ea5dc1db95ca56dd377b5";
        "devenv 2-of-3"
    )]
    #[test_case(
        TESTNET_SIGNER_KEYS, 11,
        "512036beeeb78d2eff65baa60f8da199b5ecd06ee833dd3c8f6340f8b6d4102a595c";
        "testnet 11-of-15"
    )]
    #[test_case(
        RANDOM_SIGNER_KEYS, 1,
        "5120a014d46c5ec41d7d059755296e1d12566ca7416d3707a7789d2a3c88ee1eeca2";
        "random 1-of-1"
    )]
    fn key_set_script_pubkey_is_stable<const N: usize>(
        signer_keys: [&str; N],
        signatures_required: u16,
        expected_script_pubkey: &str,
    ) {
        let public_keys = signer_keys
            .iter()
            .map(|key| key.parse::<PublicKey>().unwrap());
        let key_set = SignerKeySet::derive(public_keys, signatures_required).unwrap();

        let script_pubkey = key_set.script_pubkey();
        assert_eq!(script_pubkey.to_hex_string(), expected_script_pubkey);
    }
}
