//! Minimal Stacks node RPC client.
//!
//! Just enough of the Stacks node HTTP API to poll the sbtc-registry's
//! `current-aggregate-pubkey` data variable.
//!

use std::time::Duration;

use secp256k1::PublicKey;
use serde::Deserialize;
use url::Url;

use crate::error::Error;

/// The on-chain contract name that holds the signers' aggregate key. The
/// deployer principal is configurable, the contract name is not.
const SBTC_REGISTRY_CONTRACT: &str = "sbtc-registry";

/// The data variable inside `sbtc-registry` that holds the current
/// signers' aggregate public key.
///
/// The contract initialises the variable to a one-byte buffer containing
/// `0x00`. The signers overwrite it with the real 33-byte compressed
/// pubkey once the `rotate-keys-wrapper` contract call confirms.
const AGGREGATE_PUBKEY_DATA_VAR: &str = "current-aggregate-pubkey";

/// The Clarity binary type prefix for a `(buff N)` value.
///
/// The full framing is: one prefix byte (`0x02`), a 4-byte big-endian
/// payload length, then the payload bytes.
const CLARITY_TYPE_BUFFER: u8 = 0x02;

/// The number of header bytes preceding the buffer payload: the type
/// prefix plus the 4-byte big-endian length.
const CLARITY_BUFFER_HEADER_LEN: usize = 5;

/// Default per-request timeout for the Stacks RPC.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// A thin client for the Stacks node's HTTP RPC.
#[derive(Debug, Clone)]
pub struct StacksClient {
    /// The base URL of the Stacks node.
    base_url: Url,
    /// The HTTP client used to make the requests.
    client: reqwest::Client,
}

impl StacksClient {
    /// Build a new client that issues HTTP requests against the given
    /// node.
    pub fn new(base_url: Url) -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()?;
        Ok(Self { base_url, client })
    }

    /// Read the sbtc-registry's `current-aggregate-pubkey` data variable.
    ///
    /// Returns `Ok(None)` while the contract still holds its initial
    /// `0x00`-buffer value, and `Ok(Some(_))` once the signers have
    /// written a real key.
    pub async fn get_current_aggregate_key(
        &self,
        deployer_principal: &str,
    ) -> Result<Option<PublicKey>, Error> {
        let path = format!(
            "v2/data_var/{deployer_principal}/{SBTC_REGISTRY_CONTRACT}/{AGGREGATE_PUBKEY_DATA_VAR}?proof=0"
        );
        let url = self.base_url.join(&path)?;

        let response: DataVarResponse = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        decode_aggregate_key(&response.data)
    }
}

/// The JSON wrapper returned by `GET /v2/data_var/` RPC.
///
/// The `data` field is a hex string — the Clarity binary serialisation of
/// the data variable's value, with a `0x` prefix.
#[derive(Debug, Deserialize)]
struct DataVarResponse {
    /// Hex-encoded Clarity binary value, prefixed with `0x`.
    data: String,
}

/// Decode the hex payload returned for the aggregate-pubkey data var.
///
/// The Clarity binary framing for a `buff` value is:
///
/// ```text
/// [0x02][len: u32 BE][payload bytes]
/// ```
///
/// For `current-aggregate-pubkey` the payload is either the one-byte
/// sentinel `0x00` (initial value, mapped to `None`) or a 33-byte
/// compressed secp256k1 public key. Any other shape is treated as an
/// error.
fn decode_aggregate_key(hex_data: &str) -> Result<Option<PublicKey>, Error> {
    let trimmed = hex_data.strip_prefix("0x").unwrap_or(hex_data);
    let bytes = hex::decode(trimmed)?;

    if bytes.first() != Some(&CLARITY_TYPE_BUFFER) || bytes.len() < CLARITY_BUFFER_HEADER_LEN {
        return Err(Error::UnexpectedClarityValue);
    }
    let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    let payload = bytes
        .get(CLARITY_BUFFER_HEADER_LEN..CLARITY_BUFFER_HEADER_LEN + len)
        .ok_or(Error::UnexpectedClarityValue)?;

    if payload == [0u8] {
        return Ok(None);
    }
    Ok(Some(PublicKey::from_slice(payload)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The unset state: a one-byte buffer containing `0x00`.
    #[test]
    fn decodes_initial_sentinel_as_none() {
        // 0x02 (buffer) | 0x00000001 (length) | 0x00 (payload)
        let hex = "0x02 00000001 00".replace(' ', "");
        assert!(decode_aggregate_key(&hex).unwrap().is_none());
    }

    /// A 33-byte compressed pubkey is returned as `Some`.
    #[test]
    fn decodes_real_pubkey() {
        // Compressed pubkey for secret key = 1 (the secp256k1 generator).
        let pk_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        // 0x02 (buffer) | 0x00000021 (length = 33) | <pk bytes>
        let hex = format!("0x0200000021{pk_hex}");
        let decoded = decode_aggregate_key(&hex).unwrap().expect("Some");
        assert_eq!(hex::encode(decoded.serialize()), pk_hex);
    }

    /// A non-buffer Clarity value is a protocol error.
    #[test]
    fn rejects_non_buffer_value() {
        // 0x01 = Clarity UInt prefix
        let hex = "0x01000000000000000000000000000000000000000000000000000000000000002a";
        assert!(matches!(
            decode_aggregate_key(hex),
            Err(Error::UnexpectedClarityValue)
        ));
    }
}
