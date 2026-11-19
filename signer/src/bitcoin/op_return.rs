//! The version byte in a sweep transaction's `OP_RETURN` output, and the
//! fee assessment methods that versions select.
//!
//! This lives in its own module so that only the code here can name the
//! versions that signers read but never write.

use bitcoin::Script;
use bitcoin::Transaction;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Instruction;

use crate::storage::model::BitcoinBlockHeight;

/// The version byte in a sweep transaction's `OP_RETURN` output.
///
/// Each version fixes the rules that a sweep follows, so code that needs
/// to know how a sweep is laid out or how its fees are assessed asks the
/// version rather than reading the byte itself.
///
/// # Notes
///
/// Outside of this module, only the versions that signers write can be
/// created, through [`OpReturnVersion::V1`], [`OpReturnVersion::V2`] and
/// [`OpReturnVersion::from_chain_tip_height`]. Older versions only come
/// from parsing a sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpReturnVersion(Version);

/// The known `OP_RETURN` versions, with their byte encoding as the
/// discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Version {
    /// Withdrawal IDs are not encoded and fees are assessed
    /// proportionally. Sweeps with this version were created before
    /// withdrawals were supported, and signers no longer write it.
    V0 = 0,
    /// Withdrawal IDs are encoded with idpack and fees are assessed
    /// proportionally.
    V1 = 1,
    /// Withdrawal IDs are encoded with idpack and fees are split evenly
    /// across requests.
    V2 = 2,
}

/// The rule used to apportion a sweep transaction's miner fee to requests.
///
/// See <https://github.com/stacks-sbtc/sbtc/issues/2144>.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeAssessmentMethod {
    /// Apportion fees according to each request's transaction weight.
    Proportional,
    /// Split fees evenly across all requests, rounding each share up.
    Even,
}

impl OpReturnVersion {
    /// Withdrawal IDs are encoded with idpack and fees are assessed
    /// proportionally.
    pub const V1: Self = Self(Version::V1);

    /// Withdrawal IDs are encoded with idpack and fees are split evenly
    /// across requests.
    pub const V2: Self = Self(Version::V2);

    /// Select the version for new sweeps from the Bitcoin chain-tip block
    /// height relative to the even-fees activation height.
    pub fn from_chain_tip_height(
        chain_tip_height: BitcoinBlockHeight,
        even_fees_activation_height: BitcoinBlockHeight,
    ) -> Self {
        if chain_tip_height >= even_fees_activation_height {
            Self::V2
        } else {
            Self::V1
        }
    }

    /// Return the byte that encodes this version in the `OP_RETURN`.
    pub fn to_byte(self) -> u8 {
        self.0 as u8
    }

    /// Return the rule used to apportion the sweep's miner fee to its
    /// requests.
    pub fn fee_assessment_method(self) -> FeeAssessmentMethod {
        match self.0 {
            Version::V0 | Version::V1 => FeeAssessmentMethod::Proportional,
            Version::V2 => FeeAssessmentMethod::Even,
        }
    }

    /// Return whether the `OP_RETURN` data after the header can hold the
    /// IDs of the withdrawals serviced by the sweep.
    pub fn encodes_withdrawal_ids(self) -> bool {
        self.0 != Version::V0
    }

    /// Return the version that the given byte encodes, if it is known.
    fn from_byte(byte: u8) -> Option<Self> {
        let version = match byte {
            0 => Version::V0,
            1 => Version::V1,
            2 => Version::V2,
            _ => return None,
        };
        Some(Self(version))
    }

    /// Parse a sweep's `OP_RETURN` script into its version and the data
    /// that follows the header.
    ///
    /// The script must be an `OP_RETURN` followed by exactly one data
    /// push, and the data must hold the two magic bytes and a known
    /// version byte. This returns `None` otherwise.
    pub fn from_script(script: &Script) -> Option<(Self, &[u8])> {
        let mut instructions = script.instructions();

        let Some(Ok(Instruction::Op(OP_RETURN))) = instructions.next() else {
            return None;
        };
        let Some(Ok(Instruction::PushBytes(data))) = instructions.next() else {
            return None;
        };
        if instructions.next().is_some() {
            return None;
        }

        // The first two bytes are the magic bytes, which we do not
        // check, and the third is the version byte.
        let [_, _, version, payload @ ..] = data.as_bytes() else {
            return None;
        };
        Some((Self::from_byte(*version)?, payload))
    }

    /// Read the version from a sweep transaction, whose second output is
    /// always its `OP_RETURN` output.
    pub fn from_tx(tx: &Transaction) -> Option<Self> {
        let output = tx.output.get(1)?;
        Self::from_script(&output.script_pubkey).map(|(version, _)| version)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::ScriptBuf;
    use test_case::test_case;

    use super::*;

    /// The even-fees activation height selects the version at the
    /// boundary.
    #[test_case(99, 100, OpReturnVersion::V1; "before the boundary")]
    #[test_case(100, 100, OpReturnVersion::V2; "at the boundary")]
    #[test_case(101, 100, OpReturnVersion::V2; "after the boundary")]
    fn version_at_chain_tip_height(
        chain_height: u64,
        activation_height: u64,
        expected_version: OpReturnVersion,
    ) {
        let activation_height = BitcoinBlockHeight::from(activation_height);
        let actual_version =
            OpReturnVersion::from_chain_tip_height(chain_height.into(), activation_height);

        assert_eq!(actual_version, expected_version);
    }

    /// Each version byte parses to the rules it stands for, including
    /// version 0, which signers can read but not construct.
    #[test_case(0, FeeAssessmentMethod::Proportional, false; "version 0")]
    #[test_case(1, FeeAssessmentMethod::Proportional, true; "version 1")]
    #[test_case(2, FeeAssessmentMethod::Even, true; "version 2")]
    fn parsed_version_rules(byte: u8, fee_method: FeeAssessmentMethod, encodes_ids: bool) {
        let script = ScriptBuf::new_op_return([b'T', b'3', byte, 42]);

        let (version, payload) = OpReturnVersion::from_script(&script).unwrap();

        assert_eq!(version.to_byte(), byte);
        assert_eq!(version.fee_assessment_method(), fee_method);
        assert_eq!(version.encodes_withdrawal_ids(), encodes_ids);
        assert_eq!(payload, [42]);
    }

    /// Bytes past the last known version do not parse.
    #[test]
    fn unknown_version_byte_does_not_parse() {
        let script = ScriptBuf::new_op_return([b'T', b'3', 3]);

        assert_eq!(OpReturnVersion::from_script(&script), None);
    }
}
