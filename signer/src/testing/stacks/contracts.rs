//! Test helpers for dealing with Stacks contracts and transactions in tests.

use std::collections::BTreeSet;

use bitcoin::{OutPoint, hashes::Hash};
use blockstack_lib::chainstate::stacks::TransactionContractCall;
use blockstack_lib::clarity::vm::Value as ClarityValue;
use clarity::vm::types::PrincipalData;

use crate::{
    keys::PublicKey,
    stacks::contracts::{
        AcceptWithdrawalV1, AsContractCall, CompleteDepositV1, RejectWithdrawalV1, RotateKeysV1,
    },
};

/// An error that can occur when parsing a contract call in the Stacks blockchain.
#[derive(Debug, thiserror::Error)]
pub enum ParseContractCallError {
    /// Error when a contract call is made with an unexpected contract name.
    #[error("Unexpected contract name: expected {expected}, actual {actual}")]
    UnexpectedContractName {
        /// The expected contract name.
        expected: &'static str,
        /// The actual contract name received.
        actual: String,
    },

    /// Error when a contract call is made with an unexpected function name.
    #[error("Unexpected contract function name: expected {expected}, actual {actual}")]
    UnexpectedFunctionName {
        /// The expected function name.
        expected: &'static str,
        /// The actual function name received.
        actual: String,
    },

    /// Error when a contract call is missing an expected argument at a specific position.
    #[error("Missing contract call argument at pos {pos} for {contract_name}.{function_name}()")]
    MissingContractCallArg {
        /// The position of the missing argument.
        pos: usize,
        /// The name of the contract where the function is defined.
        contract_name: &'static str,
        /// The name of the function being called.
        function_name: &'static str,
    },

    /// Error when a contract call argument is invalid at a specific position.
    #[error(
        "Invalid contract call argument at pos {pos} for {contract_name}.{function_name}() - {source}"
    )]
    InvalidContractCallArg {
        /// The position of the invalid argument.
        pos: usize,
        /// The name of the contract where the function is defined.
        contract_name: &'static str,
        /// The name of the function being called.
        function_name: &'static str,
        /// The source error that explains why the argument is invalid.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// An enum representing the kinds of contract calls that the signers can make.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ContractCallKind {
    /// A `complete-deposit-wrapper` function call in the `sbtc-deposit` smart
    /// contract
    CompleteDepositV1,
    /// A `accept-withdrawal-request` function call in the `sbtc-withdrawal`
    /// smart contract.
    AcceptWithdrawalV1,
    /// A `reject-withdrawal-request` function call in the `sbtc-withdrawal`
    /// smart contract.
    RejectWithdrawalV1,
    /// A `rotate-keys-wrapper` function call in the `sbtc-bootstrap-signers`
    /// smart contract.
    RotateKeysV1,
}

/// A trait for parsing a Stacks [`TransactionContractCall`] into one of the
/// sBTC contract call types.
pub trait TryFromContractCall<'a>:
    AsContractCall + TryFrom<&'a TransactionContractCall, Error = ParseContractCallError>
{
    /// Validate that the contract call is for the correct contract.
    fn validate_contract_name(
        call: &TransactionContractCall,
    ) -> Result<(), ParseContractCallError> {
        if call.contract_name.as_str() != Self::CONTRACT_NAME {
            return Err(ParseContractCallError::UnexpectedContractName {
                expected: Self::CONTRACT_NAME,
                actual: call.contract_name.to_string(),
            });
        }
        Ok(())
    }

    /// Validate that the contract call is for the correct function.
    fn validate_function_name(
        call: &TransactionContractCall,
    ) -> Result<(), ParseContractCallError> {
        if call.function_name.as_str() != Self::FUNCTION_NAME {
            return Err(ParseContractCallError::UnexpectedFunctionName {
                expected: Self::FUNCTION_NAME,
                actual: call.function_name.to_string(),
            });
        }
        Ok(())
    }
}

/// A trait for determining the kind of contract call that this is.
pub trait GetContractCallKind {
    /// The kind of contract call that this is.
    fn kind(&self) -> Option<ContractCallKind>;
}

impl GetContractCallKind for TransactionContractCall {
    fn kind(&self) -> Option<ContractCallKind> {
        match (self.contract_name.as_str(), self.function_name.as_str()) {
            (CompleteDepositV1::CONTRACT_NAME, CompleteDepositV1::FUNCTION_NAME) => {
                Some(ContractCallKind::CompleteDepositV1)
            }
            (AcceptWithdrawalV1::CONTRACT_NAME, AcceptWithdrawalV1::FUNCTION_NAME) => {
                Some(ContractCallKind::AcceptWithdrawalV1)
            }
            (RejectWithdrawalV1::CONTRACT_NAME, RejectWithdrawalV1::FUNCTION_NAME) => {
                Some(ContractCallKind::RejectWithdrawalV1)
            }
            (RotateKeysV1::CONTRACT_NAME, RotateKeysV1::FUNCTION_NAME) => {
                Some(ContractCallKind::RotateKeysV1)
            }
            _ => None,
        }
    }
}

impl TryFromContractCall<'_> for CompleteDepositV1 {}

impl TryFrom<&TransactionContractCall> for CompleteDepositV1 {
    type Error = ParseContractCallError;

    fn try_from(call: &TransactionContractCall) -> Result<Self, Self::Error> {
        Self::validate_contract_name(call)?;
        Self::validate_function_name(call)?;

        let deployer = call.address;
        let args = &call.function_args;

        // Argument 0: txid (buff 32) for outpoint
        let mut outpoint_txid_bytes =
            args.try_parse_buff(0, 32, Self::CONTRACT_NAME, Self::FUNCTION_NAME)?;
        outpoint_txid_bytes.reverse();
        let outpoint_txid = bitcoin::Txid::from_slice(&outpoint_txid_bytes).map_err(|e| {
            map_contract_call_arg_error(e, 0, Self::CONTRACT_NAME, Self::FUNCTION_NAME)
        })?;

        // Argument 1: vout (uint) for outpoint
        let vout_u64 = args.try_parse_u64(1, Self::CONTRACT_NAME, Self::FUNCTION_NAME)?;
        let vout = u32::try_from(vout_u64).map_err(|e| {
            map_contract_call_arg_error(e, 1, Self::CONTRACT_NAME, Self::FUNCTION_NAME)
        })?;
        let outpoint = OutPoint { txid: outpoint_txid, vout };

        // Argument 2: amount (uint)
        let amount = args.try_parse_u64(2, Self::CONTRACT_NAME, Self::FUNCTION_NAME)?;

        // Argument 3: recipient (principal)
        let recipient = args.try_parse_principal(3, Self::CONTRACT_NAME, Self::FUNCTION_NAME)?;

        // Argument 4: sweep_block_hash (buff 32)
        let sweep_block_hash = args
            .try_parse_bitcoin_block_hash(4, Self::CONTRACT_NAME, Self::FUNCTION_NAME)?
            .into();

        // Argument 5: sweep_block_height (uint)
        let sweep_block_height = args
            .try_parse_u64(5, Self::CONTRACT_NAME, Self::FUNCTION_NAME)?
            .into();

        // Argument 6: sweep_txid (buff 32)
        let sweep_txid = args
            .try_parse_bitcoin_txid(6, Self::CONTRACT_NAME, Self::FUNCTION_NAME)?
            .into();

        Ok(Self {
            outpoint,
            amount,
            recipient,
            deployer,
            sweep_txid,
            sweep_block_hash,
            sweep_block_height,
        })
    }
}

impl TryFromContractCall<'_> for RotateKeysV1 {}

impl TryFrom<&TransactionContractCall> for RotateKeysV1 {
    type Error = ParseContractCallError;

    fn try_from(call: &TransactionContractCall) -> Result<Self, Self::Error> {
        Self::validate_contract_name(call)?;
        Self::validate_function_name(call)?;

        let deployer = call.address;

        let new_keys = call.function_args.try_parse_btree_set_of_public_keys(
            0,
            Self::CONTRACT_NAME,
            Self::FUNCTION_NAME,
        )?;

        let aggregate_key =
            call.function_args
                .try_parse_public_key(1, Self::CONTRACT_NAME, Self::FUNCTION_NAME)?;

        let signatures_required =
            call.function_args
                .try_parse_u16(2, Self::CONTRACT_NAME, Self::FUNCTION_NAME)?;

        Ok(Self {
            new_keys,
            aggregate_key,
            deployer,
            signatures_required,
        })
    }
}

// Helper for mapping general conversion errors (like TryFromIntError)
fn map_contract_call_arg_error<E: std::error::Error + Send + Sync + 'static>(
    source: E,
    pos: usize,
    contract_name: &'static str,
    function_name: &'static str,
) -> ParseContractCallError {
    ParseContractCallError::InvalidContractCallArg {
        pos,
        contract_name,
        function_name,
        source: Box::new(source),
    }
}

/// Extension trait for working with parsing contract-call arguments in a more ergonomic way.
pub trait ClarityArgsExt {
    /// Tries to get a reference to a `ClarityValue` at a specific position.
    fn try_get_arg(
        &self,
        pos: usize,
        contract_name: &'static str,
        function_name: &'static str,
    ) -> Result<&ClarityValue, ParseContractCallError>;

    /// Tries to parse the argument at `pos` as a `PublicKey`.
    fn try_parse_public_key(
        &self,
        pos: usize,
        contract_name: &'static str,
        function_name: &'static str,
    ) -> Result<PublicKey, ParseContractCallError> {
        self.try_get_arg(pos, contract_name, function_name)?
            .clone()
            .expect_buff(33) // PublicKey is 33 bytes
            .map_err(|e| map_contract_call_arg_error(e, pos, contract_name, function_name))
            .map(|bytes| {
                PublicKey::from_slice(&bytes)
                    .map_err(|e| map_contract_call_arg_error(e, pos, contract_name, function_name))
            })?
    }

    /// Tries to parse the argument at `pos` as a `BTreeSet<PublicKey>`.
    fn try_parse_btree_set_of_public_keys(
        &self,
        pos: usize,
        contract_name: &'static str,
        function_name: &'static str,
    ) -> Result<BTreeSet<PublicKey>, ParseContractCallError> {
        self.try_get_arg(pos, contract_name, function_name)?
            .clone()
            .expect_list()
            .map_err(|e| map_contract_call_arg_error(e, pos, contract_name, function_name))?
            .into_iter()
            .map(|clarity_value| {
                clarity_value
                    .expect_buff(33)
                    .map_err(|source| {
                        map_contract_call_arg_error(source, pos, contract_name, function_name)
                    })
                    .map(|bytes| {
                        PublicKey::from_slice(&bytes).map_err(|e| {
                            map_contract_call_arg_error(e, pos, contract_name, function_name)
                        })
                    })?
            })
            .collect::<Result<BTreeSet<_>, ParseContractCallError>>()
    }

    /// Tries to parse the argument at `pos` as a `u16`.
    fn try_parse_u16(
        &self,
        pos: usize,
        contract_name: &'static str,
        function_name: &'static str,
    ) -> Result<u16, ParseContractCallError> {
        self.try_get_arg(pos, contract_name, function_name)?
            .clone()
            .expect_u128()
            .map_err(|e| map_contract_call_arg_error(e, pos, contract_name, function_name))?
            .try_into()
            .map_err(|e| map_contract_call_arg_error(e, pos, contract_name, function_name))
    }

    /// Tries to parse the argument at `pos` as a `u64`.
    fn try_parse_u64(
        &self,
        pos: usize,
        contract_name: &'static str,
        function_name: &'static str,
    ) -> Result<u64, ParseContractCallError> {
        self.try_get_arg(pos, contract_name, function_name)?
            .clone()
            .expect_u128()
            .map_err(|e| map_contract_call_arg_error(e, pos, contract_name, function_name))?
            .try_into()
            .map_err(|e| map_contract_call_arg_error(e, pos, contract_name, function_name))
    }

    /// Tries to parse the argument at `pos` as [`PrincipalData`].
    fn try_parse_principal(
        &self,
        pos: usize,
        contract_name: &'static str,
        function_name: &'static str,
    ) -> Result<PrincipalData, ParseContractCallError> {
        self.try_get_arg(pos, contract_name, function_name)?
            .clone()
            .expect_principal()
            .map_err(|e| map_contract_call_arg_error(e, pos, contract_name, function_name))
    }

    /// Tries to parse the argument at `pos` as a buffer of a specific length,
    /// returning a `Vec<u8>`.
    fn try_parse_buff(
        &self,
        pos: usize,
        len: usize,
        contract_name: &'static str,
        function_name: &'static str,
    ) -> Result<Vec<u8>, ParseContractCallError> {
        let buff = self
            .try_get_arg(pos, contract_name, function_name)?
            .clone()
            .expect_buff(len)
            .map_err(|e| map_contract_call_arg_error(e, pos, contract_name, function_name))?;

        // Apparently `expect_buff` does not guarantee the length, so we check it here.
        if buff.len() != len {
            return Err(ParseContractCallError::InvalidContractCallArg {
                pos,
                contract_name,
                function_name,
                source: format!("Expected buffer of length {}, got {}", len, buff.len()).into(),
            });
        }

        Ok(buff)
    }

    /// Tries to parse the argument at `pos` as a Bitcoin transaction ID ([`bitcoin::Txid`]).
    fn try_parse_bitcoin_txid(
        &self,
        pos: usize,
        contract_name: &'static str,
        function_name: &'static str,
    ) -> Result<bitcoin::Txid, ParseContractCallError> {
        let outpoint_txid_bytes = self.try_parse_buff(pos, 32, contract_name, function_name)?;
        bitcoin::Txid::from_slice(&outpoint_txid_bytes)
            .map_err(|e| map_contract_call_arg_error(e, pos, contract_name, function_name))
    }

    /// Tries to parse the argument at `pos` as a Bitcoin block hash ([`bitcoin::BlockHash`]).
    fn try_parse_bitcoin_block_hash(
        &self,
        pos: usize,
        contract_name: &'static str,
        function_name: &'static str,
    ) -> Result<bitcoin::BlockHash, ParseContractCallError> {
        self.try_get_arg(pos, contract_name, function_name)?
            .clone()
            .expect_buff(32) // StacksBlockHash is 32 bytes
            .map_err(|e| map_contract_call_arg_error(e, pos, contract_name, function_name))
            .map(|bytes| {
                bitcoin::BlockHash::from_slice(&bytes)
                    .map_err(|e| map_contract_call_arg_error(e, pos, contract_name, function_name))
            })?
    }
}

impl ClarityArgsExt for Vec<ClarityValue> {
    fn try_get_arg(
        &self,
        pos: usize,
        contract_name: &'static str,
        function_name: &'static str,
    ) -> Result<&ClarityValue, ParseContractCallError> {
        self.get(pos)
            .ok_or_else(|| ParseContractCallError::MissingContractCallArg {
                pos,
                contract_name,
                function_name,
            })
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use bitcoin::{BlockHash, Txid};
    use clarity::{
        types::chainstate::StacksAddress,
        vm::{
            ClarityName, ContractName,
            types::{BuffData, ListData, ListTypeData, SequenceData},
        },
    };
    use fake::{Fake, Faker};
    use test_case::test_case;

    use crate::testing::get_rng;

    use super::*;

    const TEST_CONTRACT_NAME: &str = "test-contract";
    const TEST_FUNCTION_NAME: &str = "test-function";

    fn clarity_buff(data: &[u8]) -> ClarityValue {
        ClarityValue::Sequence(SequenceData::Buffer(BuffData { data: data.to_vec() }))
    }

    fn clarity_uint(val: u128) -> ClarityValue {
        ClarityValue::UInt(val)
    }

    fn clarity_list(items: Vec<ClarityValue>, list_type_data: ListTypeData) -> ClarityValue {
        ClarityValue::Sequence(SequenceData::List(ListData {
            data: items,
            type_signature: list_type_data,
        }))
    }

    fn clarity_principal(address: StacksAddress) -> ClarityValue {
        ClarityValue::Principal(PrincipalData::from(address))
    }

    fn clarity_dummy_public_key() -> ClarityValue {
        let mut rng = get_rng();
        let public_key: PublicKey = Faker.fake_with_rng(&mut rng);
        let serialized = public_key.serialize().to_vec();
        clarity_buff(&serialized)
    }

    fn create_dummy_rotate_keys_call(
        contract_name_str: &'static str,
        function_name_str: &'static str,
        args: Vec<ClarityValue>,
        deployer_addr: StacksAddress,
    ) -> TransactionContractCall {
        TransactionContractCall {
            address: deployer_addr,
            contract_name: ContractName::from(contract_name_str),
            function_name: ClarityName::from(function_name_str),
            function_args: args,
        }
    }

    fn create_dummy_complete_deposit_call(
        contract_name_str: &'static str,
        function_name_str: &'static str,
        args: Vec<ClarityValue>,
        deployer_addr: StacksAddress,
    ) -> TransactionContractCall {
        TransactionContractCall {
            address: deployer_addr,
            contract_name: ContractName::from(contract_name_str),
            function_name: ClarityName::from(function_name_str),
            function_args: args,
        }
    }

    #[test]
    fn get_arg_success() {
        let args = vec![clarity_uint(123)];
        let arg = args
            .try_get_arg(0, TEST_CONTRACT_NAME, TEST_FUNCTION_NAME)
            .unwrap();
        assert_eq!(*arg, clarity_uint(123));
    }

    #[test]
    fn get_arg_missing() {
        let args = vec![clarity_uint(123)];
        let result = args.try_get_arg(1, TEST_CONTRACT_NAME, TEST_FUNCTION_NAME);
        assert_matches!(
            result,
            Err(ParseContractCallError::MissingContractCallArg { pos: 1, .. })
        );
    }

    #[test_case(vec![clarity_dummy_public_key()], 0, true; "valid public key")]
    #[test_case(vec![clarity_uint(1)], 0, false; "wrong type for public key")]
    #[test_case(vec![clarity_buff(&[0;32])], 0, false; "public key wrong length")]
    #[test_case(vec![clarity_buff(&[0;33])], 0, false; "public key invalid bytes")] // Counting all-zeroes as invalid
    #[test_case(vec![], 0, false; "public key missing argument")]
    fn test_try_parse_public_key(args: Vec<ClarityValue>, pos: usize, should_succeed: bool) {
        let result = args.try_parse_public_key(pos, TEST_CONTRACT_NAME, TEST_FUNCTION_NAME);
        if should_succeed {
            assert_matches!(result, Ok(public_key) if public_key.serialize().len() == 33);
        } else {
            assert!(result.is_err());
            if args.is_empty() {
                assert_matches!(
                    result,
                    Err(ParseContractCallError::MissingContractCallArg { .. })
                );
            } else {
                assert_matches!(
                    result,
                    Err(ParseContractCallError::InvalidContractCallArg { .. })
                );
            }
        }
    }

    #[test]
    fn test_try_parse_btree_set_of_public_keys_success_empty() {
        let list_type = RotateKeysV1::list_data_type().clone();
        let args = vec![clarity_list(vec![], list_type)];
        let result =
            args.try_parse_btree_set_of_public_keys(0, TEST_CONTRACT_NAME, TEST_FUNCTION_NAME);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_try_parse_btree_set_of_public_keys_success_one_item() {
        let rng = &mut get_rng();
        let list_type = RotateKeysV1::list_data_type().clone();
        let public_key: PublicKey = Faker.fake_with_rng(rng);
        let pk_clarity = clarity_buff(&public_key.serialize());
        let args = vec![clarity_list(vec![pk_clarity], list_type)];
        let result =
            args.try_parse_btree_set_of_public_keys(0, TEST_CONTRACT_NAME, TEST_FUNCTION_NAME);
        assert!(result.is_ok());
        let set = result.unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&public_key));
    }

    #[test_case(vec![clarity_uint(1)], 0; "not a list")]
    #[test_case(vec![clarity_list(vec![clarity_uint(1)], RotateKeysV1::list_data_type().clone())], 0; "item wrong type")]
    #[test_case(vec![clarity_list(vec![clarity_buff(&[0;32])], RotateKeysV1::list_data_type().clone())], 0; "item wrong length")]
    #[test_case(vec![clarity_list(vec![clarity_buff(&[0;33])], RotateKeysV1::list_data_type().clone())], 0; "item invalid bytes")]
    #[test_case(vec![], 0; "missing argument for list")]
    fn test_try_parse_btree_set_of_public_keys_failures(args: Vec<ClarityValue>, pos: usize) {
        let result =
            args.try_parse_btree_set_of_public_keys(pos, TEST_CONTRACT_NAME, TEST_FUNCTION_NAME);
        assert!(result.is_err());
        if args.is_empty() {
            assert_matches!(
                result,
                Err(ParseContractCallError::MissingContractCallArg { .. })
            );
        } else {
            assert_matches!(
                result,
                Err(ParseContractCallError::InvalidContractCallArg { .. })
            );
        }
    }

    #[test_case(vec![clarity_uint(100)], 0, true, 100u16; "valid u16")]
    #[test_case(vec![clarity_uint(u16::MAX as u128)], 0, true, u16::MAX; "max u16")]
    #[test_case(vec![clarity_buff(&[0])], 0, false, 0u16; "u16 wrong type")]
    #[test_case(vec![clarity_uint(u16::MAX as u128 + 1)], 0, false, 0u16; "u16 overflow")]
    #[test_case(vec![], 0, false, 0u16; "u16 missing argument")]
    fn test_try_parse_u16(
        args: Vec<ClarityValue>,
        pos: usize,
        should_succeed: bool,
        expected_val: u16,
    ) {
        let result = args.try_parse_u16(pos, TEST_CONTRACT_NAME, TEST_FUNCTION_NAME);
        if should_succeed {
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), expected_val);
        } else {
            assert!(result.is_err());
        }
    }

    #[test_case(vec![clarity_uint(100000)], 0, true, 100000u64; "valid u64")]
    #[test_case(vec![clarity_uint(u64::MAX as u128)], 0, true, u64::MAX; "max u64")]
    #[test_case(vec![clarity_buff(&[0])], 0, false, 0u64; "u64 wrong type")]
    #[test_case(vec![clarity_uint(u64::MAX as u128 + 1)], 0, false, 0u64; "u64 overflow")]
    #[test_case(vec![], 0, false, 0u64; "u64 missing argument")]
    fn test_try_parse_u64(
        args: Vec<ClarityValue>,
        pos: usize,
        should_succeed: bool,
        expected_val: u64,
    ) {
        let result = args.try_parse_u64(pos, TEST_CONTRACT_NAME, TEST_FUNCTION_NAME);
        if should_succeed {
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), expected_val);
        } else {
            assert!(result.is_err());
        }
    }

    #[test_case(vec![clarity_buff(&[1,2,3])], 0, 3, true, vec![1,2,3]; "valid buff")]
    #[test_case(vec![clarity_uint(1)], 0, 3, false, vec![]; "buff wrong type")]
    #[test_case(vec![clarity_buff(&[1,2])], 0, 3, false, vec![]; "buff wrong length")]
    #[test_case(vec![], 0, 3, false, vec![]; "buff missing argument")]
    fn test_try_parse_buff(
        args: Vec<ClarityValue>,
        pos: usize,
        len: usize,
        should_succeed: bool,
        expected_val: Vec<u8>,
    ) {
        let result = args.try_parse_buff(pos, len, TEST_CONTRACT_NAME, TEST_FUNCTION_NAME);
        if should_succeed {
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), expected_val);
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_try_from_contract_call_validate_names() {
        let valid_call = create_dummy_rotate_keys_call(
            RotateKeysV1::CONTRACT_NAME,
            RotateKeysV1::FUNCTION_NAME,
            vec![],
            StacksAddress::burn_address(false),
        );
        assert!(RotateKeysV1::validate_contract_name(&valid_call).is_ok());
        assert!(RotateKeysV1::validate_function_name(&valid_call).is_ok());

        let wrong_contract_call = create_dummy_rotate_keys_call(
            "wrong-contract",
            RotateKeysV1::FUNCTION_NAME,
            vec![],
            StacksAddress::burn_address(false),
        );
        assert!(RotateKeysV1::validate_contract_name(&wrong_contract_call).is_err());

        let wrong_function_call = create_dummy_rotate_keys_call(
            RotateKeysV1::CONTRACT_NAME,
            "wrong-function",
            vec![],
            StacksAddress::burn_address(false),
        );
        assert!(RotateKeysV1::validate_function_name(&wrong_function_call).is_err());
    }

    #[test]
    fn rotate_keys_try_from_success() {
        let rng = &mut get_rng();
        let deployer = StacksAddress::burn_address(false);
        let pk1: PublicKey = Faker.fake_with_rng(rng);
        let pk2_bytes = {
            let mut b = pk1.serialize();
            b[0] ^= 1;
            b
        }; // different pk
        let pk2 = PublicKey::from_slice(&pk2_bytes).unwrap();

        let list_type = RotateKeysV1::list_data_type().clone();
        let new_keys_val = clarity_list(
            vec![
                clarity_buff(&pk1.serialize()),
                clarity_buff(&pk2.serialize()),
            ],
            list_type,
        );
        let agg_key_val = clarity_buff(&pk1.serialize());
        let sig_req_val = clarity_uint(2);

        let args = vec![new_keys_val, agg_key_val, sig_req_val];
        let call = create_dummy_rotate_keys_call(
            RotateKeysV1::CONTRACT_NAME,
            RotateKeysV1::FUNCTION_NAME,
            args,
            deployer,
        );

        let result = RotateKeysV1::try_from(&call);
        assert!(result.is_ok());
        let rotate_keys = result.unwrap();
        assert_eq!(rotate_keys.deployer, deployer);
        assert_eq!(rotate_keys.aggregate_key, pk1);
        assert_eq!(rotate_keys.signatures_required, 2);
        let expected_keys: BTreeSet<PublicKey> = [pk1, pk2].iter().cloned().collect();
        assert_eq!(rotate_keys.new_keys, expected_keys);
    }

    #[test]
    fn complete_deposit_try_from_success() {
        let deployer = StacksAddress::burn_address(false);

        let outpoint_txid_val = Txid::from_slice(&[1u8; 32]).unwrap();
        let mut outpoint_txid_clarity_bytes = outpoint_txid_val.to_raw_hash().to_byte_array();
        outpoint_txid_clarity_bytes.reverse(); // Simulating how it's stored/parsed

        let vout_val = 1u32;
        let amount_val = 100_000u64;
        let recipient_val = PrincipalData::from(StacksAddress::burn_address(true));
        let sweep_block_hash_val = BlockHash::from_slice(&[2u8; 32]).unwrap();
        let sweep_block_height_val = 123u64;
        let sweep_txid_val = Txid::from_slice(&[3u8; 32]).unwrap();

        let args = vec![
            clarity_buff(&outpoint_txid_clarity_bytes),                         // arg 0: outpoint_txid
            clarity_uint(vout_val as u128),                                     // arg 1: vout
            clarity_uint(amount_val as u128),                                   // arg 2: amount
            clarity_principal(StacksAddress::burn_address(true)),               // arg 3: recipient
            clarity_buff(&sweep_block_hash_val.to_raw_hash().to_byte_array()),  // arg 4: sweep_block_hash
            clarity_uint(sweep_block_height_val as u128),                       // arg 5: sweep_block_height
            clarity_buff(&sweep_txid_val.to_raw_hash().to_byte_array()),        // arg 6: sweep_txid
        ];

        let call = create_dummy_complete_deposit_call(
            CompleteDepositV1::CONTRACT_NAME,
            CompleteDepositV1::FUNCTION_NAME,
            args,
            deployer,
        );

        let result = CompleteDepositV1::try_from(&call);
        assert!(result.is_ok(), "try_from failed: {:?}", result.err());
        let complete_deposit = result.unwrap();

        assert_eq!(complete_deposit.deployer, deployer);
        assert_eq!(complete_deposit.outpoint.txid, outpoint_txid_val);
        assert_eq!(complete_deposit.outpoint.vout, vout_val);
        assert_eq!(complete_deposit.amount, amount_val);
        assert_eq!(complete_deposit.recipient, recipient_val);
        assert_eq!(
            complete_deposit.sweep_block_hash,
            sweep_block_hash_val.into()
        );
        assert_eq!(
            complete_deposit.sweep_block_height,
            sweep_block_height_val.into()
        );
        assert_eq!(complete_deposit.sweep_txid, sweep_txid_val.into());
    }
}
