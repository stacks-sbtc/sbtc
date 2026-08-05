//! Measures contract-source to event-webhook ABI expansion.
//!
//! Clarity function return types are inferred. Reusing one large tuple from
//! many small private functions therefore causes stacks-core's event
//! dispatcher to serialize the tuple type once per function. Private
//! functions are included in the published contract interface, even though
//! `contract_analysis_size` only counts public and read-only functions.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use blockstack_lib::chainstate::stacks::index::ClarityMarfTrieId as _;
use blockstack_lib::clarity_vm::clarity::ClarityInstance;
use blockstack_lib::clarity_vm::database::marf::MarfedKV;
use clarity::vm::analysis::contract_interface_builder::build_contract_interface;
use clarity::vm::analysis::mem_type_check;
use clarity::vm::clarity::TransactionConnection as _;
use clarity::vm::test_util::{TEST_BURN_STATE_DB, TEST_HEADER_DB, generate_test_burn_state_db};
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::{ClarityVersion, ContractName};
use signer::api::ApiState;
use signer::testing::context::TestContext;
use stacks_common::types::StacksEpochId;
use stacks_common::types::chainstate::StacksBlockId;
use tower::ServiceExt as _;

fn expansion_contract(tuple_fields: usize, functions: usize) -> String {
    let mut source = String::from("(define-constant shared {");
    for field in 0..tuple_fields {
        if field != 0 {
            source.push(',');
        }
        source.push_str(&format!("k{field}:u0"));
    }
    source.push_str("})");

    for function in 0..functions {
        source.push_str(&format!("(define-private (f{function}) (ok shared))"));
    }
    source
}

#[test]
fn inferred_return_types_amplify_contract_interface() {
    let tuple_fields = std::env::var("ABI_FIELDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100);
    let functions = std::env::var("ABI_FUNCTIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000);
    let source = expansion_contract(tuple_fields, functions);
    let (_, analysis) = mem_type_check(&source, ClarityVersion::Clarity3, StacksEpochId::Epoch33)
        .expect("generated contract must pass Clarity analysis");
    let interface =
        build_contract_interface(&analysis).expect("contract interface must be serializable");
    let json = interface
        .serialize()
        .expect("contract interface must serialize to JSON");

    println!(
        "source={} interface={} expansion={:.2}",
        source.len(),
        json.len(),
        json.len() as f64 / source.len() as f64
    );

    assert!(json.len() > source.len());
}

/// Runs the same contract through a cost-tracked Epoch 3.3 Clarity block.
///
/// This is ignored because the full 256 MiB reproduction intentionally uses
/// around 2.5 GiB of peak memory and takes tens of seconds in an unoptimized
/// build. It proves that the small source is accepted under consensus cost
/// accounting; the oversized interface is not an automated-scanner artifact.
#[test]
#[ignore = "slow, memory-intensive production-cost proof"]
fn full_payload_is_accepted_by_cost_tracked_clarity() {
    let source = expansion_contract(1_000, 8_200);
    let mut clarity = ClarityInstance::new(false, 0x8000_0000, MarfedKV::temporary());

    let genesis = StacksBlockId([0xf0; 32]);
    clarity
        .begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &genesis,
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        )
        .commit_to_block(&genesis);

    let mut tip = genesis;
    for (height, epoch) in [
        StacksEpochId::Epoch2_05,
        StacksEpochId::Epoch21,
        StacksEpochId::Epoch30,
        StacksEpochId::Epoch33,
    ]
    .into_iter()
    .enumerate()
    {
        let next = StacksBlockId([(height + 1) as u8; 32]);
        let burn_state = generate_test_burn_state_db(epoch);
        let mut block = clarity.begin_block(&tip, &next, &TEST_HEADER_DB, &burn_state);
        match epoch {
            StacksEpochId::Epoch2_05 => {
                block.initialize_epoch_2_05().unwrap();
            }
            StacksEpochId::Epoch21 => {
                block.initialize_epoch_2_1().unwrap();
            }
            StacksEpochId::Epoch30 => {
                block.initialize_epoch_3_0().unwrap();
            }
            StacksEpochId::Epoch33 => {
                block.initialize_epoch_3_3().unwrap();
            }
            _ => unreachable!(),
        }
        block.commit_to_block(&next);
        tip = next;
    }

    let burn_state = generate_test_burn_state_db(StacksEpochId::Epoch33);
    let next = StacksBlockId([0xaa; 32]);
    let mut block = clarity.begin_block(&tip, &next, &TEST_HEADER_DB, &burn_state);
    let contract_id = QualifiedContractIdentifier::new(
        clarity::vm::types::StandardPrincipalData::transient(),
        ContractName::from("abi-poc"),
    );

    let interface_json = block.as_transaction(|tx| {
        let (ast, analysis) = tx
            .analyze_smart_contract(&contract_id, ClarityVersion::Clarity3, &source)
            .unwrap();
        tx.initialize_smart_contract(
            &contract_id,
            ClarityVersion::Clarity3,
            &ast,
            &source,
            None,
            |_, _| None,
            None,
        )
        .unwrap();
        tx.save_analysis(&contract_id, &analysis).unwrap();

        build_contract_interface(&analysis)
            .unwrap()
            .serialize()
            .unwrap()
    });
    let cost = block.commit_to_block(&next).get_total();
    let interface_len = interface_json.len();

    println!(
        "source={} interface={} limit={} cost={cost}",
        source.len(),
        interface_len,
        signer::NEW_BLOCK_BODY_LIMIT,
    );
    assert!(source.len() < 2 * 1024 * 1024);
    assert!(interface_len > signer::NEW_BLOCK_BODY_LIMIT);

    // The real `new_block` body contains this interface plus the block and
    // transaction envelope. Posting the interface alone is therefore a
    // conservative endpoint reproduction: Axum rejects it before the handler
    // can parse or persist the block.
    let context = TestContext::default_mocked();
    let app =
        signer::api::get_router(signer::NEW_BLOCK_BODY_LIMIT).with_state(ApiState { ctx: context });
    let request = Request::builder()
        .uri("/new_block")
        .method(Method::POST)
        .body(Body::from(interface_json))
        .unwrap();
    let status = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { app.oneshot(request).await.unwrap().status() });
    println!("endpoint_status={status}");
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}
