use rs_soroban_ultrahonk::{Error, UltraHonkVerifierContract, UltraHonkVerifierContractClient};
use soroban_sdk::{Bytes, Env};
use ultrahonk_soroban_verifier::PROOF_BYTES;
use ultrahonk_test_utils::{mutate_byte, truncate};

fn register_client<'a>(env: &'a Env, vk_bytes: &Bytes) -> UltraHonkVerifierContractClient<'a> {
    let contract_id = env.register(UltraHonkVerifierContract, (vk_bytes.clone(),));
    UltraHonkVerifierContractClient::new(env, &contract_id)
}

#[test]
fn verify_simple_circuit_proof_succeeds() {
    let vk_bytes_raw: &[u8] = include_bytes!("../../../circuits/simple_circuit/target/vk");
    let proof_bin: &[u8] = include_bytes!("../../../circuits/simple_circuit/target/proof");
    let pub_inputs_bin: &[u8] =
        include_bytes!("../../../circuits/simple_circuit/target/public_inputs");

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    assert_eq!(proof_bin.len(), PROOF_BYTES);

    // Prepare inputs
    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    let client = register_client(&env, &vk_bytes);
    client.verify_proof(&public_inputs, &proof_bytes);
}

#[test]
fn verify_fib_chain_proof_succeeds() {
    let vk_bytes_raw: &[u8] = include_bytes!("../../../circuits/fib_chain/target/vk");
    let proof_bin: &[u8] = include_bytes!("../../../circuits/fib_chain/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("../../../circuits/fib_chain/target/public_inputs");

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    assert_eq!(proof_bin.len(), PROOF_BYTES);

    // Prepare inputs
    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    let client = register_client(&env, &vk_bytes);
    client.verify_proof(&public_inputs, &proof_bytes);
}

#[test]
fn print_budget_for_deploy_and_verify() {
    let vk_bytes_raw: &[u8] = include_bytes!("../../../circuits/simple_circuit/target/vk");
    let proof_bin: &[u8] = include_bytes!("../../../circuits/simple_circuit/target/proof");
    let pub_inputs_bin: &[u8] =
        include_bytes!("../../../circuits/simple_circuit/target/public_inputs");

    let env = Env::default();

    // Measure deploy budget usage.
    env.cost_estimate().budget().reset_unlimited();
    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);
    let client = register_client(&env, &vk_bytes);

    println!("=== Deploy budget usage ===");
    env.cost_estimate().budget().print();

    // Prepare proof inputs
    assert_eq!(proof_bin.len(), PROOF_BYTES);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    // Measure verify_proof invocation budget usage in isolation.
    env.cost_estimate().budget().reset_unlimited();
    client.verify_proof(&public_inputs, &proof_bytes);
    println!("=== verify_proof budget usage ===");
    env.cost_estimate().budget().print();
}

// =========================================================================
// Constructor negative tests
// =========================================================================

#[test]
fn constructor_rejects_empty_vk() {
    let result = std::panic::catch_unwind(|| {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let empty_vk = Bytes::new(&env);
        let _ = env.register(UltraHonkVerifierContract, (empty_vk,));
    });
    let panic = result.expect_err("expected constructor to panic");
    let msg = panic
        .downcast_ref::<String>()
        .map(|s| s.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("Error(Contract, #1)"),
        "constructor should fail with VkInvalidLength (#1), got: {msg}"
    );
}

#[test]
fn constructor_rejects_truncated_vk() {
    let vk_bytes_raw: &[u8] = include_bytes!("../../../circuits/simple_circuit/target/vk");

    let result = std::panic::catch_unwind(|| {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let truncated = truncate(vk_bytes_raw, vk_bytes_raw.len() - 1);
        let bad_vk = Bytes::from_slice(&env, &truncated);
        let _ = env.register(UltraHonkVerifierContract, (bad_vk,));
    });
    let panic = result.expect_err("expected constructor to panic");
    let msg = panic
        .downcast_ref::<String>()
        .map(|s| s.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("Error(Contract, #1)"),
        "constructor should fail with VkInvalidLength (#1), got: {msg}"
    );
}

#[test]
fn constructor_rejects_invalid_parameters() {
    let vk_bytes_raw: &[u8] = include_bytes!("../../../circuits/simple_circuit/target/vk");

    let result = std::panic::catch_unwind(|| {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let mut bad_vk = vk_bytes_raw.to_vec();
        // log_circuit_size is the second u64 at bytes 8..16.
        bad_vk[15] = 29;
        let bad_vk = Bytes::from_slice(&env, &bad_vk);
        let _ = env.register(UltraHonkVerifierContract, (bad_vk,));
    });
    let panic = result.expect_err("expected constructor to panic");
    let msg = panic
        .downcast_ref::<String>()
        .map(|s| s.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("Error(Contract, #2)"),
        "constructor should fail with VkInvalidParameters (#2), got: {msg}"
    );
}

#[test]
fn constructor_rejects_double_initialization() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let vk_bytes_raw: &[u8] = include_bytes!("../../../circuits/simple_circuit/target/vk");
    let vk = Bytes::from_slice(&env, vk_bytes_raw);

    let contract_id = env.register(UltraHonkVerifierContract, (vk.clone(),));

    let err = env
        .as_contract(&contract_id, || {
            UltraHonkVerifierContract::__constructor(env.clone(), vk.clone())
        })
        .expect_err("expected AlreadyInitialized");
    assert_eq!(err as u32, Error::AlreadyInitialized as u32);
}

// =========================================================================
// Verify-method negative tests
// =========================================================================

#[test]
fn verify_proof_with_bad_proof_length_fails() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let vk_bytes_raw: &[u8] = include_bytes!("../../../circuits/simple_circuit/target/vk");
    let pub_inputs_bin: &[u8] =
        include_bytes!("../../../circuits/simple_circuit/target/public_inputs");
    let vk = Bytes::from_slice(&env, vk_bytes_raw);
    let public_inputs = Bytes::from_slice(&env, pub_inputs_bin);

    let contract_id = env.register(UltraHonkVerifierContract, (vk.clone(),));

    let bad_proof = Bytes::from_slice(&env, &[0u8; 10]);
    let err = env
        .as_contract(&contract_id, || {
            UltraHonkVerifierContract::verify_proof(
                env.clone(),
                public_inputs.clone(),
                bad_proof.clone(),
            )
        })
        .expect_err("expected ProofParseError");
    assert_eq!(err as u32, Error::ProofParseError as u32);
}

#[test]
fn verify_proof_with_mutated_proof_fails() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let vk_bytes_raw: &[u8] = include_bytes!("../../../circuits/simple_circuit/target/vk");
    let proof_bin: &[u8] = include_bytes!("../../../circuits/simple_circuit/target/proof");
    let pub_inputs_bin: &[u8] =
        include_bytes!("../../../circuits/simple_circuit/target/public_inputs");
    let vk = Bytes::from_slice(&env, vk_bytes_raw);
    let proof = Bytes::from_slice(&env, proof_bin);
    let public_inputs = Bytes::from_slice(&env, pub_inputs_bin);

    let contract_id = env.register(UltraHonkVerifierContract, (vk.clone(),));

    let bad_proof = Bytes::from_slice(&env, &mutate_byte(&proof.to_alloc_vec(), 100, 0x01));
    let err = env
        .as_contract(&contract_id, || {
            UltraHonkVerifierContract::verify_proof(
                env.clone(),
                public_inputs.clone(),
                bad_proof.clone(),
            )
        })
        .expect_err("expected VerificationFailed");
    assert_eq!(err as u32, Error::VerificationFailed as u32);
}
