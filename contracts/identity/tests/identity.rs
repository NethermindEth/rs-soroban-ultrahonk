use identity::{Error, IdentityContract, IdentityContractClient};
use soroban_sdk::{testutils::Ledger, Bytes, Env};
use ultrahonk_test_utils::{mutate_byte, truncate, Fixture};

fn test_env() -> Env {
    let env = Env::default();
    env.ledger().set_protocol_version(26);
    env.cost_estimate().budget().reset_unlimited();
    env
}

// =========================================================================
// Happy path
// =========================================================================

#[test]
fn identity_proof_verifies() {
    let env = test_env();
    let f = Fixture::load("identity");
    let (proof, vk, pi) = f.into_bytes(&env);

    let contract_id = env.register(IdentityContract, (vk.clone(),));
    let client = IdentityContractClient::new(&env, &contract_id);

    client.prove_identity(&pi, &proof);
}

// =========================================================================
// Constructor negative tests
// =========================================================================

#[test]
fn constructor_rejects_empty_vk() {
    let result = std::panic::catch_unwind(|| {
        let env = test_env();
        let empty_vk = Bytes::new(&env);
        let _ = env.register(IdentityContract, (empty_vk,));
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
    let result = std::panic::catch_unwind(|| {
        let env = test_env();
        let f = Fixture::load("identity");
        let truncated = truncate(&f.vk, f.vk.len() - 1);
        let bad_vk = Bytes::from_slice(&env, &truncated);
        let _ = env.register(IdentityContract, (bad_vk,));
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
    let result = std::panic::catch_unwind(|| {
        let env = test_env();
        let f = Fixture::load("identity");
        let mut bad_vk = f.vk.clone();
        // log_circuit_size is the second u64 at bytes 8..16.
        // Setting it to 29 (> CONST_PROOF_SIZE_LOG_N = 28) makes it invalid.
        bad_vk[15] = 29;
        let bad_vk = Bytes::from_slice(&env, &bad_vk);
        let _ = env.register(IdentityContract, (bad_vk,));
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
    let env = test_env();
    let f = Fixture::load("identity");
    let vk = Bytes::from_slice(&env, &f.vk);

    let contract_id = env.register(IdentityContract, (vk.clone(),));

    // Attempt to call constructor again directly.
    let err = env
        .as_contract(&contract_id, || {
            IdentityContract::__constructor(env.clone(), vk.clone())
        })
        .expect_err("expected AlreadyInitialized");
    assert_eq!(err as u32, Error::AlreadyInitialized as u32);
}

// =========================================================================
// Verify-method negative tests
// =========================================================================

#[test]
fn prove_identity_with_bad_proof_length_fails() {
    let env = test_env();
    let f = Fixture::load("identity");
    let (_, vk, pi) = f.into_bytes(&env);

    let contract_id = env.register(IdentityContract, (vk.clone(),));

    let bad_proof = Bytes::from_slice(&env, &[0u8; 10]);
    let err = env
        .as_contract(&contract_id, || {
            IdentityContract::prove_identity(env.clone(), pi.clone(), bad_proof.clone())
        })
        .expect_err("expected ProofParseError");
    assert_eq!(err as u32, Error::ProofParseError as u32);
}

#[test]
fn prove_identity_with_mutated_proof_fails() {
    let env = test_env();
    let f = Fixture::load("identity");
    let (proof, vk, pi) = f.into_bytes(&env);

    let contract_id = env.register(IdentityContract, (vk.clone(),));

    let bad_proof = Bytes::from_slice(&env, &mutate_byte(&proof.to_alloc_vec(), 100, 0x01));
    let err = env
        .as_contract(&contract_id, || {
            IdentityContract::prove_identity(env.clone(), pi.clone(), bad_proof.clone())
        })
        .expect_err("expected VerificationFailed");
    assert_eq!(err as u32, Error::VerificationFailed as u32);
}
