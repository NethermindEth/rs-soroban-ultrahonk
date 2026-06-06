//! Negative tests for the UltraHonk verifier.
//!
//! Each test loads a valid fixture and then corrupts exactly one component
//! (proof, VK, or public inputs) to verify that the verifier correctly rejects
//! the tampered input.

use soroban_sdk::{testutils::Ledger, Bytes, Env};
use ultrahonk_soroban_verifier::{UltraHonkVerifier, VkLoadError};
use ultrahonk_test_utils::{mutate_byte, truncate, Fixture};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Set up a Soroban test environment with the required protocol version.
fn test_env() -> Env {
    let env = Env::default();
    env.ledger().set_protocol_version(26);
    env.cost_estimate().budget().reset_unlimited();
    env
}

// =========================================================================
// 1. Mutated proof — verification must fail
// =========================================================================

#[test]
fn mutated_proof_simple_circuit_fails() {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let bad_proof = mutate_byte(&f.proof, 100, 0x01);
    let proof = Bytes::from_slice(&env, &bad_proof);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_err(),
        "mutated proof must not verify (simple_circuit)"
    );
}

#[test]
fn mutated_proof_fib_chain_fails() {
    let env = test_env();
    let f = Fixture::load("fib_chain");
    let bad_proof = mutate_byte(&f.proof, 100, 0x01);
    let proof = Bytes::from_slice(&env, &bad_proof);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_err(),
        "mutated proof must not verify (fib_chain)"
    );
}

// =========================================================================
// 2. Mutated VK — new() or verify() must fail (or the Soroban host panics
//    with "point not on curve" when the corrupted G1 coordinate hits BN254)
// =========================================================================

#[test]
fn mutated_vk_simple_circuit_fails() {
    let result = std::panic::catch_unwind(|| {
        let env = test_env();
        let f = Fixture::load("simple_circuit");
        let bad_vk = mutate_byte(&f.vk, 100, 0x01);
        let proof = Bytes::from_slice(&env, &f.proof);
        let vk = Bytes::from_slice(&env, &bad_vk);
        let pi = Bytes::from_slice(&env, &f.public_inputs);

        match UltraHonkVerifier::new(&env, &vk) {
            Err(_) => (), // VK parse rejected — good
            Ok(v) => {
                assert!(
                    v.verify(&env, &proof, &pi).is_err(),
                    "mutated VK must not verify (simple_circuit)"
                );
            }
        }
    });
    // If it panicked (e.g. "point not on curve"), that's also a rejection — pass.
    if let Err(panic) = result {
        let msg = panic
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .unwrap_or("");
        assert!(
            msg.contains("not on curve")
                || msg.contains("InvalidInput")
                || msg.contains("HostError"),
            "unexpected panic: {msg}"
        );
    }
}

#[test]
fn mutated_vk_fib_chain_fails() {
    let result = std::panic::catch_unwind(|| {
        let env = test_env();
        let f = Fixture::load("fib_chain");
        let bad_vk = mutate_byte(&f.vk, 100, 0x01);
        let proof = Bytes::from_slice(&env, &f.proof);
        let vk = Bytes::from_slice(&env, &bad_vk);
        let pi = Bytes::from_slice(&env, &f.public_inputs);

        match UltraHonkVerifier::new(&env, &vk) {
            Err(_) => (),
            Ok(v) => {
                assert!(
                    v.verify(&env, &proof, &pi).is_err(),
                    "mutated VK must not verify (fib_chain)"
                );
            }
        }
    });
    if let Err(panic) = result {
        let msg = panic
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .unwrap_or("");
        assert!(
            msg.contains("not on curve")
                || msg.contains("InvalidInput")
                || msg.contains("HostError"),
            "unexpected panic: {msg}"
        );
    }
}

// =========================================================================
// 3. Mutated public inputs — verification must fail
// =========================================================================

#[test]
fn mutated_public_inputs_simple_circuit_fails() {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let bad_pi = mutate_byte(&f.public_inputs, 0, 0x01);
    let proof = Bytes::from_slice(&env, &f.proof);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &bad_pi);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_err(),
        "mutated public inputs must not verify (simple_circuit)"
    );
}

#[test]
fn mutated_public_inputs_fib_chain_fails() {
    let env = test_env();
    let f = Fixture::load("fib_chain");
    let bad_pi = mutate_byte(&f.public_inputs, 0, 0x01);
    let proof = Bytes::from_slice(&env, &f.proof);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &bad_pi);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_err(),
        "mutated public inputs must not verify (fib_chain)"
    );
}

// =========================================================================
// 4. Truncated proof (len - 1) — must fail gracefully
// =========================================================================

#[test]
fn truncated_proof_simple_circuit_fails() {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let short = truncate(&f.proof, f.proof.len() - 1);
    let proof = Bytes::from_slice(&env, &short);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_err(),
        "truncated proof must not verify (simple_circuit)"
    );
}

#[test]
fn truncated_proof_fib_chain_fails() {
    let env = test_env();
    let f = Fixture::load("fib_chain");
    let short = truncate(&f.proof, f.proof.len() - 1);
    let proof = Bytes::from_slice(&env, &short);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_err(),
        "truncated proof must not verify (fib_chain)"
    );
}

// =========================================================================
// 5. Empty proof — must fail gracefully
// =========================================================================

#[test]
fn empty_proof_simple_circuit_fails() {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let proof = Bytes::new(&env);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_err(),
        "empty proof must not verify (simple_circuit)"
    );
}

#[test]
fn empty_proof_fib_chain_fails() {
    let env = test_env();
    let f = Fixture::load("fib_chain");
    let proof = Bytes::new(&env);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_err(),
        "empty proof must not verify (fib_chain)"
    );
}

// =========================================================================
// 6. Truncated VK — new() must return Err
// =========================================================================

#[test]
fn truncated_vk_simple_circuit_fails() {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let short_vk = truncate(&f.vk, f.vk.len() - 1);
    let vk = Bytes::from_slice(&env, &short_vk);

    assert!(
        UltraHonkVerifier::new(&env, &vk).is_err(),
        "truncated VK must fail to parse (simple_circuit)"
    );
}

#[test]
fn empty_vk_fails() {
    let env = test_env();
    let vk = Bytes::new(&env);

    assert!(
        UltraHonkVerifier::new(&env, &vk).is_err(),
        "empty VK must fail to parse"
    );
}

// =========================================================================
// 6b. Exact VkLoadError variants
// =========================================================================

#[test]
fn empty_vk_returns_wrong_length() {
    let env = test_env();
    let vk = Bytes::new(&env);
    assert!(matches!(
        UltraHonkVerifier::new(&env, &vk),
        Err(VkLoadError::WrongLength)
    ));
}

#[test]
fn truncated_vk_returns_wrong_length() {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let short_vk = truncate(&f.vk, f.vk.len() - 1);
    let vk = Bytes::from_slice(&env, &short_vk);
    assert!(matches!(
        UltraHonkVerifier::new(&env, &vk),
        Err(VkLoadError::WrongLength)
    ));
}

#[test]
fn vk_with_zero_log_circuit_size_returns_invalid_parameters() {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let mut bad_vk = f.vk.clone();
    // Set circuit_size = 1 at bytes 0..8 and zero out log_circuit_size at bytes 8..16.
    bad_vk[7] = 1;
    for b in &mut bad_vk[8..16] {
        *b = 0;
    }
    let vk = Bytes::from_slice(&env, &bad_vk);
    assert!(matches!(
        UltraHonkVerifier::new(&env, &vk),
        Err(VkLoadError::InvalidParameters)
    ));
}

#[test]
fn vk_with_oversized_log_circuit_size_returns_invalid_parameters() {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let mut bad_vk = f.vk.clone();
    // circuit_size = 1 at bytes 0..8
    bad_vk[7] = 1;
    // log_circuit_size = 29 at bytes 8..16 (> CONST_PROOF_SIZE_LOG_N = 28)
    bad_vk[15] = 29;
    let vk = Bytes::from_slice(&env, &bad_vk);
    assert!(matches!(
        UltraHonkVerifier::new(&env, &vk),
        Err(VkLoadError::InvalidParameters)
    ));
}

// =========================================================================
// 7. Phase 3.1 Fixture circuits
// =========================================================================

#[test]
fn happy_path_small_circuit() {
    let env = test_env();
    let f = Fixture::load("small_circuit");
    let proof = Bytes::from_slice(&env, &f.proof);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_ok(),
        "happy path must verify (small_circuit)"
    );
}

#[test]
fn mutated_proof_small_circuit_fails() {
    let env = test_env();
    let f = Fixture::load("small_circuit");
    let bad_proof = mutate_byte(&f.proof, 100, 0x01);
    let proof = Bytes::from_slice(&env, &bad_proof);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_err(),
        "mutated proof must not verify (small_circuit)"
    );
}

#[test]
fn happy_path_lookup_heavy() {
    let env = test_env();
    let f = Fixture::load("lookup_heavy");
    let proof = Bytes::from_slice(&env, &f.proof);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_ok(),
        "happy path must verify (lookup_heavy)"
    );
}

#[test]
fn mutated_proof_lookup_heavy_fails() {
    let env = test_env();
    let f = Fixture::load("lookup_heavy");
    let bad_proof = mutate_byte(&f.proof, 100, 0x01);
    let proof = Bytes::from_slice(&env, &bad_proof);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_err(),
        "mutated proof must not verify (lookup_heavy)"
    );
}

#[test]
fn happy_path_range_heavy() {
    let env = test_env();
    let f = Fixture::load("range_heavy");
    let proof = Bytes::from_slice(&env, &f.proof);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_ok(),
        "happy path must verify (range_heavy)"
    );
}

#[test]
fn mutated_proof_range_heavy_fails() {
    let env = test_env();
    let f = Fixture::load("range_heavy");
    let bad_proof = mutate_byte(&f.proof, 100, 0x01);
    let proof = Bytes::from_slice(&env, &bad_proof);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_err(),
        "mutated proof must not verify (range_heavy)"
    );
}

#[test]
fn happy_path_many_pubs() {
    let env = test_env();
    let f = Fixture::load("many_pubs");
    let proof = Bytes::from_slice(&env, &f.proof);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_ok(),
        "happy path must verify (many_pubs)"
    );
}

#[test]
fn mutated_proof_many_pubs_fails() {
    let env = test_env();
    let f = Fixture::load("many_pubs");
    let bad_proof = mutate_byte(&f.proof, 100, 0x01);
    let proof = Bytes::from_slice(&env, &bad_proof);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_err(),
        "mutated proof must not verify (many_pubs)"
    );
}

// =========================================================================
// 8. Public-input edge cases
// =========================================================================

#[test]
fn public_inputs_not_32_byte_aligned_fails() {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let proof = Bytes::from_slice(&env, &f.proof);
    let vk = Bytes::from_slice(&env, &f.vk);
    let mut bad_pi = f.public_inputs.clone();
    bad_pi.push(0x42);
    let pi = Bytes::from_slice(&env, &bad_pi);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_err(),
        "non-32-byte-aligned public inputs must fail"
    );
}

#[test]
fn wrong_number_of_public_inputs_fails() {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let proof = Bytes::from_slice(&env, &f.proof);
    let vk = Bytes::from_slice(&env, &f.vk);
    // Duplicate the single 32-byte public input to make it look like 2 inputs
    let mut bad_pi = f.public_inputs.clone();
    bad_pi.extend_from_slice(&f.public_inputs);
    let pi = Bytes::from_slice(&env, &bad_pi);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_err(),
        "wrong number of public inputs must fail"
    );
}

#[test]
fn empty_public_inputs_when_expected_nonzero_fails() {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let proof = Bytes::from_slice(&env, &f.proof);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::new(&env);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    assert!(
        v.verify(&env, &proof, &pi).is_err(),
        "empty public inputs when circuit expects nonzero must fail"
    );
}

// =========================================================================
// 9. VK structural edge cases
// =========================================================================

#[test]
fn vk_pub_inputs_offset_too_large_returns_invalid_parameters() {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let mut bad_vk = f.vk.clone();
    // pub_inputs_offset at bytes 24..32 -> u64::MAX
    for b in &mut bad_vk[24..32] {
        *b = 0xff;
    }
    let vk = Bytes::from_slice(&env, &bad_vk);
    assert!(matches!(
        UltraHonkVerifier::new(&env, &vk),
        Err(VkLoadError::InvalidParameters)
    ));
}

#[test]
fn vk_circuit_size_mismatch_log_returns_invalid_parameters() {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let mut bad_vk = f.vk.clone();
    // circuit_size at bytes 0..8 -> 2
    for b in &mut bad_vk[0..8] {
        *b = 0;
    }
    bad_vk[7] = 2;
    // log_circuit_size at bytes 8..16 -> 10 (2^10 = 1024 != 2)
    for b in &mut bad_vk[8..16] {
        *b = 0;
    }
    bad_vk[15] = 10;
    let vk = Bytes::from_slice(&env, &bad_vk);
    assert!(matches!(
        UltraHonkVerifier::new(&env, &vk),
        Err(VkLoadError::InvalidParameters)
    ));
}

// =========================================================================
// 10. Cross-circuit confusion
// =========================================================================

#[test]
fn cross_circuit_proof_and_vk_fails() {
    let f_a = Fixture::load("simple_circuit");
    let f_b = Fixture::load("fib_chain");

    let result = std::panic::catch_unwind(|| {
        let env = test_env();
        let proof = Bytes::from_slice(&env, &f_a.proof);
        let vk = Bytes::from_slice(&env, &f_b.vk);
        let pi = Bytes::from_slice(&env, &f_a.public_inputs);
        let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
        v.verify(&env, &proof, &pi)
    });
    // If it panics (e.g. "point not on curve"), that's also a rejection — pass.
    if let Err(panic) = result {
        let msg = panic
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .unwrap_or("");
        assert!(
            msg.contains("not on curve")
                || msg.contains("HostError")
                || msg.contains("InvalidInput"),
            "unexpected panic: {msg}"
        );
    } else {
        assert!(
            result.unwrap().is_err(),
            "cross-circuit proof+VK must not verify"
        );
    }
}
