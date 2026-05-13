//! Negative tests for the UltraHonk verifier.
//!
//! Each test loads a valid fixture and then corrupts exactly one component
//! (proof, VK, or public inputs) to verify that the verifier correctly rejects
//! the tampered input.

use soroban_sdk::{testutils::Ledger, Bytes, Env};
use ultrahonk_soroban_verifier::UltraHonkVerifier;
use ultrahonk_test_utils::{mutate_byte, truncate, Fixture};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Set up a Soroban test environment with the required protocol version.
fn test_env() -> Env {
    let env = Env::default();
    env.ledger().set_protocol_version(25);
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
        v.verify(&proof, &pi).is_err(),
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
        v.verify(&proof, &pi).is_err(),
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
            Err(_) => return, // VK parse rejected — good
            Ok(v) => {
                assert!(
                    v.verify(&proof, &pi).is_err(),
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
            Err(_) => return,
            Ok(v) => {
                assert!(
                    v.verify(&proof, &pi).is_err(),
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
        v.verify(&proof, &pi).is_err(),
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
        v.verify(&proof, &pi).is_err(),
        "mutated public inputs must not verify (fib_chain)"
    );
}

// =========================================================================
// 4. Truncated proof (len - 1) — must panic in load_proof's assert_eq!
// =========================================================================

#[test]
#[should_panic(expected = "proof bytes len")]
fn truncated_proof_simple_circuit_panics() {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let short = truncate(&f.proof, f.proof.len() - 1);
    let proof = Bytes::from_slice(&env, &short);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    let _ = v.verify(&proof, &pi);
}

#[test]
#[should_panic(expected = "proof bytes len")]
fn truncated_proof_fib_chain_panics() {
    let env = test_env();
    let f = Fixture::load("fib_chain");
    let short = truncate(&f.proof, f.proof.len() - 1);
    let proof = Bytes::from_slice(&env, &short);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    let _ = v.verify(&proof, &pi);
}

// =========================================================================
// 5. Empty proof — must panic in load_proof's assert_eq!
// =========================================================================

#[test]
#[should_panic(expected = "proof bytes len")]
fn empty_proof_simple_circuit_panics() {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let proof = Bytes::new(&env);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    let _ = v.verify(&proof, &pi);
}

#[test]
#[should_panic(expected = "proof bytes len")]
fn empty_proof_fib_chain_panics() {
    let env = test_env();
    let f = Fixture::load("fib_chain");
    let proof = Bytes::new(&env);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);

    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    let _ = v.verify(&proof, &pi);
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
        v.verify(&proof, &pi).is_ok(),
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
        v.verify(&proof, &pi).is_err(),
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
        v.verify(&proof, &pi).is_ok(),
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
        v.verify(&proof, &pi).is_err(),
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
        v.verify(&proof, &pi).is_ok(),
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
        v.verify(&proof, &pi).is_err(),
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
        v.verify(&proof, &pi).is_ok(),
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
        v.verify(&proof, &pi).is_err(),
        "mutated proof must not verify (many_pubs)"
    );
}
