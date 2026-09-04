//! Negative tests for the UltraHonk verifier.
//!
//! Each test loads a valid fixture and then corrupts exactly one component
//! (proof, VK, or public inputs) to verify that the verifier correctly rejects
//! the tampered input.

use soroban_sdk::{testutils::Ledger, Bytes, Env};
use ultrahonk_soroban_verifier::{UltraHonkVerifier, VerifyError, VkLoadError};
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
            Err(_) => (), // VK parse rejected — good
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
            Err(_) => (),
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
        v.verify(&proof, &pi).is_err(),
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
        v.verify(&proof, &pi).is_err(),
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
        v.verify(&proof, &pi).is_err(),
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
        v.verify(&proof, &pi).is_err(),
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
        v.verify(&proof, &pi).is_err(),
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
        v.verify(&proof, &pi).is_err(),
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
        v.verify(&proof, &pi).is_err(),
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
        v.verify(&proof, &pi)
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

// ---------------------------------------------------------------------------
// Audit remediation tests: L-01, L-02, L-04.
//
// Each mutates a real fixture proof at a position the verifier previously
// accepted, and asserts it is now rejected with a defined error rather than
// verifying identically or trapping in the host.
// ---------------------------------------------------------------------------

/// Offset of the first proof G1 point: it follows the 16-word pairing point object.
const FIRST_G1: usize = 16 * 32;

fn remediation_case(mutate: impl Fn(&mut [u8])) -> bool {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let mut bytes = f.proof.clone();
    mutate(&mut bytes);
    assert_ne!(bytes, f.proof, "mutation must actually change the proof");
    let proof = Bytes::from_slice(&env, &bytes);
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);
    let v = UltraHonkVerifier::new(&env, &vk).expect("VK should parse");
    // Must be rejected during parsing (InvalidInput), not merely fail later at
    // sumcheck or the pairing check. A generic `is_err()` would pass even if the
    // mutation had simply broken the proof, which would not prove the fix works.
    matches!(v.verify(&proof, &pi), Err(VerifyError::InvalidInput))
}

/// L-01: a non-zero byte in the discarded high padding of a G1 limb. Barretenberg
/// rejects these because it uses every bit of both limbs; before the fix this
/// verifier discarded them, so the mutated bytes verified identically.
#[test]
fn rejects_non_canonical_g1_limb_padding() {
    assert!(
        remediation_case(|b| b[FIRST_G1] = 0x01),
        "non-canonical limb padding must be rejected"
    );
}

/// L-01: a high limb at or above 2^118 is rejected.
///
/// Note on what this does and does not isolate. Removing `limbs_are_canonical`
/// does NOT make this test fail: setting bit 118 makes the reconstructed
/// coordinate at least 2^254, which exceeds the base modulus, so the L-04
/// coordinate range check rejects it instead. The two guards overlap here by
/// construction — any high limb at or above 2^118 yields an out-of-range
/// coordinate.
///
/// The 2^118 bound is still worth enforcing at the limb level: it rejects on the
/// audit's stated criterion (canonical limb encodings) with a specific reason,
/// rather than incidentally via field validity, and it keeps the limb rule
/// complete rather than relying on a downstream check to cover half of it. The
/// low-limb half of `limbs_are_canonical` is not covered by any other guard —
/// see `rejects_non_canonical_g1_limb_padding`, which does fail when that
/// function is neutered.
#[test]
fn rejects_high_limb_above_2_118() {
    assert!(
        remediation_case(|b| b[FIRST_G1 + 32 + 17] |= 0x40),
        "high limb at or above 2^118 must be rejected"
    );
}

/// L-02: `v + k*r` reduces to the same scalar, so before the fix a valid proof
/// had many distinct byte encodings that all verified.
#[test]
fn rejects_non_canonical_scalar_encoding() {
    const R: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];
    assert!(
        remediation_case(|b| {
            let mut carry = 0u16;
            for i in (0..32).rev() {
                let s = b[i] as u16 + R[i] as u16 + carry;
                b[i] = (s & 0xff) as u8;
                carry = s >> 8;
            }
        }),
        "non-canonical scalar encoding must be rejected"
    );
}

/// L-04: a coordinate at or above the base modulus. This is the case that forces
/// the guest-side range check to run *before* any host curve call: the host's
/// `g1_is_on_curve` errors rather than returning false here, so a fix that called
/// it first would reproduce the very trap being removed.
#[test]
fn rejects_g1_coordinate_out_of_range() {
    assert!(
        remediation_case(|b| {
            for i in 15..32 {
                b[FIRST_G1 + i] = 0xff;
            }
            b[FIRST_G1 + 32 + 17] = 0x3f;
            for i in 18..32 {
                b[FIRST_G1 + 32 + i] = 0xff;
            }
        }),
        "out-of-range G1 coordinate must be rejected, not trapped"
    );
}

/// L-04: a coordinate pair that is in range but off the curve.
#[test]
fn rejects_off_curve_g1_point() {
    assert!(
        remediation_case(|b| b[FIRST_G1 + 64 + 31] ^= 0x01),
        "off-curve G1 point must be rejected"
    );
}

// ---------------------------------------------------------------------------
// L-04, verification-key path.
//
// The proof-path tests above cover 37 of the 64 G1 points. These cover the other
// 27. They deliberately assert a specific `Err(VkLoadError::InvalidPoint)` and do
// NOT accept a panic: the older `mutated_vk_*` tests in this file wrap parsing in
// `catch_unwind` and count a host trap as a rejection, so they would still pass if
// this fix regressed to the trapping behaviour L-04 exists to remove.
// ---------------------------------------------------------------------------

/// Offset of the first VK G1 commitment: it follows the four u64 header words.
const VK_FIRST_POINT: usize = 4 * 8;

fn vk_case(mutate: impl Fn(&mut [u8])) -> Option<VkLoadError> {
    let env = test_env();
    let f = Fixture::load("simple_circuit");
    let mut bytes = f.vk.clone();
    mutate(&mut bytes);
    assert_ne!(bytes, f.vk, "mutation must actually change the VK");
    UltraHonkVerifier::new(&env, &Bytes::from_slice(&env, &bytes)).err()
}

/// A VK coordinate at or above the base modulus must be rejected with a defined
/// error. This is the case that requires the guest-side range check to precede any
/// host curve call, since `g1_is_on_curve` errors rather than returning false here.
#[test]
fn vk_rejects_coordinate_out_of_range() {
    let err = vk_case(|b| {
        for i in 0..32 {
            b[VK_FIRST_POINT + i] = 0xff;
        }
    })
    .expect("out-of-range VK coordinate must be rejected");
    assert_eq!(err, VkLoadError::InvalidPoint);
}

/// A VK point whose coordinates are valid field elements but which is not on the
/// curve must also be rejected, and as a parse error rather than a host trap.
#[test]
fn vk_rejects_off_curve_point() {
    let err =
        vk_case(|b| b[VK_FIRST_POINT + 63] ^= 0x01).expect("off-curve VK point must be rejected");
    assert_eq!(err, VkLoadError::InvalidPoint);
}
