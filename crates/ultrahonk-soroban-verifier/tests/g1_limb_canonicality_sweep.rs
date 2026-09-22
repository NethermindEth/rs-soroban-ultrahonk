//! Exhaustive sweep of the G1 limb bytes that coordinate reconstruction discards.
//!
//! `combine_limbs` builds each coordinate from the low 17 bytes of the low limb and
//! the low 15 bytes of the high limb. The remaining 32 bytes per coordinate are not
//! part of the reconstructed value, and the transcript absorbs the reconstructed
//! point rather than the raw limbs — so before canonical limb encodings were
//! enforced, flipping any of those bytes produced a distinct proof that verified
//! identically. That made proof bytes unusable as a unique identifier.
//!
//! This sweeps every one of those positions and requires each to be rejected, at
//! parse time rather than later. 37 points * 2 coordinates * 32 discarded bytes =
//! 2,368 cases, ~2.4s. It runs in the normal suite.
//!
//! Provenance: the OpenZeppelin UltraHonk Verifier Audit (2026-08-31) reported this
//! same figure of 2,368 accepted positions as finding L-01, measured against commit
//! 661db07. This test reproduces their measurement as a regression guard.

use soroban_sdk::{testutils::Ledger, Bytes, Env};
use ultrahonk_soroban_verifier::{UltraHonkVerifier, VerifyError};
use ultrahonk_test_utils::Fixture;

/// Byte offsets of all 37 G1 points in the proof: 8 head, 27 Gemini folds, 2 tail.
fn g1_point_offsets() -> Vec<usize> {
    const PPO: usize = 16 * 32;
    const HEAD: usize = 8 * 128;
    const SU: usize = 28 * 8 * 32;
    const SE: usize = 40 * 32;
    const GF: usize = 27 * 128;
    const GA: usize = 28 * 32;
    let mut v = Vec::new();
    for i in 0..8 {
        v.push(PPO + i * 128);
    }
    let fold = PPO + HEAD + SU + SE;
    for i in 0..27 {
        v.push(fold + i * 128);
    }
    let tail = fold + GF + GA;
    for i in 0..2 {
        v.push(tail + i * 128);
    }
    assert_eq!(v.len(), 37);
    v
}

/// Byte positions inside a 128-byte point that `combine_limbs` discards:
/// x_lo[0..15], x_hi[0..17], y_lo[0..15], y_hi[0..17] = 64 per point.
fn discarded_positions() -> Vec<usize> {
    let mut v = Vec::new();
    for base in [0usize, 64] {
        v.extend(base..base + 15); // *_lo high bytes
        v.extend(base + 32..base + 32 + 17); // *_hi high bytes
    }
    assert_eq!(v.len(), 64);
    v
}

#[test]
fn discarded_limb_bytes_are_all_rejected() {
    let env = Env::default();
    env.ledger().set_protocol_version(26);
    env.cost_estimate().budget().reset_unlimited();

    let f = Fixture::load("simple_circuit");
    let vk = Bytes::from_slice(&env, &f.vk);
    let pi = Bytes::from_slice(&env, &f.public_inputs);
    let v = UltraHonkVerifier::new(&env, &vk).expect("VK parses");

    // Sanity: the unmodified proof verifies.
    assert!(v.verify(&Bytes::from_slice(&env, &f.proof), &pi).is_ok());

    let mut checked = 0usize;
    let mut accepted = Vec::new();
    let mut wrong_error = Vec::new();

    for pt in g1_point_offsets() {
        for d in discarded_positions() {
            let mut bytes = f.proof.clone();
            let idx = pt + d;
            bytes[idx] ^= 0x01;
            let got = v.verify(&Bytes::from_slice(&env, &bytes), &pi);
            checked += 1;
            match got {
                Ok(()) => accepted.push(idx),
                Err(VerifyError::InvalidInput) => {}
                Err(_) => wrong_error.push(idx),
            }
        }
    }

    println!(
        "swept {checked} positions; accepted {}, wrong-error {}",
        accepted.len(),
        wrong_error.len()
    );
    assert_eq!(
        checked, 2368,
        "must match the position count the audit measured"
    );
    assert!(
        accepted.is_empty(),
        "positions still accepted: {accepted:?}"
    );
    assert!(
        wrong_error.is_empty(),
        "rejected but not at parse time: {wrong_error:?}"
    );
}
