//! Zero-knowledge Sumcheck verifier for Barretenberg v0.87 UltraKeccakZK.
//!
//! Compared with the non-ZK flavor, every round univariate has nine
//! evaluations. The extra degree comes from multiplying the Honk relation by
//! the polynomial that disables the final four trace rows. Libra masks the
//! round univariates, so the initial target and final purported value also
//! contain the committed Libra claim.
//!
//! BB reference (v0.87.0):
//! - `sumcheck/sumcheck.hpp::SumcheckVerifier::verify`
//! - `polynomials/row_disabling_polynomial.hpp`
//! - `dsl/acir_proofs/honk_zk_contract.hpp::verifySumcheck`

use core::array;

use crate::{
    field::{batch_inverse, Fr},
    relations::accumulate_relation_evaluations,
    types::{VerificationKey, CONST_PROOF_SIZE_LOG_N},
    zk_types::{ZkProof, ZkTranscript, ZK_BATCHED_RELATION_PARTIAL_LENGTH},
};
use soroban_sdk::Env;

/// Lagrange denominators `d_i = ∏_{j != i}(i-j)` for the domain
/// `{0, 1, ..., 8}`. These are the constants used by the generated v0.87 ZK
/// Solidity verifier.
const ZK_BARY_BYTES: [[u8; 32]; ZK_BATCHED_RELATION_PARTIAL_LENGTH] = [
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x9d, 0x80,
    ],
    [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xef, 0xff,
        0xec, 0x51,
    ],
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0xa0,
    ],
    [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xef, 0xff,
        0xfd, 0x31,
    ],
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x40,
    ],
    [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xef, 0xff,
        0xfd, 0x31,
    ],
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0xa0,
    ],
    [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xef, 0xff,
        0xec, 0x51,
    ],
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x9d, 0x80,
    ],
];

#[inline(always)]
fn check_sum(round_univariate: &[Fr], round_target: &Fr) -> bool {
    &round_univariate[0] + &round_univariate[1] == *round_target
}

/// Evaluate values on `{0, ..., 8}` at `round_challenge` by barycentric
/// interpolation. The explicit domain-point branch matches Barretenberg's
/// univariate evaluation while avoiding a zero denominator.
#[inline(always)]
fn compute_next_target_sum(
    round_univariate: &[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH],
    round_challenge: &Fr,
    barycentric_denominators: &[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH],
    domain: &[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH],
    one: &Fr,
    zero: &Fr,
) -> Result<Fr, &'static str> {
    for (point, value) in domain.iter().zip(round_univariate.iter()) {
        if round_challenge == point {
            return Ok(value.clone());
        }
    }

    let mut denominator_terms =
        Fr::zero_array::<ZK_BATCHED_RELATION_PARTIAL_LENGTH>(round_challenge.0.env());
    let mut numerator = one.clone();
    for i in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH {
        let delta = round_challenge - &domain[i];
        numerator = numerator * &delta;
        denominator_terms[i] = &barycentric_denominators[i] * delta;
    }

    let mut denominator_inverses =
        array::from_fn::<_, ZK_BATCHED_RELATION_PARTIAL_LENGTH, _>(|_| zero.clone());
    batch_inverse(&denominator_terms, &mut denominator_inverses).map_err(|_| "invalid ZK proof")?;

    let mut result = zero.clone();
    for (value, inverse) in round_univariate.iter().zip(denominator_inverses.iter()) {
        result = result + value * inverse;
    }
    Ok(numerator * result)
}

#[inline(always)]
fn partially_evaluate_gate_separator(
    one: &Fr,
    gate_challenge: &Fr,
    partial_evaluation: Fr,
    round_challenge: &Fr,
) -> Fr {
    partial_evaluation * (one + round_challenge * (gate_challenge - one))
}

/// Evaluate the polynomial that is one on ordinary rows and zero on the last
/// four rows. At the Sumcheck challenge it is
/// `1 - u_2 * ... * u_{log_n-1}`.
#[inline(always)]
fn row_disabling_correction(
    one: &Fr,
    challenges: &[Fr; CONST_PROOF_SIZE_LOG_N],
    log_n: usize,
) -> Fr {
    let mut disabled_rows_lagrange = one.clone();
    for challenge in challenges.iter().take(log_n).skip(2) {
        disabled_rows_lagrange = disabled_rows_lagrange * challenge;
    }
    one - disabled_rows_lagrange
}

/// Verify the ZK Sumcheck portion of an UltraKeccakZK proof.
///
/// The checked final identity is
///
/// `row_disabling(u) * HonkRelations(evals, u)`
/// `    + libra_challenge * libra_evaluation == final_round_target`.
pub fn verify_zk_sumcheck(
    env: &Env,
    proof: &ZkProof,
    transcript: &ZkTranscript,
    vk: &VerificationKey,
) -> Result<(), &'static str> {
    let log_n = vk.log_circuit_size as usize;
    if log_n == 0 || log_n > CONST_PROOF_SIZE_LOG_N {
        return Err("invalid ZK proof");
    }

    let zero = Fr::zero(env);
    let one = Fr::one(env);
    let barycentric_denominators: [Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH] =
        array::from_fn(|i| Fr::from_array(env, &ZK_BARY_BYTES[i]));
    let domain: [Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH] =
        array::from_fn(|i| Fr::from_u64(env, i as u64));

    // The Honk relation has zero total sum. Libra adds a random masking
    // multivariate whose claimed Boolean-hypercube sum is `libra_sum`.
    let mut round_target = &transcript.libra_challenge * &proof.libra_sum;
    let mut gate_separator_partial_evaluation = one.clone();

    for round in 0..log_n {
        let round_univariate = &proof.sumcheck_univariates[round];
        if !check_sum(round_univariate, &round_target) {
            return Err("invalid ZK proof");
        }

        let round_challenge = &transcript.sumcheck_u_challenges[round];
        round_target = compute_next_target_sum(
            round_univariate,
            round_challenge,
            &barycentric_denominators,
            &domain,
            &one,
            &zero,
        )?;
        gate_separator_partial_evaluation = partially_evaluate_gate_separator(
            &one,
            &transcript.gate_challenges[round],
            gate_separator_partial_evaluation,
            round_challenge,
        );
    }

    // Relations themselves are unchanged. ZK only disables the four masking
    // rows and adds the Libra evaluation to the purported final value.
    let grand_honk_relation_sum = accumulate_relation_evaluations(
        env,
        &proof.sumcheck_evaluations,
        &transcript.rel_params,
        &transcript.alphas,
        gate_separator_partial_evaluation,
    );
    let correction = row_disabling_correction(&one, &transcript.sumcheck_u_challenges, log_n);
    let purported_value = grand_honk_relation_sum * correction
        + &proof.libra_evaluation * &transcript.libra_challenge;

    if purported_value == round_target {
        Ok(())
    } else {
        Err("invalid ZK proof")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nine_point_barycentric_interpolation() {
        let env = Env::default();
        let zero = Fr::zero(&env);
        let one = Fr::one(&env);
        let denominators = array::from_fn(|i| Fr::from_array(&env, &ZK_BARY_BYTES[i]));
        let domain = array::from_fn(|i| Fr::from_u64(&env, i as u64));
        let values = array::from_fn(|i| Fr::from_u64(&env, (i * i) as u64));

        let result = compute_next_target_sum(
            &values,
            &Fr::from_u64(&env, 10),
            &denominators,
            &domain,
            &one,
            &zero,
        )
        .unwrap();
        assert_eq!(result, Fr::from_u64(&env, 100));
    }

    #[test]
    fn row_disabling_factor_skips_first_two_challenges() {
        let env = Env::default();
        let one = Fr::one(&env);
        let mut challenges = Fr::zero_array::<CONST_PROOF_SIZE_LOG_N>(&env);
        challenges[0] = Fr::from_u64(&env, 17);
        challenges[1] = Fr::from_u64(&env, 19);
        challenges[2] = Fr::from_u64(&env, 2);
        challenges[3] = Fr::from_u64(&env, 3);

        assert_eq!(
            row_disabling_correction(&one, &challenges, 4),
            &one - Fr::from_u64(&env, 6)
        );
    }
}
