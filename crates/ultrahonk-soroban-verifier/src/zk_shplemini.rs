//! Shplemini verifier for Barretenberg v0.87 `UltraKeccakZKFlavor` proofs.
//!
//! In addition to the ordinary Gemini/Shplonk/KZG reduction, the ZK flavor:
//! - batches a Gemini hiding-polynomial claim at `rho^0`;
//! - opens the three Libra commitments at four points using fixed Shplonk
//!   powers `nu^58 .. nu^61`; and
//! - checks the SmallSubgroupIPA grand-sum identity that binds those openings
//!   to the Libra evaluation used by ZK sumcheck.
//!
//! Barretenberg v0.87 references:
//! - `commitment_schemes/shplonk/shplemini.hpp`
//! - `commitment_schemes/small_subgroup_ipa/small_subgroup_ipa.hpp`
//! - `dsl/acir_proofs/honk_zk_contract.hpp::verifyShplemini`

use core::array::repeat;
use core::ops::Neg;

use soroban_sdk::Env;

use crate::ec::{g1_msm, pairing_check};
use crate::field::{batch_inverse, Fr};
use crate::types::{
    G1Point, VerificationKey, CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ENTITIES, NUMBER_UNSHIFTED,
};
use crate::zk_types::{
    ZkProof, ZkTranscript, LIBRA_SUBGROUP_SIZE, NUM_LIBRA_COMMITMENTS, NUM_LIBRA_EVALUATIONS,
    ZK_BATCHED_RELATION_PARTIAL_LENGTH,
};

/// Generator of the order-256 multiplicative subgroup used by Libra.
///
/// BB: `curve::BN254::subgroup_generator`.
fn libra_subgroup_generator(env: &Env) -> Fr {
    Fr::from_array(
        env,
        &[
            0x07, 0xb0, 0xc5, 0x61, 0xa6, 0x14, 0x84, 0x04, 0xf0, 0x86, 0x20, 0x4a, 0x9f, 0x36,
            0xff, 0xb0, 0x61, 0x79, 0x42, 0x54, 0x67, 0x50, 0xf2, 0x30, 0xc8, 0x93, 0x61, 0x91,
            0x74, 0xa5, 0x7a, 0x76,
        ],
    )
}

/// Inverse of `libra_subgroup_generator`.
///
/// BB: `curve::BN254::subgroup_generator_inverse`.
fn libra_subgroup_generator_inverse(env: &Env) -> Fr {
    Fr::from_array(
        env,
        &[
            0x20, 0x4b, 0xd3, 0x27, 0x74, 0x22, 0xfa, 0xd3, 0x64, 0x75, 0x1a, 0xd9, 0x38, 0xe2,
            0xb5, 0xe6, 0xa5, 0x4c, 0xf8, 0xc6, 0x87, 0x12, 0x84, 0x8a, 0x69, 0x2c, 0x55, 0x3d,
            0x03, 0x29, 0xf5, 0xd6,
        ],
    )
}

/// Check the SmallSubgroupIPA identity for the four Libra openings.
///
/// The proof supplies `G(r)`, `A(g*r)`, `A(r)`, and `Q(r)`. The verifier
/// evaluates the public challenge polynomial `F`, the first and last Lagrange
/// polynomials, and checks
///
/// `L_1(r)A(r) + (r-g^-1)(A(gr)-A(r)-F(r)G(r))`
/// `  + L_|H|(r)(A(r)-s) - Z_H(r)Q(r) = 0`.
///
/// All 256 barycentric denominators (and `1/256`) are inverted in one batch.
fn check_libra_evaluations_consistency(
    env: &Env,
    proof: &ZkProof,
    tp: &ZkTranscript,
) -> Result<(), &'static str> {
    const INVERSE_BATCH_SIZE: usize = LIBRA_SUBGROUP_SIZE + 1;

    let zero = Fr::zero(env);
    let one = Fr::one(env);
    let r = &tp.gemini_r;
    let subgroup_generator_inverse = libra_subgroup_generator_inverse(env);

    let vanishing_poly_eval = r.pow(LIBRA_SUBGROUP_SIZE as u64) - &one;
    if vanishing_poly_eval.is_zero() {
        // Besides making the barycentric formula undefined, this event would
        // reveal Libra evaluations and is explicitly rejected by BB.
        return Err("invalid ZK proof");
    }

    // For H = <g>, the i-th barycentric denominator is r*g^{-i} - 1.
    // The last entry batches the inversion of the constant subgroup size.
    let mut denominators = Fr::zero_array::<INVERSE_BATCH_SIZE>(env);
    let mut inverse_denominators = Fr::zero_array::<INVERSE_BATCH_SIZE>(env);
    let mut root_power = one.clone();
    for denominator in denominators.iter_mut().take(LIBRA_SUBGROUP_SIZE) {
        *denominator = &(&root_power * r) - &one;
        root_power = root_power * &subgroup_generator_inverse;
    }
    denominators[LIBRA_SUBGROUP_SIZE] = Fr::from_u64(env, LIBRA_SUBGROUP_SIZE as u64);
    batch_inverse(&denominators, &mut inverse_denominators).map_err(|_| "invalid ZK proof")?;

    let barycentric_numerator = &vanishing_poly_eval * &inverse_denominators[LIBRA_SUBGROUP_SIZE];

    // F is represented in Lagrange form over H as
    //   (1, 1,u_0,...,u_0^8, 1,u_1,...,u_1^8, ...).
    // The final three of the 256 entries are zero because 1 + 28*9 = 253.
    debug_assert_eq!(
        1 + CONST_PROOF_SIZE_LOG_N * ZK_BATCHED_RELATION_PARTIAL_LENGTH,
        253
    );
    let mut challenge_poly_sum = inverse_denominators[0].clone();
    for round in 0..CONST_PROOF_SIZE_LOG_N {
        let mut challenge_power = one.clone();
        let start = 1 + round * ZK_BATCHED_RELATION_PARTIAL_LENGTH;
        for idx in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH {
            challenge_poly_sum =
                challenge_poly_sum + &(&challenge_power * &inverse_denominators[start + idx]);
            challenge_power = challenge_power * &tp.sumcheck_u_challenges[round];
        }
    }

    let challenge_poly_eval = &challenge_poly_sum * &barycentric_numerator;
    let lagrange_first = &inverse_denominators[0] * &barycentric_numerator;
    let lagrange_last = &inverse_denominators[LIBRA_SUBGROUP_SIZE - 1] * &barycentric_numerator;

    let concatenation_eval = &proof.libra_poly_evaluations[0]; // G(r)
    let shifted_grand_sum_eval = &proof.libra_poly_evaluations[1]; // A(g*r)
    let grand_sum_eval = &proof.libra_poly_evaluations[2]; // A(r)
    let quotient_eval = &proof.libra_poly_evaluations[3]; // Q(r)

    let challenge_term = concatenation_eval * &challenge_poly_eval;
    let grand_sum_identity = shifted_grand_sum_eval - grand_sum_eval - &challenge_term;

    let mut diff = &lagrange_first * grand_sum_eval;
    diff = diff + &(&(r - &subgroup_generator_inverse) * &grand_sum_identity);
    diff = diff + &(&lagrange_last * &(grand_sum_eval - &proof.libra_evaluation));
    diff = diff - &(&vanishing_poly_eval * quotient_eval);

    if diff == zero {
        Ok(())
    } else {
        Err("invalid ZK proof")
    }
}

/// Verify the Gemini + Shplonk + KZG opening claim for an UltraKeccakZK proof.
pub fn verify_zk_shplemini(
    env: &Env,
    proof: &ZkProof,
    vk: &VerificationKey,
    tp: &ZkTranscript,
) -> Result<(), &'static str> {
    let log_n = vk.log_circuit_size as usize;
    if log_n == 0 || log_n > CONST_PROOF_SIZE_LOG_N {
        return Err("invalid ZK proof");
    }

    let one = Fr::one(env);
    let two = Fr::from_u64(env, 2);
    let subgroup_generator = libra_subgroup_generator(env);

    // The SmallSubgroupIPA check binds the Libra openings to the evaluation
    // used by ZK sumcheck. It is logically independent of the final KZG check.
    check_libra_evaluations_consistency(env, proof, tp)?;

    // r, r^2, r^4, ...
    let mut r_pows = Fr::zero_array::<CONST_PROOF_SIZE_LOG_N>(env);
    r_pows[0] = tp.gemini_r.clone();
    for i in 1..log_n {
        r_pows[i] = &r_pows[i - 1] * &r_pows[i - 1];
    }

    // Invert the Shplonk/Gemini denominators, the Gemini folding
    // denominators, r itself, and the one additional Libra opening
    // denominator z-g*r in one batch.
    const MAX_INVERSE_BATCH: usize = 3 * CONST_PROOF_SIZE_LOG_N + 2;
    let further_base = 3 + log_n;
    let libra_shift_denominator_idx = further_base + 2 * (log_n - 1);
    let inverse_batch_size = libra_shift_denominator_idx + 1;
    let mut denominators = Fr::zero_array::<MAX_INVERSE_BATCH>(env);
    let mut inverse_denominators = Fr::zero_array::<MAX_INVERSE_BATCH>(env);

    denominators[0] = &tp.shplonk_z - &r_pows[0];
    denominators[1] = &tp.shplonk_z + &r_pows[0];
    denominators[2] = tp.gemini_r.clone();

    for j in (1..=log_n).rev() {
        let u = &tp.sumcheck_u_challenges[j - 1];
        denominators[3 + (log_n - j)] = &r_pows[j - 1] * &(&one - u) + u;
    }
    for j in 1..log_n {
        denominators[further_base + 2 * (j - 1)] = &tp.shplonk_z - &r_pows[j];
        denominators[further_base + 2 * (j - 1) + 1] = &tp.shplonk_z + &r_pows[j];
    }
    denominators[libra_shift_denominator_idx] =
        &tp.shplonk_z - &(&subgroup_generator * &tp.gemini_r);

    batch_inverse(
        &denominators[..inverse_batch_size],
        &mut inverse_denominators[..inverse_batch_size],
    )
    .map_err(|_| "invalid ZK proof")?;

    let pos0 = inverse_denominators[0].clone();
    let neg0 = inverse_denominators[1].clone();
    let gemini_r_inverse = inverse_denominators[2].clone();
    let libra_shift_inverse = inverse_denominators[libra_shift_denominator_idx].clone();

    // Deduplicated MSM layout:
    //   Q | Gemini masking | 35 entity commitments | 27 folds |
    //   3 Libra commitments | [1]_1 | KZG quotient.
    const Q_IDX: usize = 0;
    const MASKING_IDX: usize = 1;
    const ENTITY_BASE: usize = 2;
    const FOLD_BASE: usize = ENTITY_BASE + NUMBER_UNSHIFTED;
    const LIBRA_BASE: usize = FOLD_BASE + (CONST_PROOF_SIZE_LOG_N - 1);
    const GENERATOR_IDX: usize = LIBRA_BASE + NUM_LIBRA_COMMITMENTS;
    const KZG_IDX: usize = GENERATOR_IDX + 1;
    const TOTAL: usize = KZG_IDX + 1;

    let mut scalars = Fr::zero_array::<TOTAL>(env);
    let mut commitments = repeat::<G1Point, TOTAL>(G1Point::infinity(env));

    let unshifted_scalar = &pos0 + &(&tp.shplonk_nu * &neg0);
    let shifted_scalar = &gemini_r_inverse * &(&pos0 - &(&tp.shplonk_nu * &neg0));

    scalars[Q_IDX] = one.clone();
    commitments[Q_IDX] = proof.shplonk_q.clone();
    scalars[MASKING_IDX] = -&unshifted_scalar;
    commitments[MASKING_IDX] = proof.gemini_masking_polynomial.clone();

    // rho^0 belongs to the Gemini hiding polynomial. Entity claims therefore
    // begin at rho^1.
    let mut rho_power = tp.rho.clone();
    let mut batched_evaluation = proof.gemini_masking_evaluation.clone();
    let mut evaluation_scalars = Fr::zero_array::<NUMBER_OF_ENTITIES>(env);
    for (idx, evaluation) in proof.sumcheck_evaluations.iter().enumerate() {
        let batch_scalar = if idx < NUMBER_UNSHIFTED {
            -&unshifted_scalar
        } else {
            -&shifted_scalar
        };
        evaluation_scalars[idx] = &batch_scalar * &rho_power;
        batched_evaluation = batched_evaluation + &(evaluation * &rho_power);
        rho_power = rho_power * &tp.rho;
    }

    // The shifted wire claims use the same commitments as their unshifted
    // counterparts. Merge their scalars to avoid five redundant MSM terms.
    for (unshifted, shifted) in [(27, 35), (28, 36), (29, 37), (30, 38), (31, 39)] {
        evaluation_scalars[unshifted] =
            &evaluation_scalars[unshifted] + &evaluation_scalars[shifted];
    }

    {
        let mut j = ENTITY_BASE;
        macro_rules! push_vk {
            ($($field:ident),+ $(,)?) => {
                $(
                    commitments[j] = vk.$field.clone();
                    scalars[j] = evaluation_scalars[j - ENTITY_BASE].clone();
                    j += 1;
                )+
            };
        }
        push_vk![
            qm,
            qc,
            ql,
            qr,
            qo,
            q4,
            q_lookup,
            q_arith,
            q_delta_range,
            q_elliptic,
            q_aux,
            q_poseidon2_external,
            q_poseidon2_internal,
            s1,
            s2,
            s3,
            s4,
            id1,
            id2,
            id3,
            id4,
            t1,
            t2,
            t3,
            t4,
            lagrange_first,
            lagrange_last
        ];

        commitments[j] = proof.w1.clone();
        scalars[j] = evaluation_scalars[27].clone();
        j += 1;
        commitments[j] = proof.w2.clone();
        scalars[j] = evaluation_scalars[28].clone();
        j += 1;
        commitments[j] = proof.w3.clone();
        scalars[j] = evaluation_scalars[29].clone();
        j += 1;
        commitments[j] = proof.w4.clone();
        scalars[j] = evaluation_scalars[30].clone();
        j += 1;
        commitments[j] = proof.z_perm.clone();
        scalars[j] = evaluation_scalars[31].clone();
        j += 1;
        commitments[j] = proof.lookup_inverses.clone();
        scalars[j] = evaluation_scalars[32].clone();
        j += 1;
        commitments[j] = proof.lookup_read_counts.clone();
        scalars[j] = evaluation_scalars[33].clone();
        j += 1;
        commitments[j] = proof.lookup_read_tags.clone();
        scalars[j] = evaluation_scalars[34].clone();
        debug_assert_eq!(j + 1, FOLD_BASE);
    }

    // Reconstruct A_j(r^(2^j)) from A_j(-r^(2^j)), the multilinear
    // evaluation, and the sumcheck challenge vector.
    let mut fold_positive_evaluations = Fr::zero_array::<CONST_PROOF_SIZE_LOG_N>(env);
    let mut current_evaluation = batched_evaluation;
    for j in (1..=log_n).rev() {
        let r_power = &r_pows[j - 1];
        let u = &tp.sumcheck_u_challenges[j - 1];
        let numerator = r_power * &current_evaluation * &two
            - &(&proof.gemini_a_evaluations[j - 1] * &(r_power * &(&one - u) - u));
        current_evaluation = numerator * &inverse_denominators[3 + (log_n - j)];
        fold_positive_evaluations[j - 1] = current_evaluation.clone();
    }

    let nu_squared = &tp.shplonk_nu * &tp.shplonk_nu;
    let mut constant_term = &fold_positive_evaluations[0] * &pos0
        + &(&proof.gemini_a_evaluations[0] * &tp.shplonk_nu * &neg0);
    let mut nu_power = nu_squared.clone();

    for j in 1..log_n {
        let pos_inverse = &inverse_denominators[further_base + 2 * (j - 1)];
        let neg_inverse = &inverse_denominators[further_base + 2 * (j - 1) + 1];
        let positive_scaling = &nu_power * pos_inverse;
        let negative_scaling = &nu_power * &tp.shplonk_nu * neg_inverse;

        scalars[FOLD_BASE + j - 1] = -(&positive_scaling + &negative_scaling);
        constant_term = constant_term
            + &(&proof.gemini_a_evaluations[j] * &negative_scaling)
            + &(&fold_positive_evaluations[j] * &positive_scaling);
        commitments[FOLD_BASE + j - 1] = proof.gemini_fold_comms[j - 1].clone();

        nu_power = nu_power * &nu_squared;
    }

    // Dummy fold commitments are transcript-bound but have zero MSM scalars.
    commitments[(FOLD_BASE + log_n - 1)..(FOLD_BASE + CONST_PROOF_SIZE_LOG_N - 1)]
        .clone_from_slice(&proof.gemini_fold_comms[(log_n - 1)..(CONST_PROOF_SIZE_LOG_N - 1)]);

    // Shplemini reserves 2*28 powers for Gemini and two more powers for the
    // generic interleaving slots. Ultra has no interleaved claims, but Libra
    // still starts at nu^(2*28 + 2) = nu^58.
    const LIBRA_NU_START: u64 = (2 * CONST_PROOF_SIZE_LOG_N + 2) as u64;
    let mut libra_nu_power = tp.shplonk_nu.pow(LIBRA_NU_START);
    let mut libra_scalars = Fr::zero_array::<NUM_LIBRA_EVALUATIONS>(env);
    for (idx, libra_scalar) in libra_scalars.iter_mut().enumerate() {
        let denominator_inverse = if idx == 1 {
            &libra_shift_inverse // A(g*r) is opened at g*r
        } else {
            &pos0 // G(r), A(r), and Q(r) are opened at r
        };
        let scaling = &libra_nu_power * denominator_inverse;
        *libra_scalar = -&scaling;
        constant_term = constant_term + &(&proof.libra_poly_evaluations[idx] * &scaling);
        libra_nu_power = libra_nu_power * &tp.shplonk_nu;
    }

    commitments[LIBRA_BASE] = proof.libra_concatenation_commitment.clone();
    scalars[LIBRA_BASE] = libra_scalars[0].clone();
    commitments[LIBRA_BASE + 1] = proof.libra_grand_sum_commitment.clone();
    scalars[LIBRA_BASE + 1] = &libra_scalars[1] + &libra_scalars[2];
    commitments[LIBRA_BASE + 2] = proof.libra_quotient_commitment.clone();
    scalars[LIBRA_BASE + 2] = libra_scalars[3].clone();

    commitments[GENERATOR_IDX] = G1Point::generator(env);
    scalars[GENERATOR_IDX] = constant_term;
    commitments[KZG_IDX] = proof.kzg_quotient.clone();
    scalars[KZG_IDX] = tp.shplonk_z.clone();

    let p0 = g1_msm(env, &commitments, &scalars)?;
    let p1 = proof.kzg_quotient.0.clone().neg();
    if pairing_check(env, &p0, &p1) {
        Ok(())
    } else {
        Err("invalid ZK proof")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libra_subgroup_constants_are_inverses() {
        let env = Env::default();
        assert_eq!(
            libra_subgroup_generator(&env) * libra_subgroup_generator_inverse(&env),
            Fr::one(&env)
        );
        assert_eq!(
            libra_subgroup_generator(&env).pow(LIBRA_SUBGROUP_SIZE as u64),
            Fr::one(&env)
        );
    }
}
