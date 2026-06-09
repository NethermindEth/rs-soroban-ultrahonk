//! Relation accumulation for UltraHonk.
//!
//! Evaluates all 26 subrelations across 8 relation families at the purported
//! evaluation point, then batches them with independent alpha challenges.
//! Every formula was verified line-by-line against Barretenberg v0.82.2.
//!
//! BB reference (v0.82.2):
//!   - `relations/ultra_arithmetic_relation.hpp`
//!   - `relations/permutation_relation.hpp`
//!   - `relations/logderiv_lookup_relation.hpp`
//!   - `relations/delta_range_constraint_relation.hpp`
//!   - `relations/elliptic_relation.hpp`
//!   - `relations/auxiliary_relation.hpp`
//!   - `relations/poseidon2_external_relation.hpp`
//!   - `relations/poseidon2_internal_relation.hpp`
//!   - `sumcheck_round.hpp::SumcheckVerifierRound::compute_full_relation_purported_value`

use crate::field::Fr;
use crate::types::{RelationParameters, Wire, NUMBER_OF_SUBRELATIONS};
use core::ops::Index;
use soroban_sdk::{bytesn, crypto::bn254::Bn254Fr, Env};

impl Index<Wire> for [Fr] {
    type Output = Fr;

    #[inline(always)]
    fn index(&self, wire: Wire) -> &Self::Output {
        &self[wire.index()]
    }
}

/// Accumulate the two arithmetic subrelations (indices 0 and 1).
///
/// BB: `relations/ultra_arithmetic_relation.hpp::UltraArithmeticRelation::accumulate`
fn accumulate_arithmetic_relation(env: &Env, p: &[Fr], evals: &mut [Fr], domain_sep: &Fr) {
    let one = Fr::one(env);
    let two = Fr::from_u64(env, 2);
    let three = Fr::from_u64(env, 3);
    let neg_half = Fr::neg_half(env);

    let q_arith = &p[Wire::QArith];
    let qm = &p[Wire::Qm];
    let wr = &p[Wire::Wr];
    let wl = &p[Wire::Wl];
    let ql = &p[Wire::Ql];
    let qr = &p[Wire::Qr];
    let qo = &p[Wire::Qo];
    let q4 = &p[Wire::Q4];
    let w4 = &p[Wire::W4];
    let qc = &p[Wire::Qc];
    let w4_shift = &p[Wire::W4Shift];
    let wl_shift = &p[Wire::WlShift];
    let wo = &p[Wire::Wo];
    // Relation 0
    {
        let mut accum = (q_arith - &three) * qm * wr * wl * &neg_half;
        accum = accum + ql * wl + qr * wr + qo * wo + q4 * w4 + qc;
        accum = (accum + (q_arith - &one) * w4_shift) * q_arith * domain_sep;
        evals[0] = accum;
    }
    // Relation 1
    {
        let mut accum = wl + w4 - wl_shift + qm;
        accum = accum * (q_arith - &two) * (q_arith - &one) * q_arith * domain_sep;
        evals[1] = accum;
    }
}

/// Accumulate the two permutation subrelations (indices 2 and 3).
///
/// BB: `relations/permutation_relation.hpp::UltraPermutationRelation::accumulate`
fn accumulate_permutation_relation(
    p: &[Fr],
    rp: &RelationParameters,
    evals: &mut [Fr],
    domain_sep: &Fr,
) {
    let wl = &p[Wire::Wl];
    let wr = &p[Wire::Wr];
    let wo = &p[Wire::Wo];
    let w4 = &p[Wire::W4];
    let z_perm = &p[Wire::ZPerm];
    let lagrange_first = &p[Wire::LagrangeFirst];
    let z_perm_shift = &p[Wire::ZPermShift];
    let lagrange_last = &p[Wire::LagrangeLast];

    let grand_product_numerator = {
        let mut num = wl + &p[Wire::Id1] * &rp.beta + &rp.gamma;
        num = num
            * (wr + &p[Wire::Id2] * &rp.beta + &rp.gamma)
            * (wo + &p[Wire::Id3] * &rp.beta + &rp.gamma)
            * (w4 + &p[Wire::Id4] * &rp.beta + &rp.gamma);
        num
    };

    let grand_product_denominator = {
        let mut den = wl + &p[Wire::Sigma1] * &rp.beta + &rp.gamma;
        den = den
            * (wr + &p[Wire::Sigma2] * &rp.beta + &rp.gamma)
            * (wo + &p[Wire::Sigma3] * &rp.beta + &rp.gamma)
            * (w4 + &p[Wire::Sigma4] * &rp.beta + &rp.gamma);
        den
    };

    // Contribution 2
    {
        evals[2] = ((z_perm + lagrange_first) * grand_product_numerator
            - (z_perm_shift + lagrange_last * &rp.public_inputs_delta) * grand_product_denominator)
            * domain_sep;
    }

    // Contribution 3
    {
        evals[3] = lagrange_last * z_perm_shift * domain_sep;
    }
}

/// Accumulate the two lookup log-derivative subrelations (indices 4 and 5).
///
/// BB: `relations/logderiv_lookup_relation.hpp::LogDerivLookupRelation::accumulate`
fn accumulate_log_derivative_lookup_relation(
    p: &[Fr],
    rp: &RelationParameters,
    evals: &mut [Fr],
    domain_sep: &Fr,
) {
    let write_term = &p[Wire::Table1]
        + &rp.gamma
        + &p[Wire::Table2] * &rp.eta
        + &p[Wire::Table3] * &rp.eta_two
        + &p[Wire::Table4] * &rp.eta_three;

    let derived_entry_2 = &p[Wire::Wr] + &p[Wire::Qm] * &p[Wire::WrShift];
    let derived_entry_3 = &p[Wire::Wo] + &p[Wire::Qc] * &p[Wire::WoShift];

    let read_term = &p[Wire::Wl]
        + &rp.gamma
        + &p[Wire::Qr] * &p[Wire::WlShift]
        + derived_entry_2 * &rp.eta
        + derived_entry_3 * &rp.eta_two
        + &p[Wire::Qo] * &rp.eta_three;

    let inv = &p[Wire::LookupInverses];
    let lookup_read_tags = &p[Wire::LookupReadTags];
    let q_lookup = &p[Wire::QLookup];
    let inv_exists = lookup_read_tags + q_lookup - lookup_read_tags * q_lookup;

    evals[4] = (&read_term * &write_term * inv - inv_exists) * domain_sep;
    evals[5] = q_lookup * (&write_term * inv) - &p[Wire::LookupReadCounts] * (read_term * inv);
}

/// Accumulate the four range-check subrelations (indices 6..9).
///
/// BB: `relations/delta_range_constraint_relation.hpp::DeltaRangeConstraintRelation::accumulate`
fn accumulate_delta_range_relation(env: &Env, p: &[Fr], evals: &mut [Fr], domain_sep: &Fr) {
    let minus_one = Fr::minus_one(env);
    let minus_two = Fr::minus_two(env);
    let minus_three = Fr::minus_three(env);

    let wr = &p[Wire::Wr];
    let wl = &p[Wire::Wl];
    let wo = &p[Wire::Wo];
    let w4 = &p[Wire::W4];
    let wl_shift = &p[Wire::WlShift];
    let delta_1 = wr - wl;
    let delta_2 = wo - wr;
    let delta_3 = w4 - wo;
    let delta_4 = wl_shift - w4;
    let deltas = [delta_1, delta_2, delta_3, delta_4];
    let negs = [minus_one, minus_two, minus_three];
    let q_range_dom = &p[Wire::QRange] * domain_sep;

    // Contributions 6..9
    for i in 0..4 {
        let mut acc = deltas[i].clone();
        for n in &negs {
            acc = acc * (&deltas[i] + n);
        }
        evals[6 + i] = acc * &q_range_dom;
    }
}

/// Accumulate elliptic-curve subrelations (indices 10..11).
///
/// Uses Grumpkin curve parameter `b = -17` (so `B_NEG = 17`).
///
/// BB: `relations/elliptic_relation.hpp::EllipticRelation::accumulate`
fn accumulate_elliptic_relation(env: &Env, p: &[Fr], evals: &mut [Fr], domain_sep: &Fr) {
    let one = Fr::one(env);
    let nine = Fr::from_u64(env, 9);

    let x1 = &p[Wire::Wr];
    let y1 = &p[Wire::Wo];
    let x2 = &p[Wire::WlShift];
    let y2 = &p[Wire::W4Shift];
    let x3 = &p[Wire::WrShift];
    let y3 = &p[Wire::WoShift];

    let q_sign = &p[Wire::Ql];
    let q_double = &p[Wire::Qm];
    let q_gate = &p[Wire::QElliptic];

    let delta_x = x2 - x1;
    let y1_sq = y1 * y1;

    let x_add_id = {
        let y2_sq = y2 * y2;
        let y1y2 = y1 * y2 * q_sign;
        (x3 + x2 + x1) * &delta_x * &delta_x - &y2_sq - &y1_sq + &y1y2 + &y1y2
    };
    let y_add_id = {
        let y_diff = y2 * q_sign - y1;
        (y1 + y3) * &delta_x + (x3 - x1) * &y_diff
    };

    const B_NEG: u64 = 17;
    let b_neg = Fr::from_u64(env, B_NEG);

    let x_double_id = {
        let x_pow_4 = (&y1_sq + &b_neg) * x1;
        let y1_sqr_mul_4 = &y1_sq + &y1_sq + &y1_sq + &y1_sq;
        let x_pow_4_mul_9 = x_pow_4 * &nine;
        (x3 + x1 + x1) * y1_sqr_mul_4 - x_pow_4_mul_9
    };
    let y_double_id = {
        let x1_sqr_mul_3 = (x1 + x1 + x1) * x1;
        x1_sqr_mul_3 * (x1 - x3) - (y1 + y1) * (y1 + y3)
    };

    let q_gate_dom = q_gate * domain_sep;
    let add_factor = (one - q_double) * &q_gate_dom;
    let double_factor = q_double * q_gate_dom;

    // Contribution 10: elliptic x
    evals[10] = x_add_id * &add_factor + x_double_id * &double_factor;
    // Contribution 11: elliptic y
    evals[11] = y_add_id * add_factor + y_double_id * double_factor;
}

/// Accumulate auxiliary subrelations (indices 12..17).
///
/// Covers non-native field gates, limb accumulators, memory record checks,
/// ROM consistency, and RAM consistency.
///
/// BB: `relations/auxiliary_relation.hpp::AuxiliaryRelation::accumulate`
fn accumulate_auxiliary_relation(
    env: &Env,
    p: &[Fr],
    rp: &RelationParameters,
    evals: &mut [Fr],
    domain_sep: &Fr,
) {
    let one = Fr::one(env);
    let limb_size = Fr(Bn254Fr::from_bytes(bytesn!(
        &env,
        0x0000000000000000000000000000000000000000000000100000000000000000
    )));
    let sublimb_shift = Fr::from_u64(env, 1 << 14);

    let wl = &p[Wire::Wl];
    let wr = &p[Wire::Wr];
    let wo = &p[Wire::Wo];
    let w4 = &p[Wire::W4];
    let wl_shift = &p[Wire::WlShift];
    let wr_shift = &p[Wire::WrShift];
    let wo_shift = &p[Wire::WoShift];
    let w4_shift = &p[Wire::W4Shift];
    let ql = &p[Wire::Ql];
    let qr = &p[Wire::Qr];
    let qo = &p[Wire::Qo];
    let q4 = &p[Wire::Q4];
    let qm = &p[Wire::Qm];
    let qc = &p[Wire::Qc];
    let q_aux = &p[Wire::QAux];
    let q_arith = &p[Wire::QArith];

    let mut limb_subproduct = wl * wr_shift + wl_shift * wr;

    let mut non_native_field_gate_2 = wl * w4 + wr * wo - wo_shift;
    non_native_field_gate_2 = non_native_field_gate_2 * &limb_size - w4_shift + &limb_subproduct;
    non_native_field_gate_2 = non_native_field_gate_2 * q4;

    limb_subproduct = limb_size * &limb_subproduct + wl_shift * wr_shift;

    let non_native_field_gate_1 = (&limb_subproduct - &(wo + w4)) * qo;

    let non_native_field_gate_3 = (w4 - &(wo_shift + w4_shift) + &limb_subproduct) * qm;

    let non_native_field_identity =
        (non_native_field_gate_1 + non_native_field_gate_2 + non_native_field_gate_3) * qr;

    let mut limb_accumulator_1 = wr_shift * &sublimb_shift + wl_shift;
    limb_accumulator_1 = limb_accumulator_1 * &sublimb_shift + wo;
    limb_accumulator_1 = limb_accumulator_1 * &sublimb_shift + wr;
    limb_accumulator_1 = limb_accumulator_1 * &sublimb_shift + wl;
    limb_accumulator_1 = (limb_accumulator_1 - w4) * q4;
    let mut limb_accumulator_2 = wo_shift * &sublimb_shift + wr_shift;
    limb_accumulator_2 = limb_accumulator_2 * &sublimb_shift + wl_shift;
    limb_accumulator_2 = limb_accumulator_2 * &sublimb_shift + w4;
    limb_accumulator_2 = limb_accumulator_2 * &sublimb_shift + wo;
    limb_accumulator_2 = (limb_accumulator_2 - w4_shift) * qm;

    let limb_accumulator_identity = (limb_accumulator_1 + limb_accumulator_2) * qo;

    let memory_record_check = wo * &rp.eta_three + wr * &rp.eta_two + wl * &rp.eta + qc;
    let access_type = w4 - &memory_record_check;
    let memory_record_check = memory_record_check - w4;

    let index_delta = wl_shift - wl;
    let record_delta = w4_shift - w4;

    let index_is_monotonically_increasing = &index_delta * &index_delta - &index_delta;
    let adjacent_values_match_if_adjacent_indices_match = (&one - &index_delta) * record_delta;

    let rom_gate_common = ql * qr * q_aux * domain_sep;

    evals[13] = adjacent_values_match_if_adjacent_indices_match * &rom_gate_common;
    // Contribution 14: ROM index monotonic
    evals[14] = &index_is_monotonically_increasing * rom_gate_common;

    let access_check = &access_type * &access_type - access_type;

    let mut next_gate_access_type =
        wo_shift * &rp.eta_three + wr_shift * &rp.eta_two + wl_shift * &rp.eta;
    next_gate_access_type = w4_shift - &next_gate_access_type;

    let value_delta = wo_shift - wo;
    let adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation =
        (&one - &index_delta) * value_delta * (&one - &next_gate_access_type);

    let ram_gate_common = q_arith * q_aux * domain_sep;

    // Contribution 15,16,17: RAM
    evals[15] = adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation
        * &ram_gate_common;
    evals[16] = index_is_monotonically_increasing * &ram_gate_common;
    evals[17] =
        (&next_gate_access_type * &next_gate_access_type - next_gate_access_type) * ram_gate_common;

    let rom_consistency_check_identity = &memory_record_check * ql * qr;
    let ram_timestamp_check_identity = (&one - index_delta) * (wr_shift - wr) - wo;
    let ram_consistency_check_identity = access_check * q_arith;

    let memory_identity = rom_consistency_check_identity
        + ram_timestamp_check_identity * q4 * ql
        + memory_record_check * qm * ql
        + ram_consistency_check_identity;

    let auxiliary_identity =
        memory_identity + non_native_field_identity + limb_accumulator_identity;
    // Contribution 12
    evals[12] = auxiliary_identity * q_aux * domain_sep;
}

/// Accumulate Poseidon external subrelations (indices 18..21).
///
/// BB: `relations/poseidon2_external_relation.hpp::Poseidon2ExternalRelation::accumulate`
fn accumulate_poseidon_external_relation(p: &[Fr], evals: &mut [Fr], domain_sep: &Fr) {
    let wl = &p[Wire::Wl];
    let ql = &p[Wire::Ql];
    let wr = &p[Wire::Wr];
    let qr = &p[Wire::Qr];
    let wo = &p[Wire::Wo];
    let qo = &p[Wire::Qo];
    let w4 = &p[Wire::W4];
    let q4 = &p[Wire::Q4];
    let wl_shift = &p[Wire::WlShift];
    let wr_shift = &p[Wire::WrShift];
    let wo_shift = &p[Wire::WoShift];
    let w4_shift = &p[Wire::W4Shift];
    let q_poseidon = &p[Wire::QPoseidon2External];

    let s1 = wl + ql;
    let s2 = wr + qr;
    let s3 = wo + qo;
    let s4 = w4 + q4;

    let u1_ext = s1.pow(5);
    let u2_ext = s2.pow(5);
    let u3_ext = s3.pow(5);
    let u4_ext = s4.pow(5);

    let t0 = &u1_ext + &u2_ext;
    let t1 = &u3_ext + &u4_ext;
    let t2 = &u2_ext + &u2_ext + &t1;
    let t3 = &u4_ext + &u4_ext + &t0;

    let v4 = &t1 + &t1 + &t1 + &t1 + &t3;
    let v2 = &t0 + &t0 + &t0 + &t0 + &t2;
    let v1 = &t3 + &v2;
    let v3 = &t2 + &v4;

    let q_poseidon_dom = q_poseidon * domain_sep;
    evals[18] = (v1 - wl_shift) * &q_poseidon_dom;
    evals[19] = (v2 - wr_shift) * &q_poseidon_dom;
    evals[20] = (v3 - wo_shift) * &q_poseidon_dom;
    evals[21] = (v4 - w4_shift) * q_poseidon_dom;
}

/// Accumulate Poseidon internal subrelations (indices 22..25).
///
/// Uses the internal matrix diagonal constants from `field.rs::Fr::internal_matrix_diagonal`.
///
/// BB: `relations/poseidon2_internal_relation.hpp::Poseidon2InternalRelation::accumulate`
fn accumulate_poseidon_internal_relation(
    p: &[Fr],
    evals: &mut [Fr],
    domain_sep: &Fr,
    diag: &[Fr; 4],
) {
    let wl = &p[Wire::Wl];
    let ql = &p[Wire::Ql];
    let u1_int = (wl + ql).pow(5);
    let u2_int = &p[Wire::Wr];
    let u3_int = &p[Wire::Wo];
    let u4_int = &p[Wire::W4];
    let wl_shift = &p[Wire::WlShift];
    let wr_shift = &p[Wire::WrShift];
    let wo_shift = &p[Wire::WoShift];
    let w4_shift = &p[Wire::W4Shift];
    let q_poseidon = &p[Wire::QPoseidon2Internal];
    let q_poseidon_dom = q_poseidon * domain_sep;
    let u_sum = &u1_int + u2_int + u3_int + u4_int;

    let w1 = &u1_int * &diag[0] + &u_sum;
    let w2 = u2_int * &diag[1] + &u_sum;
    let w3 = u3_int * &diag[2] + &u_sum;
    let w4 = u4_int * &diag[3] + &u_sum;

    evals[22] = (w1 - wl_shift) * &q_poseidon_dom;
    evals[23] = (w2 - wr_shift) * &q_poseidon_dom;
    evals[24] = (w3 - wo_shift) * &q_poseidon_dom;
    evals[25] = (w4 - w4_shift) * q_poseidon_dom;
}

/// Batch all 26 subrelations with the independent alpha challenges.
///
/// `UltraFlavor` is a folding flavor, so alphas are independent challenges
/// (not powers of a single alpha).  Result:
///   `evals[0]·1 + evals[1]·α₀ + … + evals[25]·α₂₄`
///
/// BB: `relations/utils.hpp::RelationUtils::scale_and_batch_elements`
fn scale_and_batch_subrelations(evaluations: &[Fr], subrelation_challenges: &[Fr]) -> Fr {
    let mut accumulator = evaluations[0].clone();
    for i in 1..NUMBER_OF_SUBRELATIONS {
        accumulator = accumulator + &evaluations[i] * &subrelation_challenges[i - 1];
    }
    accumulator
}

/// Main entrypoint: evaluate all 26 subrelations and batch with alphas.
///
/// BB: `sumcheck_round.hpp::SumcheckVerifierRound::compute_full_relation_purported_value`
pub fn accumulate_relation_evaluations(
    env: &Env,
    purported_evaluations: &[Fr],
    rp: &RelationParameters,
    alphas: &[Fr],
    pow_partial_eval: Fr,
) -> Fr {
    let mut evaluations = Fr::zero_array::<NUMBER_OF_SUBRELATIONS>(env);
    let domain_sep = &pow_partial_eval;
    let poseidon_internal_diag = Fr::internal_matrix_diagonal(env);

    accumulate_arithmetic_relation(env, purported_evaluations, &mut evaluations, domain_sep);
    accumulate_permutation_relation(purported_evaluations, rp, &mut evaluations, domain_sep);
    accumulate_log_derivative_lookup_relation(
        purported_evaluations,
        rp,
        &mut evaluations,
        domain_sep,
    );
    accumulate_delta_range_relation(env, purported_evaluations, &mut evaluations, domain_sep);
    accumulate_elliptic_relation(env, purported_evaluations, &mut evaluations, domain_sep);
    accumulate_auxiliary_relation(env, purported_evaluations, rp, &mut evaluations, domain_sep);
    accumulate_poseidon_external_relation(purported_evaluations, &mut evaluations, domain_sep);
    accumulate_poseidon_internal_relation(
        purported_evaluations,
        &mut evaluations,
        domain_sep,
        &poseidon_internal_diag,
    );

    scale_and_batch_subrelations(&evaluations, alphas)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relations_determinism() {
        let env = Env::default();
        let mut purported_evaluations =
            Fr::zero_array::<{ crate::types::NUMBER_OF_ENTITIES }>(&env);
        for (i, eval) in purported_evaluations.iter_mut().enumerate() {
            *eval = Fr::from_u64(&env, i as u64);
        }

        let rp = RelationParameters {
            eta: Fr::from_u64(&env, 100),
            eta_two: Fr::from_u64(&env, 101),
            eta_three: Fr::from_u64(&env, 102),
            beta: Fr::from_u64(&env, 103),
            gamma: Fr::from_u64(&env, 104),
            public_inputs_delta: Fr::from_u64(&env, 105),
        };

        let mut alphas = Fr::zero_array::<{ crate::types::NUMBER_OF_ALPHAS }>(&env);
        for (i, alpha) in alphas.iter_mut().enumerate() {
            *alpha = Fr::from_u64(&env, (200 + i) as u64);
        }

        let pow_partial_eval = Fr::from_u64(&env, 300);

        let result = accumulate_relation_evaluations(
            &env,
            &purported_evaluations,
            &rp,
            &alphas,
            pow_partial_eval,
        );

        assert_eq!(
            result.to_bytes(),
            crate::debug::hex_to_bytes(
                "1ec606befa857100f90267ac1dc687413b93e8586fdbb4682dfda24b864515aa"
            )
        );
    }
}
