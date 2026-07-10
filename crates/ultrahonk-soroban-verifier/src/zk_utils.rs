//! Deserialization for Barretenberg v0.87 UltraKeccakZK proofs.

use core::array;

use soroban_sdk::{Bytes, Env};

use crate::types::{CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ENTITIES, PAIRING_POINTS_SIZE};
use crate::utils::{
    fr_word32, g1_from_proof_blob_at, g1_from_proof_chunk128, read_bytes, validate_fr_blob,
    validate_g1_proof_blob,
};
use crate::zk_types::{ZkProof, NUM_LIBRA_EVALUATIONS, ZK_BATCHED_RELATION_PARTIAL_LENGTH};
use crate::ZK_PROOF_BYTES;

const PAIRING_OBJ_BYTES: usize = PAIRING_POINTS_SIZE * 32;
const PROOF_HEAD_G1_BYTES: usize = 8 * 128;
const LIBRA_CONCAT_COMMITMENT_BYTES: usize = 128;
const LIBRA_SUM_BYTES: usize = 32;
const SUMCHECK_UNIV_BYTES: usize = CONST_PROOF_SIZE_LOG_N * ZK_BATCHED_RELATION_PARTIAL_LENGTH * 32;
const SUMCHECK_EVAL_BYTES: usize = NUMBER_OF_ENTITIES * 32;
const LIBRA_EVAL_BYTES: usize = 32;
const POST_SUMCHECK_G1_BYTES: usize = 3 * 128;
const GEMINI_MASKING_EVAL_BYTES: usize = 32;
const GEMINI_FOLD_COMMS_BYTES: usize = (CONST_PROOF_SIZE_LOG_N - 1) * 128;
const GEMINI_A_EVAL_BYTES: usize = CONST_PROOF_SIZE_LOG_N * 32;
const LIBRA_POLY_EVAL_BYTES: usize = NUM_LIBRA_EVALUATIONS * 32;
const FINAL_TWO_G1_BYTES: usize = 2 * 128;

const _: () = assert!(
    PAIRING_OBJ_BYTES
        + PROOF_HEAD_G1_BYTES
        + LIBRA_CONCAT_COMMITMENT_BYTES
        + LIBRA_SUM_BYTES
        + SUMCHECK_UNIV_BYTES
        + SUMCHECK_EVAL_BYTES
        + LIBRA_EVAL_BYTES
        + POST_SUMCHECK_G1_BYTES
        + GEMINI_MASKING_EVAL_BYTES
        + GEMINI_FOLD_COMMS_BYTES
        + GEMINI_A_EVAL_BYTES
        + LIBRA_POLY_EVAL_BYTES
        + FINAL_TWO_G1_BYTES
        == ZK_PROOF_BYTES
);

pub fn load_zk_proof(env: &Env, proof_bytes: &Bytes) -> Result<ZkProof, &'static str> {
    if proof_bytes.len() as usize != ZK_PROOF_BYTES {
        return Err("invalid ZK proof");
    }
    let mut boundary = 0u32;

    let ppo = read_bytes::<PAIRING_OBJ_BYTES>(proof_bytes, &mut boundary);
    if !validate_fr_blob(&ppo) {
        return Err("invalid ZK proof");
    }
    let pairing_point_object = array::from_fn(|i| fr_word32(env, &ppo, i));

    let head = read_bytes::<PROOF_HEAD_G1_BYTES>(proof_bytes, &mut boundary);
    if !validate_g1_proof_blob(env, &head) {
        return Err("invalid ZK proof");
    }
    let w1 = g1_from_proof_blob_at(env, &head, 0);
    let w2 = g1_from_proof_blob_at(env, &head, 1);
    let w3 = g1_from_proof_blob_at(env, &head, 2);
    let lookup_read_counts = g1_from_proof_blob_at(env, &head, 3);
    let lookup_read_tags = g1_from_proof_blob_at(env, &head, 4);
    let w4 = g1_from_proof_blob_at(env, &head, 5);
    let lookup_inverses = g1_from_proof_blob_at(env, &head, 6);
    let z_perm = g1_from_proof_blob_at(env, &head, 7);

    let libra_concat = read_bytes::<LIBRA_CONCAT_COMMITMENT_BYTES>(proof_bytes, &mut boundary);
    if !validate_g1_proof_blob(env, &libra_concat) {
        return Err("invalid ZK proof");
    }
    let libra_concatenation_commitment = g1_from_proof_chunk128(env, &libra_concat);

    let libra_sum_bytes = read_bytes::<LIBRA_SUM_BYTES>(proof_bytes, &mut boundary);
    if !validate_fr_blob(&libra_sum_bytes) {
        return Err("invalid ZK proof");
    }
    let libra_sum = fr_word32(env, &libra_sum_bytes, 0);

    let univariates = read_bytes::<SUMCHECK_UNIV_BYTES>(proof_bytes, &mut boundary);
    if !validate_fr_blob(&univariates) {
        return Err("invalid ZK proof");
    }
    let sumcheck_univariates = array::from_fn(|round| {
        array::from_fn(|idx| {
            fr_word32(
                env,
                &univariates,
                round * ZK_BATCHED_RELATION_PARTIAL_LENGTH + idx,
            )
        })
    });

    let evaluations = read_bytes::<SUMCHECK_EVAL_BYTES>(proof_bytes, &mut boundary);
    if !validate_fr_blob(&evaluations) {
        return Err("invalid ZK proof");
    }
    let sumcheck_evaluations = array::from_fn(|i| fr_word32(env, &evaluations, i));

    let libra_evaluation_bytes = read_bytes::<LIBRA_EVAL_BYTES>(proof_bytes, &mut boundary);
    if !validate_fr_blob(&libra_evaluation_bytes) {
        return Err("invalid ZK proof");
    }
    let libra_evaluation = fr_word32(env, &libra_evaluation_bytes, 0);

    let post_sumcheck = read_bytes::<POST_SUMCHECK_G1_BYTES>(proof_bytes, &mut boundary);
    if !validate_g1_proof_blob(env, &post_sumcheck) {
        return Err("invalid ZK proof");
    }
    let libra_grand_sum_commitment = g1_from_proof_blob_at(env, &post_sumcheck, 0);
    let libra_quotient_commitment = g1_from_proof_blob_at(env, &post_sumcheck, 1);
    let gemini_masking_polynomial = g1_from_proof_blob_at(env, &post_sumcheck, 2);

    let masking_eval = read_bytes::<GEMINI_MASKING_EVAL_BYTES>(proof_bytes, &mut boundary);
    if !validate_fr_blob(&masking_eval) {
        return Err("invalid ZK proof");
    }
    let gemini_masking_evaluation = fr_word32(env, &masking_eval, 0);

    let folds = read_bytes::<GEMINI_FOLD_COMMS_BYTES>(proof_bytes, &mut boundary);
    if !validate_g1_proof_blob(env, &folds) {
        return Err("invalid ZK proof");
    }
    let gemini_fold_comms = array::from_fn(|i| g1_from_proof_blob_at(env, &folds, i));

    let gemini_evals = read_bytes::<GEMINI_A_EVAL_BYTES>(proof_bytes, &mut boundary);
    if !validate_fr_blob(&gemini_evals) {
        return Err("invalid ZK proof");
    }
    let gemini_a_evaluations = array::from_fn(|i| fr_word32(env, &gemini_evals, i));

    let libra_evals = read_bytes::<LIBRA_POLY_EVAL_BYTES>(proof_bytes, &mut boundary);
    if !validate_fr_blob(&libra_evals) {
        return Err("invalid ZK proof");
    }
    let libra_poly_evaluations = array::from_fn(|i| fr_word32(env, &libra_evals, i));

    let tail = read_bytes::<FINAL_TWO_G1_BYTES>(proof_bytes, &mut boundary);
    if !validate_g1_proof_blob(env, &tail) {
        return Err("invalid ZK proof");
    }
    let shplonk_q = g1_from_proof_blob_at(env, &tail, 0);
    let kzg_quotient = g1_from_proof_blob_at(env, &tail, 1);

    debug_assert_eq!(boundary as usize, ZK_PROOF_BYTES);

    Ok(ZkProof {
        pairing_point_object,
        w1,
        w2,
        w3,
        w4,
        lookup_read_counts,
        lookup_read_tags,
        lookup_inverses,
        z_perm,
        libra_concatenation_commitment,
        libra_sum,
        sumcheck_univariates,
        sumcheck_evaluations,
        libra_evaluation,
        libra_grand_sum_commitment,
        libra_quotient_commitment,
        gemini_masking_polynomial,
        gemini_masking_evaluation,
        gemini_fold_comms,
        gemini_a_evaluations,
        libra_poly_evaluations,
        shplonk_q,
        kzg_quotient,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zk_layout_is_507_fields() {
        assert_eq!(ZK_PROOF_BYTES, 507 * 32);
    }
}
