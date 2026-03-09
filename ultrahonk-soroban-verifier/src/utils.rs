//! Utilities for loading Proof and VerificationKey, plus byte↔field/point conversion.

use crate::field::Fr;
use crate::types::{
    G1Point, Proof, VerificationKey, BATCHED_RELATION_PARTIAL_LENGTH, CONST_PROOF_SIZE_LOG_N,
    NUMBER_OF_ENTITIES, PAIRING_POINTS_SIZE,
};
use core::array;
use soroban_sdk::Bytes;

/// Convert a 32-byte big-endian array into an Fr.
fn bytes32_to_fr(bytes: &[u8; 32]) -> Fr {
    Fr::from_bytes(bytes)
}

fn read_bytes<const N: usize>(bytes: &Bytes, idx: &mut u32) -> [u8; N] {
    let mut out = [0u8; N];
    let end = *idx + N as u32;
    bytes.slice(*idx..end).copy_into_slice(&mut out);
    *idx = end;
    out
}

/// Public version of read_bytes for use by transcript.
pub fn read_bytes_pub<const N: usize>(bytes: &Bytes, idx: &mut u32) -> [u8; N] {
    read_bytes(bytes, idx)
}

/// Compute expected proof size in 32-byte fields for a given log_n (non-ZK format).
pub fn expected_proof_fields(log_n: usize) -> usize {
    PAIRING_POINTS_SIZE              // pairing point object
    + 8 * 2                          // 8 witness G1 points × 2 fields each
    + log_n * BATCHED_RELATION_PARTIAL_LENGTH  // sumcheck univariates
    + NUMBER_OF_ENTITIES             // sumcheck evaluations
    + (log_n - 1) * 2               // gemini fold commitments
    + log_n                          // gemini a evaluations
    + 2 * 2                          // shplonk_q + kzg_quotient
}

/// Load a Proof from a byte array.
///
/// bb 3.0 format: G1 points are plain (x, y) — 64 bytes each.
/// Proof size is dynamic based on log_n.
pub fn load_proof(proof_bytes: &Bytes, log_n: usize) -> Proof {
    let expected = expected_proof_fields(log_n) * 32;
    assert_eq!(proof_bytes.len() as usize, expected, "proof bytes len");
    let mut boundary = 0u32;

    fn read_g1(bytes: &Bytes, cur: &mut u32) -> G1Point {
        let x = read_bytes::<32>(bytes, cur);
        let y = read_bytes::<32>(bytes, cur);
        G1Point { x, y }
    }

    fn read_fr(bytes: &Bytes, cur: &mut u32) -> Fr {
        let arr = read_bytes::<32>(bytes, cur);
        bytes32_to_fr(&arr)
    }

    // 0) pairing point object
    let pairing_point_object: [Fr; PAIRING_POINTS_SIZE] =
        array::from_fn(|_| read_fr(proof_bytes, &mut boundary));

    // 1) w1, w2, w3
    let w1 = read_g1(proof_bytes, &mut boundary);
    let w2 = read_g1(proof_bytes, &mut boundary);
    let w3 = read_g1(proof_bytes, &mut boundary);

    // 2) lookup_read_counts, lookup_read_tags
    let lookup_read_counts = read_g1(proof_bytes, &mut boundary);
    let lookup_read_tags = read_g1(proof_bytes, &mut boundary);

    // 3) w4
    let w4 = read_g1(proof_bytes, &mut boundary);

    // 4) lookup_inverses, z_perm
    let lookup_inverses = read_g1(proof_bytes, &mut boundary);
    let z_perm = read_g1(proof_bytes, &mut boundary);

    // 5) sumcheck_univariates (only log_n rounds)
    let mut sumcheck_univariates =
        [[Fr::zero(); BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N];
    for r in 0..log_n {
        for i in 0..BATCHED_RELATION_PARTIAL_LENGTH {
            sumcheck_univariates[r][i] = read_fr(proof_bytes, &mut boundary);
        }
    }

    // 6) sumcheck_evaluations
    let sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES] =
        array::from_fn(|_| read_fr(proof_bytes, &mut boundary));

    // 7) gemini_fold_comms (only log_n - 1)
    let mut gemini_fold_comms = [G1Point::infinity(); CONST_PROOF_SIZE_LOG_N - 1];
    for i in 0..(log_n - 1) {
        gemini_fold_comms[i] = read_g1(proof_bytes, &mut boundary);
    }

    // 8) gemini_a_evaluations (only log_n)
    let mut gemini_a_evaluations = [Fr::zero(); CONST_PROOF_SIZE_LOG_N];
    for i in 0..log_n {
        gemini_a_evaluations[i] = read_fr(proof_bytes, &mut boundary);
    }

    // 9) shplonk_q, kzg_quotient
    let shplonk_q = read_g1(proof_bytes, &mut boundary);
    let kzg_quotient = read_g1(proof_bytes, &mut boundary);

    Proof {
        pairing_point_object,
        w1,
        w2,
        w3,
        w4,
        lookup_read_counts,
        lookup_read_tags,
        lookup_inverses,
        z_perm,
        sumcheck_univariates,
        sumcheck_evaluations,
        gemini_fold_comms,
        gemini_a_evaluations,
        shplonk_q,
        kzg_quotient,
    }
}

/// Load a VerificationKey.
///
/// bb 3.0 format: 3 × Fr header (log_circuit_size, num_public_inputs, pub_inputs_offset)
/// followed by 28 G1 commitment points (64 bytes each).
pub fn load_vk_from_bytes(bytes: &Bytes) -> Option<VerificationKey> {
    const HEADER_FRS: usize = 3;
    const NUM_POINTS: usize = 28;
    const EXPECTED_LEN: usize = HEADER_FRS * 32 + NUM_POINTS * 64;
    if bytes.len() as usize != EXPECTED_LEN {
        return None;
    }

    fn read_fr_as_u64(bytes: &Bytes, idx: &mut u32) -> u64 {
        let arr = read_bytes::<32>(bytes, idx);
        // Fr is big-endian; value fits in u64
        u64::from_be_bytes([arr[24], arr[25], arr[26], arr[27], arr[28], arr[29], arr[30], arr[31]])
    }
    fn read_point(bytes: &Bytes, idx: &mut u32) -> Option<G1Point> {
        let x = read_bytes::<32>(bytes, idx);
        let y = read_bytes::<32>(bytes, idx);
        Some(G1Point { x, y })
    }

    let mut idx = 0u32;
    let log_circuit_size = read_fr_as_u64(bytes, &mut idx);
    let public_inputs_size = read_fr_as_u64(bytes, &mut idx);
    let pub_inputs_offset = read_fr_as_u64(bytes, &mut idx);
    let circuit_size = 1u64 << log_circuit_size;

    let qm = read_point(bytes, &mut idx)?;
    let qc = read_point(bytes, &mut idx)?;
    let ql = read_point(bytes, &mut idx)?;
    let qr = read_point(bytes, &mut idx)?;
    let qo = read_point(bytes, &mut idx)?;
    let q4 = read_point(bytes, &mut idx)?;
    let q_lookup = read_point(bytes, &mut idx)?;
    let q_arith = read_point(bytes, &mut idx)?;
    let q_delta_range = read_point(bytes, &mut idx)?;
    let q_elliptic = read_point(bytes, &mut idx)?;
    let q_memory = read_point(bytes, &mut idx)?;
    let q_nnf = read_point(bytes, &mut idx)?;
    let q_poseidon2_external = read_point(bytes, &mut idx)?;
    let q_poseidon2_internal = read_point(bytes, &mut idx)?;
    let s1 = read_point(bytes, &mut idx)?;
    let s2 = read_point(bytes, &mut idx)?;
    let s3 = read_point(bytes, &mut idx)?;
    let s4 = read_point(bytes, &mut idx)?;
    let id1 = read_point(bytes, &mut idx)?;
    let id2 = read_point(bytes, &mut idx)?;
    let id3 = read_point(bytes, &mut idx)?;
    let id4 = read_point(bytes, &mut idx)?;
    let t1 = read_point(bytes, &mut idx)?;
    let t2 = read_point(bytes, &mut idx)?;
    let t3 = read_point(bytes, &mut idx)?;
    let t4 = read_point(bytes, &mut idx)?;
    let lagrange_first = read_point(bytes, &mut idx)?;
    let lagrange_last = read_point(bytes, &mut idx)?;

    Some(VerificationKey {
        circuit_size,
        log_circuit_size,
        public_inputs_size,
        pub_inputs_offset,
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
        q_memory,
        q_nnf,
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
        lagrange_last,
        vk_hash: [0u8; 32], // set externally by the verifier
    })
}
