//! Proof and verification-key deserialization.
//!
//! Handles the fixed-size byte layouts emitted by the Barretenberg native prover.
//! G1 coordinates use the BN254 base-field limb split (low 136 bits + high ≤118 bits).
//!
//! BB reference (v0.82.2):
//!   - `honk/proof_system/types/proof.hpp`
//!   - `flavor/ultra_flavor.hpp::Proof`
//!   - `flavor/ultra_flavor.hpp::VerificationKey_`

use crate::field::Fr;
use crate::types::{
    G1Point, Proof, VerificationKey, BATCHED_RELATION_PARTIAL_LENGTH, CONST_PROOF_SIZE_LOG_N,
    NUMBER_OF_ENTITIES, PAIRING_POINTS_SIZE,
};
use crate::PROOF_BYTES;
use core::array;
use soroban_sdk::{Bytes, Env};

/// Contiguous proof layout byte sizes (bb v0.87.0); must sum to `PROOF_BYTES`.
const PAIRING_OBJ_BYTES: usize = PAIRING_POINTS_SIZE * 32;
/// w1, w2, w3, lookup_read_counts, lookup_read_tags, w4, lookup_inverses, z_perm.
const PROOF_HEAD_G1_BYTES: usize = 8 * 128;
const SUMCHECK_UNIV_BYTES: usize = CONST_PROOF_SIZE_LOG_N * BATCHED_RELATION_PARTIAL_LENGTH * 32;
const SUMCHECK_EVAL_BYTES: usize = NUMBER_OF_ENTITIES * 32;
const GEMINI_FOLD_COMMS_BYTES: usize = (CONST_PROOF_SIZE_LOG_N - 1) * 128;
const GEMINI_A_EVAL_BYTES: usize = CONST_PROOF_SIZE_LOG_N * 32;
const FINAL_TWO_G1_BYTES: usize = 2 * 128;

const _: () = assert!(
    PAIRING_OBJ_BYTES
        + PROOF_HEAD_G1_BYTES
        + SUMCHECK_UNIV_BYTES
        + SUMCHECK_EVAL_BYTES
        + GEMINI_FOLD_COMMS_BYTES
        + GEMINI_A_EVAL_BYTES
        + FINAL_TWO_G1_BYTES
        == PROOF_BYTES
);

/// Split a 32-byte big-endian field element into (low136, high≤118) limbs.
///
/// This is the inverse of `combine_limbs`.  Used when serialising G1 coordinates
/// into the transcript buffer.
///
/// BB: `field_conversion::calc_num_bn254_frs` + native serialization
#[inline]
pub fn coord_to_halves_be(coord: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut low = [0u8; 32];
    let mut high = [0u8; 32];
    low[15..].copy_from_slice(&coord[15..]); // 17 bytes
    high[17..].copy_from_slice(&coord[..15]); // 15 bytes
    (low, high)
}

#[inline]
fn read_bytes<const N: usize>(bytes: &Bytes, idx: &mut u32) -> [u8; N] {
    let mut out = [0u8; N];
    let end = *idx + N as u32;
    bytes.slice(*idx..end).copy_into_slice(&mut out);
    *idx = end;
    out
}

#[inline]
fn combine_limbs(lo: &[u8; 32], hi: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..15].copy_from_slice(&hi[17..]);
    out[15..].copy_from_slice(&lo[15..]);
    out
}

#[inline]
fn fr_word32(env: &Env, blob: &[u8], word_idx: usize) -> Fr {
    let o = word_idx * 32;
    Fr::from_array(env, blob[o..o + 32].try_into().expect("fr32"))
}

#[inline]
fn g1_from_proof_chunk128(env: &Env, b: &[u8; 128]) -> G1Point {
    let x = combine_limbs(
        b[0..32].try_into().expect("x_lo"),
        b[32..64].try_into().expect("x_hi"),
    );
    let y = combine_limbs(
        b[64..96].try_into().expect("y_lo"),
        b[96..128].try_into().expect("y_hi"),
    );
    G1Point::from_xy(env, &x, &y)
}

#[inline]
fn g1_from_proof_blob_at(env: &Env, blob: &[u8], point_idx: usize) -> G1Point {
    let o = point_idx * 128;
    g1_from_proof_chunk128(env, blob[o..o + 128].try_into().expect("g1_128"))
}

/// Deserialize a `Proof` from its canonical byte representation.
///
/// The layout is fixed and derived from `ultra_flavor.hpp::PROOF_LENGTH_WITHOUT_PUB_INPUTS`.
/// All field elements are big-endian 32-byte scalars; G1 points use the
/// `(x_lo, x_hi, y_lo, y_hi)` limb layout (128 bytes each).
///
/// BB: `flavor/ultra_flavor.hpp::Proof` (implicit in `BaseTranscript` deserialization)
///
/// Note (bb v0.87.0): G1 coordinates are encoded as two limbs per coordinate
/// using the (lo136, hi<=118) split and stored in the order (x_lo, x_hi, y_lo, y_hi).
pub fn load_proof(env: &Env, proof_bytes: &Bytes) -> Proof {
    assert_eq!(proof_bytes.len() as usize, PROOF_BYTES, "proof bytes len");
    let mut boundary = 0u32;

    // 0) pairing point object — one host read, then in-memory Fr decode
    let ppo = read_bytes::<PAIRING_OBJ_BYTES>(proof_bytes, &mut boundary);
    let pairing_point_object = array::from_fn(|i| fr_word32(env, &ppo, i));

    // 1–4) eight consecutive G1 commitments
    let g1_head = read_bytes::<PROOF_HEAD_G1_BYTES>(proof_bytes, &mut boundary);
    let w1 = g1_from_proof_blob_at(env, &g1_head, 0);
    let w2 = g1_from_proof_blob_at(env, &g1_head, 1);
    let w3 = g1_from_proof_blob_at(env, &g1_head, 2);
    let lookup_read_counts = g1_from_proof_blob_at(env, &g1_head, 3);
    let lookup_read_tags = g1_from_proof_blob_at(env, &g1_head, 4);
    let w4 = g1_from_proof_blob_at(env, &g1_head, 5);
    let lookup_inverses = g1_from_proof_blob_at(env, &g1_head, 6);
    let z_perm = g1_from_proof_blob_at(env, &g1_head, 7);

    // 5) sumcheck_univariates (row-major)
    let su = read_bytes::<SUMCHECK_UNIV_BYTES>(proof_bytes, &mut boundary);
    let sumcheck_univariates: [[Fr; BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N] =
        array::from_fn(|r| {
            array::from_fn(|c| fr_word32(env, &su, r * BATCHED_RELATION_PARTIAL_LENGTH + c))
        });

    // 6) sumcheck_evaluations
    let se = read_bytes::<SUMCHECK_EVAL_BYTES>(proof_bytes, &mut boundary);
    let sumcheck_evaluations = array::from_fn(|i| fr_word32(env, &se, i));

    // 7) gemini_fold_comms
    let gf = read_bytes::<GEMINI_FOLD_COMMS_BYTES>(proof_bytes, &mut boundary);
    let gemini_fold_comms = array::from_fn(|i| g1_from_proof_blob_at(env, &gf, i));

    // 8) gemini_a_evaluations
    let ga = read_bytes::<GEMINI_A_EVAL_BYTES>(proof_bytes, &mut boundary);
    let gemini_a_evaluations = array::from_fn(|i| fr_word32(env, &ga, i));

    // 9) shplonk_q, kzg_quotient
    let tail_g1 = read_bytes::<FINAL_TWO_G1_BYTES>(proof_bytes, &mut boundary);
    let shplonk_q = g1_from_proof_chunk128(env, tail_g1[0..128].try_into().expect("shplonk"));
    let kzg_quotient = g1_from_proof_chunk128(env, tail_g1[128..256].try_into().expect("kzg"));

    debug_assert_eq!(boundary as usize, PROOF_BYTES);

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

/// Deserialize a `VerificationKey` from its canonical byte representation.
///
/// Layout: 4 big-endian `u64` header fields + 27 G1 commitments (64 bytes each).
/// The point order matches `PrecomputedEntities` in BB.
///
/// BB: `flavor/ultra_flavor.hpp::VerificationKey_`
pub fn load_vk_from_bytes(env: &Env, bytes: &Bytes) -> Option<VerificationKey> {
    const HEADER_WORDS: usize = 4;
    const NUM_POINTS: usize = 27;
    const POINT_BLOB_LEN: usize = NUM_POINTS * 64;
    const EXPECTED_LEN: usize = HEADER_WORDS * 8 + POINT_BLOB_LEN;
    if bytes.len() as usize != EXPECTED_LEN {
        return None;
    }

    fn read_u64(bytes: &Bytes, idx: &mut u32) -> u64 {
        u64::from_be_bytes(read_bytes::<8>(bytes, idx))
    }

    let mut idx = 0u32;
    let circuit_size = read_u64(bytes, &mut idx);
    let log_circuit_size = read_u64(bytes, &mut idx);
    let public_inputs_size = read_u64(bytes, &mut idx);
    let pub_inputs_offset = read_u64(bytes, &mut idx);

    // One contiguous read for all G1 points (27 × 64 bytes), then parse in layout order.
    let points_bytes = read_bytes::<POINT_BLOB_LEN>(bytes, &mut idx);
    let pts: [G1Point; NUM_POINTS] = array::from_fn(|i| {
        let off = i * 64;
        G1Point::from_bytes(
            env,
            <&[u8; 64]>::try_from(&points_bytes[off..off + 64]).unwrap(),
        )
    });
    debug_assert_eq!(idx as usize, EXPECTED_LEN);

    let mut it = pts.into_iter();
    Some(VerificationKey {
        circuit_size,
        log_circuit_size,
        public_inputs_size,
        pub_inputs_offset,
        qm: it.next()?,
        qc: it.next()?,
        ql: it.next()?,
        qr: it.next()?,
        qo: it.next()?,
        q4: it.next()?,
        q_lookup: it.next()?,
        q_arith: it.next()?,
        q_delta_range: it.next()?,
        q_elliptic: it.next()?,
        q_aux: it.next()?,
        q_poseidon2_external: it.next()?,
        q_poseidon2_internal: it.next()?,
        s1: it.next()?,
        s2: it.next()?,
        s3: it.next()?,
        s4: it.next()?,
        id1: it.next()?,
        id2: it.next()?,
        id3: it.next()?,
        id4: it.next()?,
        t1: it.next()?,
        t2: it.next()?,
        t3: it.next()?,
        t4: it.next()?,
        lagrange_first: it.next()?,
        lagrange_last: it.next()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn test_coord_limbs_round_trip() {
        // Create a known 32-byte array
        let mut original = [0u8; 32];

        for (i, limb) in original.iter_mut().enumerate() {
            *limb = i as u8;
        }

        let (lo, hi) = coord_to_halves_be(&original);
        let recombined = combine_limbs(&lo, &hi);

        assert_eq!(original, recombined);
    }

    #[test]
    fn test_load_vk_malformed_input() {
        let env = Env::default();

        // Too short
        let bytes_short = Bytes::from_slice(&env, &[0u8; 10]);
        assert!(load_vk_from_bytes(&env, &bytes_short).is_none());

        // Too long
        const HEADER_WORDS: usize = 4;
        const NUM_POINTS: usize = 27;
        const EXPECTED_LEN: usize = HEADER_WORDS * 8 + NUM_POINTS * 64;

        let long_bytes = [0u8; EXPECTED_LEN + 1];
        let bytes_long = Bytes::from_slice(&env, &long_bytes);
        assert!(load_vk_from_bytes(&env, &bytes_long).is_none());
    }
}
