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
use crate::{VkLoadError, PROOF_BYTES};
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

#[inline]
pub(crate) fn read_bytes<const N: usize>(bytes: &Bytes, idx: &mut u32) -> [u8; N] {
    let mut out = [0u8; N];
    let end = *idx + N as u32;
    bytes.slice(*idx..end).copy_into_slice(&mut out);
    *idx = end;
    out
}

#[inline]
pub(crate) fn combine_limbs(lo: &[u8; 32], hi: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..15].copy_from_slice(&hi[17..]);
    out[15..].copy_from_slice(&lo[15..]);
    out
}

#[inline]
pub(crate) fn fr_word32(env: &Env, blob: &[u8], word_idx: usize) -> Fr {
    let o = word_idx * 32;
    Fr::from_array(env, blob[o..o + 32].try_into().expect("fr32"))
}

#[inline]
pub(crate) fn g1_from_proof_chunk128(env: &Env, b: &[u8; 128]) -> G1Point {
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
pub(crate) fn g1_from_proof_blob_at(env: &Env, blob: &[u8], point_idx: usize) -> G1Point {
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
pub fn load_proof(env: &Env, proof_bytes: &Bytes) -> Result<Proof, &'static str> {
    if proof_bytes.len() as usize != PROOF_BYTES {
        return Err("proof bytes length mismatch");
    }
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

    Ok(Proof {
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
    })
}

/// Deserialize a `VerificationKey` from its canonical byte representation.
///
/// Layout: 4 big-endian `u64` header fields + 27 G1 commitments (64 bytes each).
/// The point order matches `PrecomputedEntities` in BB.
///
/// BB: `flavor/ultra_flavor.hpp::VerificationKey_`
pub fn load_vk_from_bytes(env: &Env, bytes: &Bytes) -> Result<VerificationKey, VkLoadError> {
    const HEADER_WORDS: usize = 4;
    const NUM_POINTS: usize = 27;
    const POINT_BLOB_LEN: usize = NUM_POINTS * 64;
    const EXPECTED_LEN: usize = HEADER_WORDS * 8 + POINT_BLOB_LEN;
    if bytes.len() as usize != EXPECTED_LEN {
        return Err(VkLoadError::WrongLength);
    }

    fn read_u64(bytes: &Bytes, idx: &mut u32) -> u64 {
        u64::from_be_bytes(read_bytes::<8>(bytes, idx))
    }

    let mut idx = 0u32;
    let circuit_size = read_u64(bytes, &mut idx);
    let log_circuit_size = read_u64(bytes, &mut idx);
    let public_inputs_size = read_u64(bytes, &mut idx);
    let pub_inputs_offset = read_u64(bytes, &mut idx);

    // Validate structural parameters immediately after parsing.
    if log_circuit_size == 0
        || log_circuit_size
            > u64::try_from(CONST_PROOF_SIZE_LOG_N).map_err(|_| VkLoadError::InvalidParameters)?
    {
        return Err(VkLoadError::InvalidParameters);
    }
    if public_inputs_size < PAIRING_POINTS_SIZE as u64 {
        return Err(VkLoadError::InvalidParameters);
    }
    if circuit_size != (1u64 << log_circuit_size) {
        return Err(VkLoadError::InvalidParameters);
    }
    if pub_inputs_offset > circuit_size {
        return Err(VkLoadError::InvalidParameters);
    }

    // One contiguous read for all G1 points (27 × 64 bytes), then parse in layout order.
    let points_bytes = read_bytes::<POINT_BLOB_LEN>(bytes, &mut idx);
    let pts: [G1Point; NUM_POINTS] = array::from_fn(|i| {
        let off = i * 64;
        let chunk: &[u8; 64] = (&points_bytes[off..off + 64])
            .try_into()
            .expect("vk point chunk");
        G1Point::from_bytes(env, chunk)
    });
    debug_assert_eq!(idx as usize, EXPECTED_LEN);

    Ok(VerificationKey {
        circuit_size,
        log_circuit_size,
        public_inputs_size,
        pub_inputs_offset,
        qm: pts[0].clone(),
        qc: pts[1].clone(),
        ql: pts[2].clone(),
        qr: pts[3].clone(),
        qo: pts[4].clone(),
        q4: pts[5].clone(),
        q_lookup: pts[6].clone(),
        q_arith: pts[7].clone(),
        q_delta_range: pts[8].clone(),
        q_elliptic: pts[9].clone(),
        q_aux: pts[10].clone(),
        q_poseidon2_external: pts[11].clone(),
        q_poseidon2_internal: pts[12].clone(),
        s1: pts[13].clone(),
        s2: pts[14].clone(),
        s3: pts[15].clone(),
        s4: pts[16].clone(),
        id1: pts[17].clone(),
        id2: pts[18].clone(),
        id3: pts[19].clone(),
        id4: pts[20].clone(),
        t1: pts[21].clone(),
        t2: pts[22].clone(),
        t3: pts[23].clone(),
        t4: pts[24].clone(),
        lagrange_first: pts[25].clone(),
        lagrange_last: pts[26].clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    /// Split a 32-byte big-endian field element into (low136, high≤118) limbs.
    ///
    /// This is the inverse of `combine_limbs`.  Used when serialising G1 coordinates
    /// into the transcript buffer.
    ///
    /// BB: `field_conversion::calc_num_bn254_frs` + native serialization
    pub(crate) fn coord_to_halves_be(coord: &[u8]) -> ([u8; 32], [u8; 32]) {
        let mut low = [0u8; 32];
        let mut high = [0u8; 32];
        low[15..].copy_from_slice(&coord[15..]); // 17 bytes
        high[17..].copy_from_slice(&coord[..15]); // 15 bytes
        (low, high)
    }

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
    fn test_load_proof_malformed_input() {
        let env = Env::default();

        // Too short
        let bytes_short = Bytes::from_slice(&env, &[0u8; 10]);
        let result = load_proof(&env, &bytes_short);

        assert_eq!(result.err().unwrap(), "proof bytes length mismatch");

        // Too long
        let long_bytes = [0u8; PROOF_BYTES + 1];
        let bytes_long = Bytes::from_slice(&env, &long_bytes);
        assert_eq!(
            load_proof(&env, &bytes_long).err().unwrap(),
            "proof bytes length mismatch"
        );
    }

    #[test]
    fn test_load_vk_malformed_input() {
        let env = Env::default();

        // Too short
        let bytes_short = Bytes::from_slice(&env, &[0u8; 10]);
        assert_eq!(
            load_vk_from_bytes(&env, &bytes_short).unwrap_err(),
            VkLoadError::WrongLength
        );

        // Too long
        const HEADER_WORDS: usize = 4;
        const NUM_POINTS: usize = 27;
        const EXPECTED_LEN: usize = HEADER_WORDS * 8 + NUM_POINTS * 64;

        let long_bytes = [0u8; EXPECTED_LEN + 1];
        let bytes_long = Bytes::from_slice(&env, &long_bytes);
        assert_eq!(
            load_vk_from_bytes(&env, &bytes_long).unwrap_err(),
            VkLoadError::WrongLength
        );

        // Correct length but log_circuit_size = 0
        let mut zero_log = [0u8; EXPECTED_LEN];
        // circuit_size = 1 (big-endian at offset 0..8)
        zero_log[7] = 1;
        // log_circuit_size = 0 (already zero at offset 8..16)
        let bytes_zero_log = Bytes::from_slice(&env, &zero_log);
        assert_eq!(
            load_vk_from_bytes(&env, &bytes_zero_log).unwrap_err(),
            VkLoadError::InvalidParameters
        );

        // Correct length but log_circuit_size > CONST_PROOF_SIZE_LOG_N
        let mut large_log = [0u8; EXPECTED_LEN];
        // circuit_size = 1
        large_log[7] = 1;
        // log_circuit_size = 29 (big-endian at offset 8..16)
        large_log[15] = 29;
        let bytes_large_log = Bytes::from_slice(&env, &large_log);
        assert_eq!(
            load_vk_from_bytes(&env, &bytes_large_log).unwrap_err(),
            VkLoadError::InvalidParameters
        );

        // circuit_size does not equal 1 << log_circuit_size
        let mut mismatch_cs = [0u8; EXPECTED_LEN];
        // circuit_size = 2 (big-endian at offset 0..8)
        mismatch_cs[7] = 2;
        // log_circuit_size = 10 (big-endian at offset 8..16)
        mismatch_cs[15] = 10;
        // public_inputs_size = 16 to pass the minimum check
        mismatch_cs[23] = 16;
        let bytes_mismatch_cs = Bytes::from_slice(&env, &mismatch_cs);
        assert_eq!(
            load_vk_from_bytes(&env, &bytes_mismatch_cs).unwrap_err(),
            VkLoadError::InvalidParameters
        );

        // pub_inputs_offset > circuit_size
        let mut bad_offset = [0u8; EXPECTED_LEN];
        // circuit_size = 1 << 10 = 1024
        bad_offset[5] = 0x04;
        // log_circuit_size = 10
        bad_offset[15] = 10;
        // public_inputs_size = 16
        bad_offset[23] = 16;
        // pub_inputs_offset = u64::MAX
        for b in &mut bad_offset[24..32] {
            *b = 0xff;
        }
        let bytes_bad_offset = Bytes::from_slice(&env, &bad_offset);
        assert_eq!(
            load_vk_from_bytes(&env, &bytes_bad_offset).unwrap_err(),
            VkLoadError::InvalidParameters
        );
    }
}
