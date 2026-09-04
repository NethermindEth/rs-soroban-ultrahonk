//! Proof and verification-key deserialization.
//!
//! Handles the fixed-size byte layouts emitted by the Barretenberg native prover.
//! G1 coordinates use the BN254 base-field limb split (low 136 bits + high ≤118 bits).
//!
//! BB reference (v0.87.0):
//!   - `honk/proof_system/types/proof.hpp`
//!   - `stdlib_circuit_builders/ultra_flavor.hpp::Proof`
//!   - `stdlib_circuit_builders/ultra_flavor.hpp::VerificationKey_`

use crate::field::Fr;
use crate::types::{
    fr_is_canonical, G1Point, PointError, Proof, VerificationKey, BATCHED_RELATION_PARTIAL_LENGTH,
    CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ENTITIES, PAIRING_POINTS_SIZE,
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

/// True when a G1 coordinate limb pair is canonically encoded, i.e. `lo < 2^136`
/// and `hi < 2^118`, which is what the honest Barretenberg serializer emits.
///
/// `combine_limbs` keeps only the low 17 bytes of `lo` and the low 15 bytes of
/// `hi`. Barretenberg does not truncate: it reconstructs by addition,
/// `lo + (hi << 136)`, so on non-canonical limbs the two implementations
/// compute different points and Barretenberg rejects the proof. Enforcing the
/// canonical widths here removes the divergence and the re-encoding vector at
/// the same time.
#[inline]
pub(crate) fn limbs_are_canonical(lo: &[u8; 32], hi: &[u8; 32]) -> bool {
    // lo < 2^136: the top 15 bytes must be zero.
    if lo[..15].iter().any(|b| *b != 0) {
        return false;
    }
    // hi < 2^118: the top 17 bytes must be zero, and the next byte must be
    // below 0x40 so that the retained window is 118 bits rather than 120.
    if hi[..17].iter().any(|b| *b != 0) {
        return false;
    }
    hi[17] < 0x40
}

/// Canonical-encoding variant of [`fr_word32`].
///
/// `Fr::from_array` reduces modulo the scalar order rather than rejecting, so
/// `v` and `v + k*r` decode identically and the transcript absorbs the reduced
/// value either way. Rejecting here makes the scalar encoding of a proof unique.
#[inline]
pub(crate) fn try_fr_word32(env: &Env, blob: &[u8], word_idx: usize) -> Result<Fr, &'static str> {
    let o = word_idx * 32;
    let w: &[u8; 32] = blob[o..o + 32].try_into().expect("fr32");
    if !fr_is_canonical(w) {
        return Err("non-canonical scalar encoding");
    }
    Ok(Fr::from_array(env, w))
}

/// Parse one 128-byte G1 chunk with canonical-limb and curve validation.
#[inline]
pub(crate) fn try_g1_from_proof_chunk128(env: &Env, b: &[u8; 128]) -> Result<G1Point, PointError> {
    let x_lo: &[u8; 32] = b[0..32].try_into().expect("x_lo");
    let x_hi: &[u8; 32] = b[32..64].try_into().expect("x_hi");
    let y_lo: &[u8; 32] = b[64..96].try_into().expect("y_lo");
    let y_hi: &[u8; 32] = b[96..128].try_into().expect("y_hi");
    if !limbs_are_canonical(x_lo, x_hi) || !limbs_are_canonical(y_lo, y_hi) {
        return Err(PointError::NonCanonicalLimb);
    }
    let x = combine_limbs(x_lo, x_hi);
    let y = combine_limbs(y_lo, y_hi);
    G1Point::try_from_xy(env, &x, &y)
}

#[inline]
pub(crate) fn try_g1_at(env: &Env, blob: &[u8], idx: usize) -> Result<G1Point, PointError> {
    let o = idx * 128;
    try_g1_from_proof_chunk128(env, blob[o..o + 128].try_into().expect("g1_128"))
}

/// Deserialize a `Proof` from its canonical byte representation.
///
/// The layout is fixed and derived from `ultra_flavor.hpp::PROOF_LENGTH_WITHOUT_PUB_INPUTS`.
/// All field elements are big-endian 32-byte scalars; G1 points use the
/// `(x_lo, x_hi, y_lo, y_hi)` limb layout (128 bytes each).
///
/// BB: `stdlib_circuit_builders/ultra_flavor.hpp::Proof` (implicit in `BaseTranscript` deserialization)
///
/// Note (bb v0.87.0): G1 coordinates are encoded as two limbs per coordinate
/// using the (lo136, hi<=118) split and stored in the order (x_lo, x_hi, y_lo, y_hi).
fn point_err(e: PointError) -> &'static str {
    match e {
        PointError::CoordinateOutOfRange => "g1 coordinate out of range",
        PointError::NotOnCurve => "g1 point not on curve",
        PointError::NonCanonicalLimb => "non-canonical g1 limb encoding",
    }
}

pub fn load_proof(env: &Env, proof_bytes: &Bytes) -> Result<Proof, &'static str> {
    if proof_bytes.len() as usize != PROOF_BYTES {
        return Err("proof bytes length mismatch");
    }
    let mut boundary = 0u32;

    // 0) pairing point object — one host read, then in-memory Fr decode
    let ppo = read_bytes::<PAIRING_OBJ_BYTES>(proof_bytes, &mut boundary);
    let mut pairing_point_object = Fr::zero_array::<PAIRING_POINTS_SIZE>(env);
    for (i, slot) in pairing_point_object.iter_mut().enumerate() {
        *slot = try_fr_word32(env, &ppo, i)?;
    }

    // 1–4) eight consecutive G1 commitments
    let g1_head = read_bytes::<PROOF_HEAD_G1_BYTES>(proof_bytes, &mut boundary);
    let w1 = try_g1_at(env, &g1_head, 0).map_err(point_err)?;
    let w2 = try_g1_at(env, &g1_head, 1).map_err(point_err)?;
    let w3 = try_g1_at(env, &g1_head, 2).map_err(point_err)?;
    let lookup_read_counts = try_g1_at(env, &g1_head, 3).map_err(point_err)?;
    let lookup_read_tags = try_g1_at(env, &g1_head, 4).map_err(point_err)?;
    let w4 = try_g1_at(env, &g1_head, 5).map_err(point_err)?;
    let lookup_inverses = try_g1_at(env, &g1_head, 6).map_err(point_err)?;
    let z_perm = try_g1_at(env, &g1_head, 7).map_err(point_err)?;

    // 5) sumcheck_univariates (row-major)
    let su = read_bytes::<SUMCHECK_UNIV_BYTES>(proof_bytes, &mut boundary);
    let mut sumcheck_univariates: [[Fr; BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N] =
        array::from_fn(|_| Fr::zero_array(env));
    for (r, row) in sumcheck_univariates.iter_mut().enumerate() {
        for (c, cell) in row.iter_mut().enumerate() {
            *cell = try_fr_word32(env, &su, r * BATCHED_RELATION_PARTIAL_LENGTH + c)?;
        }
    }

    // 6) sumcheck_evaluations
    let se = read_bytes::<SUMCHECK_EVAL_BYTES>(proof_bytes, &mut boundary);
    let mut sumcheck_evaluations = Fr::zero_array::<NUMBER_OF_ENTITIES>(env);
    for (i, slot) in sumcheck_evaluations.iter_mut().enumerate() {
        *slot = try_fr_word32(env, &se, i)?;
    }

    // 7) gemini_fold_comms
    let gf = read_bytes::<GEMINI_FOLD_COMMS_BYTES>(proof_bytes, &mut boundary);
    let mut gemini_fold_comms: [G1Point; CONST_PROOF_SIZE_LOG_N - 1] =
        array::from_fn(|_| G1Point::infinity(env));
    for (i, slot) in gemini_fold_comms.iter_mut().enumerate() {
        *slot = try_g1_at(env, &gf, i).map_err(point_err)?;
    }

    // 8) gemini_a_evaluations
    let ga = read_bytes::<GEMINI_A_EVAL_BYTES>(proof_bytes, &mut boundary);
    let mut gemini_a_evaluations = Fr::zero_array::<CONST_PROOF_SIZE_LOG_N>(env);
    for (i, slot) in gemini_a_evaluations.iter_mut().enumerate() {
        *slot = try_fr_word32(env, &ga, i)?;
    }

    // 9) shplonk_q, kzg_quotient
    let tail_g1 = read_bytes::<FINAL_TWO_G1_BYTES>(proof_bytes, &mut boundary);
    let shplonk_q = try_g1_from_proof_chunk128(env, tail_g1[0..128].try_into().expect("shplonk"))
        .map_err(point_err)?;
    let kzg_quotient = try_g1_from_proof_chunk128(env, tail_g1[128..256].try_into().expect("kzg"))
        .map_err(point_err)?;

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

/// Reject non-canonical public-input encodings.
///
/// Unlike the proof scalars (L-02), public inputs are **not** a malleability
/// surface: `generate_eta_challenge` absorbs the raw public-input bytes into the
/// transcript, so `v` and `v + k*r` already produce different challenges and a
/// proof for one does not verify against the other. Verification fails closed
/// either way.
///
/// What this removes is an internal asymmetry. The transcript binds the raw bytes
/// while `compute_public_input_delta` decodes through `Fr::from_array`, which
/// reduces. For a non-canonical input the two paths therefore disagree about what
/// the value is. That is harmless today only because the transcript mismatch
/// rejects first. Enforcing canonicality here makes "both paths see the same
/// value" an enforced invariant rather than an accident of ordering, so that a
/// later change to how the transcript absorbs public inputs cannot silently
/// introduce the malleability that L-02 exists to remove.
///
/// The honest pipeline is unaffected: bb serialises public inputs as canonical
/// field elements.
pub fn validate_public_inputs_canonical(public_inputs: &Bytes) -> Result<(), &'static str> {
    let mut idx = 0u32;
    while idx < public_inputs.len() {
        let mut w = [0u8; 32];
        public_inputs.slice(idx..idx + 32).copy_into_slice(&mut w);
        if !fr_is_canonical(&w) {
            return Err("non-canonical public input encoding");
        }
        idx += 32;
    }
    Ok(())
}

/// Reject non-canonical padding in the Gemini evaluation slots (audit N-05).
///
/// The proof carries `CONST_PROOF_SIZE_LOG_N` Gemini evaluations regardless of the
/// circuit size, but only indices `0..log_n` are used: `verify_shplemini` reads
/// `gemini_a_evaluations[j - 1]` for `j` in `1..=log_n` and `[j]` for `j` in
/// `1..log_n`. The honest prover emits zero in the remaining slots.
///
/// This is the one padded surface where this verifier diverged from Barretenberg.
/// bb masks the padded sumcheck rounds and the unused fold commitments exactly as
/// we do, but its Shplemini reduction still binds the padded Gemini evaluations
/// through the constant-term accumulator, so bb rejects a proof carrying non-zero
/// values there while we previously ignored them. Rejecting at parse time reaches
/// the same accept/reject outcome as bb without reimplementing its constant-term
/// accumulation over the fixed 28-slot layout.
///
/// Deliberately scoped to the evaluations. Extending it to the unused fold
/// commitments would make this verifier *stricter* than bb, which masks them, and
/// would depend on the generator-valued padding convention, which is confirmed
/// only at `log_circuit_size` 12 and 13. See VERIFIER_PROVENANCE.md §4.3.
pub fn validate_gemini_padding(proof: &Proof, log_n: usize) -> Result<(), &'static str> {
    if log_n == 0 || log_n > CONST_PROOF_SIZE_LOG_N {
        return Err("log_circuit_size out of range");
    }
    let env = proof.gemini_a_evaluations[0].0.env();
    let zero = Fr::zero(env);
    for slot in proof.gemini_a_evaluations.iter().skip(log_n) {
        if *slot != zero {
            return Err("non-zero padding in unused Gemini evaluation slot");
        }
    }
    Ok(())
}

/// Deserialize a `VerificationKey` from its canonical byte representation.
///
/// Layout: 4 big-endian `u64` header fields + 27 G1 commitments (64 bytes each).
/// The point order matches `PrecomputedEntities` in BB.
///
/// BB: `stdlib_circuit_builders/ultra_flavor.hpp::VerificationKey_`
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
    let mut pts: [G1Point; NUM_POINTS] = array::from_fn(|_| G1Point::infinity(env));
    for (i, slot) in pts.iter_mut().enumerate() {
        let off = i * 64;
        let chunk: &[u8; 64] = (&points_bytes[off..off + 64])
            .try_into()
            .expect("vk point chunk");
        *slot = G1Point::try_from_bytes(env, chunk).map_err(|_| VkLoadError::InvalidPoint)?;
    }
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
