//! Fiat–Shamir transcript for UltraHonk.
//!
//! This module implements the Keccak-256 based transcript used by the native
//! Barretenberg `UltraFlavor` verifier (v0.82.2).  Every challenge round,
//! serialization step, and splitting primitive is documented with its BB source
//! counterpart so that upgrades to BB can be re-audited mechanically.
//!
//! BB reference: `aztec-packages-v0.82.2/barretenberg/cpp/src/barretenberg/transcript/transcript.hpp`
//!               (`KeccakTranscriptParams` / `NativeTranscriptParams`).

use crate::trace;
use crate::{
    field::Fr,
    hash::hash32,
    types::{
        G1Point, Proof, RelationParameters, Transcript, BATCHED_RELATION_PARTIAL_LENGTH,
        CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ALPHAS, NUMBER_OF_ENTITIES, PAIRING_POINTS_SIZE,
    },
};
use soroban_sdk::{crypto::bn254::Bn254Fr, Bytes, Env};

/// Serialize one affine coordinate into the transcript buffer using the
/// BN254 base-field limb split: low 136 bits + high ≤118 bits.
///
/// BB: `transcript/transcript.hpp` — `add_element_frs_to_hash_buffer` for
///      `BN254::AffineElement` (via `convert_to_bn254_frs<BaseField>`).
#[inline]
fn push_coord_halves(buf: &mut Bytes, coord: &[u8]) {
    // low 136 bits (17 bytes) + high ≤118 bits (15 bytes)
    let mut low = [0u8; 32];
    low[15..].copy_from_slice(&coord[15..]);
    buf.extend_from_slice(&low);

    let mut high = [0u8; 32];
    high[17..].copy_from_slice(&coord[..15]);
    buf.extend_from_slice(&high);
}

/// Serialize a G1 affine point into the transcript buffer.
/// Each coordinate is split with `push_coord_halves`, yielding 4 × 32 bytes.
///
/// BB: `transcript/transcript.hpp` — `receive_from_prover<Commitment>` serialises
///      `curve::BN254::AffineElement` the same way.
fn push_point(buf: &mut Bytes, pt: &G1Point) {
    // 4 × 32-byte limbs per point
    let bytes = pt.0.to_array();
    push_coord_halves(buf, &bytes[..32]);
    push_coord_halves(buf, &bytes[32..]);
}

/// Split a 32-byte challenge digest into two 128-bit field elements.
///
/// The low 128 bits become the first challenge; the high 128 bits (only ~126
/// are valid for BN254) become the second.  This is the same split performed
/// by `NativeTranscriptParams::split_challenge`.
///
/// BB: `transcript/transcript.hpp::NativeTranscriptParams::split_challenge`
#[inline]
fn split_challenge_from_be32(env: &Env, challenge_bytes: &[u8; 32]) -> (Fr, Fr) {
    let mut low_bytes = [0u8; 32];
    low_bytes[16..].copy_from_slice(&challenge_bytes[16..]);
    let mut high_bytes = [0u8; 32];
    high_bytes[16..].copy_from_slice(&challenge_bytes[..16]);
    (
        Fr::from_array(env, &low_bytes),
        Fr::from_array(env, &high_bytes),
    )
}

/// Convenience wrapper: split a `Fr` challenge by first serialising it.
///
/// BB: `transcript/transcript.hpp::NativeTranscriptParams::split_challenge`
fn split_challenge(challenge: &Fr) -> (Fr, Fr) {
    let env = challenge.0.env();
    split_challenge_from_be32(env, &challenge.to_bytes())
}

/// Hash a transcript buffer with Keccak-256 and interpret the digest as a
/// BN254 scalar field element.
///
/// BB: `transcript/transcript.hpp::keccak_hash_uint256`
#[inline(always)]
fn hash_to_fr(bytes: &Bytes) -> Fr {
    Fr(Bn254Fr::from_bytes(hash32(bytes)))
}

/// Encode a `u64` as a 32-byte big-endian buffer (zero-padded on the left).
///
/// BB serialises small integers by converting them to `bb::fr` and writing the
/// canonical 32-byte form, which yields the same layout.
///
/// BB: `oink_verifier.cpp::execute_preamble_round` (circuit_size, public_input_size,
///      pub_inputs_offset are serialised this way).
fn u64_to_be32(x: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&x.to_be_bytes());
    out
}

/// Generate the η, η₂, η₃ challenges (sorted-list accumulator round).
///
/// This function also absorbs the transcript preamble
/// (`circuit_size`, `public_inputs_size`, `pub_inputs_offset`, all public inputs,
/// the pairing-point object, and the first three wire commitments w₁, w₂, w₃).
/// The first hash yields η and η₂; hashing the previous challenge bytes alone
/// yields η₃ (duplex construction).
///
/// BB: `oink_verifier.cpp::execute_sorted_list_accumulator_round`
fn generate_eta_challenge(
    env: &Env,
    proof: &Proof,
    public_inputs: &Bytes,
    circuit_size: u64,
    public_inputs_size: u64,
    pub_inputs_offset: u64,
) -> (Fr, Fr, Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&u64_to_be32(circuit_size));
    data.extend_from_slice(&u64_to_be32(public_inputs_size));
    data.extend_from_slice(&u64_to_be32(pub_inputs_offset));
    data.append(public_inputs);
    for fr in &proof.pairing_point_object {
        data.extend_from_slice(&fr.to_bytes());
    }
    for w in &[&proof.w1, &proof.w2, &proof.w3] {
        push_point(&mut data, w);
    }

    let first = hash_to_fr(&data);
    let first_bytes = first.to_bytes();
    let (eta, eta_two) = split_challenge_from_be32(env, &first_bytes);
    let prev_bytes = Bytes::from_array(env, &first_bytes);
    let second = hash_to_fr(&prev_bytes);
    let (eta_three, _) = split_challenge(&second);

    (eta, eta_two, eta_three, second)
}

/// Generate the β and γ challenges (log-derivative inverse round).
///
/// Absorbs `lookup_read_counts`, `lookup_read_tags`, and `w4` before hashing.
/// Returns the two split challenges plus the next `previous_challenge` scalar.
///
/// BB: `oink_verifier.cpp::execute_log_derivative_inverse_round`
fn generate_beta_and_gamma_challenges(
    env: &Env,
    previous_challenge: Fr,
    proof: &Proof,
) -> (Fr, Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    for w in &[
        &proof.lookup_read_counts,
        &proof.lookup_read_tags,
        &proof.w4,
    ] {
        push_point(&mut data, w);
    }
    let next_previous_challenge = hash_to_fr(&data);
    let (beta, gamma) = split_challenge(&next_previous_challenge);
    (beta, gamma, next_previous_challenge)
}

/// Generate α₀ … α₂₄ (alpha batching challenges for subrelations).
///
/// Absorbs `lookup_inverses` and `z_perm`, then performs repeated duplex hashing
/// to obtain 25 challenges.  This matches the `generate_alphas_round` sequence in
/// the Oink verifier.
///
/// BB: `oink_verifier.cpp::generate_alphas_round`
fn generate_alpha_challenges(
    env: &Env,
    previous_challenge: Fr,
    proof: &Proof,
) -> ([Fr; NUMBER_OF_ALPHAS], Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    for w in &[&proof.lookup_inverses, &proof.z_perm] {
        push_point(&mut data, w);
    }
    let mut next_previous_challenge = hash_to_fr(&data);

    let mut alphas = Fr::zero_array::<NUMBER_OF_ALPHAS>(env);
    let (a0, a1) = split_challenge(&next_previous_challenge);
    alphas[0] = a0;
    alphas[1] = a1;

    for i in 1..(NUMBER_OF_ALPHAS / 2) {
        let next_bytes = Bytes::from_array(env, &next_previous_challenge.to_bytes());
        next_previous_challenge = hash_to_fr(&next_bytes);
        let (lo, hi) = split_challenge(&next_previous_challenge);
        alphas[2 * i] = lo;
        alphas[2 * i + 1] = hi;
    }

    if (NUMBER_OF_ALPHAS & 1) == 1 && NUMBER_OF_ALPHAS > 2 {
        let next_bytes = Bytes::from_array(env, &next_previous_challenge.to_bytes());
        next_previous_challenge = hash_to_fr(&next_bytes);
        let (last, _) = split_challenge(&next_previous_challenge);
        alphas[NUMBER_OF_ALPHAS - 1] = last;
    }

    (alphas, next_previous_challenge)
}

/// Orchestrate the Oink challenge rounds that produce relation parameters.
///
/// Sequentially calls `generate_eta_challenge` → `generate_beta_and_gamma_challenges`
/// to obtain η, η₂, η₃, β, γ.  `public_inputs_delta` is left zero; it is filled
/// later by `verifier.rs::compute_public_input_delta`.
///
/// BB: `oink_verifier.cpp::OinkVerifier::verify` (challenge rounds 0–4)
fn generate_relation_parameters_challenges(
    env: &Env,
    proof: &Proof,
    public_inputs: &Bytes,
    circuit_size: u64,
    public_inputs_size: u64,
    pub_inputs_offset: u64,
) -> (RelationParameters, Fr) {
    let (eta, eta_two, eta_three, previous_challenge) = generate_eta_challenge(
        env,
        proof,
        public_inputs,
        circuit_size,
        public_inputs_size,
        pub_inputs_offset,
    );
    let (beta, gamma, next_previous_challenge) =
        generate_beta_and_gamma_challenges(env, previous_challenge, proof);
    let rp = RelationParameters {
        eta,
        eta_two,
        eta_three,
        beta,
        gamma,
        public_inputs_delta: Fr::zero(env),
    };
    (rp, next_previous_challenge)
}

/// Generate the gate-separator challenges β₀ … β₂₇.
///
/// Each challenge is produced by hashing the previous challenge bytes alone
/// and taking the low 128 bits.  Only the first `log_n` values are used in
/// practice; the rest are padding to `CONST_PROOF_SIZE_LOG_N`.
///
/// BB: `ultra_verifier.cpp::verify_proof` (gate-challenge loop)
fn generate_gate_challenges(
    env: &Env,
    previous_challenge: Fr,
) -> ([Fr; CONST_PROOF_SIZE_LOG_N], Fr) {
    let mut next_previous_challenge = previous_challenge;
    let mut gate_challenges = Fr::zero_array::<CONST_PROOF_SIZE_LOG_N>(env);
    for challenge in gate_challenges.iter_mut() {
        let next_bytes = Bytes::from_array(env, &next_previous_challenge.to_bytes());
        next_previous_challenge = hash_to_fr(&next_bytes);
        *challenge = split_challenge(&next_previous_challenge).0;
    }
    (gate_challenges, next_previous_challenge)
}

/// Generate the Sumcheck round challenges u₀ … u₂₇.
///
/// For each round the previous challenge bytes and the round's univariate
/// coefficients are hashed together; the low 128 bits become uᵢ.
///
/// BB: `sumcheck/sumcheck.hpp::SumcheckVerifier::verify` (challenge loop)
fn generate_sumcheck_challenges(
    env: &Env,
    proof: &Proof,
    previous_challenge: Fr,
) -> ([Fr; CONST_PROOF_SIZE_LOG_N], Fr) {
    let mut next_previous_challenge = previous_challenge;
    let mut sumcheck_challenges = Fr::zero_array::<CONST_PROOF_SIZE_LOG_N>(env);
    for (r, challenge) in sumcheck_challenges.iter_mut().enumerate() {
        let mut data = Bytes::new(env);
        data.extend_from_slice(&next_previous_challenge.to_bytes());
        for c in proof.sumcheck_univariates[r].iter() {
            data.extend_from_slice(&c.to_bytes());
        }
        next_previous_challenge = hash_to_fr(&data);
        *challenge = split_challenge(&next_previous_challenge).0;
    }
    (sumcheck_challenges, next_previous_challenge)
}

/// Generate ρ (the Gemini batching challenge).
///
/// Absorbs all 40 sumcheck evaluation claims before hashing.
///
/// BB: `commitment_schemes/shplonk/shplemini.hpp` (`get_challenge<Fr>("rho")`)
fn generate_rho_challenge(env: &Env, proof: &Proof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    for e in proof.sumcheck_evaluations.iter() {
        data.extend_from_slice(&e.to_bytes());
    }
    let next_previous_challenge = hash_to_fr(&data);
    let rho = split_challenge(&next_previous_challenge).0;
    (rho, next_previous_challenge)
}

/// Generate the Gemini folding challenge r.
///
/// Absorbs the 27 fold commitments (`gemini_fold_comms`) before hashing.
///
/// BB: `commitment_schemes/shplonk/shplemini.hpp` (`get_challenge<Fr>("Gemini:r")`)
fn generate_gemini_r_challenge(env: &Env, proof: &Proof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    for pt in proof.gemini_fold_comms.iter() {
        push_point(&mut data, pt);
    }
    let next_previous_challenge = hash_to_fr(&data);
    let gemini_r = split_challenge(&next_previous_challenge).0;
    (gemini_r, next_previous_challenge)
}

/// Generate ν (the Shplonk batching challenge).
///
/// Absorbs the 28 Gemini fold evaluations (`gemini_a_evaluations`) before hashing.
///
/// BB: `commitment_schemes/shplonk/shplemini.hpp` (`get_challenge<Fr>("Shplonk:nu")`)
fn generate_shplonk_nu_challenge(env: &Env, proof: &Proof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    for a in proof.gemini_a_evaluations.iter() {
        data.extend_from_slice(&a.to_bytes());
    }
    let next_previous_challenge = hash_to_fr(&data);
    let shplonk_nu = split_challenge(&next_previous_challenge).0;
    (shplonk_nu, next_previous_challenge)
}

/// Generate z (the Shplonk evaluation point).
///
/// Absorbs the Shplonk quotient commitment `shplonk_q` before hashing.
///
/// BB: `commitment_schemes/shplonk/shplemini.hpp` (`get_challenge<Fr>("Shplonk:z")`)
fn generate_shplonk_z_challenge(env: &Env, proof: &Proof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    push_point(&mut data, &proof.shplonk_q);
    let next_previous_challenge = hash_to_fr(&data);
    let shplonk_z = split_challenge(&next_previous_challenge).0;
    (shplonk_z, next_previous_challenge)
}

/// Build the full transcript: all Fiat–Shamir challenges for UltraHonk verification.
///
/// Challenge order (identical to BB native verifier):
/// 1. η, η₂, η₃  – sorted-list / lookup accumulator  
/// 2. β, γ        – log-derivative inverse  
/// 3. α₀…α₂₄      – subrelation batching  
/// 4. gate βᵢ     – sumcheck gate separator  
/// 5. uᵢ          – sumcheck round challenges  
/// 6. ρ           – Gemini batching  
/// 7. r           – Gemini folding  
/// 8. ν           – Shplonk batching  
/// 9. z           – Shplonk evaluation point  
///
/// BB: `oink_verifier.cpp::OinkVerifier::verify` + `ultra_verifier.cpp::verify_proof` +
///      `sumcheck/sumcheck.hpp::SumcheckVerifier::verify` +
///      `commitment_schemes/shplonk/shplemini.hpp::ShpleminiVerifier_::compute_batch_opening_claim`
/// Verify that a deserialized Proof contains all expected elements with correct sizes.
///
/// Fixed-size arrays guarantee these lengths in Rust, but explicit checks document
/// the security assumption and protect against future refactoring.
fn validate_proof(proof: &Proof) -> Result<(), &'static str> {
    if proof.pairing_point_object.len() != PAIRING_POINTS_SIZE {
        return Err("invalid pairing_point_object size");
    }
    if proof.sumcheck_univariates.len() != CONST_PROOF_SIZE_LOG_N {
        return Err("invalid sumcheck_univariates size");
    }
    for univ in proof.sumcheck_univariates.iter() {
        if univ.len() != BATCHED_RELATION_PARTIAL_LENGTH {
            return Err("invalid sumcheck_univariate coefficient count");
        }
    }
    if proof.sumcheck_evaluations.len() != NUMBER_OF_ENTITIES {
        return Err("invalid sumcheck_evaluations size");
    }
    if proof.gemini_fold_comms.len() != CONST_PROOF_SIZE_LOG_N - 1 {
        return Err("invalid gemini_fold_comms size");
    }
    if proof.gemini_a_evaluations.len() != CONST_PROOF_SIZE_LOG_N {
        return Err("invalid gemini_a_evaluations size");
    }
    Ok(())
}

pub fn generate_transcript(
    env: &Env,
    proof: &Proof,
    public_inputs: &Bytes,
    circuit_size: u64,
    public_inputs_size: u64,
    pub_inputs_offset: u64,
) -> Result<Transcript, &'static str> {
    validate_proof(proof)?;

    // 1) eta/beta/gamma
    let (rp, previous_challenge) = generate_relation_parameters_challenges(
        env,
        proof,
        public_inputs,
        circuit_size,
        public_inputs_size,
        pub_inputs_offset,
    );

    // 2) alphas
    let (alphas, previous_challenge) = generate_alpha_challenges(env, previous_challenge, proof);

    // 3) gate challenges
    let (gate_chals, previous_challenge) = generate_gate_challenges(env, previous_challenge);

    // 4) sumcheck challenges
    let (u_chals, previous_challenge) =
        generate_sumcheck_challenges(env, proof, previous_challenge);

    // 5) rho
    let (rho, previous_challenge) = generate_rho_challenge(env, proof, previous_challenge);

    // 6) gemini_r
    let (gemini_r, previous_challenge) =
        generate_gemini_r_challenge(env, proof, previous_challenge);

    // 7) shplonk_nu
    let (shplonk_nu, previous_challenge) =
        generate_shplonk_nu_challenge(env, proof, previous_challenge);

    // 8) shplonk_z
    let (shplonk_z, _previous_challenge) =
        generate_shplonk_z_challenge(env, proof, previous_challenge);

    trace!("===== TRANSCRIPT PARAMETERS =====");
    trace!("eta = 0x{}", crate::debug::Hex(&rp.eta.to_bytes()));
    trace!("eta_two = 0x{}", crate::debug::Hex(&rp.eta_two.to_bytes()));
    trace!(
        "eta_three = 0x{}",
        crate::debug::Hex(&rp.eta_three.to_bytes())
    );
    trace!("beta = 0x{}", crate::debug::Hex(&rp.beta.to_bytes()));
    trace!("gamma = 0x{}", crate::debug::Hex(&rp.gamma.to_bytes()));
    trace!("rho = 0x{}", crate::debug::Hex(&rho.to_bytes()));
    trace!("gemini_r = 0x{}", crate::debug::Hex(&gemini_r.to_bytes()));
    trace!(
        "shplonk_nu = 0x{}",
        crate::debug::Hex(&shplonk_nu.to_bytes())
    );
    trace!("shplonk_z = 0x{}", crate::debug::Hex(&shplonk_z.to_bytes()));
    trace!("circuit_size = {}", circuit_size);
    trace!("public_inputs_total = {}", public_inputs_size);
    trace!("public_inputs_offset = {}", pub_inputs_offset);
    trace!("=================================");

    Ok(Transcript {
        rel_params: rp,
        alphas,
        gate_challenges: gate_chals,
        sumcheck_u_challenges: u_chals,
        rho,
        gemini_r,
        shplonk_nu,
        shplonk_z,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{load_proof, load_vk_from_bytes};
    use soroban_sdk::{Bytes, Env};
    use ultrahonk_test_utils::Fixture;

    #[test]
    fn test_transcript_determinism() {
        let env = Env::default();
        let f = Fixture::load("simple_circuit");
        let proof_bytes = Bytes::from_slice(&env, &f.proof);
        let vk_bytes = Bytes::from_slice(&env, &f.vk);
        let pi_bytes = Bytes::from_slice(&env, &f.public_inputs);

        let proof = load_proof(&env, &proof_bytes).unwrap();
        let vk = load_vk_from_bytes(&env, &vk_bytes).unwrap();

        let t = generate_transcript(
            &env,
            &proof,
            &pi_bytes,
            vk.circuit_size,
            vk.public_inputs_size,
            1, // pub_inputs_offset
        )
        .unwrap();

        assert_eq!(
            t.rel_params.eta.to_bytes(),
            crate::debug::hex_to_bytes(
                "0000000000000000000000000000000085cff885ac2961fd2caf69da4ab04a55"
            )
        );
        assert_eq!(
            t.rel_params.beta.to_bytes(),
            crate::debug::hex_to_bytes(
                "00000000000000000000000000000000cf2d1a0f78861f5dfc916c1550073a26"
            )
        );
        assert_eq!(
            t.rel_params.gamma.to_bytes(),
            crate::debug::hex_to_bytes(
                "000000000000000000000000000000000b9a9dc0b29d2edaa5de654ffd600900"
            )
        );
        assert_eq!(
            t.rho.to_bytes(),
            crate::debug::hex_to_bytes(
                "00000000000000000000000000000000ddc594911e07b3b91b1afc817c04d331"
            )
        );
        assert_eq!(
            t.shplonk_z.to_bytes(),
            crate::debug::hex_to_bytes(
                "000000000000000000000000000000001c9e9d4cde5bde269eed51b980ab19fe"
            )
        );
    }
}
