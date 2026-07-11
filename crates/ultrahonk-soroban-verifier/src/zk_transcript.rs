//! Keccak Fiat-Shamir transcript for Barretenberg v0.87 `UltraKeccakZKFlavor`.
//!
//! The round manifest follows `honk_zk_contract.hpp::ZKTranscriptLib` from
//! Barretenberg v0.87.0. Compared with the non-ZK transcript, it absorbs the
//! Libra masking claims and Gemini hiding-polynomial claim and derives one
//! additional challenge, `Libra:Challenge`.

use crate::trace;
use crate::{
    field::Fr,
    hash::hash32,
    types::{
        G1Point, RelationParameters, CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ALPHAS, NUMBER_OF_ENTITIES,
        PAIRING_POINTS_SIZE,
    },
    zk_types::{ZkProof, ZkTranscript, ZK_BATCHED_RELATION_PARTIAL_LENGTH},
};
use soroban_sdk::{crypto::bn254::Bn254Fr, Bytes, Env};

/// Append one BN254 base-field coordinate as `(low 136 bits, high 118 bits)`.
#[inline]
fn push_coord_halves(buf: &mut Bytes, coord: &[u8]) {
    let mut low = [0u8; 32];
    low[15..].copy_from_slice(&coord[15..]);
    buf.extend_from_slice(&low);

    let mut high = [0u8; 32];
    high[17..].copy_from_slice(&coord[..15]);
    buf.extend_from_slice(&high);
}

/// Append a proof commitment in Barretenberg's four-field-element encoding.
fn push_point(buf: &mut Bytes, point: &G1Point) {
    let bytes = point.0.to_array();
    push_coord_halves(buf, &bytes[..32]);
    push_coord_halves(buf, &bytes[32..]);
}

#[inline]
fn hash_to_fr(bytes: &Bytes) -> Fr {
    Fr(Bn254Fr::from_bytes(hash32(bytes)))
}

/// Split a Keccak challenge into low and high 128-bit field elements.
#[inline]
fn split_challenge_from_be32(env: &Env, challenge: &[u8; 32]) -> (Fr, Fr) {
    let mut low = [0u8; 32];
    low[16..].copy_from_slice(&challenge[16..]);

    let mut high = [0u8; 32];
    high[16..].copy_from_slice(&challenge[..16]);

    (Fr::from_array(env, &low), Fr::from_array(env, &high))
}

#[inline]
fn split_challenge(challenge: &Fr) -> (Fr, Fr) {
    split_challenge_from_be32(challenge.0.env(), &challenge.to_bytes())
}

#[inline]
fn u64_to_be32(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

/// Preamble, wire commitments, and the two eta hash rounds.
fn generate_eta_challenges(
    env: &Env,
    proof: &ZkProof,
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

    for value in &proof.pairing_point_object {
        data.extend_from_slice(&value.to_bytes());
    }
    for commitment in [&proof.w1, &proof.w2, &proof.w3] {
        push_point(&mut data, commitment);
    }

    let first = hash_to_fr(&data);
    let (eta, eta_two) = split_challenge(&first);

    let second_data = Bytes::from_array(env, &first.to_bytes());
    let second = hash_to_fr(&second_data);
    let (eta_three, _) = split_challenge(&second);

    (eta, eta_two, eta_three, second)
}

fn generate_beta_gamma(env: &Env, proof: &ZkProof, previous_challenge: Fr) -> (Fr, Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    for commitment in [
        &proof.lookup_read_counts,
        &proof.lookup_read_tags,
        &proof.w4,
    ] {
        push_point(&mut data, commitment);
    }

    let next = hash_to_fr(&data);
    let (beta, gamma) = split_challenge(&next);
    (beta, gamma, next)
}

fn generate_relation_parameters(
    env: &Env,
    proof: &ZkProof,
    public_inputs: &Bytes,
    circuit_size: u64,
    public_inputs_size: u64,
    pub_inputs_offset: u64,
) -> (RelationParameters, Fr) {
    let (eta, eta_two, eta_three, previous) = generate_eta_challenges(
        env,
        proof,
        public_inputs,
        circuit_size,
        public_inputs_size,
        pub_inputs_offset,
    );
    let (beta, gamma, next) = generate_beta_gamma(env, proof, previous);

    (
        RelationParameters {
            eta,
            eta_two,
            eta_three,
            beta,
            gamma,
            public_inputs_delta: Fr::zero(env),
        },
        next,
    )
}

fn generate_alpha_challenges(
    env: &Env,
    proof: &ZkProof,
    previous_challenge: Fr,
) -> ([Fr; NUMBER_OF_ALPHAS], Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    push_point(&mut data, &proof.lookup_inverses);
    push_point(&mut data, &proof.z_perm);

    let mut previous = hash_to_fr(&data);
    let mut alphas = Fr::zero_array::<NUMBER_OF_ALPHAS>(env);
    let (alpha_zero, alpha_one) = split_challenge(&previous);
    alphas[0] = alpha_zero;
    alphas[1] = alpha_one;

    for i in 1..(NUMBER_OF_ALPHAS / 2) {
        let data = Bytes::from_array(env, &previous.to_bytes());
        previous = hash_to_fr(&data);
        let (low, high) = split_challenge(&previous);
        alphas[2 * i] = low;
        alphas[2 * i + 1] = high;
    }

    if NUMBER_OF_ALPHAS > 2 && NUMBER_OF_ALPHAS % 2 == 1 {
        let data = Bytes::from_array(env, &previous.to_bytes());
        previous = hash_to_fr(&data);
        alphas[NUMBER_OF_ALPHAS - 1] = split_challenge(&previous).0;
    }

    (alphas, previous)
}

fn generate_gate_challenges(
    env: &Env,
    previous_challenge: Fr,
) -> ([Fr; CONST_PROOF_SIZE_LOG_N], Fr) {
    let mut previous = previous_challenge;
    let mut challenges = Fr::zero_array::<CONST_PROOF_SIZE_LOG_N>(env);
    for challenge in &mut challenges {
        let data = Bytes::from_array(env, &previous.to_bytes());
        previous = hash_to_fr(&data);
        *challenge = split_challenge(&previous).0;
    }
    (challenges, previous)
}

/// Absorb `[Libra:concatenation_commitment]` and `Libra:Sum`.
fn generate_libra_challenge(env: &Env, proof: &ZkProof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    push_point(&mut data, &proof.libra_concatenation_commitment);
    data.extend_from_slice(&proof.libra_sum.to_bytes());

    let next = hash_to_fr(&data);
    (split_challenge(&next).0, next)
}

fn generate_sumcheck_challenges(
    env: &Env,
    proof: &ZkProof,
    previous_challenge: Fr,
) -> ([Fr; CONST_PROOF_SIZE_LOG_N], Fr) {
    let mut previous = previous_challenge;
    let mut challenges = Fr::zero_array::<CONST_PROOF_SIZE_LOG_N>(env);

    for (round, challenge) in challenges.iter_mut().enumerate() {
        let mut data = Bytes::new(env);
        data.extend_from_slice(&previous.to_bytes());
        for evaluation in &proof.sumcheck_univariates[round] {
            data.extend_from_slice(&evaluation.to_bytes());
        }
        previous = hash_to_fr(&data);
        *challenge = split_challenge(&previous).0;
    }

    (challenges, previous)
}

/// Absorb all final Sumcheck claims, both remaining Libra commitments, and the
/// Gemini hiding-polynomial commitment/evaluation before deriving rho.
fn generate_rho_challenge(env: &Env, proof: &ZkProof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    for evaluation in &proof.sumcheck_evaluations {
        data.extend_from_slice(&evaluation.to_bytes());
    }
    data.extend_from_slice(&proof.libra_evaluation.to_bytes());
    push_point(&mut data, &proof.libra_grand_sum_commitment);
    push_point(&mut data, &proof.libra_quotient_commitment);
    push_point(&mut data, &proof.gemini_masking_polynomial);
    data.extend_from_slice(&proof.gemini_masking_evaluation.to_bytes());

    let next = hash_to_fr(&data);
    (split_challenge(&next).0, next)
}

fn generate_gemini_r_challenge(env: &Env, proof: &ZkProof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    for commitment in &proof.gemini_fold_comms {
        push_point(&mut data, commitment);
    }

    let next = hash_to_fr(&data);
    (split_challenge(&next).0, next)
}

/// Absorb the 28 Gemini evaluations followed by the four SmallSubgroupIPA
/// evaluations before deriving Shplonk's batching challenge.
fn generate_shplonk_nu_challenge(env: &Env, proof: &ZkProof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    for evaluation in &proof.gemini_a_evaluations {
        data.extend_from_slice(&evaluation.to_bytes());
    }
    for evaluation in &proof.libra_poly_evaluations {
        data.extend_from_slice(&evaluation.to_bytes());
    }

    let next = hash_to_fr(&data);
    (split_challenge(&next).0, next)
}

fn generate_shplonk_z_challenge(env: &Env, proof: &ZkProof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    push_point(&mut data, &proof.shplonk_q);

    let next = hash_to_fr(&data);
    (split_challenge(&next).0, next)
}

fn validate_proof(proof: &ZkProof) -> Result<(), &'static str> {
    if proof.pairing_point_object.len() != PAIRING_POINTS_SIZE {
        return Err("invalid pairing_point_object size");
    }
    if proof.sumcheck_univariates.len() != CONST_PROOF_SIZE_LOG_N {
        return Err("invalid sumcheck_univariates size");
    }
    if proof
        .sumcheck_univariates
        .iter()
        .any(|univariate| univariate.len() != ZK_BATCHED_RELATION_PARTIAL_LENGTH)
    {
        return Err("invalid ZK sumcheck univariate coefficient count");
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

/// Derive every Fiat-Shamir challenge used by UltraKeccakZK verification.
///
/// Challenge order:
/// eta/eta_two/eta_three, beta/gamma, alphas, gate challenges,
/// Libra challenge, Sumcheck challenges, rho, Gemini r, Shplonk nu, Shplonk z.
pub fn generate_zk_transcript(
    env: &Env,
    proof: &ZkProof,
    public_inputs: &Bytes,
    circuit_size: u64,
    public_inputs_size: u64,
    pub_inputs_offset: u64,
) -> Result<ZkTranscript, &'static str> {
    validate_proof(proof)?;

    let (rel_params, previous) = generate_relation_parameters(
        env,
        proof,
        public_inputs,
        circuit_size,
        public_inputs_size,
        pub_inputs_offset,
    );
    let (alphas, previous) = generate_alpha_challenges(env, proof, previous);
    let (gate_challenges, previous) = generate_gate_challenges(env, previous);
    let (libra_challenge, previous) = generate_libra_challenge(env, proof, previous);
    let (sumcheck_u_challenges, previous) = generate_sumcheck_challenges(env, proof, previous);
    let (rho, previous) = generate_rho_challenge(env, proof, previous);
    let (gemini_r, previous) = generate_gemini_r_challenge(env, proof, previous);
    let (shplonk_nu, previous) = generate_shplonk_nu_challenge(env, proof, previous);
    let (shplonk_z, _) = generate_shplonk_z_challenge(env, proof, previous);

    trace!("===== ZK TRANSCRIPT PARAMETERS =====");
    trace!("eta = 0x{}", crate::debug::Hex(&rel_params.eta.to_bytes()));
    trace!(
        "libra_challenge = 0x{}",
        crate::debug::Hex(&libra_challenge.to_bytes())
    );
    trace!("rho = 0x{}", crate::debug::Hex(&rho.to_bytes()));
    trace!("gemini_r = 0x{}", crate::debug::Hex(&gemini_r.to_bytes()));
    trace!(
        "shplonk_nu = 0x{}",
        crate::debug::Hex(&shplonk_nu.to_bytes())
    );
    trace!("shplonk_z = 0x{}", crate::debug::Hex(&shplonk_z.to_bytes()));
    trace!("====================================");

    Ok(ZkTranscript {
        rel_params,
        alphas,
        gate_challenges,
        libra_challenge,
        sumcheck_u_challenges,
        rho,
        gemini_r,
        shplonk_nu,
        shplonk_z,
    })
}
