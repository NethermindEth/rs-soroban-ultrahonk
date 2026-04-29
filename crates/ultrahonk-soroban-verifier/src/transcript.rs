//! Fiat–Shamir transcript for UltraHonk

use crate::field::ArkFr;
use crate::trace;
use crate::{
    field::Fr,
    hash::hash32,
    types::{
        G1Point, Proof, RelationParameters, Transcript, CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ALPHAS,
    },
    utils::coord_to_halves_be,
};
use soroban_sdk::{Bytes, Env};

fn push_point(buf: &mut Bytes, pt: &G1Point) {
    // Serialize a coordinate into two bn254::Fr limbs (lo136, hi<=118)
    let bytes = pt.0.to_array();
    let (x_lo, x_hi) = coord_to_halves_be(&bytes[..32]);
    let (y_lo, y_hi) = coord_to_halves_be(&bytes[32..]);
    buf.extend_from_slice(&x_lo);
    buf.extend_from_slice(&x_hi);
    buf.extend_from_slice(&y_lo);
    buf.extend_from_slice(&y_hi);
}

/// Split a 32-byte field element into the two 128-bit transcript “halves” (lo/hi limb layout).
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

fn split_challenge(challenge: &Fr) -> (Fr, Fr) {
    let env = challenge.0.env();
    split_challenge_from_be32(&env, &challenge.to_bytes())
}

#[inline(always)]
fn hash_to_fr(bytes: &Bytes) -> Fr {
    Fr(ArkFr::from_bytes(hash32(bytes)))
}

fn u64_to_be32(x: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&x.to_be_bytes());
    out
}

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

fn generate_shplonk_z_challenge(env: &Env, proof: &Proof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    push_point(&mut data, &proof.shplonk_q);
    let next_previous_challenge = hash_to_fr(&data);
    let shplonk_z = split_challenge(&next_previous_challenge).0;
    (shplonk_z, next_previous_challenge)
}

pub fn generate_transcript(
    env: &Env,
    proof: &Proof,
    public_inputs: &Bytes,
    circuit_size: u64,
    public_inputs_size: u64,
    pub_inputs_offset: u64,
) -> Transcript {
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
    trace!("eta = 0x{}", hex::encode(rp.eta.to_bytes()));
    trace!("eta_two = 0x{}", hex::encode(rp.eta_two.to_bytes()));
    trace!("eta_three = 0x{}", hex::encode(rp.eta_three.to_bytes()));
    trace!("beta = 0x{}", hex::encode(rp.beta.to_bytes()));
    trace!("gamma = 0x{}", hex::encode(rp.gamma.to_bytes()));
    trace!("rho = 0x{}", hex::encode(rho.to_bytes()));
    trace!("gemini_r = 0x{}", hex::encode(gemini_r.to_bytes()));
    trace!("shplonk_nu = 0x{}", hex::encode(shplonk_nu.to_bytes()));
    trace!("shplonk_z = 0x{}", hex::encode(shplonk_z.to_bytes()));
    trace!("circuit_size = {}", circuit_size);
    trace!("public_inputs_total = {}", public_inputs_size);
    trace!("public_inputs_offset = {}", pub_inputs_offset);
    trace!("=================================");

    Transcript {
        rel_params: rp,
        alphas,
        gate_challenges: gate_chals,
        sumcheck_u_challenges: u_chals,
        rho,
        gemini_r,
        shplonk_nu,
        shplonk_z,
    }
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

        let proof = load_proof(&env, &proof_bytes);
        let vk = load_vk_from_bytes(&env, &vk_bytes).unwrap();

        let t = generate_transcript(
            &env,
            &proof,
            &pi_bytes,
            vk.circuit_size,
            vk.public_inputs_size,
            1, // pub_inputs_offset
        );

        assert_eq!(
            hex::encode(t.rel_params.eta.to_bytes()),
            "0000000000000000000000000000000085cff885ac2961fd2caf69da4ab04a55"
        );
        assert_eq!(
            hex::encode(t.rel_params.beta.to_bytes()),
            "00000000000000000000000000000000cf2d1a0f78861f5dfc916c1550073a26"
        );
        assert_eq!(
            hex::encode(t.rel_params.gamma.to_bytes()),
            "000000000000000000000000000000000b9a9dc0b29d2edaa5de654ffd600900"
        );
        assert_eq!(
            hex::encode(t.rho.to_bytes()),
            "00000000000000000000000000000000ddc594911e07b3b91b1afc817c04d331"
        );
        assert_eq!(
            hex::encode(t.shplonk_z.to_bytes()),
            "000000000000000000000000000000001c9e9d4cde5bde269eed51b980ab19fe"
        );
    }
}
