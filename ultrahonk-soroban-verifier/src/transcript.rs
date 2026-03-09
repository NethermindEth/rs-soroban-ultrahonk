//! Fiat–Shamir transcript for UltraHonk (bb 3.0 non-ZK format)

use crate::trace;
use crate::{
    field::Fr,
    hash::hash32,
    types::{
        G1Point, Proof, RelationParameters, Transcript, CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ALPHAS,
    },
};
use soroban_sdk::{Bytes, Env};

/// Push a G1 point as plain (x, y) — 64 bytes total.
fn push_point(buf: &mut Bytes, pt: &G1Point) {
    buf.extend_from_slice(&pt.x);
    buf.extend_from_slice(&pt.y);
}

fn split_challenge(challenge: Fr) -> (Fr, Fr) {
    let bytes = challenge.to_bytes(); // big-endian 32 bytes
    // Split into two 127-bit halves (matching Solidity: lo = v & (2^127-1), hi = v >> 127)
    let hi128 = u128::from_be_bytes(bytes[0..16].try_into().unwrap());
    let lo128 = u128::from_be_bytes(bytes[16..32].try_into().unwrap());

    let lo_val = lo128 & ((1u128 << 127) - 1);
    let hi_val = (hi128 << 1) | (lo128 >> 127);

    let mut lo_bytes = [0u8; 32];
    lo_bytes[16..].copy_from_slice(&lo_val.to_be_bytes());
    let mut hi_bytes = [0u8; 32];
    hi_bytes[16..].copy_from_slice(&hi_val.to_be_bytes());
    (Fr::from_bytes(&lo_bytes), Fr::from_bytes(&hi_bytes))
}

#[inline(always)]
fn hash_to_fr(bytes: &Bytes) -> Fr {
    Fr::from_bytes(&hash32(bytes))
}

fn generate_eta_challenge(
    env: &Env,
    proof: &Proof,
    public_inputs: &Bytes,
    vk_hash: &[u8; 32],
    public_inputs_size: u64,
) -> (Fr, Fr, Fr, Fr) {
    let mut data = Bytes::new(env);
    // 1) VK hash
    data.extend_from_slice(vk_hash);
    // 2) Non-pairing public inputs
    let non_pairing_count = public_inputs_size as usize - crate::types::PAIRING_POINTS_SIZE;
    let non_pairing_bytes = non_pairing_count * 32;
    if public_inputs.len() as usize >= non_pairing_bytes {
        let mut idx = 0u32;
        for _ in 0..non_pairing_count {
            let chunk: [u8; 32] = crate::utils::read_bytes_pub(public_inputs, &mut idx);
            data.extend_from_slice(&chunk);
        }
    }
    // 3) Pairing point object (from proof)
    for fr in &proof.pairing_point_object {
        data.extend_from_slice(&fr.to_bytes());
    }
    // 4) w1, w2, w3 as plain (x, y)
    for w in &[&proof.w1, &proof.w2, &proof.w3] {
        push_point(&mut data, w);
    }

    trace!("eta round data len = {}", data.len());
    trace!("eta round data (first 64 bytes) = 0x{}", {
        let mut first64 = [0u8; 64];
        data.slice(0..64).copy_into_slice(&mut first64);
        hex::encode(first64)
    });
    let previous_challenge = hash_to_fr(&data);
    trace!("eta previous_challenge (raw hash→Fr) = 0x{}", hex::encode(previous_challenge.to_bytes()));
    let (eta, eta_two) = split_challenge(previous_challenge);
    let prev_bytes = Bytes::from_array(env, &previous_challenge.to_bytes());
    let previous_challenge = hash_to_fr(&prev_bytes);
    let (eta_three, _) = split_challenge(previous_challenge);

    (eta, eta_two, eta_three, previous_challenge)
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
    let (beta, gamma) = split_challenge(next_previous_challenge);
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
    let next_previous_challenge = hash_to_fr(&data);

    // Generate a single alpha, then compute powers: alpha, alpha^2, ..., alpha^NUMBER_OF_ALPHAS
    let (alpha, _) = split_challenge(next_previous_challenge);
    let mut alphas = [Fr::zero(); NUMBER_OF_ALPHAS];
    alphas[0] = alpha;
    for i in 1..NUMBER_OF_ALPHAS {
        alphas[i] = alphas[i - 1] * alpha;
    }

    (alphas, next_previous_challenge)
}

fn generate_gate_challenges(
    env: &Env,
    previous_challenge: Fr,
    log_n: usize,
) -> ([Fr; CONST_PROOF_SIZE_LOG_N], Fr) {
    // Hash once to get gate_challenges[0], then square for subsequent rounds
    let next_bytes = Bytes::from_array(env, &previous_challenge.to_bytes());
    let next_previous_challenge = hash_to_fr(&next_bytes);
    let mut gate_challenges = [Fr::zero(); CONST_PROOF_SIZE_LOG_N];
    (gate_challenges[0], _) = split_challenge(next_previous_challenge);
    for i in 1..log_n {
        gate_challenges[i] = gate_challenges[i - 1] * gate_challenges[i - 1];
    }
    (gate_challenges, next_previous_challenge)
}

fn generate_sumcheck_challenges(
    env: &Env,
    proof: &Proof,
    previous_challenge: Fr,
    log_n: usize,
) -> ([Fr; CONST_PROOF_SIZE_LOG_N], Fr) {
    let mut next_previous_challenge = previous_challenge;
    let mut sumcheck_challenges = [Fr::zero(); CONST_PROOF_SIZE_LOG_N];
    for r in 0..log_n {
        let mut data = Bytes::new(env);
        data.extend_from_slice(&next_previous_challenge.to_bytes());
        for &c in proof.sumcheck_univariates[r].iter() {
            data.extend_from_slice(&c.to_bytes());
        }
        next_previous_challenge = hash_to_fr(&data);
        sumcheck_challenges[r] = split_challenge(next_previous_challenge).0;
    }
    (sumcheck_challenges, next_previous_challenge)
}

fn generate_rho_challenge(env: &Env, proof: &Proof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    for &e in proof.sumcheck_evaluations.iter() {
        data.extend_from_slice(&e.to_bytes());
    }
    let next_previous_challenge = hash_to_fr(&data);
    let rho = split_challenge(next_previous_challenge).0;
    (rho, next_previous_challenge)
}

fn generate_gemini_r_challenge(
    env: &Env,
    proof: &Proof,
    previous_challenge: Fr,
    log_n: usize,
) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    for i in 0..(log_n - 1) {
        push_point(&mut data, &proof.gemini_fold_comms[i]);
    }
    let next_previous_challenge = hash_to_fr(&data);
    let gemini_r = split_challenge(next_previous_challenge).0;
    (gemini_r, next_previous_challenge)
}

fn generate_shplonk_nu_challenge(
    env: &Env,
    proof: &Proof,
    previous_challenge: Fr,
    log_n: usize,
) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    for i in 0..log_n {
        data.extend_from_slice(&proof.gemini_a_evaluations[i].to_bytes());
    }
    let next_previous_challenge = hash_to_fr(&data);
    let shplonk_nu = split_challenge(next_previous_challenge).0;
    (shplonk_nu, next_previous_challenge)
}

fn generate_shplonk_z_challenge(env: &Env, proof: &Proof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    push_point(&mut data, &proof.shplonk_q);
    let next_previous_challenge = hash_to_fr(&data);
    let shplonk_z = split_challenge(next_previous_challenge).0;
    (shplonk_z, next_previous_challenge)
}

pub fn generate_transcript(
    env: &Env,
    proof: &Proof,
    public_inputs: &Bytes,
    vk_hash: &[u8; 32],
    public_inputs_size: u64,
    log_n: usize,
) -> Transcript {
    // 1) eta/beta/gamma
    let (eta, eta_two, eta_three, previous_challenge) =
        generate_eta_challenge(env, proof, public_inputs, vk_hash, public_inputs_size);
    let (beta, gamma, previous_challenge) =
        generate_beta_and_gamma_challenges(env, previous_challenge, proof);
    let rp = RelationParameters {
        eta,
        eta_two,
        eta_three,
        beta,
        gamma,
        public_inputs_delta: Fr::zero(),
    };

    // 2) alphas (powers of a single alpha)
    let (alphas, previous_challenge) = generate_alpha_challenges(env, previous_challenge, proof);

    // 3) gate challenges (first from hash, rest by squaring)
    let (gate_chals, previous_challenge) =
        generate_gate_challenges(env, previous_challenge, log_n);

    // 4) sumcheck challenges
    let (u_chals, previous_challenge) =
        generate_sumcheck_challenges(env, proof, previous_challenge, log_n);

    // 5) rho
    let (rho, previous_challenge) = generate_rho_challenge(env, proof, previous_challenge);

    // 6) gemini_r
    let (gemini_r, previous_challenge) =
        generate_gemini_r_challenge(env, proof, previous_challenge, log_n);

    // 7) shplonk_nu
    let (shplonk_nu, previous_challenge) =
        generate_shplonk_nu_challenge(env, proof, previous_challenge, log_n);

    // 8) shplonk_z
    let (shplonk_z, _previous_challenge) =
        generate_shplonk_z_challenge(env, proof, previous_challenge);

    #[cfg(all(feature = "trace", feature = "std"))]
    {
        println!("===== TRANSCRIPT PARAMETERS =====");
        println!("eta = 0x{}", hex::encode(rp.eta.to_bytes()));
        println!("eta_two = 0x{}", hex::encode(rp.eta_two.to_bytes()));
        println!("eta_three = 0x{}", hex::encode(rp.eta_three.to_bytes()));
        println!("beta = 0x{}", hex::encode(rp.beta.to_bytes()));
        println!("gamma = 0x{}", hex::encode(rp.gamma.to_bytes()));
        for (i, a) in alphas.iter().enumerate() {
            println!("alpha[{}] = 0x{}", i, hex::encode(a.to_bytes()));
        }
        for (i, g) in gate_chals.iter().enumerate().take(log_n) {
            println!("gate_challenge[{}] = 0x{}", i, hex::encode(g.to_bytes()));
        }
        for (i, u) in u_chals.iter().enumerate().take(log_n) {
            println!("sumcheck_u[{}] = 0x{}", i, hex::encode(u.to_bytes()));
        }
        println!("rho = 0x{}", hex::encode(rho.to_bytes()));
        println!("gemini_r = 0x{}", hex::encode(gemini_r.to_bytes()));
        println!("shplonk_nu = 0x{}", hex::encode(shplonk_nu.to_bytes()));
        println!("shplonk_z = 0x{}", hex::encode(shplonk_z.to_bytes()));
        println!("=================================");
    }

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
