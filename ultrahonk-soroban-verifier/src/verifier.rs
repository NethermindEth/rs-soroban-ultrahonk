//! UltraHonk verifier

use crate::{
    ec::{EcOps, SorobanEc},
    field::Fr,
    hash::hash32,
    shplemini::verify_shplemini,
    sumcheck::verify_sumcheck,
    transcript::generate_transcript,
    types::PAIRING_POINTS_SIZE,
    utils::{load_proof, load_vk_from_bytes},
};
use soroban_sdk::{Bytes, Env};

/// Error type describing the specific reason verification failed.
#[derive(Debug)]
pub enum VerifyError {
    InvalidInput(&'static str),
    SumcheckFailed(&'static str),
    ShplonkFailed(&'static str),
}

pub struct UltraHonkVerifier<E: EcOps> {
    env: Env,
    ec: E,
    vk: crate::types::VerificationKey,
}

/// Compute the VK hash: keccak256(vk_bytes) reduced mod BN254 scalar field order.
fn compute_vk_hash(_env: &Env, vk_bytes: &Bytes) -> [u8; 32] {
    Fr::from_bytes(&hash32(vk_bytes)).to_bytes()
}

impl<'a> UltraHonkVerifier<SorobanEc<'a>> {
    pub fn new(env: &'a Env, vk_bytes: &Bytes) -> Result<Self, VerifyError> {
        let vk_hash = compute_vk_hash(env, vk_bytes);
        load_vk_from_bytes(vk_bytes)
            .map(|mut vk| {
                vk.vk_hash = vk_hash;
                Self::new_with_vk(env, vk)
            })
            .ok_or(VerifyError::InvalidInput("vk parse error"))
    }

    pub fn new_with_vk(env: &'a Env, vk: crate::types::VerificationKey) -> Self {
        Self {
            env: env.clone(),
            ec: SorobanEc(env),
            vk,
        }
    }
}

impl<E: EcOps> UltraHonkVerifier<E> {
    pub fn new_with_backend(env: &Env, ec: E, vk_bytes: &Bytes) -> Result<Self, VerifyError> {
        let vk_hash = compute_vk_hash(env, vk_bytes);
        load_vk_from_bytes(vk_bytes)
            .map(|mut vk| {
                vk.vk_hash = vk_hash;
                Self {
                    env: env.clone(),
                    ec,
                    vk,
                }
            })
            .ok_or(VerifyError::InvalidInput("vk parse error"))
    }

    /// Expose a reference to the parsed VK for debugging/inspection.
    pub fn get_vk(&self) -> &crate::types::VerificationKey {
        &self.vk
    }

    /// Top-level verify
    pub fn verify(
        &self,
        proof_bytes: &Bytes,
        public_inputs_bytes: &Bytes,
    ) -> Result<(), VerifyError> {
        let log_n = self.vk.log_circuit_size as usize;

        // 1) parse proof (dynamic size based on log_n)
        let proof = load_proof(proof_bytes, log_n);

        // 2) sanity on public inputs (length and VK metadata if present)
        if public_inputs_bytes.len() % 32 != 0 {
            return Err(VerifyError::InvalidInput(
                "public inputs must be 32-byte aligned",
            ));
        }
        let provided = (public_inputs_bytes.len() / 32) as u64;
        let expected = self
            .vk
            .public_inputs_size
            .checked_sub(PAIRING_POINTS_SIZE as u64)
            .ok_or(VerifyError::InvalidInput("vk inputs < 16"))?;
        if expected != provided {
            return Err(VerifyError::InvalidInput("public inputs mismatch"));
        }

        // 3) Fiat–Shamir transcript (uses VK hash, not circuit metadata)
        let mut t = generate_transcript(
            &self.env,
            &proof,
            public_inputs_bytes,
            &self.vk.vk_hash,
            self.vk.public_inputs_size,
            log_n,
        );

        // 4) Public delta
        t.rel_params.public_inputs_delta = Self::compute_public_input_delta(
            public_inputs_bytes,
            &proof.pairing_point_object,
            t.rel_params.beta,
            t.rel_params.gamma,
            self.vk.pub_inputs_offset,
        )
        .map_err(VerifyError::InvalidInput)?;

        crate::trace!("public_inputs_delta = 0x{}", hex::encode(t.rel_params.public_inputs_delta.to_bytes()));

        // 5) Sum-check
        verify_sumcheck(&proof, &t, &self.vk).map_err(VerifyError::SumcheckFailed)?;

        // 6) Shplonk
        verify_shplemini(&self.ec, &proof, &self.vk, &t).map_err(VerifyError::ShplonkFailed)?;

        Ok(())
    }

    fn compute_public_input_delta(
        public_inputs: &Bytes,
        pairing_point_object: &[Fr],
        beta: Fr,
        gamma: Fr,
        offset: u64,
    ) -> Result<Fr, &'static str> {
        // bb 3.0 uses a fixed separator (1 << 28) instead of circuit_size
        const PERMUTATION_ARGUMENT_VALUE_SEPARATOR: u64 = 1 << 28;
        let mut numerator = Fr::one();
        let mut denominator = Fr::one();

        let mut numerator_acc =
            gamma + beta * Fr::from_u64(PERMUTATION_ARGUMENT_VALUE_SEPARATOR + offset);
        let mut denominator_acc = gamma - beta * Fr::from_u64(offset + 1);

        let mut idx = 0u32;
        while idx < public_inputs.len() {
            let mut arr = [0u8; 32];
            public_inputs.slice(idx..idx + 32).copy_into_slice(&mut arr);
            let public_input = Fr::from_bytes(&arr);
            numerator = numerator * (numerator_acc + public_input);
            denominator = denominator * (denominator_acc + public_input);
            numerator_acc = numerator_acc + beta;
            denominator_acc = denominator_acc - beta;
            idx += 32;
        }
        for public_input in pairing_point_object {
            numerator = numerator * (numerator_acc + *public_input);
            denominator = denominator * (denominator_acc + *public_input);
            numerator_acc = numerator_acc + beta;
            denominator_acc = denominator_acc - beta;
        }
        let denominator_inv = denominator
            .inverse()
            .ok_or("public input delta denom is zero")?;
        Ok(numerator * denominator_inv)
    }
}
