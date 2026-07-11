//! Top-level UltraHonk verifier orchestration.
//!
//! Implements the verifier flow that BB splits across `ultra_verifier.cpp`,
//! `oink_verifier.cpp`, and `decider_verifier.cpp`.  The Rust code inlines the
//! Oink and Decider steps into a single `verify` method.
//!
//! BB reference (v0.87.0):
//!   - `ultra_honk/ultra_verifier.cpp::UltraVerifier_::verify_proof`
//!   - `ultra_honk/oink_verifier.cpp::OinkVerifier::verify`
//!   - `ultra_honk/decider_verifier.cpp::DeciderVerifier_::verify`

use crate::{
    field::Fr,
    shplemini::verify_shplemini,
    sumcheck::verify_sumcheck,
    transcript::generate_transcript,
    types::PAIRING_POINTS_SIZE,
    utils::{load_proof, load_vk_from_bytes},
    zk_shplemini::verify_zk_shplemini,
    zk_sumcheck::verify_zk_sumcheck,
    zk_transcript::generate_zk_transcript,
    zk_utils::load_zk_proof,
    PROOF_BYTES, ZK_PROOF_BYTES,
};
use soroban_sdk::{Bytes, Env};

/// Error type describing why a verification key could not be loaded from bytes.
///
/// Intentionally minimal: the VK is public data, so callers do not need a
/// fine-grained oracle. The two variants separate deployer mistakes (wrong
/// byte count) from invalid structural parameters that could indicate
/// corruption or an adversarially crafted VK.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum VkLoadError {
    /// Byte slice length does not match the exact expected VK size (1760 bytes).
    WrongLength,
    /// Header parsed successfully but contains out-of-range values.
    InvalidParameters,
}

/// Error type describing the specific reason verification failed.
#[derive(Debug)]
pub enum VerifyError {
    InvalidInput,
    SumcheckFailed,
    ShplonkFailed,
}

/// UltraHonk proof flavors accepted by this verifier.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ProofFlavor {
    /// Barretenberg v0.87 `UltraKeccakFlavor` (non-zero-knowledge).
    UltraKeccak,
    /// Barretenberg v0.87 `UltraKeccakZKFlavor` (Libra + hiding polynomial).
    UltraKeccakZk,
}

impl ProofFlavor {
    pub const fn proof_bytes(self) -> usize {
        match self {
            Self::UltraKeccak => PROOF_BYTES,
            Self::UltraKeccakZk => ZK_PROOF_BYTES,
        }
    }

    pub fn from_proof_len(len: usize) -> Option<Self> {
        match len {
            PROOF_BYTES => Some(Self::UltraKeccak),
            ZK_PROOF_BYTES => Some(Self::UltraKeccakZk),
            _ => None,
        }
    }
}

pub struct UltraHonkVerifier {
    env: Env,
    vk: crate::types::VerificationKey,
}

impl UltraHonkVerifier {
    pub fn new_with_vk(env: &Env, vk: crate::types::VerificationKey) -> Self {
        Self {
            env: env.clone(),
            vk,
        }
    }

    /// Load a non-recursive UltraHonk verification key.
    ///
    /// The v0.87 byte format has no recursion discriminator. Callers must not
    /// supply a recursive VK: this verifier does not aggregate its pairing
    /// accumulator.
    pub fn new(env: &Env, vk_bytes: &Bytes) -> Result<Self, VkLoadError> {
        load_vk_from_bytes(env, vk_bytes).map(|vk| Self::new_with_vk(env, vk))
    }

    /// Expose a reference to the parsed VK for debugging/inspection.
    pub fn get_vk(&self) -> &crate::types::VerificationKey {
        &self.vk
    }

    /// Verify an UltraKeccak or UltraKeccakZK proof against the loaded VK.
    ///
    /// Steps (matching BB verifier flow):
    /// 1. Select the proof flavor and validate public inputs against VK metadata.
    /// 2. Parse and validate the canonical proof encoding.
    /// 3. Generate Fiat–Shamir challenges (Oink rounds).
    /// 4. Compute `public_inputs_delta` (grand-product permutation argument).
    /// 5. Run sumcheck verification.
    /// 6. Run Shplemini batch-opening (Gemini + Shplonk + KZG pairing check).
    ///
    /// BB: `ultra_verifier.cpp::UltraVerifier_::verify_proof`
    pub fn verify(
        &self,
        env: &Env,
        proof_bytes: &Bytes,
        public_inputs_bytes: &Bytes,
    ) -> Result<(), VerifyError> {
        let flavor = ProofFlavor::from_proof_len(proof_bytes.len() as usize)
            .ok_or(VerifyError::InvalidInput)?;
        self.verify_with_flavor(env, proof_bytes, public_inputs_bytes, flavor)
    }

    /// Verify a proof while requiring an explicit flavor.
    pub fn verify_with_flavor(
        &self,
        env: &Env,
        proof_bytes: &Bytes,
        public_inputs_bytes: &Bytes,
        flavor: ProofFlavor,
    ) -> Result<(), VerifyError> {
        if proof_bytes.len() as usize != flavor.proof_bytes() {
            return Err(VerifyError::InvalidInput);
        }
        let provided = self.validate_public_input_length(public_inputs_bytes)?;
        match flavor {
            ProofFlavor::UltraKeccak => {
                self.verify_non_zk(env, proof_bytes, public_inputs_bytes, provided)
            }
            ProofFlavor::UltraKeccakZk => {
                self.verify_zk(env, proof_bytes, public_inputs_bytes, provided)
            }
        }
    }

    fn validate_public_input_length(
        &self,
        public_inputs_bytes: &Bytes,
    ) -> Result<u64, VerifyError> {
        if !public_inputs_bytes.len().is_multiple_of(32) {
            return Err(VerifyError::InvalidInput);
        }
        let provided = (public_inputs_bytes.len() / 32) as u64;
        let expected = self
            .vk
            .public_inputs_size
            .checked_sub(PAIRING_POINTS_SIZE as u64)
            .ok_or(VerifyError::InvalidInput)?;
        if expected != provided {
            return Err(VerifyError::InvalidInput);
        }

        // The transcript hashes the supplied bytes while the arithmetic host
        // reduces them modulo the BN254 scalar modulus. Requiring the unique
        // encoding prevents two byte strings from representing the same
        // circuit public input (critical for nullifier/replay semantics).
        let mut idx = 0u32;
        while idx < public_inputs_bytes.len() {
            let mut value = [0u8; 32];
            public_inputs_bytes
                .slice(idx..idx + 32)
                .copy_into_slice(&mut value);
            if !Fr::is_canonical_bytes(&value) {
                return Err(VerifyError::InvalidInput);
            }
            idx += 32;
        }
        Ok(provided)
    }

    fn verify_non_zk(
        &self,
        env: &Env,
        proof_bytes: &Bytes,
        public_inputs_bytes: &Bytes,
        provided: u64,
    ) -> Result<(), VerifyError> {
        // 1) parse proof
        let proof = load_proof(env, proof_bytes).map_err(|_| VerifyError::InvalidInput)?;

        // 3) Fiat–Shamir transcript
        let pis_total = provided + PAIRING_POINTS_SIZE as u64;
        let pub_inputs_offset = self.vk.pub_inputs_offset;
        let mut t = generate_transcript(
            &self.env,
            &proof,
            public_inputs_bytes,
            self.vk.circuit_size,
            pis_total,
            pub_inputs_offset,
        )
        .map_err(|_| VerifyError::InvalidInput)?;

        // 4) Public delta
        t.rel_params.public_inputs_delta = Self::compute_public_input_delta(
            env,
            public_inputs_bytes,
            &proof.pairing_point_object,
            &t.rel_params.beta,
            &t.rel_params.gamma,
            pub_inputs_offset,
            self.vk.circuit_size,
        )
        .map_err(|_| VerifyError::InvalidInput)?;

        // 5) Sum-check
        verify_sumcheck(env, &proof, &t, &self.vk).map_err(|_| VerifyError::SumcheckFailed)?;

        // 6) Shplonk
        verify_shplemini(&self.env, &proof, &self.vk, &t)
            .map_err(|_| VerifyError::ShplonkFailed)?;

        Ok(())
    }

    fn verify_zk(
        &self,
        env: &Env,
        proof_bytes: &Bytes,
        public_inputs_bytes: &Bytes,
        provided: u64,
    ) -> Result<(), VerifyError> {
        let proof = load_zk_proof(env, proof_bytes).map_err(|_| VerifyError::InvalidInput)?;
        let pis_total = provided + PAIRING_POINTS_SIZE as u64;
        let pub_inputs_offset = self.vk.pub_inputs_offset;

        let mut transcript = generate_zk_transcript(
            &self.env,
            &proof,
            public_inputs_bytes,
            self.vk.circuit_size,
            pis_total,
            pub_inputs_offset,
        )
        .map_err(|_| VerifyError::InvalidInput)?;

        transcript.rel_params.public_inputs_delta = Self::compute_public_input_delta(
            env,
            public_inputs_bytes,
            &proof.pairing_point_object,
            &transcript.rel_params.beta,
            &transcript.rel_params.gamma,
            pub_inputs_offset,
            self.vk.circuit_size,
        )
        .map_err(|_| VerifyError::InvalidInput)?;

        verify_zk_sumcheck(env, &proof, &transcript, &self.vk)
            .map_err(|_| VerifyError::SumcheckFailed)?;
        verify_zk_shplemini(&self.env, &proof, &self.vk, &transcript)
            .map_err(|_| VerifyError::ShplonkFailed)?;

        Ok(())
    }

    /// Compute the public-input delta factor for the permutation grand-product argument.
    ///
    /// Formula (matching BB):
    ///   numerator   = ∏ᵢ (γ + xᵢ + β·(n + i + offset))
    ///   denominator = ∏ᵢ (γ + xᵢ − β·(1 + i + offset))
    ///   delta       = numerator · denominator⁻¹
    ///
    /// The pairing-point object values are appended after the user-supplied public inputs.
    ///
    /// BB: `honk/library/grand_product_delta.hpp::compute_public_input_delta`
    fn compute_public_input_delta(
        env: &Env,
        public_inputs: &Bytes,
        pairing_point_object: &[Fr],
        beta: &Fr,
        gamma: &Fr,
        offset: u64,
        n: u64,
    ) -> Result<Fr, &'static str> {
        let mut numerator = Fr::one(env);
        let mut denominator = Fr::one(env);

        let beta_n = beta * &Fr::from_u64(env, n + offset);
        let beta_off = beta * &Fr::from_u64(env, offset + 1);
        let mut numerator_acc = gamma + beta_n;
        let mut denominator_acc = gamma - &beta_off;

        let mut idx = 0u32;
        while idx < public_inputs.len() {
            let mut arr = [0u8; 32];
            public_inputs.slice(idx..idx + 32).copy_into_slice(&mut arr);
            let public_input = Fr::from_array(env, &arr);
            numerator = numerator * (&numerator_acc + &public_input);
            denominator = denominator * (&denominator_acc + &public_input);
            numerator_acc = &numerator_acc + beta;
            denominator_acc = &denominator_acc - beta;
            idx += 32;
        }
        for public_input in pairing_point_object {
            numerator = &numerator * &(&numerator_acc + public_input);
            denominator = &denominator * &(&denominator_acc + public_input);
            numerator_acc = &numerator_acc + beta;
            denominator_acc = &denominator_acc - beta;
        }
        if denominator.is_zero() {
            return Err("denominator is zero in public_input_delta");
        }
        let denominator_inv = denominator.inverse();
        Ok(numerator * denominator_inv)
    }
}
