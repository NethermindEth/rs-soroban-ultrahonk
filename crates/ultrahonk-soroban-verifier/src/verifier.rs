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
    utils::{
        load_proof, load_vk_from_bytes, validate_gemini_padding, validate_public_inputs_canonical,
    },
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
    /// A verification-key G1 commitment was malformed: either a coordinate at or
    /// above the base field modulus, or a point that is not on the BN254 curve.
    ///
    /// Note there is no limb-canonicality case here, unlike the proof path: the VK
    /// stores each point as a plain 64-byte `x || y`, so there are no limbs to
    /// decode and `PointError::NonCanonicalLimb` is unreachable from this path.
    InvalidPoint,
}

/// Error type describing the specific reason verification failed.
#[derive(Debug)]
pub enum VerifyError {
    InvalidInput,
    SumcheckFailed,
    ShplonkFailed,
}

pub struct UltraHonkVerifier {
    env: Env,
    vk: crate::types::VerificationKey,
}

impl UltraHonkVerifier {
    /// Build a verifier from an already-parsed key.
    ///
    /// Crate-internal: a `VerificationKey` can only be obtained from
    /// [`load_vk_from_bytes`], which validates every commitment, so this cannot be
    /// reached with an unvalidated key. Exposing it would reintroduce that path,
    /// since the struct's fields are public. Use [`Self::new`] instead, which parses
    /// and validates the key bytes.
    pub(crate) fn new_with_vk(env: &Env, vk: crate::types::VerificationKey) -> Self {
        Self {
            env: env.clone(),
            vk,
        }
    }

    pub fn new(env: &Env, vk_bytes: &Bytes) -> Result<Self, VkLoadError> {
        load_vk_from_bytes(env, vk_bytes).map(|vk| Self::new_with_vk(env, vk))
    }

    /// Expose a reference to the parsed VK for debugging/inspection.
    pub fn get_vk(&self) -> &crate::types::VerificationKey {
        &self.vk
    }

    /// Verify an UltraHonk proof against the loaded VK.
    ///
    /// Steps (matching BB verifier flow). The numbers match the `// n)` labels in
    /// the body, so a step traced by number lands on the block that performs it:
    /// 1. Parse proof bytes (canonical G1 limbs, coordinates and scalars enforced
    ///    at parse time; see VERIFIER_PROVENANCE.md §4.3).
    /// 2. Reject non-zero padding in the unused Gemini evaluation slots.
    /// 3. Validate the public inputs: 32-byte alignment, canonical encodings, and
    ///    count against VK metadata.
    /// 4. Generate Fiat–Shamir challenges (Oink rounds).
    /// 5. Compute `public_inputs_delta` (grand-product permutation argument).
    /// 6. Run sumcheck verification.
    /// 7. Run Shplemini batch-opening (Gemini + Shplonk + KZG pairing check).
    ///
    /// BB: `ultra_verifier.cpp::UltraVerifier_::verify_proof`
    /// Note: this takes no `Env` parameter. The verifier's stored handle is used
    /// throughout, which makes a cross-`Env` mismatch unrepresentable rather than
    /// merely unlikely.
    pub fn verify(
        &self,
        proof_bytes: &Bytes,
        public_inputs_bytes: &Bytes,
    ) -> Result<(), VerifyError> {
        let env = &self.env;
        // 1) parse proof
        let proof = load_proof(env, proof_bytes).map_err(|_| VerifyError::InvalidInput)?;

        // 2) reject non-canonical padding in the unused Gemini evaluation slots.
        // Done here rather than in `load_proof` because it needs log_circuit_size,
        // which comes from the VK. Runs before transcript generation.
        validate_gemini_padding(&proof, self.vk.log_circuit_size as usize)
            .map_err(|_| VerifyError::InvalidInput)?;

        // 3) validate public inputs (alignment, canonical encodings, count vs VK)
        if !public_inputs_bytes.len().is_multiple_of(32) {
            return Err(VerifyError::InvalidInput);
        }
        validate_public_inputs_canonical(public_inputs_bytes)
            .map_err(|_| VerifyError::InvalidInput)?;
        let provided = (public_inputs_bytes.len() / 32) as u64;
        let expected = self
            .vk
            .public_inputs_size
            .checked_sub(PAIRING_POINTS_SIZE as u64)
            .ok_or(VerifyError::InvalidInput)?;
        if expected != provided {
            return Err(VerifyError::InvalidInput);
        }

        // 4) Fiat–Shamir transcript
        let pis_total = provided + PAIRING_POINTS_SIZE as u64;
        let pub_inputs_offset = self.vk.pub_inputs_offset;
        let mut t = generate_transcript(
            env,
            &proof,
            public_inputs_bytes,
            self.vk.circuit_size,
            pis_total,
            pub_inputs_offset,
        )
        .map_err(|_| VerifyError::InvalidInput)?;

        // 5) Public delta
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

        // 6) Sum-check
        verify_sumcheck(env, &proof, &t, &self.vk).map_err(|_| VerifyError::SumcheckFailed)?;

        // 7) Shplemini (Gemini + Shplonk + KZG)
        verify_shplemini(env, &proof, &self.vk, &t).map_err(|_| VerifyError::ShplonkFailed)?;

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
