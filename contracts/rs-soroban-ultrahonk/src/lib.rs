#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl, symbol_short, Bytes, Env, Symbol};
use ultrahonk_soroban_verifier::{UltraHonkVerifier, VkLoadError, PROOF_BYTES};

/// On-chain UltraHonk proof verifier.
///
/// The verification key (VK) is immutable: it is set once at deployment time
/// and cannot be changed afterwards. The deployer is solely responsible for
/// supplying the correct VK. There is no admin key, governance mechanism, or
/// upgrade path to modify the VK after deployment.
///
/// **Trust model:** This wrapper has no governor, no deployer auth, and no
/// access controls. Anyone can deploy an instance with an arbitrary VK.
/// Callers MUST independently verify the stored VK (via `vk_bytes`) against
/// a known-good circuit before trusting any proofs verified by this contract.
/// Do not rely on the contract address alone as a trust anchor.
#[contract]
pub struct UltraHonkVerifierContract;

#[contracterror]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// VK byte slice does not match the expected exact length.
    VkInvalidLength = 1,
    /// VK header contains out-of-range structural parameters.
    VkInvalidParameters = 2,
    /// Proof byte slice does not match the expected exact length.
    ProofParseError = 3,
    /// Cryptographic verification failed.
    VerificationFailed = 4,
    /// No VK has been stored in contract instance storage.
    VkNotSet = 5,
    /// Constructor has already been called; VK is immutable.
    AlreadyInitialized = 6,
}

#[contractimpl]
impl UltraHonkVerifierContract {
    fn key_vk() -> Symbol {
        symbol_short!("vk")
    }

    /// Initialize the on-chain VK once at deploy time.
    /// Validates the VK bytes by parsing them before storage so that empty or
    /// malformed VKs are rejected at deployment time.
    pub fn __constructor(env: Env, vk_bytes: Bytes) -> Result<(), Error> {
        if env.storage().instance().has(&Self::key_vk()) {
            return Err(Error::AlreadyInitialized);
        }
        let _ = UltraHonkVerifier::new(&env, &vk_bytes).map_err(|e| match e {
            VkLoadError::WrongLength => Error::VkInvalidLength,
            VkLoadError::InvalidParameters => Error::VkInvalidParameters,
        })?;
        env.storage().instance().set(&Self::key_vk(), &vk_bytes);
        Ok(())
    }

    /// Return the stored verification key bytes for auditability.
    pub fn vk_bytes(env: Env) -> Result<Bytes, Error> {
        env.storage()
            .instance()
            .get(&Self::key_vk())
            .ok_or(Error::VkNotSet)
    }

    /// Verify an UltraHonk proof using the stored VK.
    pub fn verify_proof(env: Env, public_inputs: Bytes, proof_bytes: Bytes) -> Result<(), Error> {
        if proof_bytes.len() as usize != PROOF_BYTES {
            return Err(Error::ProofParseError);
        }

        let vk_bytes: Bytes = env
            .storage()
            .instance()
            .get(&Self::key_vk())
            .ok_or(Error::VkNotSet)?;
        // Deserialize verification key bytes
        let verifier = UltraHonkVerifier::new(&env, &vk_bytes).map_err(|e| match e {
            VkLoadError::WrongLength => Error::VkInvalidLength,
            VkLoadError::InvalidParameters => Error::VkInvalidParameters,
        })?;

        // Verify
        verifier
            .verify(&env, &proof_bytes, &public_inputs)
            .map_err(|_| Error::VerificationFailed)?;
        Ok(())
    }
}
