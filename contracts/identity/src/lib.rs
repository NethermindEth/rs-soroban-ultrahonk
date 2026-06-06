#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl, symbol_short, Bytes, Env, Symbol};
use ultrahonk_soroban_verifier::{UltraHonkVerifier, VkLoadError, PROOF_BYTES};

/// Identity verification contract.
///
/// The verification key (VK) is immutable: it is set once at deployment time
/// and cannot be changed afterwards. The deployer is solely responsible for
/// supplying the correct VK. There is no admin key, governance mechanism, or
/// upgrade path to modify the VK after deployment.
///
/// Callers should verify the stored VK (via `vk_bytes`) matches the expected
/// circuit before trusting proofs.
#[contract]
pub struct IdentityContract;

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
impl IdentityContract {
    fn key_vk() -> Symbol {
        symbol_short!("vk")
    }

    pub fn __constructor(env: Env, vk_bytes: Bytes) -> Result<(), Error> {
        if env.storage().instance().has(&Self::key_vk()) {
            return Err(Error::AlreadyInitialized);
        }
        // Validate VK bytes by attempting to parse them before storing.
        // This rejects empty, truncated, or structurally invalid VKs at deploy time.
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

    pub fn prove_identity(env: Env, public_inputs: Bytes, proof_bytes: Bytes) -> Result<(), Error> {
        if proof_bytes.len() as usize != PROOF_BYTES {
            return Err(Error::ProofParseError);
        }

        let vk_bytes: Bytes = env
            .storage()
            .instance()
            .get(&Self::key_vk())
            .ok_or(Error::VkNotSet)?;

        let verifier = UltraHonkVerifier::new(&env, &vk_bytes).map_err(|e| match e {
            VkLoadError::WrongLength => Error::VkInvalidLength,
            VkLoadError::InvalidParameters => Error::VkInvalidParameters,
        })?;

        verifier
            .verify(&env, &proof_bytes, &public_inputs)
            .map_err(|_| Error::VerificationFailed)?;

        Ok(())
    }
}
