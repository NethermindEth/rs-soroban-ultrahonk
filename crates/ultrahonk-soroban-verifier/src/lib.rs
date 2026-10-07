#![cfg_attr(not(feature = "std"), no_std)]

//! UltraHonk proof verification for Soroban contracts using Barretenberg's
//! **non-ZK, non-recursive `UltraKeccakFlavor`** on BN254.
//!
//! Compatible proof tooling: Noir/Nargo **1.0.0-beta.9** and Barretenberg
//! **0.87.0** with the Keccak oracle. The Soroban SDK dependency is **28.x**;
//! deployed contracts require Stellar protocol **28 or newer**.
//!
//! # Usage
//!
//! Pass the contract's environment and binary verification key to
//! [`UltraHonkVerifier::new`], then call [`UltraHonkVerifier::verify`]:
//!
//! ```
//! use soroban_sdk::{Bytes, Env};
//! use ultrahonk_soroban_verifier::UltraHonkVerifier;
//!
//! fn verify(
//!     env: &Env,
//!     vk: &Bytes,
//!     proof: &Bytes,
//!     public_inputs: &Bytes,
//! ) -> Result<(), &'static str> {
//!     let verifier = UltraHonkVerifier::new(env, vk)
//!         .map_err(|_| "invalid verification key")?;
//!     verifier.verify(proof, public_inputs)
//!         .map_err(|_| "invalid proof")
//! }
//! ```
//!
//! All `Bytes` arguments must belong to the same `Env`. Verification keys are
//! 1,760 bytes; proofs are [`PROOF_BYTES`] bytes. Public inputs are concatenated
//! canonical, big-endian 32-byte field elements in circuit order.
//!
//! # Security properties
//!
//! This proof flavor provides **no witness-hiding guarantee**. Verification does
//! not authenticate the transaction submitter or prevent replay. Proof bytes
//! are not unique identifiers. Applications must choose a trusted verification
//! key and implement their own authorization and replay protection.
//!
//! # Features
//!
//! Default features are empty; the core supports `no_std` with `alloc`.
//! `std` enables standard-library debug formatting helpers. `trace` emits
//! diagnostic output only when `std` is also enabled. Use default features for
//! Soroban Wasm builds.

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod debug;
pub mod ec;
pub mod field;
pub mod hash;
pub mod relations;
pub mod shplemini;
pub mod sumcheck;
pub mod transcript;
pub mod types;
pub mod utils;
pub mod verifier;

pub const PROOF_FIELDS: usize = 456;
pub const PROOF_BYTES: usize = PROOF_FIELDS * 32;

pub use verifier::{UltraHonkVerifier, VerifyError, VkLoadError};
