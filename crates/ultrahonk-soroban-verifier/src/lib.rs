#![cfg_attr(not(feature = "std"), no_std)]

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
pub mod zk_shplemini;
pub mod zk_sumcheck;
pub mod zk_transcript;
pub mod zk_types;
pub mod zk_utils;

/// Fixed proof size for the non-ZK UltraKeccak flavor.
pub const PROOF_FIELDS: usize = 456;
pub const PROOF_BYTES: usize = PROOF_FIELDS * 32;
/// Fixed proof size for Barretenberg v0.87 UltraKeccakZK.
pub const ZK_PROOF_FIELDS: usize = 507;
pub const ZK_PROOF_BYTES: usize = ZK_PROOF_FIELDS * 32;

pub use verifier::{ProofFlavor, UltraHonkVerifier, VkLoadError};
