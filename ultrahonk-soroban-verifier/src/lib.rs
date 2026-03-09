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
// Proof size is dynamic based on log_n — use utils::expected_proof_fields(log_n)

pub use ec::{EcOps, SorobanEc};
pub use verifier::UltraHonkVerifier;

#[cfg(feature = "std")]
pub use ec::ArkEc;
