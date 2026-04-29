//! Shared test utilities for the UltraHonk workspace.
//!
//! Provides [`Fixture`] for loading circuit artifacts from `/circuits/<name>/target/`
//! and helpers for creating negative-test inputs.

use soroban_sdk::{Bytes, Env};
use std::{fs, path::PathBuf};

/// A loaded set of circuit artifacts (proof, verification key, public inputs).
pub struct Fixture {
    pub proof: Vec<u8>,
    pub vk: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

impl Fixture {
    /// Loads a circuit's built artifacts.
    ///
    /// `name` must match a directory under the top-level `circuits/` directory
    /// (e.g. `"simple_circuit"`, `"fib_chain"`).
    pub fn load(name: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../circuits")
            .join(name)
            .join("target");
        Self {
            proof: fs::read(root.join("proof")).expect("missing proof"),
            vk: fs::read(root.join("vk")).expect("missing vk"),
            public_inputs: fs::read(root.join("public_inputs")).expect("missing public_inputs"),
        }
    }

    /// Converts the raw byte vectors into Soroban `Bytes` values.
    pub fn into_bytes(self, env: &Env) -> (Bytes, Bytes, Bytes) {
        (
            Bytes::from_slice(env, &self.proof),
            Bytes::from_slice(env, &self.vk),
            Bytes::from_slice(env, &self.public_inputs),
        )
    }
}

/// Returns a copy of `bytes` with the byte at `offset` XOR'd by `mask`.
///
/// Useful for deterministic, single-byte proof/VK/public-input mutations in
/// negative tests.
///
/// # Panics
///
/// Panics if `offset >= bytes.len()`.
pub fn mutate_byte(bytes: &[u8], offset: usize, mask: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[offset] ^= mask;
    out
}

/// Returns a copy of `bytes` truncated to `len` bytes.
///
/// Useful for testing how the verifier handles short/malformed inputs.
///
/// # Panics
///
/// Panics if `len > bytes.len()`.
pub fn truncate(bytes: &[u8], len: usize) -> Vec<u8> {
    bytes[..len].to_vec()
}
