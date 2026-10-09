//! Transcript determinism test.
//!
//! Loads a known fixture and checks that the Fiat–Shamir challenges derived by
//! `generate_transcript` match hard-coded reference values produced by
//! Barretenberg for the same proof.

use soroban_sdk::{Bytes, Env};
use ultrahonk_soroban_verifier::transcript::generate_transcript;
use ultrahonk_soroban_verifier::utils::{load_proof, load_vk_from_bytes};
use ultrahonk_test_utils::Fixture;

/// Parse a 64-character lower-case hex string into `[u8; 32]`.
/// Panics on invalid input (intended for hard-coded test vectors only).
fn hex_to_bytes(hex: &str) -> [u8; 32] {
    fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid hex char"),
        }
    }
    let b = hex.as_bytes();
    assert_eq!(b.len(), 64, "expected 64 hex characters");
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (nibble(b[i * 2]) << 4) | nibble(b[i * 2 + 1]);
    }
    out
}

#[test]
fn transcript_determinism() {
    let env = Env::default();
    let f = Fixture::load("simple_circuit");
    let proof_bytes = Bytes::from_slice(&env, &f.proof);
    let vk_bytes = Bytes::from_slice(&env, &f.vk);
    let pi_bytes = Bytes::from_slice(&env, &f.public_inputs);

    let proof = load_proof(&env, &proof_bytes).unwrap();
    let vk = load_vk_from_bytes(&env, &vk_bytes).unwrap();

    let t = generate_transcript(
        &env,
        &proof,
        &pi_bytes,
        vk.circuit_size,
        vk.public_inputs_size,
        1, // pub_inputs_offset
    )
    .unwrap();

    assert_eq!(
        t.rel_params.eta.to_bytes(),
        hex_to_bytes("0000000000000000000000000000000085cff885ac2961fd2caf69da4ab04a55")
    );
    assert_eq!(
        t.rel_params.beta.to_bytes(),
        hex_to_bytes("00000000000000000000000000000000cf2d1a0f78861f5dfc916c1550073a26")
    );
    assert_eq!(
        t.rel_params.gamma.to_bytes(),
        hex_to_bytes("000000000000000000000000000000000b9a9dc0b29d2edaa5de654ffd600900")
    );
    assert_eq!(
        t.rho.to_bytes(),
        hex_to_bytes("00000000000000000000000000000000ddc594911e07b3b91b1afc817c04d331")
    );
    assert_eq!(
        t.shplonk_z.to_bytes(),
        hex_to_bytes("000000000000000000000000000000001c9e9d4cde5bde269eed51b980ab19fe")
    );
}
