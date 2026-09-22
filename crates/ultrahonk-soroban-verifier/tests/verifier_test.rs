use soroban_sdk::{testutils::Ledger, Bytes, Env};
use std::{fs, path::Path};
use ultrahonk_soroban_verifier::UltraHonkVerifier;

fn run(dir: &str) -> Result<(), String> {
    let path = Path::new(dir);
    let env = Env::default();
    env.ledger().set_protocol_version(28);
    env.cost_estimate().budget().reset_unlimited();

    // Proof bytes
    let proof_bytes: Vec<u8> = fs::read(path.join("proof")).map_err(|e| e.to_string())?;
    let proof = Bytes::from_slice(&env, &proof_bytes);

    // Use binary VK
    let vk_bytes = fs::read(path.join("vk")).map_err(|e| e.to_string())?;
    let vk = Bytes::from_slice(&env, &vk_bytes);
    let verifier = UltraHonkVerifier::new(&env, &vk).map_err(|e| format!("{e:?}"))?;

    // Public inputs bytes
    let public_inputs = fs::read(path.join("public_inputs")).map_err(|e| e.to_string())?;
    let public_inputs = Bytes::from_slice(&env, &public_inputs);
    verifier
        .verify(&proof, &public_inputs)
        .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

#[test]
fn simple_circuit_proof_verifies() -> Result<(), String> {
    run("../../circuits/simple_circuit/target")
}

#[test]
fn fib_chain_proof_verifies() -> Result<(), String> {
    run("../../circuits/fib_chain/target")
}

// ---------------------------------------------------------------------------
// N-01: pin the fixed G2 constants.
//
// `LHS_G2_BYTES` was documented as the negated generator `-[1]_2` when it is in
// fact the SRS element `[x]_2`; the audit called that the riskiest item in N-01,
// because a contributor who trusted the old comment and substituted the "correct"
// -[1]_2 would silently change the pairing equation and break every proof in a way
// no comment fix can prevent.
//
// The comment is corrected, but a comment is not a constraint. These tests pin the
// bytes themselves: the G2 generator, its negation (which the SRS point is NOT),
// and the property that distinguishes them — negation preserves the x-coordinate,
// so a point whose x differs from the generator's cannot be its negation.
// ---------------------------------------------------------------------------

/// BN254 base field modulus p, big-endian.
const P_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

fn be32(b: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(b);
    o
}

/// Subtract big-endian 32-byte `b` from `a` (both < p). Used to compute p - y.
fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = a[i] as i16 - b[i] as i16 - borrow;
        if d < 0 {
            d += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = d as u8;
    }
    out
}

/// The two fixed G2 constants must remain distinct points, and the SRS element must
/// not be the negated generator. If someone "corrects" `LHS_G2_BYTES` to -[1]_2 this
/// test fails rather than the pairing silently changing meaning.
#[test]
fn g2_constants_are_distinct_points_not_negations() {
    // Byte layout per constant: x1 || x0 || y1 || y0, each 32 bytes big-endian.
    let gen = ultrahonk_soroban_verifier::ec::rhs_g2_bytes_for_test();
    let srs = ultrahonk_soroban_verifier::ec::lhs_g2_bytes_for_test();

    // Negation preserves x. If the SRS element were +/- the generator, its x would match.
    assert_ne!(
        gen[0..64],
        srs[0..64],
        "SRS G2 element must not share the generator's x-coordinate; if it did, it \
         could plausibly be +/-[1]_2 and the LHS_G2_BYTES label would be defensible"
    );

    // Explicitly: the SRS element is not the generator's negation.
    let neg_y1 = sub_be(&P_BE, &be32(&gen[64..96]));
    let neg_y0 = sub_be(&P_BE, &be32(&gen[96..128]));
    let is_negated_generator =
        gen[0..64] == srs[0..64] && srs[64..96] == neg_y1 && srs[96..128] == neg_y0;
    assert!(
        !is_negated_generator,
        "LHS_G2_BYTES must be the SRS element [x]_2, not the negated generator -[1]_2"
    );
}
