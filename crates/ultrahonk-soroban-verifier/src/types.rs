//! Core type definitions for the UltraHonk verifier.
//!
//! `VerificationKey`, `Proof`, `Transcript`, and `RelationParameters` layouts
//! are derived from Barretenberg `UltraFlavor` v0.82.2.
//!
//! BB reference: `barretenberg/flavor/ultra_flavor.hpp`

use crate::field::Fr;
use soroban_sdk::crypto::bn254::Bn254G1Affine;
use soroban_sdk::Env;

pub const CONST_PROOF_SIZE_LOG_N: usize = 28;
pub const NUMBER_OF_SUBRELATIONS: usize = 26;
pub const BATCHED_RELATION_PARTIAL_LENGTH: usize = 8;
pub const NUMBER_OF_ENTITIES: usize = 40;
pub const NUMBER_UNSHIFTED: usize = 35;
pub const NUMBER_TO_BE_SHIFTED: usize = 5;
pub const PAIRING_POINTS_SIZE: usize = 16;
pub const NUMBER_OF_ALPHAS: usize = NUMBER_OF_SUBRELATIONS - 1;

/// Wire indices for the UltraHonk protocol.
///
/// Maps every polynomial entity (selectors, sigmas, IDs, tables, witness wires,
/// shifted wires) to its position in the `AllEntities` tuple.  Indices 0–34 are
/// unshifted; 35–39 are the shifted counterparts of `Wl`, `Wr`, `Wo`, `W4`, `ZPerm`.
///
/// BB: `flavor/ultra_flavor.hpp::AllEntities` / `CommitmentLabels`
#[derive(Copy, Clone, Debug)]
pub enum Wire {
    Qm = 0,
    Qc = 1,
    Ql = 2,
    Qr = 3,
    Qo = 4,
    Q4 = 5,
    QLookup = 6,
    QArith = 7,
    QRange = 8,
    QElliptic = 9,
    QAux = 10,
    QPoseidon2External = 11,
    QPoseidon2Internal = 12,
    Sigma1 = 13,
    Sigma2 = 14,
    Sigma3 = 15,
    Sigma4 = 16,
    Id1 = 17,
    Id2 = 18,
    Id3 = 19,
    Id4 = 20,
    Table1 = 21,
    Table2 = 22,
    Table3 = 23,
    Table4 = 24,
    LagrangeFirst = 25,
    LagrangeLast = 26,
    Wl = 27,
    Wr = 28,
    Wo = 29,
    W4 = 30,
    ZPerm = 31,
    LookupInverses = 32,
    LookupReadCounts = 33,
    LookupReadTags = 34,
    WlShift = 35,
    WrShift = 36,
    WoShift = 37,
    W4Shift = 38,
    ZPermShift = 39,
}

impl Wire {
    pub fn index(&self) -> usize {
        *self as usize
    }
}

/// A BN254 G1 point in affine coordinates.
///
/// Thin wrapper around the Soroban host type `Bn254G1Affine`.
///
/// BB: `curve::BN254::AffineElement`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct G1Point(pub Bn254G1Affine);

impl G1Point {
    #[inline(always)]
    pub fn as_bn254(&self) -> &Bn254G1Affine {
        &self.0
    }

    pub fn from_xy(env: &Env, x: &[u8; 32], y: &[u8; 32]) -> Self {
        let mut bytes: [u8; 64] = [0u8; 64];
        bytes[..32].copy_from_slice(x);
        bytes[32..].copy_from_slice(y);
        Self::from_bytes(env, &bytes)
    }

    #[inline(always)]
    pub fn from_bytes(env: &Env, bytes: &[u8; 64]) -> Self {
        G1Point(Bn254G1Affine::from_array(env, bytes))
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_array()
    }

    #[inline(always)]
    pub fn infinity(env: &Env) -> Self {
        G1Point(Bn254G1Affine::from_array(env, &[0u8; 64]))
    }

    pub fn generator(env: &Env) -> Self {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x[31] = 1;
        y[31] = 2;
        G1Point::from_xy(env, &x, &y)
    }
}

/// Verification key for UltraHonk circuits.
///
/// Header: 4 big-endian `u64` fields (`circuit_size`, `log_circuit_size`,
/// `public_inputs_size`, `pub_inputs_offset`) followed by 27 G1 commitments
/// (64 bytes each) in `PrecomputedEntities` order.
///
/// BB: `flavor/ultra_flavor.hpp::VerificationKey_`
#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub circuit_size: u64,
    pub log_circuit_size: u64,
    pub public_inputs_size: u64,
    pub pub_inputs_offset: u64,
    // Selectors and wire commitments:
    pub qm: G1Point,
    pub qc: G1Point,
    pub ql: G1Point,
    pub qr: G1Point,
    pub qo: G1Point,
    pub q4: G1Point,
    pub q_lookup: G1Point,
    pub q_arith: G1Point,
    pub q_delta_range: G1Point,
    pub q_elliptic: G1Point,
    pub q_aux: G1Point,
    pub q_poseidon2_external: G1Point,
    pub q_poseidon2_internal: G1Point,
    // Copy constraints:
    pub s1: G1Point,
    pub s2: G1Point,
    pub s3: G1Point,
    pub s4: G1Point,
    pub id1: G1Point,
    pub id2: G1Point,
    pub id3: G1Point,
    pub id4: G1Point,
    // Lookup table commitments:
    pub t1: G1Point,
    pub t2: G1Point,
    pub t3: G1Point,
    pub t4: G1Point,
    // Fixed first/last
    pub lagrange_first: G1Point,
    pub lagrange_last: G1Point,
}

/// UltraHonk proof structure.
///
/// Fixed-size layout (14 592 bytes = `PROOF_BYTES`):
/// - 16 Fr elements (pairing point object)
/// - 8 G1 commitments (wire + lookup)
/// - 28 × 8 Fr elements (sumcheck univariates)
/// - 40 Fr elements (sumcheck evaluations)
/// - 27 G1 commitments (Gemini fold)
/// - 28 Fr elements (Gemini fold evaluations)
/// - 2 G1 commitments (Shplonk Q + KZG quotient)
///
/// BB: `flavor/ultra_flavor.hpp::Proof`
#[derive(Clone, Debug)]
pub struct Proof {
    // Pairing point object (16 Fr elements)
    pub pairing_point_object: [Fr; PAIRING_POINTS_SIZE],
    // Wire commitments
    pub w1: G1Point,
    pub w2: G1Point,
    pub w3: G1Point,
    pub w4: G1Point,
    // Lookup helpers
    pub lookup_read_counts: G1Point,
    pub lookup_read_tags: G1Point,
    pub lookup_inverses: G1Point,
    pub z_perm: G1Point,
    // Sumcheck polynomials
    pub sumcheck_univariates: [[Fr; BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N],
    pub sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES],
    // Gemini fold commitments
    pub gemini_fold_comms: [G1Point; CONST_PROOF_SIZE_LOG_N - 1],
    pub gemini_a_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N],
    // Shplonk
    pub shplonk_q: G1Point,
    pub kzg_quotient: G1Point,
}

/// Relation parameters used by all subrelation accumulators.
///
/// BB: `relations/relation_parameters.hpp::RelationParameters`
#[derive(Clone, Debug)]
pub struct RelationParameters {
    pub eta: Fr,
    pub eta_two: Fr,
    pub eta_three: Fr,
    pub beta: Fr,
    pub gamma: Fr,
    pub public_inputs_delta: Fr,
}

/// Container for all Fiat–Shamir challenges derived by the transcript.
///
/// BB: Fields are scattered across `DeciderVerificationKey_` and the
///      transcript itself in the C++ codebase.
#[derive(Clone, Debug)]
pub struct Transcript {
    pub rel_params: RelationParameters,
    pub alphas: [Fr; NUMBER_OF_ALPHAS],
    pub gate_challenges: [Fr; CONST_PROOF_SIZE_LOG_N],
    pub sumcheck_u_challenges: [Fr; CONST_PROOF_SIZE_LOG_N],
    pub rho: Fr,
    pub gemini_r: Fr,
    pub shplonk_nu: Fr,
    pub shplonk_z: Fr,
}
