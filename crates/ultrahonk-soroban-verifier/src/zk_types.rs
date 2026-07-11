//! Types specific to Barretenberg v0.87 `UltraKeccakZKFlavor` proofs.

use crate::field::Fr;
use crate::types::{
    G1Point, RelationParameters, CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ALPHAS, NUMBER_OF_ENTITIES,
    PAIRING_POINTS_SIZE,
};

/// ZK sumcheck univariates have one more evaluation than the non-ZK flavor.
pub const ZK_BATCHED_RELATION_PARTIAL_LENGTH: usize = 9;
pub const NUM_LIBRA_COMMITMENTS: usize = 3;
pub const NUM_LIBRA_EVALUATIONS: usize = 4;
pub const LIBRA_SUBGROUP_SIZE: usize = 256;

/// A fixed-size UltraKeccakZK proof as emitted by Barretenberg v0.87.0.
#[derive(Clone, Debug)]
pub struct ZkProof {
    pub pairing_point_object: [Fr; PAIRING_POINTS_SIZE],

    pub w1: G1Point,
    pub w2: G1Point,
    pub w3: G1Point,
    pub w4: G1Point,
    pub lookup_read_counts: G1Point,
    pub lookup_read_tags: G1Point,
    pub lookup_inverses: G1Point,
    pub z_perm: G1Point,

    /// Commitment to the concatenated Libra masking univariates.
    pub libra_concatenation_commitment: G1Point,
    pub libra_sum: Fr,

    pub sumcheck_univariates: [[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N],
    pub sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES],
    pub libra_evaluation: Fr,

    pub libra_grand_sum_commitment: G1Point,
    pub libra_quotient_commitment: G1Point,
    pub gemini_masking_polynomial: G1Point,
    pub gemini_masking_evaluation: Fr,

    pub gemini_fold_comms: [G1Point; CONST_PROOF_SIZE_LOG_N - 1],
    pub gemini_a_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N],
    /// Concatenation(r), grand-sum(g*r), grand-sum(r), quotient(r).
    pub libra_poly_evaluations: [Fr; NUM_LIBRA_EVALUATIONS],

    pub shplonk_q: G1Point,
    pub kzg_quotient: G1Point,
}

/// Fiat-Shamir challenges for an UltraKeccakZK proof.
#[derive(Clone, Debug)]
pub struct ZkTranscript {
    pub rel_params: RelationParameters,
    pub alphas: [Fr; NUMBER_OF_ALPHAS],
    pub gate_challenges: [Fr; CONST_PROOF_SIZE_LOG_N],
    pub libra_challenge: Fr,
    pub sumcheck_u_challenges: [Fr; CONST_PROOF_SIZE_LOG_N],
    pub rho: Fr,
    pub gemini_r: Fr,
    pub shplonk_nu: Fr,
    pub shplonk_z: Fr,
}
