use crate::{field::Fr, types::G1Point};
use soroban_sdk::{
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr as Bn254Fr},
    BytesN, Env, Vec,
};

const RHS_G2_BYTES: [u8; 128] = [
    0x19, 0x8e, 0x93, 0x93, 0x92, 0x0d, 0x48, 0x3a, 0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d, 0x25,
    0xf1, 0xaa, 0x49, 0x33, 0x35, 0xa9, 0xe7, 0x12, 0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3, 0x12, 0xc2,
    0x18, 0x00, 0xde, 0xef, 0x12, 0x1f, 0x1e, 0x76, 0x42, 0x6a, 0x00, 0x66, 0x5e, 0x5c, 0x44, 0x79,
    0x67, 0x43, 0x22, 0xd4, 0xf7, 0x5e, 0xda, 0xdd, 0x46, 0xde, 0xbd, 0x5c, 0xd9, 0x92, 0xf6, 0xed,
    0x09, 0x06, 0x89, 0xd0, 0x58, 0x5f, 0xf0, 0x75, 0xec, 0x9e, 0x99, 0xad, 0x69, 0x0c, 0x33, 0x95,
    0xbc, 0x4b, 0x31, 0x33, 0x70, 0xb3, 0x8e, 0xf3, 0x55, 0xac, 0xda, 0xdc, 0xd1, 0x22, 0x97, 0x5b,
    0x12, 0xc8, 0x5e, 0xa5, 0xdb, 0x8c, 0x6d, 0xeb, 0x4a, 0xab, 0x71, 0x80, 0x8d, 0xcb, 0x40, 0x8f,
    0xe3, 0xd1, 0xe7, 0x69, 0x0c, 0x43, 0xd3, 0x7b, 0x4c, 0xe6, 0xcc, 0x01, 0x66, 0xfa, 0x7d, 0xaa,
];

const LHS_G2_BYTES: [u8; 128] = [
    0x26, 0x0e, 0x01, 0xb2, 0x51, 0xf6, 0xf1, 0xc7, 0xe7, 0xff, 0x4e, 0x58, 0x07, 0x91, 0xde, 0xe8,
    0xea, 0x51, 0xd8, 0x7a, 0x35, 0x8e, 0x03, 0x8b, 0x4e, 0xfe, 0x30, 0xfa, 0xc0, 0x93, 0x83, 0xc1,
    0x01, 0x18, 0xc4, 0xd5, 0xb8, 0x37, 0xbc, 0xc2, 0xbc, 0x89, 0xb5, 0xb3, 0x98, 0xb5, 0x97, 0x4e,
    0x9f, 0x59, 0x44, 0x07, 0x3b, 0x32, 0x07, 0x8b, 0x7e, 0x23, 0x1f, 0xec, 0x93, 0x88, 0x83, 0xb0,
    0x04, 0xfc, 0x63, 0x69, 0xf7, 0x11, 0x0f, 0xe3, 0xd2, 0x51, 0x56, 0xc1, 0xbb, 0x9a, 0x72, 0x85,
    0x9c, 0xf2, 0xa0, 0x46, 0x41, 0xf9, 0x9b, 0xa4, 0xee, 0x41, 0x3c, 0x80, 0xda, 0x6a, 0x5f, 0xe4,
    0x22, 0xfe, 0xbd, 0xa3, 0xc0, 0xc0, 0x63, 0x2a, 0x56, 0x47, 0x5b, 0x42, 0x14, 0xe5, 0x61, 0x5e,
    0x11, 0xe6, 0xdd, 0x3f, 0x96, 0xe6, 0xce, 0xa2, 0x85, 0x4a, 0x87, 0xd4, 0xda, 0xcc, 0x5e, 0x55,
];

// ---------------------------------------------------------------------------
// EcOps trait — abstracts BN254 elliptic curve operations
// ---------------------------------------------------------------------------

/// Trait abstracting BN254 G1 elliptic curve operations.
///
/// Two implementations are provided:
/// - `SorobanEc`: delegates to Soroban native host functions (Protocol 25)
/// - `ArkEc`: pure-Rust via arkworks (available behind `std` feature for testing)
pub trait EcOps {
    type G1: Clone;

    fn msm(&self, coms: &[G1Point], scalars: &[Fr]) -> Result<Self::G1, &'static str>;
    fn negate(&self, pt: &G1Point) -> Self::G1;
    fn pairing_check(&self, p0: &Self::G1, p1: &Self::G1) -> bool;
}

// ---------------------------------------------------------------------------
// Soroban backend — delegates to env.crypto().bn254()
// ---------------------------------------------------------------------------

pub struct SorobanEc<'a>(pub &'a Env);

#[inline(always)]
fn fr_to_bn254(env: &Env, fr: &Fr) -> Bn254Fr {
    Bn254Fr::from_bytes(BytesN::from_array(env, &fr.to_bytes()))
}

#[inline(always)]
fn g1_from_point(env: &Env, pt: &G1Point) -> Bn254G1Affine {
    Bn254G1Affine::from_array(env, &pt.to_bytes())
}

#[inline(always)]
fn rhs_g2_affine(env: &Env) -> Bn254G2Affine {
    Bn254G2Affine::from_array(env, &RHS_G2_BYTES)
}

#[inline(always)]
fn lhs_g2_affine(env: &Env) -> Bn254G2Affine {
    Bn254G2Affine::from_array(env, &LHS_G2_BYTES)
}

impl<'a> EcOps for SorobanEc<'a> {
    type G1 = Bn254G1Affine;

    #[inline(always)]
    fn msm(&self, coms: &[G1Point], scalars: &[Fr]) -> Result<Bn254G1Affine, &'static str> {
        if coms.len() != scalars.len() {
            return Err("msm len mismatch");
        }
        let bn = self.0.crypto().bn254();
        let mut acc = Bn254G1Affine::from_array(self.0, &G1Point::infinity().to_bytes());
        for (c, s) in coms.iter().zip(scalars.iter()) {
            if s.is_zero() {
                continue;
            }
            let p = g1_from_point(self.0, c);
            let scalar = fr_to_bn254(self.0, s);
            let term = bn.g1_mul(&p, &scalar);
            acc = bn.g1_add(&acc, &term);
        }
        Ok(acc)
    }

    #[inline(always)]
    fn negate(&self, pt: &G1Point) -> Bn254G1Affine {
        -g1_from_point(self.0, pt)
    }

    #[inline(always)]
    fn pairing_check(&self, p0: &Bn254G1Affine, p1: &Bn254G1Affine) -> bool {
        let mut g1s: Vec<Bn254G1Affine> = Vec::new(self.0);
        g1s.push_back(p0.clone());
        g1s.push_back(p1.clone());
        let mut g2s: Vec<Bn254G2Affine> = Vec::new(self.0);
        g2s.push_back(rhs_g2_affine(self.0));
        g2s.push_back(lhs_g2_affine(self.0));
        self.0.crypto().bn254().pairing_check(g1s, g2s)
    }
}

// ---------------------------------------------------------------------------
// Arkworks backend — pure-Rust, for testing without Soroban host functions
// ---------------------------------------------------------------------------

#[cfg(feature = "std")]
pub mod ark_backend {
    use super::*;
    use ark_bn254::{Bn254, G1Affine as ArkG1Affine, G1Projective, G2Affine as ArkG2Affine};
    use ark_ff::{PrimeField, Zero};
    use ark_ec::pairing::Pairing;
    use core::ops::Mul;

    pub struct ArkEc;

    fn ark_g1_from_point(pt: &G1Point) -> ArkG1Affine {
        let bytes = pt.to_bytes();
        // Check for point at infinity
        if bytes == [0u8; 64] {
            return ArkG1Affine::identity();
        }
        // BN254 coords are big-endian 32-byte each
        let mut x_le = [0u8; 32];
        let mut y_le = [0u8; 32];
        x_le.copy_from_slice(&bytes[..32]);
        x_le.reverse();
        y_le.copy_from_slice(&bytes[32..]);
        y_le.reverse();
        let x = ark_bn254::Fq::from_le_bytes_mod_order(&x_le);
        let y = ark_bn254::Fq::from_le_bytes_mod_order(&y_le);
        ArkG1Affine::new(x, y)
    }

    fn ark_g2_from_bytes(bytes: &[u8; 128]) -> ArkG2Affine {
        // G2 point: 4 x 32 bytes = (x_c0, x_c1, y_c0, y_c1) big-endian
        let mut buf = [0u8; 32];

        buf.copy_from_slice(&bytes[0..32]);
        buf.reverse();
        let x_c0 = ark_bn254::Fq::from_le_bytes_mod_order(&buf);

        buf.copy_from_slice(&bytes[32..64]);
        buf.reverse();
        let x_c1 = ark_bn254::Fq::from_le_bytes_mod_order(&buf);

        buf.copy_from_slice(&bytes[64..96]);
        buf.reverse();
        let y_c0 = ark_bn254::Fq::from_le_bytes_mod_order(&buf);

        buf.copy_from_slice(&bytes[96..128]);
        buf.reverse();
        let y_c1 = ark_bn254::Fq::from_le_bytes_mod_order(&buf);

        let x = ark_bn254::Fq2::new(x_c0, x_c1);
        let y = ark_bn254::Fq2::new(y_c0, y_c1);
        ArkG2Affine::new(x, y)
    }

    impl EcOps for ArkEc {
        type G1 = ArkG1Affine;

        fn msm(&self, coms: &[G1Point], scalars: &[Fr]) -> Result<ArkG1Affine, &'static str> {
            if coms.len() != scalars.len() {
                return Err("msm len mismatch");
            }
            let mut acc = G1Projective::from(ArkG1Affine::identity());
            for (c, s) in coms.iter().zip(scalars.iter()) {
                if s.is_zero() {
                    continue;
                }
                let p = ark_g1_from_point(c);
                let proj = G1Projective::from(p);
                acc = acc + proj.mul(s.0);
            }
            Ok(acc.into())
        }

        fn negate(&self, pt: &G1Point) -> ArkG1Affine {
            let p = ark_g1_from_point(pt);
            -p
        }

        fn pairing_check(&self, p0: &ArkG1Affine, p1: &ArkG1Affine) -> bool {
            let rhs_g2 = ark_g2_from_bytes(&RHS_G2_BYTES);
            let lhs_g2 = ark_g2_from_bytes(&LHS_G2_BYTES);
            let result = Bn254::multi_pairing(
                [*p0, *p1],
                [rhs_g2, lhs_g2],
            );
            result.is_zero()
        }
    }
}

#[cfg(feature = "std")]
pub use ark_backend::ArkEc;
