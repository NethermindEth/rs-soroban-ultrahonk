pub use soroban_sdk::crypto::bn254::Bn254Fr as ArkFr;

use core::array::repeat;
use core::ops::{Add, Mul, Neg, Sub};
use soroban_sdk::{Bytes, Env, U256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fr(pub ArkFr);

impl Fr {
    #[inline(always)]
    pub fn zero(env: &Env) -> Self {
        Self(ArkFr::from_u256(U256::from_u32(env, 0)))
    }

    #[inline(always)]
    pub fn one(env: &Env) -> Self {
        Self(ArkFr::from_u256(U256::from_u32(env, 1)))
    }

    #[inline(always)]
    pub fn zero_array<const N: usize>(env: &Env) -> [Self; N] {
        repeat(Self::zero(env))
    }

    #[inline(always)]
    pub fn from_u64(env: &Env, x: u64) -> Self {
        Self(ArkFr::from_u256(U256::from_u128(env, x as u128)))
    }

    #[inline(always)]
    pub fn from_array(env: &Env, value: &[u8; 32]) -> Self {
        Self(ArkFr::from_u256(U256::from_be_bytes(
            env,
            &Bytes::from_array(env, value),
        )))
    }

    #[inline(always)]
    pub fn from_parts(env: &Env, lolo: u64, lohi: u64, hilo: u64, hihi: u64) -> Self {
        Self(ArkFr::from_u256(U256::from_parts(
            env, lolo, lohi, hilo, hihi,
        )))
    }

    /// Precomputed NEG_HALF = (p - 1)/2 in BN254 scalar field.
    #[inline(always)]
    pub fn neg_half(env: &Env) -> Self {
        Self::from_parts(
            env,
            0x183227397098d014,
            0xdc2822db40c0ac2e,
            0x9419f4243cdcb848,
            0xa1f0fac9f8000000,
        )
    }

    /// Internal matrix diagonal values for Poseidon hash.
    #[inline(always)]
    pub fn internal_matrix_diagonal(env: &Env) -> [Self; 4] {
        [
            Self::from_parts(
                env,
                0x10dc6e9c006ea38b,
                0x04b1e03b4bd9490c,
                0x0d03f98929ca1d7f,
                0xb56821fd19d3b6e7,
            ),
            Self::from_parts(
                env,
                0x0c28145b6a44df3e,
                0x0149b3d0a30b3bb5,
                0x99df9756d4dd9b84,
                0xa86b38cfb45a740b,
            ),
            Self::from_parts(
                env,
                0x00544b8338791518,
                0xb2c7645a50392798,
                0xb21f75bb60e35961,
                0x70067d00141cac15,
            ),
            Self::from_parts(
                env,
                0x222c01175718386f,
                0x2e2e82eb122789e3,
                0x52e105a3b8fa8526,
                0x13bc534433ee428b,
            ),
        ]
    }

    /// Convert to 32-byte big-endian representation.
    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes().to_array()
    }

    #[inline(always)]
    pub fn inverse(&self) -> Self {
        Self(self.0.inv())
    }

    #[inline(always)]
    pub fn pow(&self, exp: u64) -> Self {
        Self(self.0.pow(exp))
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        *self.0.as_u256() == U256::from_u32(self.0.env(), 0)
    }
}

/// Montgomery batch inversion: compute all inverses of `vals[..n]` using a
/// single field inversion + 3*(n-1) multiplications, writing results into `out`.
/// Both `vals` and `out` must have the same length.
/// Returns an error if any element is zero (the product is non-invertible).
pub fn batch_inverse(vals: &[Fr], out: &mut [Fr]) -> Result<(), &'static str> {
    let n = vals.len();
    assert_eq!(n, out.len(), "batch_inverse: len mismatch");

    if n == 0 {
        return Ok(());
    }

    // 1) Build prefix products in `out`: out[i] = vals[0] * vals[1] * ... * vals[i]
    out[0] = vals[0].clone();
    for i in 1..n {
        out[i] = &out[i - 1] * &vals[i];
    }

    // 2) Invert the total product
    let mut inv_acc = out[n - 1].inverse();

    // 3) Sweep back to recover individual inverses
    for i in (1..n).rev() {
        out[i] = &inv_acc * &out[i - 1];
        inv_acc = inv_acc * &vals[i];
    }
    out[0] = inv_acc;
    Ok(())
}

impl Add for Fr {
    type Output = Fr;
    fn add(self, rhs: Fr) -> Fr {
        Fr(self.0 + rhs.0)
    }
}

impl Add<&Fr> for Fr {
    type Output = Fr;
    fn add(self, rhs: &Fr) -> Fr {
        Fr(self.0.env().crypto().bn254().fr_add(&self.0, &rhs.0))
    }
}

impl Add<Fr> for &Fr {
    type Output = Fr;
    fn add(self, rhs: Fr) -> Fr {
        Fr(self.0.env().crypto().bn254().fr_add(&self.0, &rhs.0))
    }
}

impl Add for &Fr {
    type Output = Fr;
    fn add(self, rhs: &Fr) -> Fr {
        Fr(self.0.env().crypto().bn254().fr_add(&self.0, &rhs.0))
    }
}

impl Sub for Fr {
    type Output = Fr;
    fn sub(self, rhs: Fr) -> Fr {
        Fr(self.0 - rhs.0)
    }
}

impl Sub<&Fr> for Fr {
    type Output = Fr;
    fn sub(self, rhs: &Fr) -> Fr {
        Fr(self.0.env().crypto().bn254().fr_sub(&self.0, &rhs.0))
    }
}

impl Sub<Fr> for &Fr {
    type Output = Fr;
    fn sub(self, rhs: Fr) -> Fr {
        Fr(self.0.env().crypto().bn254().fr_sub(&self.0, &rhs.0))
    }
}

impl Sub for &Fr {
    type Output = Fr;
    fn sub(self, rhs: &Fr) -> Fr {
        Fr(self.0.env().crypto().bn254().fr_sub(&self.0, &rhs.0))
    }
}

impl Mul for Fr {
    type Output = Fr;
    fn mul(self, rhs: Fr) -> Fr {
        Fr(self.0 * rhs.0)
    }
}

impl Mul<&Fr> for Fr {
    type Output = Fr;
    fn mul(self, rhs: &Fr) -> Fr {
        Fr(self.0.env().crypto().bn254().fr_mul(&self.0, &rhs.0))
    }
}

impl Mul<Fr> for &Fr {
    type Output = Fr;
    fn mul(self, rhs: Fr) -> Fr {
        Fr(self.0.env().crypto().bn254().fr_mul(&self.0, &rhs.0))
    }
}

impl Mul for &Fr {
    type Output = Fr;
    fn mul(self, rhs: &Fr) -> Fr {
        Fr(self.0.env().crypto().bn254().fr_mul(&self.0, &rhs.0))
    }
}

impl Neg for Fr {
    type Output = Fr;
    fn neg(self) -> Fr {
        Fr::zero(&self.0.env()) - &self
    }
}

impl Neg for &Fr {
    type Output = Fr;
    fn neg(self) -> Fr {
        Fr::zero(&self.0.env()) - self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn batch_inverse_round_trip() {
        let env = Env::default();
        let inputs = [
            Fr::from_u64(&env, 2),
            Fr::from_u64(&env, 3),
            Fr::from_u64(&env, 5),
        ];
        let mut inverses = [Fr::zero(&env), Fr::zero(&env), Fr::zero(&env)];
        batch_inverse(&inputs, &mut inverses).unwrap();

        for i in 0..3 {
            assert_eq!(&inputs[i] * &inverses[i], Fr::one(&env));
        }
    }

    #[test]
    fn batch_inverse_empty() {
        let inputs: [Fr; 0] = [];
        let mut inverses: [Fr; 0] = [];
        assert_eq!(batch_inverse(&inputs, &mut inverses), Ok(()));
    }

    #[test]
    fn batch_inverse_single() {
        let env = Env::default();
        let inputs = [Fr::from_u64(&env, 42)];
        let mut inverses = [Fr::zero(&env)];
        batch_inverse(&inputs, &mut inverses).unwrap();
        assert_eq!(&inputs[0] * &inverses[0], Fr::one(&env));
    }

    #[test]
    fn batch_inverse_all_equal() {
        let env = Env::default();
        let inputs = [
            Fr::from_u64(&env, 7),
            Fr::from_u64(&env, 7),
            Fr::from_u64(&env, 7),
        ];
        let mut inverses = [Fr::zero(&env), Fr::zero(&env), Fr::zero(&env)];
        batch_inverse(&inputs, &mut inverses).unwrap();

        let expected_inv = Fr::from_u64(&env, 7).inverse();
        for i in 0..3 {
            assert_eq!(inverses[i], expected_inv);
        }
    }

    #[test]
    fn hex_round_trip() {
        let env = Env::default();
        let hex_parts = [0, 0, 0, 0x1234567890abcdef];
        let fr = Fr::from_parts(&env, hex_parts[0], hex_parts[1], hex_parts[2], hex_parts[3]);
        let bytes = fr.to_bytes();

        #[cfg(not(feature = "std"))]
        use alloc::{format, string::String};
        #[cfg(feature = "std")]
        use std::{format, string::String};

        // Convert the last 8 bytes back to hex and compare
        let mut out_hex = String::from("0x");
        for b in &bytes[24..32] {
            out_hex.push_str(&format!("{:02x}", b));
        }
        assert_eq!(out_hex, "0x1234567890abcdef");
    }
}
