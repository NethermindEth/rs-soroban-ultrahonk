pub use soroban_sdk::crypto::bn254::Bn254Fr as ArkFr;

use core::ops::{Add, Mul, Neg, Sub};

use crate::env::Bn254FrGenerator;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fr(pub ArkFr);

impl Fr {
    /// Convert to 32-byte big-endian representation.
    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes().to_array()
    }

    pub fn inverse(&self) -> Self {
        Self(self.0.inv())
    }

    pub fn pow(&self, exp: u64) -> Self {
        Self(self.0.pow(exp))
    }

    pub fn is_zero(&self) -> bool {
        self == &self.0.env().zero()
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
        self.0.env().zero() - &self
    }
}

impl Neg for &Fr {
    type Output = Fr;
    fn neg(self) -> Fr {
        self.0.env().zero() - self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn batch_inverse_round_trip() {
        let env = Env::default();
        let inputs = [env.fr_from_u64(2), env.fr_from_u64(3), env.fr_from_u64(5)];
        let mut inverses = [env.zero(), env.zero(), env.zero()];
        batch_inverse(&inputs, &mut inverses).unwrap();

        for i in 0..3 {
            assert_eq!(&inputs[i] * &inverses[i], env.one());
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
        let inputs = [env.fr_from_u64(42)];
        let mut inverses = [env.zero()];
        batch_inverse(&inputs, &mut inverses).unwrap();
        assert_eq!(&inputs[0] * &inverses[0], env.one());
    }

    #[test]
    fn batch_inverse_all_equal() {
        let env = Env::default();
        let inputs = [env.fr_from_u64(7), env.fr_from_u64(7), env.fr_from_u64(7)];
        let mut inverses = [env.zero(), env.zero(), env.zero()];
        batch_inverse(&inputs, &mut inverses).unwrap();

        let expected_inv = env.fr_from_u64(7).inverse();
        for i in 0..3 {
            assert_eq!(inverses[i], expected_inv);
        }
    }

    #[test]
    fn hex_round_trip() {
        let env = Env::default();
        let hex_parts = [0, 0, 0, 0x1234567890abcdef];
        let fr = env.fr_from_parts(hex_parts[0], hex_parts[1], hex_parts[2], hex_parts[3]);
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
