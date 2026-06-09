use core::array::repeat;
use core::ops::{Add, Mul, Neg, Sub};
use soroban_sdk::{bytesn, crypto::bn254::Bn254Fr, BytesN, Env, U256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fr(pub Bn254Fr);

impl Fr {
    #[inline(always)]
    pub fn zero(env: &Env) -> Self {
        Self(Bn254Fr::from_u256(U256::from_u32(env, 0)))
    }

    #[inline(always)]
    pub fn one(env: &Env) -> Self {
        Self(Bn254Fr::from_u256(U256::from_u32(env, 1)))
    }

    #[inline(always)]
    pub fn zero_array<const N: usize>(env: &Env) -> [Self; N] {
        repeat(Self::zero(env))
    }

    #[inline(always)]
    pub fn from_u64(env: &Env, x: u64) -> Self {
        Self(Bn254Fr::from_u256(U256::from_u128(env, x as u128)))
    }

    #[inline(always)]
    pub fn from_array(env: &Env, value: &[u8; 32]) -> Self {
        Self(Bn254Fr::from_bytes(BytesN::from_array(env, value)))
    }

    /// Precomputed NEG_HALF = (p - 1)/2 in BN254 scalar field.
    #[inline(always)]
    pub fn neg_half(env: &Env) -> Self {
        Self(Bn254Fr::from_bytes(bytesn!(
            &env,
            0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000
        )))
    }

    #[inline(always)]
    pub fn minus_one(env: &Env) -> Self {
        Self(Bn254Fr::from_bytes(bytesn!(
            &env,
            0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
        )))
    }

    #[inline(always)]
    pub fn minus_two(env: &Env) -> Self {
        Self(Bn254Fr::from_bytes(bytesn!(
            &env,
            0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffff
        )))
    }

    #[inline(always)]
    pub fn minus_three(env: &Env) -> Self {
        Self(Bn254Fr::from_bytes(bytesn!(
            &env,
            0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffffe
        )))
    }

    /// Internal matrix diagonal values for Poseidon hash.
    #[inline(always)]
    pub fn internal_matrix_diagonal(env: &Env) -> [Self; 4] {
        [
            Self(Bn254Fr::from_bytes(bytesn!(
                &env,
                0x10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7
            ))),
            Self(Bn254Fr::from_bytes(bytesn!(
                &env,
                0x0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b
            ))),
            Self(Bn254Fr::from_bytes(bytesn!(
                &env,
                0x00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15
            ))),
            Self(Bn254Fr::from_bytes(bytesn!(
                &env,
                0x222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b
            ))),
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
    if out[n - 1].is_zero() {
        return Err("denominator is zero");
    }
    let mut inv_acc = out[n - 1].inverse();

    // 3) Sweep back to recover individual inverses
    for i in (1..n).rev() {
        out[i] = &inv_acc * &out[i - 1];
        inv_acc = inv_acc * &vals[i];
    }
    out[0] = inv_acc;
    Ok(())
}

macro_rules! binop_fr {
    ($trait:ident, $method:ident, $host_fn:ident, $op:tt) => {
        impl $trait for Fr {
            type Output = Fr;

            fn $method(self, rhs: Fr) -> Fr {
                Fr(self.0 $op rhs.0)
            }
        }

        impl $trait<&Fr> for Fr {
            type Output = Fr;

            fn $method(self, rhs: &Fr) -> Fr {
                Fr(self.0.env().crypto().bn254().$host_fn(&self.0, &rhs.0))
            }
        }

        impl $trait<Fr> for &Fr {
            type Output = Fr;

            fn $method(self, rhs: Fr) -> Fr {
                Fr(self.0.env().crypto().bn254().$host_fn(&self.0, &rhs.0))
            }
        }

        impl $trait for &Fr {
            type Output = Fr;

            fn $method(self, rhs: &Fr) -> Fr {
                Fr(self.0.env().crypto().bn254().$host_fn(&self.0, &rhs.0))
            }
        }
    };
}

binop_fr!(Add, add, fr_add, +);
binop_fr!(Sub, sub, fr_sub, -);
binop_fr!(Mul, mul, fr_mul, *);

impl Neg for Fr {
    type Output = Fr;
    fn neg(self) -> Fr {
        Fr::zero(self.0.env()) - &self
    }
}

impl Neg for &Fr {
    type Output = Fr;
    fn neg(self) -> Fr {
        Fr::zero(self.0.env()) - self
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
        for inverse in inverses {
            assert_eq!(inverse, expected_inv);
        }
    }

    #[test]
    fn batch_inverse_zero_element() {
        let env = Env::default();
        let inputs = [Fr::from_u64(&env, 2), Fr::zero(&env), Fr::from_u64(&env, 5)];
        let mut inverses = [Fr::zero(&env), Fr::zero(&env), Fr::zero(&env)];
        assert_eq!(
            batch_inverse(&inputs, &mut inverses),
            Err("denominator is zero")
        );
    }

    #[test]
    fn hex_round_trip() {
        let env = Env::default();
        let fr = Fr(Bn254Fr::from_bytes(bytesn!(
            &env,
            0x0000000000000000000000000000000000000000000000001234567890abcdef
        )));
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
