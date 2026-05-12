use ark_bn254::Fr as ArkFr;
use ark_ff::BigInteger256;
use ark_ff::{Field, PrimeField, Zero};
use core::ops::{Add, Mul, Neg, Sub};
use hex;

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, string::String};

#[inline(always)]
fn normalize_hex(s: &str) -> String {
    let raw = s.trim_start_matches("0x");
    if raw.len() & 1 == 1 {
        let mut out = String::with_capacity(raw.len() + 1);
        out.push('0');
        out.push_str(raw);
        out
    } else {
        raw.to_owned()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fr(pub ArkFr);

impl Fr {
    /// Construct from u64.
    pub fn from_u64(x: u64) -> Self {
        Fr(ArkFr::from(x))
    }

    /// Construct from hex string (with or without 0x prefix).
    /// Normalize to even digits before `hex::decode` so OddLength exception won't occur.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        let bytes = hex::decode(normalize_hex(s)).expect("hex decode failed");
        let mut padded = [0u8; 32];
        let offset = 32 - bytes.len();
        padded[offset..].copy_from_slice(&bytes);
        Self::from_bytes(&padded)
    }

    /// Construct from a 32-byte big-endian array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        // ark-ff takes LE (little-endian) so BE → LE
        let mut tmp = *bytes;
        tmp.reverse();
        Fr(ArkFr::from_le_bytes_mod_order(&tmp))
    }

    /// Convert to 32-byte big-endian representation.
    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 32] {
        let bi: BigInteger256 = self.0.into_bigint();
        let mut out = [0u8; 32];
        for (i, limb) in bi.0.iter().rev().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    pub fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(Fr)
    }

    pub fn zero() -> Self {
        Fr(ArkFr::zero())
    }

    pub fn one() -> Self {
        Fr(ArkFr::ONE)
    }

    pub fn pow(&self, exp: u128) -> Self {
        let mut bits = [0u64; 4];
        bits[0] = exp as u64;
        Fr(self.0.pow(bits))
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
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
    out[0] = vals[0];
    for i in 1..n {
        out[i] = out[i - 1] * vals[i];
    }

    // 2) Invert the total product
    let mut inv_acc = out[n - 1]
        .inverse()
        .ok_or("batch_inverse: product is zero (at least one input element is zero)")?;

    // 3) Sweep back to recover individual inverses
    for i in (1..n).rev() {
        out[i] = inv_acc * out[i - 1];
        inv_acc = inv_acc * vals[i];
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

impl Sub for Fr {
    type Output = Fr;
    fn sub(self, rhs: Fr) -> Fr {
        Fr(self.0 - rhs.0)
    }
}

impl Mul for Fr {
    type Output = Fr;
    fn mul(self, rhs: Fr) -> Fr {
        Fr(self.0 * rhs.0)
    }
}

impl Neg for Fr {
    type Output = Fr;
    fn neg(self) -> Fr {
        Fr(-self.0)
    }
}
