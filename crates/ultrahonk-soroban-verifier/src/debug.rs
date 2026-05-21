#[cfg(feature = "std")]
use crate::field::Fr;
#[cfg(feature = "std")]
use crate::types::G1Point;

/// trace! macro is a lightweight debug print macro that only outputs when the `trace` feature is enabled.
/// you can use it like this: cargo test --features trace -- --nocapture / cargo run --features trace
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        #[cfg(all(feature = "trace", feature = "std"))]
        {
            println!($($arg)*);
        }
    };
}

/// Parse a 64-character lower-case hex string into `[u8; 32]`.
/// Panics on invalid input (intended for hard-coded test vectors only).
#[cfg(test)]
pub fn hex_to_bytes(hex: &str) -> [u8; 32] {
    fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid hex char"),
        }
    }
    let b = hex.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (nibble(b[i * 2]) << 4) | nibble(b[i * 2 + 1]);
    }
    out
}

/// Zero-allocation Display wrapper for formatting byte slices as lower-case hex.
pub struct Hex<'a>(pub &'a [u8]);

impl core::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for &b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// ark_bn254::Fr → BE fixed-width hex (0x + 64 nibbles)
#[cfg(feature = "std")]
#[inline(always)]
pub fn fr_to_hex(fr: &Fr) -> String {
    format!("0x{}", Hex(&fr.to_bytes()))
}

/// G1Point → (x_hex, y_hex)
#[cfg(feature = "std")]
#[inline(always)]
pub fn g1_to_hex(pt: &G1Point) -> (String, String) {
    let bytes = pt.0.to_array();
    (
        format!("0x{}", Hex(&bytes[..32])),
        format!("0x{}", Hex(&bytes[32..])),
    )
}

/// Outputs commitment/scalar pairs
#[allow(unused_variables)]
#[cfg(feature = "std")]
pub fn dump_pairs(coms: &[G1Point], scalars: &[Fr], head_tail: usize) {
    #[cfg(feature = "trace")]
    {
        assert_eq!(
            coms.len(),
            scalars.len(),
            "commitment / scalar length mismatch"
        );

        let len = coms.len();
        trace!("========= FULL LIST =========");
        for i in 0..len {
            if head_tail != usize::MAX && i >= head_tail && i < len - head_tail {
                if i == head_tail {
                    trace!("    ...");
                }
                continue;
            }
            let (x_hex, y_hex) = g1_to_hex(&coms[i]);
            let s_hex = fr_to_hex(&scalars[i]);
            trace!(
                "[#{:02}]  s = {:>66}  C.x = {:>66}  C.y = {:>66}",
                i,
                s_hex,
                x_hex,
                y_hex
            );
        }
        trace!("================================");
    }
    #[cfg(not(feature = "trace"))]
    {
        let _ = (coms, scalars, head_tail);
    }
}

/// Outputs a specific slice of commitment/scalar pairs, useful for
/// cross-checking against Solidity's first 40 entities (1..=40).
#[allow(dead_code)]
#[allow(unused_variables)]
#[cfg(feature = "std")]
pub fn dump_pairs_range(coms: &[G1Point], scalars: &[Fr], start: usize, end_inclusive: usize) {
    #[cfg(feature = "trace")]
    {
        assert_eq!(
            coms.len(),
            scalars.len(),
            "commitment / scalar length mismatch"
        );
        let end = end_inclusive.min(coms.len().saturating_sub(1));
        let start = start.min(end);
        trace!("========= RANGE LIST [{}..={}] =========", start, end);
        for i in start..=end {
            let (x_hex, y_hex) = g1_to_hex(&coms[i]);
            let s_hex = fr_to_hex(&scalars[i]);
            trace!(
                "[#{:02}]  s = {}  C.x = {}  C.y = {}",
                i,
                s_hex,
                x_hex,
                y_hex
            );
        }
        trace!("========================================");
    }
    #[cfg(not(feature = "trace"))]
    {
        let _ = (coms, scalars, start, end_inclusive);
    }
}

/// Debug Fr vector with hex output
#[inline(always)]
#[allow(unused_variables)]
#[cfg(feature = "std")]
pub fn dbg_vec(tag: &str, xs: &[Fr]) {
    #[cfg(feature = "trace")]
    {
        for (i, v) in xs.iter().enumerate() {
            trace!("{tag}[{i:02}] = 0x{}", Hex(&v.to_bytes()), tag = tag, i = i);
        }
    }
    #[cfg(not(feature = "trace"))]
    {
        let _ = (tag, xs);
    }
}

/// Debug Fr with hex output
#[inline(always)]
#[allow(unused_variables)]
#[cfg(feature = "std")]
pub fn dbg_fr(tag: &str, x: &Fr) {
    #[cfg(feature = "trace")]
    {
        trace!("{:<18}: 0x{}", tag, Hex(&x.to_bytes()));
    }
    #[cfg(not(feature = "trace"))]
    {
        let _ = (tag, x);
    }
}
