use soroban_sdk::{Bytes, BytesN};

/// Compute Keccak-256 using the Soroban host function.
#[inline(always)]
pub fn hash32(data: &Bytes) -> BytesN<32> {
    data.env().crypto().keccak256(data).to_bytes()
}
