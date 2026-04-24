use crate::field::{ArkFr, Fr};
use core::array::repeat;
use soroban_sdk::{Bytes, Env, U256};

pub trait Bn254FrGenerator {
    fn zero(&self) -> Fr;
    fn one(&self) -> Fr;
    fn zero_array<const N: usize>(&self) -> [Fr; N] {
        repeat(self.zero())
    }

    // TODO Remove
    fn fr_from_u64(&self, x: u64) -> Fr;

    fn fr_from_array(&self, value: &[u8; 32]) -> Fr;

    fn fr_from_parts(&self, lolo: u64, lohi: u64, hilo: u64, hihi: u64) -> Fr;

    /// Precomputed NEG_HALF = (p - 1)/2 in BN254 scalar field.
    fn neg_half(&self) -> Fr {
        self.fr_from_parts(
            0x183227397098d014,
            0xdc2822db40c0ac2e,
            0x9419f4243cdcb848,
            0xa1f0fac9f8000000,
        )
    }

    /// Internal matrix diagonal values for Poseidon hash
    fn internal_matrix_diagonal(&self) -> [Fr; 4] {
        [
            self.fr_from_parts(
                0x10dc6e9c006ea38b,
                0x04b1e03b4bd9490c,
                0x0d03f98929ca1d7f,
                0xb56821fd19d3b6e7,
            ),
            self.fr_from_parts(
                0x0c28145b6a44df3e,
                0x0149b3d0a30b3bb5,
                0x99df9756d4dd9b84,
                0xa86b38cfb45a740b,
            ),
            self.fr_from_parts(
                0x00544b8338791518,
                0xb2c7645a50392798,
                0xb21f75bb60e35961,
                0x70067d00141cac15,
            ),
            self.fr_from_parts(
                0x222c01175718386f,
                0x2e2e82eb122789e3,
                0x52e105a3b8fa8526,
                0x13bc534433ee428b,
            ),
        ]
    }
}

impl Bn254FrGenerator for Env {
    fn zero(&self) -> Fr {
        Fr(ArkFr::from_u256(U256::from_u32(self, 0)))
    }

    fn one(&self) -> Fr {
        Fr(ArkFr::from_u256(U256::from_u32(self, 1)))
    }

    fn fr_from_u64(&self, x: u64) -> Fr {
        Fr(ArkFr::from_u256(U256::from_u128(self, x as u128)))
    }

    fn fr_from_array(&self, value: &[u8; 32]) -> Fr {
        Fr(ArkFr::from_u256(U256::from_be_bytes(
            self,
            &Bytes::from_array(self, value),
        )))
    }

    fn fr_from_parts(&self, lolo: u64, lohi: u64, hilo: u64, hihi: u64) -> Fr {
        Fr(ArkFr::from_u256(U256::from_parts(
            self, lolo, lohi, hilo, hihi,
        )))
    }
}
