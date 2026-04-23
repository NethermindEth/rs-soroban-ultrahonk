use crate::field::Fr;
use core::array::repeat;
use soroban_sdk::Env;

pub trait Bn254FrGenerator {
    fn zero(&self) -> Fr;
    fn one(&self) -> Fr;
    fn zero_array<const N: usize>(&self) -> [Fr; N] {
        repeat(self.zero())
    }
}

impl Bn254FrGenerator for Env {
    fn zero(&self) -> Fr {
        Fr::zero()
    }

    fn one(&self) -> Fr {
        Fr::one()
    }
}
