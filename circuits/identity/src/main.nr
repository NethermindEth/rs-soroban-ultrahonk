use dep::poseidon::poseidon2::Poseidon2;

fn main(preimage: Field, hash: pub Field) {
    let computed_hash = Poseidon2::hash([preimage], 1);
    assert(computed_hash == hash);
}
