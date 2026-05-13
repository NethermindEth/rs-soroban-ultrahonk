fn main(x: pub u64) {
    let mut val = x;
    for _ in 0..100 {
        assert(val < 1000000);
        val = val + 1;
    }
}
