fn main(x: pub u32) {
    let mut sum: u32 = x;
    for _ in 0..50 {
        sum = sum ^ (sum << 1);
    }
    assert(sum != 0);
}
