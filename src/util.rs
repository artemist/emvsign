pub fn left_pad_slice<const LEN: usize>(slice: &[u8]) -> [u8; LEN] {
    let mut s = [0; LEN];
    s[LEN - slice.len()..].copy_from_slice(slice);
    s
}
