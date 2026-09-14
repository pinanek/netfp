pub(crate) fn random_byte() -> u8 {
    rand::random()
}

pub fn random_32_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    bytes
}
