pub(crate) fn random_byte() -> u8 {
    rand::random()
}

/// Generates 32 random bytes using the thread-local random number generator.
pub fn random_32_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    bytes
}
