//! Integer types used by network protocol length fields.

use crate::error::Error;

/// An unsigned 24-bit integer, encoded in network byte order.
///
/// ```
/// use netfp::primitives::U24;
///
/// assert_eq!(U24::new(0x01_02_03)?.to_be_bytes(), [1, 2, 3]);
/// assert!(U24::new(U24::MAX + 1).is_err());
/// # Ok::<(), netfp::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct U24(usize);

impl U24 {
    /// Largest representable value: `0xFF_FFFF`.
    pub const MAX: usize = (1 << 24) - 1;

    /// Creates a new 24-bit unsigned integer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] if `value` exceeds `0xFF_FFFF`.
    pub const fn new(value: usize) -> Result<Self, Error> {
        if value > Self::MAX {
            return Err(Error::LengthOverflow {
                max: Self::MAX,
                actual: value,
            });
        }

        Ok(Self(value))
    }

    /// Returns the value encoded as three bytes in network byte order.
    pub const fn to_be_bytes(self) -> [u8; 3] {
        [(self.0 >> 16) as u8, (self.0 >> 8) as u8, self.0 as u8]
    }
}
