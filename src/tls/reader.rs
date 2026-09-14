use crate::error::Error;

/// A bounds-checked reader for TLS wire-format data.
///
/// `TlsReader` advances through a borrowed byte slice and decodes unsigned
/// integers in network byte order. Reads never advance the cursor when there
/// is not enough input available.
///
/// # Examples
///
/// ```
/// use netfp::tls::TlsReader;
///
/// let mut reader = TlsReader::new(&[0x03, 0x03, 0x00, 0x05]);
/// assert_eq!(reader.read_u16()?, 0x0303);
/// assert_eq!(reader.read_u16()?, 5);
/// assert!(reader.is_empty());
/// # Ok::<(), netfp::Error>(())
/// ```
pub struct TlsReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> TlsReader<'a> {
    /// Creates a reader positioned at the beginning of `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Returns the number of unread bytes.
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    /// Returns `true` when no unread bytes remain.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Reads one unsigned byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if no byte remains.
    pub fn read_u8(&mut self) -> Result<u8, Error> {
        Ok(self.read_bytes(1)?[0])
    }

    /// Reads a big-endian 16-bit unsigned integer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if fewer than two bytes remain.
    pub fn read_u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.read_array::<2>()?))
    }

    /// Reads a big-endian 24-bit unsigned integer.
    ///
    /// TLS handshake message lengths use this three-byte representation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if fewer than three bytes remain.
    pub fn read_u24(&mut self) -> Result<usize, Error> {
        let bytes = self.read_array::<3>()?;

        Ok((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
    }

    /// Reads and returns the next `len` bytes without copying them.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if fewer than `len` bytes remain. The
    /// reader position is unchanged when this happens.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let remaining = self.remaining();

        if remaining < len {
            return Err(Error::UnexpectedEof {
                needed: len,
                remaining,
            });
        }

        let start = self.position;
        let end = start + len;

        self.position = end;

        Ok(&self.bytes[start..end])
    }

    /// Reads the next `N` bytes into a fixed-size array.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if fewer than `N` bytes remain. The
    /// reader position is unchanged when this happens.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let bytes = self.read_bytes(N)?;

        Ok(bytes
            .try_into()
            .expect("slice length must match requested array length"))
    }
}
