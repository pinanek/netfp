use crate::{
    error::Error,
    primitives::U24,
    tls::{HANDSHAKE_HEADER_LEN, TlsHandshakeType, TlsReader},
};

/// A borrowed TLS handshake message.
///
/// ```text
/// +----------------------------------+
/// | Handshake Type      1 byte       |
/// | Body Length         3 bytes      |
/// | Body                N bytes      |
/// +----------------------------------+
/// ```
pub struct TlsHandshake<'a> {
    handshake_type: TlsHandshakeType,
    body: &'a [u8],
}

impl<'a> TlsHandshake<'a> {
    /// Creates a handshake message that borrows `body`.
    pub const fn new(handshake_type: TlsHandshakeType, body: &'a [u8]) -> Self {
        Self {
            handshake_type,
            body,
        }
    }

    /// Parses the first complete TLS handshake message in `bytes`.
    ///
    /// The returned `usize` is the number of bytes consumed. Any remaining
    /// bytes may contain subsequent handshake messages.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if the header or declared body is
    /// incomplete. Returns [`Error::LengthOverflow`] if the total message
    /// length overflows `usize`.
    pub fn try_from_bytes(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        if bytes.len() < HANDSHAKE_HEADER_LEN {
            return Err(Error::UnexpectedEof {
                needed: HANDSHAKE_HEADER_LEN,
                remaining: bytes.len(),
            });
        }

        let mut reader = TlsReader::new(bytes);
        let handshake_type = TlsHandshakeType(reader.read_u8()?);
        let body_length = reader.read_u24()?;
        let message_length =
            HANDSHAKE_HEADER_LEN
                .checked_add(body_length)
                .ok_or(Error::LengthOverflow {
                    max: usize::MAX,
                    actual: usize::MAX,
                })?;

        if bytes.len() < message_length {
            return Err(Error::UnexpectedEof {
                needed: message_length,
                remaining: bytes.len(),
            });
        }

        Ok((
            Self {
                handshake_type,
                body: &bytes[HANDSHAKE_HEADER_LEN..message_length],
            },
            message_length,
        ))
    }

    /// Encodes this handshake message, including its four-byte header.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] if the body exceeds the maximum value
    /// representable by the 24-bit handshake length field.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, Error> {
        let body_length = U24::new(self.body.len())?;
        let mut bytes = Vec::with_capacity(HANDSHAKE_HEADER_LEN + self.body.len());
        bytes.push(self.handshake_type.as_u8());
        bytes.extend_from_slice(&body_length.to_be_bytes());
        bytes.extend_from_slice(self.body);
        Ok(bytes)
    }

    /// Returns the handshake message type.
    pub const fn handshake_type(&self) -> TlsHandshakeType {
        self.handshake_type
    }

    /// Returns the handshake body without its four-byte header.
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_round_trips_and_leaves_following_bytes() {
        let handshake = TlsHandshake::new(TlsHandshakeType::CLIENT_HELLO, &[1, 2, 3]);
        let mut encoded = handshake.try_to_bytes().unwrap();
        encoded.push(0xff);

        let (decoded, consumed) = TlsHandshake::try_from_bytes(&encoded).unwrap();
        assert_eq!(decoded.handshake_type(), TlsHandshakeType::CLIENT_HELLO);
        assert_eq!(decoded.body(), &[1, 2, 3]);
        assert_eq!(consumed, 7);
    }
}
