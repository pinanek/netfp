use crate::{
    error::Error,
    tls::{TLS_RECORD_HEADER_LEN, TlsContentType, TlsReader, TlsVersion},
};

/// A borrowed TLS record.
///
/// ```text
/// +--------------------------------------------------+
/// | Content Type           1 byte                    |
/// | Legacy Record Version  2 bytes                   |
/// | Payload Length         2 bytes                   |
/// +--------------------------------------------------+
/// | Payload                N bytes                   |
/// +--------------------------------------------------+
/// ```
///
/// The payload borrows from the encoded input, so parsing a record does not
/// allocate or copy its contents.
///
/// # Examples
///
/// ```
/// use netfp::tls::{TlsContentType, TlsRecord, TlsVersion};
///
/// let bytes = [0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
/// let (record, consumed) = TlsRecord::try_from_bytes(&bytes)?;
///
/// assert_eq!(record.content_type(), &TlsContentType::HANDSHAKE);
/// assert_eq!(record.legacy_version(), &TlsVersion::TLS12);
/// assert_eq!(record.payload(), &[0x01, 0x00]);
/// assert_eq!(consumed, bytes.len());
/// # Ok::<(), netfp::Error>(())
/// ```
pub struct TlsRecord<'a> {
    content_type: TlsContentType,
    legacy_version: TlsVersion,
    payload: &'a [u8],
}

impl<'a> TlsRecord<'a> {
    /// Parses the first complete TLS record in `bytes`.
    ///
    /// The returned `usize` is the number of bytes consumed by the record.
    /// Any bytes after that offset belong to subsequent records and are not
    /// inspected.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] when the record header is incomplete or
    /// the declared payload is not fully available. Returns
    /// [`Error::LengthOverflow`] if the calculated record length overflows
    /// `usize`.
    pub fn try_from_bytes(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        if bytes.len() < TLS_RECORD_HEADER_LEN {
            return Err(Error::UnexpectedEof {
                needed: TLS_RECORD_HEADER_LEN,
                remaining: bytes.len(),
            });
        }

        let mut reader = TlsReader::new(bytes);

        let content_type = TlsContentType(reader.read_u8()?);

        let legacy_version = TlsVersion(reader.read_u16()?);

        let payload_len = usize::from(reader.read_u16()?);

        let record_len =
            TLS_RECORD_HEADER_LEN
                .checked_add(payload_len)
                .ok_or(Error::LengthOverflow {
                    max: usize::MAX,
                    actual: usize::MAX,
                })?;

        if bytes.len() < record_len {
            return Err(Error::UnexpectedEof {
                needed: record_len,
                remaining: bytes.len(),
            });
        }

        let payload = &bytes[TLS_RECORD_HEADER_LEN..record_len];

        Ok((
            Self {
                content_type,
                legacy_version,
                payload,
            },
            record_len,
        ))
    }

    /// Returns the record content type.
    pub fn content_type(&self) -> &TlsContentType {
        &self.content_type
    }

    /// Returns the legacy record-layer TLS version.
    pub fn legacy_version(&self) -> &TlsVersion {
        &self.legacy_version
    }

    /// Returns the record payload without its five-byte header.
    pub fn payload(&self) -> &[u8] {
        self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_the_first_record() {
        let bytes = [0x16, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb, 0xff, 0xff];
        let (record, consumed) = TlsRecord::try_from_bytes(&bytes).unwrap();

        assert_eq!(record.content_type(), &TlsContentType::HANDSHAKE);
        assert_eq!(record.legacy_version(), &TlsVersion::TLS12);
        assert_eq!(record.payload(), &[0xaa, 0xbb]);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn rejects_an_incomplete_header() {
        let error = TlsRecord::try_from_bytes(&[0x16, 0x03]).err().unwrap();

        assert!(matches!(
            error,
            Error::UnexpectedEof {
                needed: TLS_RECORD_HEADER_LEN,
                remaining: 2
            }
        ));
    }

    #[test]
    fn rejects_an_incomplete_payload() {
        let error = TlsRecord::try_from_bytes(&[0x16, 0x03, 0x03, 0x00, 0x03, 0xaa])
            .err()
            .unwrap();

        assert!(matches!(
            error,
            Error::UnexpectedEof {
                needed: 8,
                remaining: 6
            }
        ));
    }
}
