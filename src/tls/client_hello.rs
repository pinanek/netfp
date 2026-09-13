use crate::{
    error::Error,
    primitives::U24,
    tls::{
        HANDSHAKE_HEADER_LEN, MAX_TLS_PLAINTEXT_LEN, TLS_RECORD_HEADER_LEN, TlsCipherSuite,
        TlsContentType, TlsExtension, TlsHandshakeType, TlsVersion,
    },
    utils::random_32_bytes,
};

/// A TLS `ClientHello` handshake message.
///
/// ```text
/// +-----------------------------------------------------+
/// | Content Type          1 byte    Handshake (0x16)    |
/// | Legacy Record Version 2 bytes                       |
/// | Record Length         2 bytes                       |
/// +-----------------------------------------------------+
/// | Handshake Message                                   |
/// |                                                     |
/// | +-------------------------------------------------+ |
/// | | Handshake Type      1 byte    ClientHello (0x01)| |
/// | | Handshake Length    3 bytes   (u24)             | |
/// | +-------------------------------------------------+ |
/// | | ClientHello                                     | |
/// | |                                                 | |
/// | | Legacy Version       2 bytes                    | |
/// | | Random              32 bytes                    | |
/// | |                                                 | |
/// | | Session ID Length    1 byte                     | |
/// | | Session ID           N bytes                    | |
/// | |                                                 | |
/// | | Cipher Suites Length 2 bytes                    | |
/// | | Cipher Suites        N x 2 bytes                | |
/// | |                                                 | |
/// | | Compression Length   1 byte                     | |
/// | | Compression Methods  N bytes                    | |
/// | |                                                 | |
/// | | Extensions Length    2 bytes                    | |
/// | |                                                 | |
/// | | +---------------------------------------------+ | |
/// | | | Extension                                   | | |
/// | | | +-----------------------------------------+ | | |
/// | | | | Type       2 bytes                      | | | |
/// | | | | Length     2 bytes                      | | | |
/// | | | | Data       N bytes                      | | | |
/// | | | +-----------------------------------------+ | | |
/// | | |                     ...                     | | |
/// | | +---------------------------------------------+ | |
/// | +-------------------------------------------------+ |
/// +-----------------------------------------------------+
/// ```
#[derive(Debug)]
pub struct TlsClientHello {
    tls_version: TlsVersion,
    record_version: TlsVersion,
    random: [u8; 32],
    session_id: [u8; 32],
    cipher_suites: Vec<TlsCipherSuite>,
    extensions: Vec<TlsExtension>,
}

impl TlsClientHello {
    /// Creates a new TLS `ClientHello`.
    ///
    /// The ClientHello random and legacy session ID are generated with the
    /// thread-local random number generator.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] if the cipher suite list exceeds
    /// the maximum size representable by TLS.
    pub fn new(
        version: TlsVersion,
        record_version: TlsVersion,
        cipher_suites: Vec<TlsCipherSuite>,
        extensions: Vec<TlsExtension>,
    ) -> Result<Self, Error> {
        if cipher_suites.is_empty() {
            return Err(Error::Malformed(
                "ClientHello must contain at least one cipher suite",
            ));
        }

        let cipher_suites_length =
            cipher_suites
                .len()
                .checked_mul(2)
                .ok_or(Error::LengthOverflow {
                    max: u16::MAX as usize,
                    actual: usize::MAX,
                })?;

        u16::try_from(cipher_suites_length).map_err(|_| Error::LengthOverflow {
            max: u16::MAX as usize,
            actual: cipher_suites_length,
        })?;

        Ok(Self {
            tls_version: version,
            record_version,
            random: random_32_bytes(),
            session_id: random_32_bytes(),
            cipher_suites,
            extensions,
        })
    }

    /// Encodes this `ClientHello` as a complete TLS record.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] if the handshake body or TLS record
    /// payload exceeds the maximum size supported by the corresponding TLS
    /// length field.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut hello_body = Vec::new();

        // Legacy version
        hello_body.extend_from_slice(&self.tls_version.legacy_version().to_be_bytes());

        // Random
        hello_body.extend_from_slice(&self.random);

        // Session id
        hello_body.push(self.session_id.len() as u8);
        hello_body.extend_from_slice(&self.session_id);

        // Cipher suites
        let cipher_suites_length = (self.cipher_suites.len() * 2) as u16;
        hello_body.extend_from_slice(&cipher_suites_length.to_be_bytes());

        for cipher_suite in &self.cipher_suites {
            hello_body.extend_from_slice(&cipher_suite.to_be_bytes());
        }

        // Legacy compression method
        hello_body.extend_from_slice(&[1, 0]);

        // Extensions
        let mut encoded_extensions = Vec::new();
        for extension in &self.extensions {
            encoded_extensions.extend_from_slice(&extension.to_bytes());
        }
        let extensions_length =
            u16::try_from(encoded_extensions.len()).map_err(|_| Error::LengthOverflow {
                max: u16::MAX as usize,
                actual: encoded_extensions.len(),
            })?;

        hello_body.extend_from_slice(&extensions_length.to_be_bytes());
        hello_body.extend_from_slice(&encoded_extensions);

        // Handshake message
        let hello_body_length = hello_body.len();
        let mut handshake_message = Vec::with_capacity(HANDSHAKE_HEADER_LEN + hello_body_length);
        let handshake_body_length = U24::new(hello_body_length)?;

        handshake_message.push(TlsHandshakeType::CLIENT_HELLO.as_u8());
        handshake_message.extend_from_slice(&handshake_body_length.to_be_bytes());
        handshake_message.extend_from_slice(&hello_body);

        // Record
        let handshake_message_length = handshake_message.len();
        if handshake_message_length > MAX_TLS_PLAINTEXT_LEN {
            return Err(Error::LengthOverflow {
                max: MAX_TLS_PLAINTEXT_LEN,
                actual: handshake_message_length,
            });
        }

        let mut encoded_record =
            Vec::with_capacity(TLS_RECORD_HEADER_LEN + handshake_message_length);
        let record_payload_length = handshake_message_length as u16;

        encoded_record.push(TlsContentType::HANDSHAKE.as_u8());
        encoded_record.extend_from_slice(&self.record_version.to_be_bytes());
        encoded_record.extend_from_slice(&record_payload_length.to_be_bytes());
        encoded_record.extend_from_slice(&handshake_message);

        Ok(encoded_record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::{TlsExtensionType, TlsReader, TlsRecord};

    #[test]
    fn encodes_a_complete_client_hello_record() {
        let extension = TlsExtension::new(TlsExtensionType::SERVER_NAME, vec![0, 1, 2]).unwrap();
        let hello = TlsClientHello::new(
            TlsVersion::TLS13,
            TlsVersion::TLS10,
            vec![TlsCipherSuite::TLS_AES_128_GCM_SHA256],
            vec![extension],
        )
        .unwrap();

        let encoded = hello.to_bytes().unwrap();
        let (record, consumed) = TlsRecord::try_from_bytes(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(record.content_type(), &TlsContentType::HANDSHAKE);
        assert_eq!(record.legacy_version(), &TlsVersion::TLS10);

        let mut handshake = TlsReader::new(record.payload());
        assert_eq!(
            handshake.read_u8().unwrap(),
            TlsHandshakeType::CLIENT_HELLO.as_u8()
        );
        assert_eq!(handshake.read_u24().unwrap(), handshake.remaining());
        assert_eq!(handshake.read_u16().unwrap(), TlsVersion::TLS12.as_u16());
        handshake.read_array::<32>().unwrap();
        assert_eq!(handshake.read_u8().unwrap(), 32);
        handshake.read_array::<32>().unwrap();
        assert_eq!(handshake.read_u16().unwrap(), 2);
        assert_eq!(
            handshake.read_u16().unwrap(),
            TlsCipherSuite::TLS_AES_128_GCM_SHA256.as_u16()
        );
        assert_eq!(handshake.read_bytes(2).unwrap(), &[1, 0]);
        assert_eq!(handshake.read_u16().unwrap(), 7);
        assert_eq!(
            handshake.read_u16().unwrap(),
            TlsExtensionType::SERVER_NAME.as_u16()
        );
        assert_eq!(handshake.read_u16().unwrap(), 3);
        assert_eq!(handshake.read_bytes(3).unwrap(), &[0, 1, 2]);
        assert!(handshake.is_empty());
    }

    #[test]
    fn rejects_an_empty_cipher_suite_list() {
        let error =
            TlsClientHello::new(TlsVersion::TLS12, TlsVersion::TLS12, vec![], vec![]).unwrap_err();

        assert!(matches!(error, Error::Malformed(_)));
    }
}
