use crate::{
    error::Error,
    tls::{
        TlsCipherSuite, TlsContentType, TlsExtension, TlsExtensionType, TlsHandshake,
        TlsHandshakeType, TlsReader, TlsRecord, TlsVersion,
    },
};

/// Incrementally decodes a TLS `ServerHello` from raw bytes or parsed records.
///
/// The decoder buffers incomplete TLS records and handshake fragments across
/// calls.
#[derive(Debug)]
pub struct ServerHelloDecoder {
    record_buffer: Vec<u8>,
    handshake_buffer: Vec<u8>,
}

impl Default for ServerHelloDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerHelloDecoder {
    /// Creates an empty decoder.
    pub fn new() -> Self {
        Self {
            record_buffer: Vec::new(),
            handshake_buffer: Vec::new(),
        }
    }

    /// Adds raw TLS bytes and returns a decoded `ServerHello` when complete.
    ///
    /// Input may contain a partial record, multiple records, or a handshake
    /// split across records. Incomplete data is retained for the next call.
    ///
    /// # Errors
    ///
    /// Returns an error if a complete record or handshake is malformed.
    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<Option<TlsServerHello>, Error> {
        self.record_buffer.extend_from_slice(bytes);

        loop {
            let (record, consumed) = match TlsRecord::try_from_bytes(&self.record_buffer) {
                Ok(record) => record,
                Err(Error::UnexpectedEof { .. }) => return Ok(None),
                Err(error) => return Err(error),
            };

            let is_handshake = record.content_type() == &TlsContentType::HANDSHAKE;
            if is_handshake {
                self.handshake_buffer.extend_from_slice(record.payload());
            }
            self.record_buffer.drain(..consumed);

            if is_handshake {
                if let Some(server_hello) = self.try_parse()? {
                    return Ok(Some(server_hello));
                }
            }
        }
    }

    /// Adds one parsed TLS record and returns a decoded `ServerHello` when complete.
    ///
    /// # Errors
    ///
    /// Returns an error if the accumulated handshake is malformed.
    pub fn push_record(&mut self, record: &TlsRecord<'_>) -> Result<Option<TlsServerHello>, Error> {
        if record.content_type() != &TlsContentType::HANDSHAKE {
            return Ok(None);
        }

        self.handshake_buffer.extend_from_slice(record.payload());

        self.try_parse()
    }

    fn try_parse(&mut self) -> Result<Option<TlsServerHello>, Error> {
        let (handshake, consumed) = match TlsHandshake::try_from_bytes(&self.handshake_buffer) {
            Ok(handshake) => handshake,
            Err(Error::UnexpectedEof { .. }) => return Ok(None),
            Err(error) => return Err(error),
        };

        if handshake.handshake_type() != TlsHandshakeType::SERVER_HELLO {
            return Err(Error::Malformed("expected ServerHello"));
        }

        let server_hello = TlsServerHello::try_from_bytes(handshake.body())?;
        self.handshake_buffer.drain(..consumed);

        Ok(Some(server_hello))
    }
}

/// A TLS `ServerHello` handshake body.
///
/// This type represents only the `ServerHello` body. It does not include the
/// TLS handshake header or TLS record header.
///
/// ```text
/// +--------------------------------------------------+
/// | Legacy Version       2 bytes                     |
/// | Random              32 bytes                     |
/// | Session ID Length    1 byte                      |
/// | Session ID           N bytes                     |
/// | Cipher Suite         2 bytes                     |
/// | Compression Method   1 byte                      |
/// | Extensions Length    2 bytes                     |
/// | Extensions           N bytes                     |
/// +--------------------------------------------------+
/// ```
#[derive(Debug)]
pub struct TlsServerHello {
    legacy_version: TlsVersion,
    tls_version: TlsVersion,
    random: [u8; 32],
    session_id: Vec<u8>,
    cipher_suite: TlsCipherSuite,
    extensions: Vec<TlsExtension>,
}

impl TlsServerHello {
    /// Parses a `ServerHello` handshake body.
    ///
    /// The input must begin with the legacy version field; it must not include
    /// the TLS record header or the handshake message header. Use
    /// [`ServerHelloDecoder`] when processing record-layer data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] when a declared field extends beyond
    /// the input. Returns [`Error::Malformed`] when the session ID,
    /// compression method, extension block, or `supported_versions` extension
    /// is invalid.
    pub fn try_from_bytes(handshake_body: &[u8]) -> Result<Self, Error> {
        let mut negotiated_version: Option<TlsVersion> = None;

        let mut reader = TlsReader::new(handshake_body);

        let legacy_version = TlsVersion(reader.read_u16()?);

        let random = reader.read_array::<32>()?;

        let session_id_length = reader.read_u8()? as usize;
        if session_id_length > 32 {
            return Err(Error::Malformed("ServerHello session ID exceeds 32 bytes"));
        }
        let session_id = reader.read_bytes(session_id_length)?;

        let cipher_suite = TlsCipherSuite(reader.read_u16()?);

        let compression_method = reader.read_u8()?;
        if compression_method != 0 {
            return Err(Error::Malformed(
                "unsupported ServerHello compression method",
            ));
        }

        let mut extensions = Vec::new();

        if reader.remaining() > 0 {
            let extensions_length = reader.read_u16()? as usize;
            let extensions_data = reader.read_bytes(extensions_length)?;

            if reader.remaining() != 0 {
                return Err(Error::Malformed(
                    "trailing bytes after ServerHello extensions",
                ));
            }

            let mut extensions_reader = TlsReader::new(extensions_data);

            while extensions_reader.remaining() > 0 {
                let extension_type = TlsExtensionType(extensions_reader.read_u16()?);

                let extension_length = extensions_reader.read_u16()? as usize;

                let extension_data = extensions_reader.read_bytes(extension_length)?;

                if extension_type == TlsExtensionType::SUPPORTED_VERSIONS {
                    if negotiated_version.is_some() {
                        return Err(Error::Malformed(
                            "duplicate supported_versions extension in ServerHello",
                        ));
                    }

                    if extension_data.len() != 2 {
                        return Err(Error::Malformed(
                            "invalid supported_versions extension in ServerHello",
                        ));
                    }

                    negotiated_version = Some(TlsVersion(u16::from_be_bytes([
                        extension_data[0],
                        extension_data[1],
                    ])));
                }

                extensions.push(TlsExtension::new(extension_type, extension_data.to_vec())?);
            }
        }

        Ok(Self {
            legacy_version,
            random,
            tls_version: negotiated_version.unwrap_or(legacy_version),
            session_id: Vec::from(session_id),
            cipher_suite,
            extensions,
        })
    }

    /// Returns the legacy version carried in the `ServerHello` body.
    pub const fn legacy_version(&self) -> TlsVersion {
        self.legacy_version
    }

    /// Returns the negotiated TLS version.
    ///
    /// For TLS 1.3, this is read from the `supported_versions` extension. For
    /// earlier versions, it is the same as [`Self::legacy_version`].
    pub const fn tls_version(&self) -> TlsVersion {
        self.tls_version
    }

    /// Returns the server random value.
    pub const fn random(&self) -> &[u8; 32] {
        &self.random
    }

    /// Returns the echoed legacy session ID.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Returns the extensions in their original wire order.
    pub fn extensions(&self) -> &[TlsExtension] {
        &self.extensions
    }

    /// Returns the cipher suite selected by the server.
    pub fn cipher_suite(&self) -> &TlsCipherSuite {
        &self.cipher_suite
    }

    /// Returns the ALPN protocol selected by the server, if present.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] or [`Error::UnexpectedEof`] if the ALPN
    /// extension is malformed or does not contain exactly one UTF-8 protocol.
    pub fn alpn_protocol(&self) -> Result<Option<&str>, Error> {
        let Some(extension) = self.extensions.iter().find(|extension| {
            extension.extension_type() == TlsExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
        }) else {
            return Ok(None);
        };

        let extension_data = extension.extension_data();
        let mut reader = TlsReader::new(extension_data);

        let protocol_list_length = usize::from(reader.read_u16()?);

        if protocol_list_length != reader.remaining() {
            return Err(Error::Malformed(
                "invalid ALPN protocol list length in ServerHello",
            ));
        }

        let protocol_length = usize::from(reader.read_u8()?);
        let protocol = reader.read_bytes(protocol_length)?;

        if !reader.is_empty() {
            return Err(Error::Malformed(
                "ServerHello ALPN extension contains multiple protocols",
            ));
        }

        let protocol = core::str::from_utf8(protocol)
            .map_err(|_| Error::Malformed("ServerHello ALPN protocol is not valid UTF-8"))?;

        Ok(Some(protocol))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_hello_body(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&TlsVersion::TLS12.to_be_bytes());
        body.extend_from_slice(&[0x42; 32]);
        body.extend_from_slice(&[2, 0xaa, 0xbb]);
        body.extend_from_slice(&TlsCipherSuite::TLS_AES_128_GCM_SHA256.to_be_bytes());
        body.push(0);
        if !extensions.is_empty() {
            body.extend_from_slice(&from_usize(extensions.len()));
            body.extend_from_slice(extensions);
        }
        body
    }

    fn from_usize(value: usize) -> [u8; 2] {
        u16::try_from(value).unwrap().to_be_bytes()
    }

    #[test]
    fn parses_tls13_server_hello_and_alpn() {
        let extensions = [
            0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h',
            b'2',
        ];
        let hello = TlsServerHello::try_from_bytes(&server_hello_body(&extensions)).unwrap();

        assert_eq!(hello.legacy_version(), TlsVersion::TLS12);
        assert_eq!(hello.tls_version(), TlsVersion::TLS13);
        assert_eq!(hello.random(), &[0x42; 32]);
        assert_eq!(hello.session_id(), &[0xaa, 0xbb]);
        assert_eq!(
            hello.cipher_suite(),
            &TlsCipherSuite::TLS_AES_128_GCM_SHA256
        );
        assert_eq!(hello.extensions().len(), 2);
        assert_eq!(
            hello.extensions()[0].extension_type(),
            TlsExtensionType::SUPPORTED_VERSIONS
        );
        assert_eq!(
            hello.extensions()[1].extension_type(),
            TlsExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
        );
        assert_eq!(hello.alpn_protocol().unwrap(), Some("h2"));
    }

    #[test]
    fn decoder_reassembles_partial_records_and_a_fragmented_server_hello() {
        let body = server_hello_body(&[]);
        let handshake = TlsHandshake::new(TlsHandshakeType::SERVER_HELLO, &body)
            .try_to_bytes()
            .unwrap();

        let split = 12;
        let mut records = tls_record(&handshake[..split]);
        records.extend_from_slice(&tls_record(&handshake[split..]));
        let mut decoder = ServerHelloDecoder::new();

        assert!(decoder.push_bytes(&records[..3]).unwrap().is_none());
        let hello = decoder.push_bytes(&records[3..]).unwrap().unwrap();
        assert_eq!(hello.tls_version(), TlsVersion::TLS12);
    }

    #[test]
    fn rejects_malformed_alpn() {
        let extensions = [0x00, 0x10, 0x00, 0x04, 0x00, 0x03, 0x01, b'h'];
        let hello = TlsServerHello::try_from_bytes(&server_hello_body(&extensions)).unwrap();

        assert!(matches!(hello.alpn_protocol(), Err(Error::Malformed(_))));
    }

    fn tls_record(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![TlsContentType::HANDSHAKE.as_u8()];
        record.extend_from_slice(&TlsVersion::TLS12.to_be_bytes());
        record.extend_from_slice(&from_usize(payload.len()));
        record.extend_from_slice(payload);
        record
    }
}
