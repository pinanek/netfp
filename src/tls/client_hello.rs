use crate::{
    error::Error,
    tls::{TlsCipherSuite, TlsExtension, TlsExtensionType, TlsReader, TlsVersion},
    utils::random_32_bytes,
};

/// A TLS `ClientHello` handshake body.
///
/// This type represents only the `ClientHello` body. It does not include the
/// TLS handshake header or TLS record header.
///
/// ```text
/// +--------------------------------------------------+
/// | Legacy Version       2 bytes                     |
/// | Random              32 bytes                     |
/// | Session ID Length    1 byte                      |
/// | Session ID           N bytes                     |
/// | Cipher Suites Length 2 bytes                     |
/// | Cipher Suites        N x 2 bytes                 |
/// | Compression Length   1 byte                      |
/// | Compression Methods  N bytes                     |
/// | Extensions Length    2 bytes                     |
/// | Extensions           N bytes                     |
/// +--------------------------------------------------+
/// ```
#[derive(Debug)]
pub struct TlsClientHello {
    legacy_version: TlsVersion,
    random: [u8; 32],
    session_id: Vec<u8>,
    cipher_suites: Vec<TlsCipherSuite>,
    compression_methods: Vec<u8>,
    extensions: Vec<TlsExtension>,
}

impl TlsClientHello {
    /// Creates a new TLS `ClientHello` body.
    ///
    /// TLS 1.3 is encoded with the TLS 1.2 legacy version.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if `cipher_suites` is empty. Returns
    /// [`Error::LengthOverflow`] if the cipher-suite list exceeds the maximum
    /// size representable by its 16-bit length field.
    pub fn new(
        version: TlsVersion,
        cipher_suites: Vec<TlsCipherSuite>,
        extensions: Vec<TlsExtension>,
    ) -> Result<Self, Error> {
        if cipher_suites.is_empty() {
            return Err(Error::Malformed(
                "ClientHello must contain at least one cipher suite",
            ));
        }

        let encoded_length = cipher_suites
            .len()
            .checked_mul(2)
            .ok_or(Error::LengthOverflow {
                max: u16::MAX as usize,
                actual: usize::MAX,
            })?;
        u16::try_from(encoded_length).map_err(|_| Error::LengthOverflow {
            max: u16::MAX as usize,
            actual: encoded_length,
        })?;

        Ok(Self {
            legacy_version: version.legacy_version(),
            random: random_32_bytes(),
            session_id: random_32_bytes().to_vec(),
            cipher_suites,
            compression_methods: vec![0],
            extensions,
        })
    }

    /// Parses a TLS `ClientHello` body.
    ///
    /// The input must begin with the legacy version and must not include a TLS
    /// handshake header or record header.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if a declared field extends beyond the
    /// input. Returns [`Error::Malformed`] for an invalid session ID,
    /// cipher-suite list, compression-method list, extension block, or trailing
    /// bytes.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = TlsReader::new(bytes);
        let legacy_version = TlsVersion(reader.read_u16()?);
        let random = reader.read_array::<32>()?;

        let session_id_length = usize::from(reader.read_u8()?);
        if session_id_length > 32 {
            return Err(Error::Malformed("ClientHello session ID exceeds 32 bytes"));
        }
        let session_id = reader.read_bytes(session_id_length)?.to_vec();

        let cipher_suites_length = usize::from(reader.read_u16()?);
        if cipher_suites_length == 0 || cipher_suites_length % 2 != 0 {
            return Err(Error::Malformed(
                "ClientHello cipher-suite list must contain complete 16-bit values",
            ));
        }
        let cipher_suites_data = reader.read_bytes(cipher_suites_length)?;
        let mut cipher_suites_reader = TlsReader::new(cipher_suites_data);
        let mut cipher_suites = Vec::with_capacity(cipher_suites_length / 2);
        while !cipher_suites_reader.is_empty() {
            cipher_suites.push(TlsCipherSuite(cipher_suites_reader.read_u16()?));
        }

        let compression_methods_length = usize::from(reader.read_u8()?);
        if compression_methods_length == 0 {
            return Err(Error::Malformed(
                "ClientHello must contain at least one compression method",
            ));
        }
        let compression_methods = reader.read_bytes(compression_methods_length)?.to_vec();

        let mut extensions = Vec::new();
        if !reader.is_empty() {
            let extensions_length = usize::from(reader.read_u16()?);
            let extensions_data = reader.read_bytes(extensions_length)?;
            if !reader.is_empty() {
                return Err(Error::Malformed(
                    "trailing bytes after ClientHello extensions",
                ));
            }

            let mut extensions_reader = TlsReader::new(extensions_data);
            while !extensions_reader.is_empty() {
                let extension_type = TlsExtensionType(extensions_reader.read_u16()?);
                let extension_length = usize::from(extensions_reader.read_u16()?);
                let extension_data = extensions_reader.read_bytes(extension_length)?;
                extensions.push(TlsExtension::new(extension_type, extension_data.to_vec())?);
            }
        }

        Ok(Self {
            legacy_version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    /// Encodes this `ClientHello` body.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] if the encoded extensions exceed the
    /// maximum size representable by their 16-bit length field.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.legacy_version.to_be_bytes());
        body.extend_from_slice(&self.random);

        body.push(self.session_id.len() as u8);
        body.extend_from_slice(&self.session_id);

        let cipher_suites_length = (self.cipher_suites.len() * 2) as u16;
        body.extend_from_slice(&cipher_suites_length.to_be_bytes());
        for cipher_suite in &self.cipher_suites {
            body.extend_from_slice(&cipher_suite.to_be_bytes());
        }

        body.push(self.compression_methods.len() as u8);
        body.extend_from_slice(&self.compression_methods);

        let mut encoded_extensions = Vec::new();
        for extension in &self.extensions {
            encoded_extensions.extend_from_slice(&extension.to_bytes());
        }
        let extensions_length =
            u16::try_from(encoded_extensions.len()).map_err(|_| Error::LengthOverflow {
                max: u16::MAX as usize,
                actual: encoded_extensions.len(),
            })?;
        body.extend_from_slice(&extensions_length.to_be_bytes());
        body.extend_from_slice(&encoded_extensions);

        Ok(body)
    }

    /// Returns the legacy version carried in the `ClientHello` body.
    pub const fn legacy_version(&self) -> TlsVersion {
        self.legacy_version
    }

    /// Returns the client random value.
    pub const fn random(&self) -> &[u8; 32] {
        &self.random
    }

    /// Returns the legacy session ID.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Returns the offered cipher suites in wire order.
    pub fn cipher_suites(&self) -> &[TlsCipherSuite] {
        &self.cipher_suites
    }

    /// Returns the offered compression methods in wire order.
    pub fn compression_methods(&self) -> &[u8] {
        &self.compression_methods
    }

    /// Returns the extensions in wire order.
    pub fn extensions(&self) -> &[TlsExtension] {
        &self.extensions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_body_round_trips() {
        let extension = TlsExtension::new(TlsExtensionType::SERVER_NAME, vec![0, 1, 2]).unwrap();
        let hello = TlsClientHello::new(
            TlsVersion::TLS13,
            vec![TlsCipherSuite::TLS_AES_128_GCM_SHA256],
            vec![extension],
        )
        .unwrap();

        let encoded = hello.try_to_bytes().unwrap();
        let decoded = TlsClientHello::try_from_bytes(&encoded).unwrap();

        assert_eq!(decoded.legacy_version, TlsVersion::TLS12);
        assert_eq!(decoded.random, hello.random);
        assert_eq!(decoded.session_id, hello.session_id);
        assert_eq!(decoded.cipher_suites, hello.cipher_suites);
        assert_eq!(decoded.compression_methods, vec![0]);
        assert_eq!(decoded.extensions.len(), 1);
        assert_eq!(
            decoded.extensions[0].extension_type(),
            TlsExtensionType::SERVER_NAME
        );
        assert_eq!(decoded.extensions[0].extension_data(), &[0, 1, 2]);
    }

    #[test]
    fn rejects_an_odd_cipher_suite_length() {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[0, 0, 1, 0x13]);

        assert!(matches!(
            TlsClientHello::try_from_bytes(&body),
            Err(Error::Malformed(_))
        ));
    }
}
