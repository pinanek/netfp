mod client_hello;
mod reader;
mod record;
mod server_hello;

pub use client_hello::TlsClientHello;
pub use reader::TlsReader;
pub use record::TlsRecord;
pub use server_hello::{ServerHelloDecoder, TlsServerHello};

use crate::{error::Error, utils::random_byte};

/// One TLSPlaintext record can contain at most 2^14 bytes.
pub const MAX_TLS_PLAINTEXT_LEN: usize = 1 << 14;

const HANDSHAKE_HEADER_LEN: usize = 4;

const TLS_RECORD_HEADER_LEN: usize = 5;

/// Available versions of TLS
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsVersion(u16);

impl TlsVersion {
    pub const SSL20: Self = Self(0x0002);
    pub const SSL30: Self = Self(0x0300);
    pub const TLS10: Self = Self(0x0301);
    pub const TLS11: Self = Self(0x0302);
    pub const TLS12: Self = Self(0x0303);
    pub const TLS13: Self = Self(0x0304);
}

impl TlsVersion {
    /// Returns the underlying 16-bit value.
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns the underlying value encoded as two bytes in network byte order.
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.as_u16().to_be_bytes()
    }

    /// Returns the legacy version used for this TLS version.
    ///
    /// For TLS 1.2 and earlier, the legacy version is the version itself.
    /// For TLS 1.3, the legacy version is TLS 1.2.
    pub const fn legacy_version(self) -> Self {
        if self.0 == Self::TLS13.0 {
            Self::TLS12
        } else {
            self
        }
    }
}

/// A reserved TLS GREASE code point.
///
/// GREASE values are used to detect implementations that incorrectly reject
/// unknown protocol identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Grease(u16);

impl Grease {
    /// Returns a randomly selected GREASE value.
    ///
    /// The returned value is always one of the reserved GREASE code points:
    /// `[0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa]`
    ///
    /// See: <https://datatracker.ietf.org/doc/html/draft-davidben-tls-grease-01#page-5>
    pub fn random() -> Self {
        let n = u16::from(random_byte() & 0x0f);
        let byte = (n << 4) | 0x0a;

        Self((byte << 8) | byte)
    }

    /// Returns the underlying 16-bit value.
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns the value encoded as two bytes in network byte order.
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

/// The content type of a TLS record.
///
/// See: <https://www.iana.org/assignments/tls-parameters#tls-parameters-5>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsContentType(pub u8);

impl TlsContentType {
    pub const HANDSHAKE: Self = Self(22);

    /// Returns the underlying 8-bit value.
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

/// Handshake type of a TLS record
///
/// See: <https://www.iana.org/assignments/tls-parameters#tls-parameters-7>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsHandshakeType(pub u8);

impl TlsHandshakeType {
    pub const CLIENT_HELLO: Self = Self(1);
    pub const SERVER_HELLO: Self = Self(2);

    /// Returns the underlying 8-bit value.
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

/// A TLS cipher suite identifier.
///
/// Any 16-bit value can be represented, including unknown, reserved,
/// experimental, and GREASE values.
///
/// See: <https://www.iana.org/assignments/tls-parameters#tls-parameters-4>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsCipherSuite(pub u16);

impl TlsCipherSuite {
    // TLS 1.3
    pub const TLS_AES_128_GCM_SHA256: Self = Self(0x1301);
    pub const TLS_AES_256_GCM_SHA384: Self = Self(0x1302);
    pub const TLS_CHACHA20_POLY1305_SHA256: Self = Self(0x1303);
    pub const TLS_AES_128_CCM_SHA256: Self = Self(0x1304);
    pub const TLS_AES_128_CCM_8_SHA256: Self = Self(0x1305);

    // DHE-RSA
    pub const TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA: Self = Self(0x0016);

    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA: Self = Self(0x0033);
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA: Self = Self(0x0039);

    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: Self = Self(0x0067);
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: Self = Self(0x006b);

    pub const TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: Self = Self(0x009e);
    pub const TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: Self = Self(0x009f);

    pub const TLS_DHE_RSA_WITH_AES_128_CCM: Self = Self(0xc09e);
    pub const TLS_DHE_RSA_WITH_AES_256_CCM: Self = Self(0xc09f);

    pub const TLS_DHE_RSA_WITH_AES_128_CCM_8: Self = Self(0xc0a2);
    pub const TLS_DHE_RSA_WITH_AES_256_CCM_8: Self = Self(0xc0a3);

    pub const TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA: Self = Self(0x0045);
    pub const TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA: Self = Self(0x0088);

    pub const TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: Self = Self(0x00be);
    pub const TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256: Self = Self(0x00c4);

    pub const TLS_DHE_RSA_WITH_SEED_CBC_SHA: Self = Self(0x009a);

    // ECDHE-ECDSA
    pub const TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: Self = Self(0xc008);

    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: Self = Self(0xc009);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: Self = Self(0xc00a);

    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: Self = Self(0xc023);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: Self = Self(0xc024);

    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: Self = Self(0xc02b);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: Self = Self(0xc02c);

    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CCM: Self = Self(0xc0ac);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CCM: Self = Self(0xc0ad);

    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: Self = Self(0xc0ae);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8: Self = Self(0xc0af);

    pub const TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256: Self = Self(0xc072);
    pub const TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384: Self = Self(0xc073);

    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xcca9);

    pub const OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xcc14);

    pub const TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: Self = Self(0xc007);

    // ECDHE-RSA
    pub const TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: Self = Self(0xc012);

    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: Self = Self(0xc013);
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: Self = Self(0xc014);

    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: Self = Self(0xc027);
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: Self = Self(0xc028);

    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: Self = Self(0xc02f);
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: Self = Self(0xc030);

    pub const TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256: Self = Self(0xc060);
    pub const TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384: Self = Self(0xc061);

    pub const TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: Self = Self(0xc076);
    pub const TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384: Self = Self(0xc077);

    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xcca8);

    pub const OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xcc13);

    pub const TLS_ECDHE_RSA_WITH_RC4_128_SHA: Self = Self(0xc011);

    // RSA
    pub const TLS_RSA_WITH_RC4_128_MD5: Self = Self(0x0004);
    pub const TLS_RSA_WITH_RC4_128_SHA: Self = Self(0x0005);
    pub const TLS_RSA_WITH_IDEA_CBC_SHA: Self = Self(0x0007);
    pub const TLS_RSA_WITH_3DES_EDE_CBC_SHA: Self = Self(0x000a);

    pub const TLS_RSA_WITH_AES_128_CBC_SHA: Self = Self(0x002f);
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: Self = Self(0x0035);

    pub const TLS_RSA_WITH_AES_128_CBC_SHA256: Self = Self(0x003c);
    pub const TLS_RSA_WITH_AES_256_CBC_SHA256: Self = Self(0x003d);

    pub const TLS_RSA_WITH_AES_128_GCM_SHA256: Self = Self(0x009c);
    pub const TLS_RSA_WITH_AES_256_GCM_SHA384: Self = Self(0x009d);

    pub const TLS_RSA_WITH_AES_128_CCM: Self = Self(0xc09c);
    pub const TLS_RSA_WITH_AES_256_CCM: Self = Self(0xc09d);

    pub const TLS_RSA_WITH_AES_128_CCM_8: Self = Self(0xc0a0);
    pub const TLS_RSA_WITH_AES_256_CCM_8: Self = Self(0xc0a1);

    pub const TLS_RSA_WITH_CAMELLIA_128_CBC_SHA: Self = Self(0x0041);
    pub const TLS_RSA_WITH_CAMELLIA_256_CBC_SHA: Self = Self(0x0084);

    pub const TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256: Self = Self(0x00ba);
    pub const TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256: Self = Self(0x00c0);

    /// Returns the raw 16-bit cipher suite identifier.
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns the identifier in network byte order.
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl From<u16> for TlsCipherSuite {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<TlsCipherSuite> for u16 {
    fn from(value: TlsCipherSuite) -> Self {
        value.0
    }
}

/// A TLS extension type.
///
/// Any 16-bit extension identifier can be represented, including unknown,
/// reserved, experimental, and GREASE values.
///
/// See: <https://www.iana.org/assignments/tls-extensiontype-values#tls-extensiontype-values-1>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsExtensionType(pub u16);

impl TlsExtensionType {
    pub const SERVER_NAME: Self = Self(0x0000);
    pub const MAX_FRAGMENT_LENGTH: Self = Self(0x0001);
    pub const SUPPORTED_GROUPS: Self = Self(0x000a);
    pub const EC_POINT_FORMATS: Self = Self(0x000b);
    pub const SIGNATURE_ALGORITHMS: Self = Self(0x000d);
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: Self = Self(0x0010);
    pub const EXTENDED_MASTER_SECRET: Self = Self(0x0017);
    pub const SESSION_TICKET: Self = Self(0x0023);
    pub const SUPPORTED_VERSIONS: Self = Self(0x002b);
    pub const PSK_KEY_EXCHANGE_MODES: Self = Self(0x002d);
    pub const KEY_SHARE: Self = Self(0x0033);
    pub const RENEGOTIATION_INFO: Self = Self(0xff01);

    /// Returns the raw 16-bit extension identifier.
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns the identifier in network byte order.
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

/// A TLS supported group used for key exchange.
///
/// See: <https://www.iana.org/assignments/tls-parameters#tls-parameters-8>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsSupportedGroup(pub u16);

impl TlsSupportedGroup {
    pub const SECP256R1: Self = Self(0x0017);
    pub const SECP384R1: Self = Self(0x0018);
    pub const SECP521R1: Self = Self(0x0019);
    pub const X25519: Self = Self(0x001d);

    /// Returns the raw 16-bit supported group identifier.
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns the identifier in network byte order.
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

/// An application protocol identifier used with TLS ALPN negotiation.
///
/// See: <https://www.iana.org/assignments/tls-extensiontype-values#alpn-protocol-ids>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AlpnProtocol<'a>(&'a [u8]);

impl AlpnProtocol<'static> {
    pub const HTTP_09: Self = Self(b"http/0.9");
    pub const HTTP_10: Self = Self(b"http/1.0");
    pub const HTTP_11: Self = Self(b"http/1.1");

    pub const SPDY_1: Self = Self(b"spdy/1");
    pub const SPDY_2: Self = Self(b"spdy/2");
    pub const SPDY_3: Self = Self(b"spdy/3");

    pub const H2: Self = Self(b"h2");
    pub const H2C: Self = Self(b"h2c");
    pub const H3: Self = Self(b"h3");
    pub const HQ: Self = Self(b"hq");
}

impl<'a> AlpnProtocol<'a> {
    /// Returns the underlying value as bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

/// A TLS signature scheme identifier.
///
/// See: <https://www.iana.org/assignments/tls-parameters#tls-parameters-16>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsSignatureAlgorithm(pub u16);

impl TlsSignatureAlgorithm {
    pub const RSA_PKCS1_SHA1: Self = Self(0x0201);

    pub const RSA_PKCS1_SHA256: Self = Self(0x0401);
    pub const ECDSA_SECP256R1_SHA256: Self = Self(0x0403);
    pub const RSA_PSS_RSAE_SHA256: Self = Self(0x0804);

    pub const RSA_PKCS1_SHA384: Self = Self(0x0501);
    pub const ECDSA_SECP384R1_SHA384: Self = Self(0x0503);
    pub const RSA_PSS_RSAE_SHA384: Self = Self(0x0805);

    pub const RSA_PKCS1_SHA512: Self = Self(0x0601);
    pub const RSA_PSS_RSAE_SHA512: Self = Self(0x0806);

    /// Returns the raw 16-bit signature algorithm identifier.
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns the identifier in network byte order.
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

/// A TLS PSK key exchange mode.
///
/// Any 8-bit value can be represented, including unknown or future values.
///
/// See: <https://www.iana.org/assignments/tls-parameters#tls-parameters-18>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsPskKeyExchangeMode(pub u8);

impl TlsPskKeyExchangeMode {
    pub const PSK_KE: Self = Self(0x00);
    pub const PSK_DHE_KE: Self = Self(0x01);

    /// Returns the raw 8-bit identifier.
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

/// A generic TLS extension.
///
/// A TLS extension consists of a 16-bit extension type, a 16-bit length field,
/// and the extension-specific payload.
///
/// ```text
/// +----------------------+
/// | Extension Type       | 2 bytes
/// +----------------------+
/// | Extension Length     | 2 bytes
/// +----------------------+
/// | Extension Data       | N bytes
/// +----------------------+
/// ```
#[derive(Debug, Clone)]
pub struct TlsExtension {
    extension_type: TlsExtensionType,
    extension_data: Vec<u8>,
}

impl TlsExtension {
    /// Creates a new TLS extension.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] if `extension_data` exceeds the
    /// maximum length representable by the 16-bit TLS extension length field.
    pub fn new(extension_type: TlsExtensionType, extension_data: Vec<u8>) -> Result<Self, Error> {
        u16::try_from(extension_data.len()).map_err(|_| Error::LengthOverflow {
            max: u16::MAX as usize,
            actual: extension_data.len(),
        })?;

        Ok(Self {
            extension_type,
            extension_data,
        })
    }

    /// Encodes this TLS extension into its wire representation.
    ///
    /// The returned bytes in network byte order.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded_extension = Vec::with_capacity(4 + self.extension_data.len());

        let extension_data_length = self.extension_data.len() as u16;

        encoded_extension.extend_from_slice(&self.extension_type.to_be_bytes());
        encoded_extension.extend_from_slice(&extension_data_length.to_be_bytes());
        encoded_extension.extend_from_slice(&self.extension_data);

        encoded_extension
    }

    /// Returns the extension-specific payload.
    pub fn extension_data(&self) -> &[u8] {
        &self.extension_data
    }

    /// Returns the extension type identifier.
    pub fn extension_type(&self) -> TlsExtensionType {
        self.extension_type
    }
}
