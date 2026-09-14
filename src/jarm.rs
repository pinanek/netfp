//! Rust implementation of the JARM active TLS server fingerprinting algorithm.
//!
//! This implementation is based on the original Salesforce JARM 1.0 project:
//! <https://github.com/salesforce/jarm>. The reference Python implementation is
//! included in this repository at `jarm/jarm.py`.
//!
//! Original JARM is Copyright (c) 2020, Salesforce.com, Inc. and licensed
//! under the BSD 3-Clause License:
//! <https://github.com/salesforce/jarm/blob/master/LICENSE.txt>.

use sha2::{Digest, Sha256};

use crate::{
    error::Error,
    tls::{
        AlpnProtocol, Grease, TlsCipherSuite, TlsClientHello, TlsContentType, TlsExtension,
        TlsExtensionType, TlsHandshake, TlsHandshakeType, TlsPskKeyExchangeMode, TlsRecord,
        TlsServerHello, TlsSignatureAlgorithm, TlsSupportedGroup, TlsVersion,
    },
    utils::random_32_bytes,
};

const JARM_PROBE_COUNT: usize = 10;

const JARM_CIPHER_ORDER: &[TlsCipherSuite] = &[
    TlsCipherSuite::TLS_RSA_WITH_RC4_128_MD5,
    TlsCipherSuite::TLS_RSA_WITH_RC4_128_SHA,
    TlsCipherSuite::TLS_RSA_WITH_IDEA_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256,
    TlsCipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256,
    TlsCipherSuite::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
    TlsCipherSuite::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_SEED_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
    TlsCipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    TlsCipherSuite::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TlsCipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TlsCipherSuite::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    TlsCipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_RC4_128_SHA,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
    TlsCipherSuite::TLS_RSA_WITH_AES_128_CCM,
    TlsCipherSuite::TLS_RSA_WITH_AES_256_CCM,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM,
    TlsCipherSuite::TLS_RSA_WITH_AES_128_CCM_8,
    TlsCipherSuite::TLS_RSA_WITH_AES_256_CCM_8,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM_8,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM_8,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    TlsCipherSuite::OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TlsCipherSuite::OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    // TLS 1.3 suites deliberately appear last, as required by JARM.
    TlsCipherSuite::TLS_AES_128_GCM_SHA256,
    TlsCipherSuite::TLS_AES_256_GCM_SHA384,
    TlsCipherSuite::TLS_CHACHA20_POLY1305_SHA256,
    TlsCipherSuite::TLS_AES_128_CCM_SHA256,
    TlsCipherSuite::TLS_AES_128_CCM_8_SHA256,
];

const ALL_CIPHER_SUITES: &[TlsCipherSuite] = &[
    TlsCipherSuite::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM_8,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM_8,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    TlsCipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TlsCipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    TlsCipherSuite::TLS_DHE_RSA_WITH_SEED_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TlsCipherSuite::TLS_AES_256_GCM_SHA384,
    TlsCipherSuite::TLS_AES_128_GCM_SHA256,
    TlsCipherSuite::OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TlsCipherSuite::TLS_AES_128_CCM_8_SHA256,
    TlsCipherSuite::TLS_AES_128_CCM_SHA256,
    TlsCipherSuite::TLS_CHACHA20_POLY1305_SHA256,
    TlsCipherSuite::OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_RC4_128_SHA,
    TlsCipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256,
    TlsCipherSuite::TLS_RSA_WITH_AES_128_CCM,
    TlsCipherSuite::TLS_RSA_WITH_AES_128_CCM_8,
    TlsCipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
    TlsCipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256,
    TlsCipherSuite::TLS_RSA_WITH_AES_256_CCM,
    TlsCipherSuite::TLS_RSA_WITH_AES_256_CCM_8,
    TlsCipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
    TlsCipherSuite::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TlsCipherSuite::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    TlsCipherSuite::TLS_RSA_WITH_IDEA_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_RC4_128_MD5,
    TlsCipherSuite::TLS_RSA_WITH_RC4_128_SHA,
];

const NO_TLS13_CIPHER_SUITES: &[TlsCipherSuite] = &[
    TlsCipherSuite::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM_8,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM_8,
    TlsCipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    TlsCipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TlsCipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TlsCipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    TlsCipherSuite::TLS_DHE_RSA_WITH_SEED_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TlsCipherSuite::OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TlsCipherSuite::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TlsCipherSuite::OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TlsCipherSuite::TLS_ECDHE_RSA_WITH_RC4_128_SHA,
    TlsCipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256,
    TlsCipherSuite::TLS_RSA_WITH_AES_128_CCM,
    TlsCipherSuite::TLS_RSA_WITH_AES_128_CCM_8,
    TlsCipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
    TlsCipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256,
    TlsCipherSuite::TLS_RSA_WITH_AES_256_CCM,
    TlsCipherSuite::TLS_RSA_WITH_AES_256_CCM_8,
    TlsCipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
    TlsCipherSuite::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TlsCipherSuite::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    TlsCipherSuite::TLS_RSA_WITH_IDEA_CBC_SHA,
    TlsCipherSuite::TLS_RSA_WITH_RC4_128_MD5,
    TlsCipherSuite::TLS_RSA_WITH_RC4_128_SHA,
];

const SIGNATURE_ALGORITHMS: &[TlsSignatureAlgorithm] = &[
    TlsSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
    TlsSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
    TlsSignatureAlgorithm::RSA_PKCS1_SHA256,
    TlsSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
    TlsSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
    TlsSignatureAlgorithm::RSA_PKCS1_SHA384,
    TlsSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
    TlsSignatureAlgorithm::RSA_PKCS1_SHA512,
    TlsSignatureAlgorithm::RSA_PKCS1_SHA1,
];

const PSK_KEY_EXCHANGE_MODES: &[TlsPskKeyExchangeMode] = &[TlsPskKeyExchangeMode::PSK_DHE_KE];

const SUPPORTED_GROUPS: &[TlsSupportedGroup] = &[
    TlsSupportedGroup::X25519,
    TlsSupportedGroup::SECP256R1,
    TlsSupportedGroup::SECP384R1,
    TlsSupportedGroup::SECP521R1,
];

const TLS12_SUPPORTED_VERSIONS: &[TlsVersion] =
    &[TlsVersion::TLS10, TlsVersion::TLS11, TlsVersion::TLS12];

const TLS13_SUPPORTED_VERSIONS: &[TlsVersion] = &[
    TlsVersion::TLS10,
    TlsVersion::TLS11,
    TlsVersion::TLS12,
    TlsVersion::TLS13,
];

const ALL_ALPNS: &[AlpnProtocol] = &[
    AlpnProtocol::HTTP_09,
    AlpnProtocol::HTTP_10,
    AlpnProtocol::HTTP_11,
    AlpnProtocol::SPDY_1,
    AlpnProtocol::SPDY_2,
    AlpnProtocol::SPDY_3,
    AlpnProtocol::H2,
    AlpnProtocol::H2C,
    AlpnProtocol::HQ,
];

const RARE_ALPNS: &[AlpnProtocol] = &[
    AlpnProtocol::HTTP_09,
    AlpnProtocol::HTTP_10,
    AlpnProtocol::SPDY_1,
    AlpnProtocol::SPDY_2,
    AlpnProtocol::SPDY_3,
    AlpnProtocol::H2C,
    AlpnProtocol::HQ,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CipherListKind {
    All,
    NoTls13,
}

impl CipherListKind {
    const fn as_slice(self) -> &'static [TlsCipherSuite] {
        match self {
            Self::All => ALL_CIPHER_SUITES,
            Self::NoTls13 => NO_TLS13_CIPHER_SUITES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VersionSupport {
    None,
    Tls12,
    Tls13,
}

impl VersionSupport {
    /// Returns the version list to encode for the selected probe version.
    ///
    /// TLS 1.3 probes use the TLS 1.3 list even when the profile is [`Self::None`],
    /// matching the original JARM implementation.
    const fn supported_versions(self, protocol_version: TlsVersion) -> &'static [TlsVersion] {
        match (self, protocol_version) {
            (Self::Tls12, _) => TLS12_SUPPORTED_VERSIONS,
            (Self::Tls13, _) => TLS13_SUPPORTED_VERSIONS,

            (Self::None, TlsVersion::TLS13) => TLS13_SUPPORTED_VERSIONS,

            (Self::None, _) => &[],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CipherListOrder {
    Forward,
    Reverse,
    /// Selects the upper half and orders it from the midpoint outward.
    TopHalf,
    /// Selects the lower half in canonical order.
    BottomHalf,
    /// Alternates around the midpoint, taking the upper item first.
    MiddleOut,
}

impl CipherListOrder {
    fn reorder(self, ciphers: &[TlsCipherSuite]) -> Vec<TlsCipherSuite> {
        match self {
            Self::Forward => ciphers.to_vec(),

            Self::Reverse => ciphers.iter().rev().copied().collect(),

            Self::BottomHalf => {
                let midpoint = ciphers.len() / 2;

                if ciphers.len() % 2 == 1 {
                    ciphers[midpoint + 1..].to_vec()
                } else {
                    ciphers[midpoint..].to_vec()
                }
            }

            Self::TopHalf => {
                let midpoint = ciphers.len() / 2;
                let mut reordered = Vec::with_capacity(ciphers.len().div_ceil(2));

                if ciphers.len() % 2 == 1 {
                    reordered.push(ciphers[midpoint]);
                }

                reordered.extend(ciphers[..midpoint].iter().rev().copied());

                reordered
            }

            Self::MiddleOut => {
                let cipher_count = ciphers.len();

                if cipher_count == 0 {
                    return Vec::new();
                }

                let midpoint = cipher_count / 2;
                let mut reordered = Vec::with_capacity(cipher_count);

                if cipher_count % 2 == 1 {
                    reordered.push(ciphers[midpoint]);

                    for offset in 1..=midpoint {
                        reordered.push(ciphers[midpoint + offset]);
                        reordered.push(ciphers[midpoint - offset]);
                    }
                } else {
                    for offset in 1..=midpoint {
                        reordered.push(ciphers[midpoint - 1 + offset]);
                        reordered.push(ciphers[midpoint - offset]);
                    }
                }

                reordered
            }
        }
    }
}

/// Ordering applied to order-sensitive values within JARM extensions.
///
/// This controls ALPN protocols and supported versions; it does not reorder the
/// extension blocks themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtensionOrder {
    Forward,
    Reverse,
}

impl ExtensionOrder {
    fn reorder<T: Copy>(self, values: &[T]) -> Vec<T> {
        match self {
            Self::Forward => values.to_vec(),
            Self::Reverse => values.iter().rev().copied().collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlpnProfile {
    /// Advertises the complete canonical JARM ALPN list.
    All,
    /// Advertises the reduced list that omits HTTP/1.1 and HTTP/2.
    Rare,
}

impl<'a> AlpnProfile {
    const fn as_slice(self) -> &'static [AlpnProtocol<'a>] {
        match self {
            Self::All => ALL_ALPNS,
            Self::Rare => RARE_ALPNS,
        }
    }
}

#[derive(Debug)]
struct JarmProbeDefinition {
    host: String,
    protocol_version: TlsVersion,
    cipher_list_kind: CipherListKind,
    cipher_list_order: CipherListOrder,
    extension_order: ExtensionOrder,
    alpn_profile: AlpnProfile,
    version_support: VersionSupport,
    grease: bool,
}

impl JarmProbeDefinition {
    fn client_hello_probe(&self) -> Result<Vec<u8>, Error> {
        let mut cipher_suites = Vec::new();

        if self.grease {
            cipher_suites.push(TlsCipherSuite(Grease::random().as_u16()));
        }

        cipher_suites.extend(
            self.cipher_list_order
                .reorder(self.cipher_list_kind.as_slice()),
        );

        let record_version = if self.protocol_version == TlsVersion::TLS13 {
            TlsVersion::TLS10
        } else {
            self.protocol_version
        };

        let client_hello =
            TlsClientHello::new(self.protocol_version, cipher_suites, self.extensions()?)?;
        let client_hello_body = client_hello.try_to_bytes()?;
        let handshake = TlsHandshake::new(TlsHandshakeType::CLIENT_HELLO, &client_hello_body);
        let handshake_bytes = handshake.try_to_bytes()?;
        TlsRecord::new(TlsContentType::HANDSHAKE, record_version, &handshake_bytes).try_to_bytes()
    }

    fn extensions(&self) -> Result<Vec<TlsExtension>, Error> {
        let mut extensions = Vec::new();

        if self.grease {
            extensions.push(self.grease_extension()?);
        }

        extensions.push(self.server_name_extension()?);
        extensions.push(self.extended_master_secret_extension()?);
        extensions.push(self.max_fragment_length_extension()?);
        extensions.push(self.renegotiation_info_extension()?);
        extensions.push(self.supported_groups_extension()?);
        extensions.push(self.ec_point_formats_extension()?);
        extensions.push(self.session_ticket_extension()?);
        extensions.push(self.alpn_extension()?);
        extensions.push(self.signature_algorithms_extension()?);
        extensions.push(self.key_share_extension()?);
        extensions.push(self.psk_key_exchange_modes_extension()?);

        if self.protocol_version == TlsVersion::TLS13
            || self.version_support != VersionSupport::None
        {
            extensions.push(self.supported_versions_extension()?);
        }

        Ok(extensions)
    }

    fn grease_extension(&self) -> Result<TlsExtension, Error> {
        TlsExtension::new(TlsExtensionType(Grease::random().as_u16()), Vec::new())
    }

    fn server_name_extension(&self) -> Result<TlsExtension, Error> {
        let host_bytes = self.host.as_bytes();

        let mut extension_data = Vec::new();

        extension_data.extend_from_slice(&((host_bytes.len() + 3) as u16).to_be_bytes());

        extension_data.push(0x00);

        extension_data.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        extension_data.extend_from_slice(host_bytes);

        TlsExtension::new(TlsExtensionType::SERVER_NAME, extension_data)
    }

    fn extended_master_secret_extension(&self) -> Result<TlsExtension, Error> {
        TlsExtension::new(TlsExtensionType::EXTENDED_MASTER_SECRET, Vec::new())
    }

    fn max_fragment_length_extension(&self) -> Result<TlsExtension, Error> {
        TlsExtension::new(TlsExtensionType::MAX_FRAGMENT_LENGTH, Vec::from([0x01]))
    }

    fn renegotiation_info_extension(&self) -> Result<TlsExtension, Error> {
        TlsExtension::new(TlsExtensionType::RENEGOTIATION_INFO, Vec::from([0x00]))
    }

    fn supported_groups_extension(&self) -> Result<TlsExtension, Error> {
        let mut data = Vec::new();

        data.extend_from_slice(&((SUPPORTED_GROUPS.len() * size_of::<u16>()) as u16).to_be_bytes());

        for group in SUPPORTED_GROUPS {
            data.extend_from_slice(&group.to_be_bytes());
        }

        TlsExtension::new(TlsExtensionType::SUPPORTED_GROUPS, data)
    }

    fn ec_point_formats_extension(&self) -> Result<TlsExtension, Error> {
        TlsExtension::new(TlsExtensionType::EC_POINT_FORMATS, Vec::from([0x01, 0x00]))
    }

    fn session_ticket_extension(&self) -> Result<TlsExtension, Error> {
        TlsExtension::new(TlsExtensionType::SESSION_TICKET, Vec::new())
    }

    fn alpn_extension(&self) -> Result<TlsExtension, Error> {
        let mut protocols = Vec::new();

        for alpn in self.extension_order.reorder(self.alpn_profile.as_slice()) {
            let protocol = alpn.as_bytes();

            protocols.push(protocol.len() as u8);
            protocols.extend_from_slice(protocol);
        }

        let mut data = Vec::new();

        data.extend_from_slice(&(protocols.len() as u16).to_be_bytes());
        data.extend_from_slice(&protocols);

        TlsExtension::new(
            TlsExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            data,
        )
    }

    fn signature_algorithms_extension(&self) -> Result<TlsExtension, Error> {
        let mut algorithms = Vec::new();

        for algorithm in SIGNATURE_ALGORITHMS {
            algorithms.extend_from_slice(&algorithm.to_be_bytes());
        }

        let mut data = Vec::new();

        data.extend_from_slice(&(algorithms.len() as u16).to_be_bytes());
        data.extend_from_slice(&algorithms);

        TlsExtension::new(TlsExtensionType::SIGNATURE_ALGORITHMS, data)
    }

    fn key_share_extension(&self) -> Result<TlsExtension, Error> {
        let mut key_shares = Vec::new();

        if self.grease {
            key_shares.extend_from_slice(&Grease::random().to_be_bytes());

            key_shares.extend_from_slice(&1u16.to_be_bytes());
            key_shares.push(0x00);
        }

        key_shares.extend_from_slice(&TlsSupportedGroup::X25519.to_be_bytes());
        key_shares.extend_from_slice(&32u16.to_be_bytes());
        key_shares.extend_from_slice(&random_32_bytes());

        let mut data = Vec::new();

        data.extend_from_slice(&(key_shares.len() as u16).to_be_bytes());
        data.extend_from_slice(&key_shares);

        TlsExtension::new(TlsExtensionType::KEY_SHARE, data)
    }

    fn psk_key_exchange_modes_extension(&self) -> Result<TlsExtension, Error> {
        let mut data = Vec::with_capacity(PSK_KEY_EXCHANGE_MODES.len() + 1);

        data.push(PSK_KEY_EXCHANGE_MODES.len() as u8);

        for mode in PSK_KEY_EXCHANGE_MODES {
            data.push(mode.as_u8());
        }

        TlsExtension::new(TlsExtensionType::PSK_KEY_EXCHANGE_MODES, data)
    }

    fn supported_versions_extension(&self) -> Result<TlsExtension, Error> {
        let mut versions = Vec::new();

        if self.grease {
            versions.extend_from_slice(&Grease::random().to_be_bytes());
        }

        for version in self.extension_order.reorder(
            self.version_support
                .supported_versions(self.protocol_version),
        ) {
            versions.extend_from_slice(&version.to_be_bytes());
        }

        let mut data = Vec::with_capacity(versions.len() + 1);

        data.push(versions.len() as u8);
        data.extend_from_slice(&versions);

        TlsExtension::new(TlsExtensionType::SUPPORTED_VERSIONS, data)
    }
}

#[derive(Debug)]
struct JarmServerHello {
    cipher_suite: TlsCipherSuite,
    legacy_version_byte: u8,
    alpn: String,
    extension_types: Vec<TlsExtensionType>,
}

impl TryFrom<&TlsServerHello> for JarmServerHello {
    type Error = Error;

    fn try_from(value: &TlsServerHello) -> Result<Self, Self::Error> {
        Ok(Self {
            cipher_suite: *value.cipher_suite(),
            legacy_version_byte: value.legacy_version().to_be_bytes()[1],
            alpn: value.alpn_protocol()?.unwrap_or_default().to_owned(),
            extension_types: value
                .extensions()
                .iter()
                .map(TlsExtension::extension_type)
                .collect(),
        })
    }
}

fn jarm_probe_definitions(host: impl Into<String>) -> Vec<JarmProbeDefinition> {
    let host = host.into();

    vec![
        // 1. tls1_2_forward
        JarmProbeDefinition {
            host: host.clone(),
            protocol_version: TlsVersion::TLS12,
            cipher_list_kind: CipherListKind::All,
            cipher_list_order: CipherListOrder::Forward,
            extension_order: ExtensionOrder::Reverse,
            alpn_profile: AlpnProfile::All,
            version_support: VersionSupport::Tls12,
            grease: false,
        },
        // 2. tls1_2_reverse
        JarmProbeDefinition {
            host: host.clone(),
            protocol_version: TlsVersion::TLS12,
            cipher_list_kind: CipherListKind::All,
            cipher_list_order: CipherListOrder::Reverse,
            extension_order: ExtensionOrder::Forward,
            alpn_profile: AlpnProfile::All,
            version_support: VersionSupport::Tls12,
            grease: false,
        },
        // 3. tls1_2_top_half
        JarmProbeDefinition {
            host: host.clone(),
            protocol_version: TlsVersion::TLS12,
            cipher_list_kind: CipherListKind::All,
            cipher_list_order: CipherListOrder::TopHalf,
            extension_order: ExtensionOrder::Forward,
            alpn_profile: AlpnProfile::All,
            version_support: VersionSupport::None,
            grease: false,
        },
        // 4. tls1_2_bottom_half
        JarmProbeDefinition {
            host: host.clone(),
            protocol_version: TlsVersion::TLS12,
            cipher_list_kind: CipherListKind::All,
            cipher_list_order: CipherListOrder::BottomHalf,
            extension_order: ExtensionOrder::Forward,
            alpn_profile: AlpnProfile::Rare,
            version_support: VersionSupport::None,
            grease: false,
        },
        // 5. tls1_2_middle_out
        JarmProbeDefinition {
            host: host.clone(),
            protocol_version: TlsVersion::TLS12,
            cipher_list_kind: CipherListKind::All,
            cipher_list_order: CipherListOrder::MiddleOut,
            extension_order: ExtensionOrder::Reverse,
            alpn_profile: AlpnProfile::Rare,
            version_support: VersionSupport::None,
            grease: true,
        },
        // 6. tls1_1_middle_out
        JarmProbeDefinition {
            host: host.clone(),
            protocol_version: TlsVersion::TLS11,
            cipher_list_kind: CipherListKind::All,
            cipher_list_order: CipherListOrder::Forward,
            extension_order: ExtensionOrder::Forward,
            alpn_profile: AlpnProfile::All,
            version_support: VersionSupport::None,
            grease: false,
        },
        // 7. tls1_3_forward
        JarmProbeDefinition {
            host: host.clone(),
            protocol_version: TlsVersion::TLS13,
            cipher_list_kind: CipherListKind::All,
            cipher_list_order: CipherListOrder::Forward,
            extension_order: ExtensionOrder::Reverse,
            alpn_profile: AlpnProfile::All,
            version_support: VersionSupport::Tls13,
            grease: false,
        },
        // 8. tls1_3_reverse
        JarmProbeDefinition {
            host: host.clone(),
            protocol_version: TlsVersion::TLS13,
            cipher_list_kind: CipherListKind::All,
            cipher_list_order: CipherListOrder::Reverse,
            extension_order: ExtensionOrder::Forward,
            alpn_profile: AlpnProfile::All,
            version_support: VersionSupport::Tls13,
            grease: false,
        },
        // 9. tls1_3_invalid
        JarmProbeDefinition {
            host: host.clone(),
            protocol_version: TlsVersion::TLS13,
            cipher_list_kind: CipherListKind::NoTls13,
            cipher_list_order: CipherListOrder::Forward,
            extension_order: ExtensionOrder::Forward,
            alpn_profile: AlpnProfile::All,
            version_support: VersionSupport::Tls13,
            grease: false,
        },
        // 10. tls1_3_middle_out
        JarmProbeDefinition {
            host: host.clone(),
            protocol_version: TlsVersion::TLS13,
            cipher_list_kind: CipherListKind::All,
            cipher_list_order: CipherListOrder::MiddleOut,
            extension_order: ExtensionOrder::Reverse,
            alpn_profile: AlpnProfile::All,
            version_support: VersionSupport::Tls13,
            grease: true,
        },
    ]
}

/// Builds the ten JARM `ClientHello` probes in canonical order.
///
/// Each returned byte vector is a complete TLS record ready to send over a
/// separate TCP connection to the target server.
///
/// This function does not resolve the host or open any network connections.
///
/// # Errors
///
/// Returns [`Error::LengthOverflow`] when the host or an encoded TLS field
/// cannot fit in its protocol length field, or [`Error::Malformed`] if a
/// generated `ClientHello` is invalid.
pub fn generate_jarm_probes(host: impl Into<String>) -> Result<Vec<Vec<u8>>, Error> {
    jarm_probe_definitions(host)
        .iter()
        .map(JarmProbeDefinition::client_hello_probe)
        .collect()
}

/// Produces a JARM fingerprint from probe responses.
///
/// JARM actively fingerprints a TLS server by sending ten specially ordered
/// `ClientHello` messages. The selected cipher suite, legacy TLS version,
/// ALPN protocol, and extension types from each response are combined into a
/// 62-character fingerprint.
///
/// # Examples
///
/// ```no_run
/// use std::{
///     io::{Read, Write},
///     net::TcpStream,
/// };
///
/// use netfp::{
///     generate_jarm_probes, jarm_fingerprint,
///     tls::{ServerHelloDecoder, TlsServerHello},
/// };
///
/// fn scan_probe(
///     address: &str,
///     probe: &[u8],
/// ) -> Result<Option<TlsServerHello>, Box<dyn std::error::Error>> {
///     let mut stream = TcpStream::connect(address)?;
///     stream.write_all(probe)?;
///
///     let mut decoder = ServerHelloDecoder::new();
///     let mut read_buffer = [0; 4096];
///
///     loop {
///         let bytes_read = stream.read(&mut read_buffer)?;
///         if bytes_read == 0 {
///             return Ok(None);
///         }
///
///         if let Some(server_hello) = decoder.push_bytes(&read_buffer[..bytes_read])? {
///             return Ok(Some(server_hello));
///         }
///     }
/// }
///
/// let responses = generate_jarm_probes("example.com")?
///     .iter()
///     .map(|probe| scan_probe("example.com:443", probe))
///     .collect::<Result<Vec<_>, _>>()?;
/// let fingerprint = jarm_fingerprint(&responses);
///
/// println!("{fingerprint}");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// Responses must be supplied in the same order as the records returned by
/// [`generate_jarm_probes`]. A missing response is represented by `None`.
/// Missing entries at the end of the slice are also treated as absent
/// responses; entries beyond the first ten are ignored.
///
/// The returned value is always 62 lowercase ASCII characters. If every
/// response is absent, it consists of 62 zeroes.
pub fn jarm_fingerprint(server_hellos: &[Option<TlsServerHello>]) -> String {
    let mut received_server_hello = false;
    let mut cipher_and_version = String::with_capacity(JARM_PROBE_COUNT * 3);
    let mut alpn_and_extensions = String::new();

    for probe_index in 0..JARM_PROBE_COUNT {
        let server_hello = server_hellos
            .get(probe_index)
            .and_then(Option::as_ref)
            .and_then(|response| JarmServerHello::try_from(response).ok());

        let Some(server_hello) = server_hello else {
            cipher_and_version.push_str("000");
            continue;
        };
        received_server_hello = true;

        let cipher_ordinal = JARM_CIPHER_ORDER
            .iter()
            .position(|candidate| candidate == &server_hello.cipher_suite)
            .map_or(JARM_CIPHER_ORDER.len() + 1, |index| index + 1);
        let version = "abcdef"
            .chars()
            .nth(usize::from(server_hello.legacy_version_byte))
            .unwrap_or('0');

        let extension_types = server_hello
            .extension_types
            .iter()
            .map(|extension_type| format!("{:04x}", extension_type.as_u16()))
            .collect::<Vec<_>>()
            .join("-");

        cipher_and_version.push_str(&format!("{cipher_ordinal:02x}"));
        cipher_and_version.push(version);
        alpn_and_extensions.push_str(&server_hello.alpn);
        alpn_and_extensions.push_str(&extension_types);
    }

    if !received_server_hello {
        return "0".repeat(62);
    }

    let digest = Sha256::digest(alpn_and_extensions.as_bytes());
    let digest_hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{cipher_and_version}{digest_hex}")[..62].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_matches_known_digest_vector() {
        let responses = (0..10)
            .map(|_| Some(test_server_hello()))
            .collect::<Vec<_>>();

        assert_eq!(
            jarm_fingerprint(&responses),
            "41d41d41d41d41d41d41d41d41d41da0bfb9dc5a7a50dfa51c2a70be11dda8"
        );
    }

    fn test_server_hello() -> TlsServerHello {
        let mut body = Vec::new();
        body.extend_from_slice(&TlsVersion::TLS12.to_be_bytes());
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&TlsCipherSuite::TLS_AES_128_GCM_SHA256.to_be_bytes());
        body.push(0);

        let extensions = [
            0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h',
            b'2',
        ];
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        TlsServerHello::try_from_bytes(&body).unwrap()
    }
}
