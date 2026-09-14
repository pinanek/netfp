use md5::{Digest, Md5};

use crate::{
    Error,
    tls::{Grease, TlsClientHello, TlsExtensionType, TlsReader, TlsServerHello},
};

/// Computes the JA3 fingerprint of a parsed TLS `ClientHello`.
///
/// # Errors
///
/// Returns an error if the `supported_groups` or `ec_point_formats` extension
/// contains an invalid vector encoding.
pub fn ja3_fingerprint(client_hello: &TlsClientHello) -> Result<String, Error> {
    let cipher_suites = client_hello
        .cipher_suites()
        .iter()
        .filter(|cipher_suite| !Grease::is_grease(cipher_suite.as_u16()))
        .map(|cipher_suite| cipher_suite.as_u16().to_string())
        .collect::<Vec<_>>()
        .join("-");

    let extensions = client_hello
        .extensions()
        .iter()
        .filter(|extension| !Grease::is_grease(extension.extension_type().as_u16()))
        .map(|extension| extension.extension_type().as_u16().to_string())
        .collect::<Vec<_>>()
        .join("-");

    let supported_groups_data = client_hello
        .extensions()
        .iter()
        .find(|extension| extension.extension_type() == TlsExtensionType::SUPPORTED_GROUPS)
        .map(|extension| extension.extension_data());

    let supported_groups = if let Some(data) = supported_groups_data {
        let mut reader = TlsReader::new(data);
        let groups_length = usize::from(reader.read_u16()?);
        let groups_data = reader.read_bytes(groups_length)?;

        if !reader.is_empty() || groups_length % 2 != 0 {
            return Err(Error::Malformed("invalid supported_groups extension"));
        }

        let mut groups_reader = TlsReader::new(groups_data);
        let mut groups = Vec::with_capacity(groups_length / 2);
        while !groups_reader.is_empty() {
            let group = groups_reader.read_u16()?;
            if !Grease::is_grease(group) {
                groups.push(group.to_string());
            }
        }

        groups.join("-")
    } else {
        String::new()
    };

    let ec_point_formats_data = client_hello
        .extensions()
        .iter()
        .find(|extension| extension.extension_type() == TlsExtensionType::EC_POINT_FORMATS)
        .map(|extension| extension.extension_data());

    let ec_point_formats = if let Some(data) = ec_point_formats_data {
        let mut reader = TlsReader::new(data);
        let formats_length = usize::from(reader.read_u8()?);
        let formats_data = reader.read_bytes(formats_length)?;

        if !reader.is_empty() {
            return Err(Error::Malformed("invalid ec_point_formats extension"));
        }

        formats_data
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("-")
    } else {
        String::new()
    };

    let source = format!(
        "{},{},{},{},{}",
        client_hello.legacy_version().as_u16(),
        cipher_suites,
        extensions,
        supported_groups,
        ec_point_formats,
    );

    let digest = Md5::digest(source.as_bytes());
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Computes the JA3S fingerprint of a parsed TLS `ServerHello`.
pub fn ja3s_fingerprint(server_hello: &TlsServerHello) -> String {
    let extensions = server_hello
        .extensions()
        .iter()
        .map(|extension| extension.extension_type().as_u16().to_string())
        .collect::<Vec<_>>()
        .join("-");

    let source = format!(
        "{},{},{}",
        server_hello.legacy_version().as_u16(),
        server_hello.cipher_suite().as_u16(),
        extensions,
    );

    Md5::digest(source.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::{TlsCipherSuite, TlsExtension, TlsSupportedGroup, TlsVersion};

    #[test]
    fn computes_ja3_and_excludes_grease() {
        let cipher_suites = [
            TlsCipherSuite(0x0a0a),
            TlsCipherSuite::TLS_AES_128_GCM_SHA256,
            TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ];

        let mut supported_groups = Vec::new();
        supported_groups.extend_from_slice(&6u16.to_be_bytes());
        supported_groups.extend_from_slice(&0x2a2au16.to_be_bytes());
        supported_groups.extend_from_slice(&TlsSupportedGroup::X25519.to_be_bytes());
        supported_groups.extend_from_slice(&TlsSupportedGroup::SECP256R1.to_be_bytes());

        let extensions = [
            TlsExtension::new(TlsExtensionType(0x1a1a), Vec::new()).unwrap(),
            TlsExtension::new(TlsExtensionType::SUPPORTED_GROUPS, supported_groups).unwrap(),
            TlsExtension::new(TlsExtensionType::EC_POINT_FORMATS, vec![1, 0]).unwrap(),
            TlsExtension::new(TlsExtensionType::SERVER_NAME, Vec::new()).unwrap(),
        ];
        let encoded_extensions = extensions
            .iter()
            .flat_map(TlsExtension::to_bytes)
            .collect::<Vec<_>>();

        let mut body = Vec::new();
        body.extend_from_slice(&TlsVersion::TLS12.to_be_bytes());
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
        for cipher_suite in cipher_suites {
            body.extend_from_slice(&cipher_suite.to_be_bytes());
        }
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(encoded_extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&encoded_extensions);

        let client_hello = TlsClientHello::try_from_bytes(&body).unwrap();
        assert_eq!(
            ja3_fingerprint(&client_hello).unwrap(),
            "4eb147fcea0e7960db5e8e2fd1978cfa"
        );
    }

    #[test]
    fn computes_ja3s_like_the_original_implementation() {
        let extensions = [
            TlsExtension::new(TlsExtensionType(0x1a1a), Vec::new()).unwrap(),
            TlsExtension::new(
                TlsExtensionType::SUPPORTED_VERSIONS,
                TlsVersion::TLS13.to_be_bytes().to_vec(),
            )
            .unwrap(),
        ];
        let encoded_extensions = extensions
            .iter()
            .flat_map(TlsExtension::to_bytes)
            .collect::<Vec<_>>();

        let mut body = Vec::new();
        body.extend_from_slice(&TlsVersion::TLS12.to_be_bytes());
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&TlsCipherSuite::TLS_AES_128_GCM_SHA256.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(encoded_extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&encoded_extensions);

        let server_hello = TlsServerHello::try_from_bytes(&body).unwrap();
        assert_eq!(
            ja3s_fingerprint(&server_hello),
            "4e64de91c49a3bfadb26a811b72d64c2"
        );
    }
}
