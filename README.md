# netfp

[![Crates.io](https://img.shields.io/crates/v/netfp.svg)](https://crates.io/crates/netfp)
[![Documentation](https://docs.rs/netfp/badge.svg)](https://docs.rs/netfp)
[![CI](https://github.com/pinanek/netfp/actions/workflows/test.yml/badge.svg)](https://github.com/pinanek/netfp/actions/workflows/test.yml)
[![License](https://img.shields.io/crates/l/netfp.svg)](https://github.com/pinanek/netfp/blob/main/LICENSE)

Rust primitives and implementations for network fingerprinting.

## Supported fingerprints

- [JA3 and JA3S](https://github.com/salesforce/ja3) passive TLS client and server fingerprinting
- [JARM](https://github.com/salesforce/jarm) active TLS server fingerprinting

## Crate features

- `ja3` *(default)* — enables JA3 and JA3S fingerprinting.
- `jarm` *(default)* — enables JARM probe generation and fingerprinting.

## License

Licensed under the [MIT License](https://github.com/pinanek/netfp/blob/main/LICENSE).

## Credit

JA3, JA3S, and JARM were created by Salesforce. Their original implementations
are available in the [JA3](https://github.com/salesforce/ja3) and
[JARM](https://github.com/salesforce/jarm) repositories under the BSD 3-Clause
License.
