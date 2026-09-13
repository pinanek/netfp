# netfp

Rust primitives and implementations for network fingerprinting.

```toml
[dependencies]
netfp = "0.1"
```

Documentation: <https://docs.rs/netfp>

## Supported fingerprints

- [JARM](https://github.com/salesforce/jarm) active TLS server fingerprinting

## Crate features

- `jarm` *(default)* — enables JARM probe generation and fingerprinting.

## License

Licensed under the [MIT License](https://github.com/pinanek/netfp/blob/main/LICENSE).

## Credit

The JARM algorithm was created by Salesforce and is available from the
[original JARM repository](https://github.com/salesforce/jarm) under the
[BSD 3-Clause License](https://github.com/salesforce/jarm/blob/master/LICENSE.txt).
