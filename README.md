# Rust OCI Client

Formerly known as `oci-distribution`

[![oci-client documentation](https://docs.rs/oci-client/badge.svg)](https://docs.rs/oci-client)

This Rust library implements the
[OCI Distribution specification](https://github.com/opencontainers/distribution-spec/blob/master/spec.md),
which is the protocol that Docker Hub and other container registries use.

## TLS backends

This crate offers three Cargo features for TLS, you must enable exactly one of them.

- `rustls-tls` (default): Uses the `rustls` library with its built-in `aws-lc-rs` crypto provider.
- `rustls-tls-no-provider`: Uses `rustls`, but leaves the crypto provider to you. Before you build a `Client`, install one, for example with `rustls::crypto::ring::default_provider().install_default()`. Choose this feature when your application already picks a crypto provider and you want to avoid `aws-lc-rs`.
- `native-tls`: Uses the TLS library of your operating system instead of `rustls`.

## Code of Conduct

This project has adopted the [CNCF Code of
Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).
