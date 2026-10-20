//! An OCI Distribution client for fetching oci images from an OCI compliant remote store
//!
//! This crate implements the client side of the
//! [OCI Distribution specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md).
//! Docker Hub and other container registries use this protocol. [`Client`]
//! gives the registry operations, for example pull, push and list tags.
//!
//! # TLS backends
//!
//! This crate has three Cargo features for TLS. If you use the default HTTP
//! transport, you must enable exactly one of them:
//!
//! - `rustls-tls` (default): The client uses `rustls` with its `aws-lc-rs`
//!   crypto provider.
//! - `rustls-tls-no-provider`: The client uses `rustls`, and you supply the
//!   crypto provider. Install the provider before you build a [`Client`].
//! - `native-tls`: The client uses the TLS library of the operating system.
//!
//! You do not have to enable a TLS feature in two cases:
//!
//! - You give the client your own HTTP transport. The transport supplies
//!   TLS.
//! - You build for `wasm32-unknown-unknown`. The browser supplies TLS. The
//!   features have no effect.
//!
//! The next section explains how to use a custom transport.
//!
//! # Custom HTTP transport
//!
//! By default, [`Client`] sends its requests with a reqwest client. An
//! application can have an HTTP stack of its own, for example for a TLS
//! policy, observability or traffic shaping. Such an application can give its
//! stack to [`Client::new_with_transport`]. The [`transport`] module gives the
//! contract that the stack must obey, and an example.
#![deny(missing_docs)]

use sha2::Digest;

pub mod annotations;
mod blob;
pub mod client;
pub mod config;
pub(crate) mod digest;
pub mod errors;
pub mod manifest;
pub mod secrets;
pub mod token_cache;
pub mod transport;

#[doc(inline)]
pub use client::Client;
#[doc(inline)]
pub use oci_spec::distribution::{ParseError, Reference};
#[doc(inline)]
pub use token_cache::RegistryOperation;

/// Computes the SHA256 digest of a byte vector
pub(crate) fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}
