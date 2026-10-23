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
//!
//! # Blocking client
//!
//! `blocking::Client` mirrors [`Client`] for use from synchronous Rust
//! code. It requires the `blocking` feature. It takes a custom transport
//! the same way [`Client`] does.
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use sha2::Digest;

pub mod annotations;
mod blob;
#[cfg(all(feature = "blocking", not(target_arch = "wasm32")))]
pub mod blocking;
#[cfg(all(feature = "blocking", target_arch = "wasm32"))]
compile_error!(
    "the `blocking` feature needs OS threads for its background thread. \
     `wasm32` targets have no OS threads"
);
pub mod client;
pub mod config;
pub(crate) mod digest;
pub mod errors;
pub mod manifest;
pub mod secrets;
pub mod token_cache;
pub mod transport;
mod types;

#[doc(inline)]
pub use client::Client;
#[doc(inline)]
pub use oci_spec::distribution::{ParseError, Reference};
#[doc(inline)]
pub use token_cache::RegistryOperation;

/// Default value for `ClientConfig::max_concurrent_upload`
pub const DEFAULT_MAX_CONCURRENT_UPLOAD: usize = 16;

/// Default value for `ClientConfig::max_concurrent_download`
pub const DEFAULT_MAX_CONCURRENT_DOWNLOAD: usize = 16;

/// Default value for `ClientConfig::default_token_expiration_secs`
pub const DEFAULT_TOKEN_EXPIRATION_SECS: usize = 60;

pub(crate) static DEFAULT_USER_AGENT: &str =
    concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// Media types accepted when pulling a manifest from the registry
pub(crate) const MIME_TYPES_DISTRIBUTION_MANIFEST: &[&str] = &[
    manifest::IMAGE_MANIFEST_MEDIA_TYPE,
    manifest::IMAGE_MANIFEST_LIST_MEDIA_TYPE,
    manifest::OCI_IMAGE_MEDIA_TYPE,
    manifest::OCI_IMAGE_INDEX_MEDIA_TYPE,
];

/// Maximum size of a single chunk when pushing a blob in chunks
pub(crate) const PUSH_CHUNK_MAX_SIZE: usize = 4096 * 1024;

/// Computes the SHA256 digest of a byte vector
pub(crate) fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}
