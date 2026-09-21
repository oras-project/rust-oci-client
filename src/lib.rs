//! An OCI Distribution client for fetching oci images from an OCI compliant remote store
#![deny(missing_docs)]

use sha2::Digest;

pub mod annotations;
mod blob;
#[cfg(feature = "blocking")]
pub mod blocking;
pub mod client;
pub mod config;
pub(crate) mod digest;
pub mod errors;
pub mod manifest;
pub mod secrets;
pub mod token_cache;
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
