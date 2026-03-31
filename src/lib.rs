//! An OCI Distribution client for fetching oci images from an OCI compliant remote store
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
mod token_cache;

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

#[cfg(test)]
mod test_helpers {
    use std::sync::OnceLock;

    static PROVIDER_INIT: OnceLock<()> = OnceLock::new();

    pub(crate) fn jsonwebtoken_install_default_crypto_provider() {
        PROVIDER_INIT.get_or_init(|| {
            let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
        });
    }
}
