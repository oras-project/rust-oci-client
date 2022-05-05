//! An OCI Distribution client for fetching oci images from an OCI compliant remote store
#![deny(missing_docs)]

pub mod client;
pub mod errors;
pub mod manifest;
pub mod oci_annotations;
mod reference;
mod regexp;
pub mod secrets;
mod token_cache;

#[doc(inline)]
pub use client::Client;
#[doc(inline)]
pub use reference::{ParseError, Reference};
#[doc(inline)]
pub use token_cache::RegistryOperation;

#[macro_use]
extern crate lazy_static;
