//! Types for working with registry access secrets

use std::fmt;

/// A method for authenticating to a registry
#[derive(Eq, PartialEq, Clone)]
pub enum RegistryAuth {
    /// Access the registry anonymously
    Anonymous,
    /// Access the registry using HTTP Basic authentication
    Basic(String, String),
    /// Access the registry using Bearer token authentication
    Bearer(String),
}

impl fmt::Debug for RegistryAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryAuth::Anonymous => write!(f, "Anonymous"),
            RegistryAuth::Basic(username, _) => f
                .debug_tuple("Basic")
                .field(username)
                .field(&"<redacted>")
                .finish(),
            RegistryAuth::Bearer(_) => f.debug_tuple("Bearer").field(&"<redacted>").finish(),
        }
    }
}

pub(crate) trait Authenticable {
    fn apply_authentication(self, auth: &RegistryAuth) -> Self;
}

impl Authenticable for reqwest::RequestBuilder {
    fn apply_authentication(self, auth: &RegistryAuth) -> Self {
        match auth {
            RegistryAuth::Anonymous => self,
            RegistryAuth::Basic(username, password) => self.basic_auth(username, Some(password)),
            RegistryAuth::Bearer(token) => self.bearer_auth(token),
        }
    }
}
