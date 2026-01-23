use oci_spec::distribution::Reference;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// A token granted during the OAuth2-like workflow for OCI registries.
#[derive(Deserialize, Clone)]
#[serde(untagged)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RegistryToken {
    Token { token: String },
    AccessToken { access_token: String },
}

impl fmt::Debug for RegistryToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted = String::from("<redacted>");
        match self {
            RegistryToken::Token { .. } => {
                f.debug_struct("Token").field("token", &redacted).finish()
            }
            RegistryToken::AccessToken { .. } => f
                .debug_struct("AccessToken")
                .field("access_token", &redacted)
                .finish(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum RegistryTokenType {
    Bearer(RegistryToken),
    Basic(String, String),
}

impl RegistryToken {
    pub fn bearer_token(&self) -> String {
        format!("Bearer {}", self.token())
    }

    pub fn token(&self) -> &str {
        match self {
            RegistryToken::Token { token } => token,
            RegistryToken::AccessToken { access_token } => access_token,
        }
    }
}

/// Desired operation for registry authentication
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegistryOperation {
    /// Authenticate for push operations
    Push,
    /// Authenticate for pull operations
    Pull,
}

#[derive(Debug, Deserialize)]
struct BearerTokenClaims {
    exp: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TokenCacheKey {
    registry: String,
    repository: String,
    operation: RegistryOperation,
}

struct TokenCacheValue {
    token: RegistryTokenType,
    expiration: u64,
}

#[derive(Clone)]
pub(crate) struct TokenCache {
    // (registry, repository, scope) -> (token, expiration)
    tokens: Arc<RwLock<BTreeMap<TokenCacheKey, TokenCacheValue>>>,
    /// Default token expiration in seconds, to use when claim doesn't specify a value
    pub default_expiration_secs: usize,
}

impl TokenCache {
    pub(crate) fn new(default_expiration_secs: usize) -> Self {
        TokenCache {
            tokens: Arc::new(RwLock::new(BTreeMap::new())),
            default_expiration_secs,
        }
    }

    pub(crate) async fn insert(
        &self,
        reference: &Reference,
        op: RegistryOperation,
        token: RegistryTokenType,
    ) {
        let expiration = match token {
            RegistryTokenType::Basic(_, _) => u64::MAX,
            RegistryTokenType::Bearer(ref t) => {
                match parse_expiration_from_jwt(t.token(), self.default_expiration_secs) {
                    Some(value) => value,
                    None => return,
                }
            }
        };
        let registry = reference.resolve_registry().to_string();
        let repository = reference.repository().to_string();
        debug!(%registry, %repository, ?op, %expiration, "Inserting token");
        self.tokens.write().await.insert(
            TokenCacheKey {
                registry,
                repository,
                operation: op,
            },
            TokenCacheValue { token, expiration },
        );
    }

    pub(crate) async fn get(
        &self,
        reference: &Reference,
        op: RegistryOperation,
    ) -> Option<RegistryTokenType> {
        let registry = reference.resolve_registry().to_string();
        let repository = reference.repository().to_string();
        let key = TokenCacheKey {
            registry,
            repository,
            operation: op,
        };
        match self.tokens.read().await.get(&key) {
            Some(TokenCacheValue {
                ref token,
                expiration,
            }) => {
                let now = SystemTime::now();
                let epoch = now
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs();
                if epoch > *expiration {
                    debug!(%key.registry, %key.repository, ?key.operation, %expiration, miss=false, expired=true, "Fetching token");
                    None
                } else {
                    debug!(%key.registry, %key.repository, ?key.operation, %expiration, miss=false, expired=false, "Fetching token");
                    Some(token.clone())
                }
            }
            None => {
                debug!(%key.registry, %key.repository, ?key.operation, miss = true, "Fetching token");
                None
            }
        }
    }
}

fn parse_expiration_from_jwt(token_str: &str, default_expiration_secs: usize) -> Option<u64> {
    match jsonwebtoken::dangerous::insecure_decode::<BearerTokenClaims>(token_str) {
        Ok(token) => {
            let token_exp = match token.claims.exp {
                Some(exp) => exp,
                None => {
                    // the token doesn't have a claim that states a
                    // value for the expiration. We assume it has a 60
                    // seconds validity as indicated here:
                    // https://docs.docker.com/reference/api/registry/auth/#token-response-fields
                    // > (Optional) The duration in seconds since the token was issued
                    // > that it will remain valid. When omitted, this defaults to 60 seconds.
                    // > For compatibility with older clients, a token should never be returned
                    // > with less than 60 seconds to live.
                    let now = SystemTime::now();
                    let epoch = now
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_secs();
                    let expiration = epoch + default_expiration_secs as u64;
                    debug!(?token, "Cannot extract expiration from token's claims, assuming a {} seconds validity", default_expiration_secs);
                    expiration
                }
            };

            Some(token_exp)
        }
        Err(error) => {
            warn!(?error, "Invalid bearer token");
            None
        }
    }
}
