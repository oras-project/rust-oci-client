//! Token cache for OCI registry authentication

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
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
pub enum RegistryToken {
    /// Token value
    Token {
        /// The string value of the token
        token: String,
    },
    /// AccessToken value
    AccessToken {
        /// The string value of the access_token
        access_token: String,
    },
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
/// Type of registry auth token
pub enum RegistryTokenType {
    /// Bearer auth token type
    Bearer(RegistryToken),
    /// Basic auth token type
    Basic(String, String),
}

impl RegistryToken {
    /// Returns the bearer token in a form suitable to use for an Authorization header
    pub fn bearer_token(&self) -> String {
        format!("Bearer {}", self.token())
    }

    /// Returns the token value
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
/// A cache to hold authentication tokens
pub struct TokenCache {
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

    /// Insert a token corresponding to reference and operation keys
    pub async fn insert(
        &self,
        reference: &Reference,
        op: RegistryOperation,
        token: RegistryTokenType,
    ) {
        let expiration = match token {
            RegistryTokenType::Basic(_, _) => u64::MAX,
            RegistryTokenType::Bearer(ref t) => {
                match bearer_token_cache_expiration(t.token(), self.default_expiration_secs) {
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

/// The longest time we keep a bearer token in the cache, even when its claimed
/// expiration is further in the future.
const MAX_TOKEN_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// Picks a cache eviction time for a bearer token.
///
/// This function reads the unverified `exp` claim from the token payload. It
/// does not check the token signature, and it must not be used to decide
/// whether the token is valid. The registry that issued the token is the
/// only party that can make that decision; this cache only avoids
/// requesting a new token before the old one expires.
///
/// A bearer token can be a JWT (a signed token with three base64 parts) or
/// an opaque string, as GHCR issues. This function returns `None` only when
/// the token looks like a JWT but its payload is not valid base64 or valid
/// JSON, because we then cannot tell how long the token lasts.
fn bearer_token_cache_expiration(token_str: &str, default_expiration_secs: usize) -> Option<u64> {
    let mut parts = token_str.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        // The token is not a JWT (e.g., an opaque token issued by registries
        // like GHCR). Use the default expiration as a best-effort assumption,
        // mirroring the behaviour for JWT tokens that carry no `exp` claim.
        debug!(
            "Bearer token is not a JWT, assuming a {} seconds validity",
            default_expiration_secs
        );
        return Some(default_expiration(default_expiration_secs));
    };

    // Registry tokens are opaque credentials. We only inspect the untrusted payload
    // to choose a cache eviction time; signature verification is neither required nor
    // useful here because the registry that issued the token also controls its lifetime.
    let payload = match URL_SAFE_NO_PAD.decode(payload) {
        Ok(payload) => payload,
        Err(error) => {
            warn!(?error, "Invalid bearer token payload encoding");
            return None;
        }
    };
    let claims: BearerTokenClaims = match serde_json::from_slice(&payload) {
        Ok(claims) => claims,
        Err(error) => {
            warn!(?error, "Invalid bearer token payload");
            return None;
        }
    };

    let exp = match claims.exp {
        Some(exp) => exp,
        None => {
            // The token doesn't have a claim that states a value for the expiration.
            // The registry auth specification defaults such tokens to 60 seconds:
            // https://distribution.github.io/distribution/spec/auth/token/
            debug!(
                "Cannot extract expiration from token's claims, assuming a {} seconds validity",
                default_expiration_secs
            );
            default_expiration(default_expiration_secs)
        }
    };

    // Cap the cache TTL so that a token with a far-future or malicious `exp`
    // claim cannot pin a stale token in the cache indefinitely. The registry
    // still rejects an expired or revoked token on the next real request.
    let max_exp = default_expiration(MAX_TOKEN_CACHE_TTL_SECS as usize);
    Some(exp.min(max_exp))
}

fn default_expiration(default_expiration_secs: usize) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
        + default_expiration_secs as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::distribution::Reference;
    use rstest::rstest;
    use serde::Serialize;

    // An opaque token as issued by registries like GHCR — not a JWT.
    const OPAQUE_TOKEN: &str = "ghs_exampleOpaqueTokenFromGHCR1234567890";

    #[derive(Serialize)]
    struct ClaimsWithExp {
        exp: u64,
    }

    #[derive(Serialize)]
    struct ClaimsWithoutExp {
        sub: &'static str,
    }

    fn make_jwt_with_exp(exp: u64) -> String {
        make_jwt(&ClaimsWithExp { exp })
    }

    fn make_jwt_without_exp() -> String {
        make_jwt(&ClaimsWithoutExp { sub: "test" })
    }

    fn make_jwt(claims: &impl Serialize) -> String {
        let payload = serde_json::to_vec(claims).expect("failed to serialize JWT claims");
        format!("e30.{}.signature", URL_SAFE_NO_PAD.encode(payload))
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn jwt_with_near_exp_uses_claims_expiration() {
        let exp = now_secs() + 3600;
        let token = make_jwt_with_exp(exp);
        let cached_exp = bearer_token_cache_expiration(&token, 60)
            .expect("should return Some for valid JWT with exp");
        assert_eq!(cached_exp, exp);
    }

    #[test]
    fn jwt_with_far_future_exp_is_capped() {
        // A claimed expiration far in the future (year 2286) must not pin the
        // cached token for that long. We cap the cache TTL instead.
        let token = make_jwt_with_exp(9999999999);
        let before = now_secs();
        let cached_exp = bearer_token_cache_expiration(&token, 60)
            .expect("should return Some for valid JWT with exp");
        let after = now_secs();
        assert!(cached_exp < 9999999999);
        assert!(cached_exp >= before + MAX_TOKEN_CACHE_TTL_SECS);
        assert!(cached_exp <= after + MAX_TOKEN_CACHE_TTL_SECS);
    }

    /// Tokens whose `exp` claim cannot be read fall back to the default
    /// expiration: a JWT with no `exp` claim, an opaque token (as GHCR
    /// issues), and a JWE-style token (5 dot-separated parts, which is not a
    /// JWT we can read a claim from).
    #[rstest]
    #[case::jwt_without_exp(make_jwt_without_exp())]
    #[case::opaque_token(OPAQUE_TOKEN.to_string())]
    #[case::five_part_jwe("a.b.c.d.e".to_string())]
    fn token_without_readable_exp_uses_default_expiration(#[case] token: String) {
        let before = now_secs();
        let exp = bearer_token_cache_expiration(&token, 60)
            .expect("should return Some with default expiration");
        let after = now_secs();
        assert!(exp >= before + 60);
        assert!(exp <= after + 60);
    }

    /// A token that looks like a JWT (three dot-separated parts) but whose
    /// payload cannot be read as a bearer token's claims returns `None`, so
    /// the caller does not cache it.
    #[rstest]
    #[case::invalid_base64("not-valid-base64!!!".to_string())]
    #[case::empty_segment("".to_string())]
    // `URL_SAFE_NO_PAD` rejects a payload that carries `=` padding.
    #[case::padded_base64("eyJzdWIiOiJ0ZXN0In0=".to_string())]
    #[case::not_json(URL_SAFE_NO_PAD.encode(b"not json"))]
    #[case::exp_as_string(URL_SAFE_NO_PAD.encode(br#"{"exp":"9999999999"}"#))]
    #[case::exp_negative(URL_SAFE_NO_PAD.encode(br#"{"exp":-1}"#))]
    #[case::exp_float(URL_SAFE_NO_PAD.encode(br#"{"exp":1.5}"#))]
    fn malformed_jwt_payload_returns_none(#[case] payload: String) {
        let token = format!("e30.{payload}.signature");
        assert!(bearer_token_cache_expiration(&token, 60).is_none());
    }

    #[tokio::test]
    async fn opaque_token_is_cached() {
        let cache = TokenCache::new(60);
        let reference: Reference = "ghcr.io/kubewarden/policies/pod-privileged:v1.0.10"
            .parse()
            .unwrap();
        let token = RegistryTokenType::Bearer(RegistryToken::Token {
            token: OPAQUE_TOKEN.to_string(),
        });

        cache
            .insert(&reference, RegistryOperation::Pull, token)
            .await;

        assert!(
            cache
                .get(&reference, RegistryOperation::Pull)
                .await
                .is_some(),
            "opaque bearer token should be cached"
        );
    }
}
