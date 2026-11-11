// A registry says how a request must authenticate in the response to that request:
//
// > If a 401 Unauthorized response is returned, the client should take action based on the
// > contents of the "WWW-Authenticate" header and try the endpoint again.
//
// https://distribution.github.io/distribution/spec/auth/token/
//
// The challenge names the scopes that the registry requires for the request. Registries do
// not agree on them: for the catalog, the distribution registry requires `registry:catalog:*`
// and Zot requires `repository::pull`. The client must send the request, follow the challenge
// that it gets, and send the request again.
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode, Uri},
    routing::get,
    Router,
};
use oci_client::{
    client::{ClientConfig, ClientProtocol},
    secrets::RegistryAuth,
    Client, Reference,
};
use rstest::rstest;
use tokio::net::TcpListener;

/// `user:pass`
const BASIC_CREDENTIALS: &str = "Basic dXNlcjpwYXNz";
/// A JWT with an empty header and payload. The token cache only reads the payload.
const BEARER_TOKEN: &str = "e30.e30.signature";
const TAGS: &str = "/v2/repo/tags/list";
const CATALOG: &str = "/v2/_catalog";

/// How the registry authenticates requests.
#[derive(Clone, Copy)]
enum Authentication {
    None,
    Basic,
    /// Bearer tokens. The registry requires `catalog_scope` for the catalog.
    Bearer {
        catalog_scope: &'static str,
    },
}

/// The path and the `Authorization` header of a request.
type Request = (String, Option<String>);

#[derive(Clone)]
struct Registry {
    authentication: Authentication,
    /// The requests to the registry, in order.
    requests: Arc<Mutex<Vec<Request>>>,
    /// The scopes of each request to the token service, in order.
    token_requests: Arc<Mutex<Vec<Vec<String>>>>,
}

impl Registry {
    fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }

    fn token_requests(&self) -> Vec<Vec<String>> {
        self.token_requests.lock().unwrap().clone()
    }
}

type Response = (StatusCode, [(&'static str, String); 1], &'static str);

fn unauthorized(challenge: String) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", challenge)],
        "",
    )
}

async fn resource(State(registry): State<Registry>, uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path();
    let authorization = headers
        .get("Authorization")
        .map(|value| value.to_str().unwrap_or("<not utf-8>").to_string());
    registry
        .requests
        .lock()
        .unwrap()
        .push((path.to_string(), authorization.clone()));

    match registry.authentication {
        Authentication::None => {}
        Authentication::Basic => {
            if authorization.as_deref() != Some(BASIC_CREDENTIALS) {
                return unauthorized(r#"Basic realm="registry""#.to_string());
            }
        }
        Authentication::Bearer { catalog_scope } => {
            let scope = match path {
                CATALOG => catalog_scope,
                TAGS => "repository:repo:pull",
                _ => "",
            };
            // The last token that the token service granted must cover the request.
            let granted = registry
                .token_requests
                .lock()
                .unwrap()
                .last()
                .is_some_and(|scopes| scope.is_empty() || scopes.iter().any(|s| s == scope));
            let has_token = authorization.as_deref() == Some(&format!("Bearer {BEARER_TOKEN}"));
            if !(has_token && granted) {
                let host = headers.get("Host").unwrap().to_str().unwrap();
                return unauthorized(format!(
                    r#"Bearer realm="http://{host}/token",service="registry",scope="{scope}""#
                ));
            }
        }
    }

    let body = match path {
        CATALOG => r#"{"repositories":["repo"]}"#,
        TAGS => r#"{"name":"repo","tags":["latest"]}"#,
        _ => "{}",
    };
    (
        StatusCode::OK,
        [("Content-Type", "application/json".to_string())],
        body,
    )
}

async fn token(
    State(registry): State<Registry>,
    Query(query): Query<Vec<(String, String)>>,
) -> String {
    let scopes = query
        .into_iter()
        .filter(|(name, _)| name == "scope")
        .map(|(_, scope)| scope)
        .collect();
    registry.token_requests.lock().unwrap().push(scopes);
    format!(r#"{{"token":"{BEARER_TOKEN}"}}"#)
}

async fn spawn(authentication: Authentication) -> (Registry, Reference) {
    let registry = Registry {
        authentication,
        requests: Default::default(),
        token_requests: Default::default(),
    };
    let router = Router::new()
        .route("/v2/", get(resource))
        .route(CATALOG, get(resource))
        .route(TAGS, get(resource))
        .route("/token", get(token))
        .with_state(registry.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let image = Reference::try_from(format!("{address}/repo:latest")).unwrap();
    (registry, image)
}

fn client() -> Client {
    Client::new(ClientConfig {
        protocol: ClientProtocol::Http,
        ..Default::default()
    })
}

fn credentials() -> RegistryAuth {
    RegistryAuth::Basic("user".to_string(), "pass".to_string())
}

fn request(path: &str, authorization: Option<&str>) -> Request {
    (path.to_string(), authorization.map(String::from))
}

#[rstest]
#[case::distribution("registry:catalog:*", &["registry:catalog:*"])]
#[case::zot("repository::pull", &["registry:catalog:*", "repository::pull"])]
#[tokio::test]
#[ignore = "fails until the fix in a later commit"]
async fn the_catalog_gets_a_token_for_the_scope_of_the_challenge(
    #[case] catalog_scope: &'static str,
    #[case] token_scopes: &[&str],
) {
    let (registry, image) = spawn(Authentication::Bearer { catalog_scope }).await;

    let catalog = client()
        .catalog(&image, &credentials(), None, None)
        .await
        .unwrap();

    assert_eq!(catalog.repositories, vec!["repo"]);
    assert_eq!(registry.token_requests(), vec![token_scopes.to_vec()]);
}

#[tokio::test]
#[ignore = "fails until the fix in a later commit"]
async fn a_token_is_fetched_after_the_challenge_and_used_again() {
    let (registry, image) = spawn(Authentication::Bearer {
        catalog_scope: "registry:catalog:*",
    })
    .await;
    let client = client();
    let bearer = format!("Bearer {BEARER_TOKEN}");

    for _ in 0..2 {
        client
            .list_tags(&image, &credentials(), None, None)
            .await
            .unwrap();
    }

    assert_eq!(
        registry.requests(),
        vec![
            request(TAGS, None),
            request(TAGS, Some(&bearer)),
            request(TAGS, Some(&bearer)),
        ]
    );
    assert_eq!(
        registry.token_requests(),
        vec![vec!["repository:repo:pull"]]
    );
}

#[tokio::test]
#[ignore = "fails until the fix in a later commit"]
async fn basic_credentials_are_sent_after_the_challenge_and_used_again() {
    let (registry, image) = spawn(Authentication::Basic).await;
    let client = client();

    for _ in 0..2 {
        client
            .list_tags(&image, &credentials(), None, None)
            .await
            .unwrap();
    }

    assert_eq!(
        registry.requests(),
        vec![
            request(TAGS, None),
            request(TAGS, Some(BASIC_CREDENTIALS)),
            request(TAGS, Some(BASIC_CREDENTIALS)),
        ]
    );
}

#[tokio::test]
#[ignore = "fails until the fix in a later commit"]
async fn a_registry_without_authentication_gets_the_request_only() {
    let (registry, image) = spawn(Authentication::None).await;

    client()
        .list_tags(&image, &credentials(), None, None)
        .await
        .unwrap();

    assert_eq!(registry.requests(), vec![request(TAGS, None)]);
}
