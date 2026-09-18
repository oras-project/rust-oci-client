// A registry may name another host in the blob upload `Location` header. Following it is
// allowed by the distribution specification, sending the registry credentials there is not:
//
// > clients [...] MUST NOT forward Authorization headers across host boundaries unless
// > explicitly configured to do so.
use std::sync::{Arc, Mutex};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{any, get, post},
    Router,
};
use oci_client::{
    client::{ClientConfig, ClientProtocol},
    secrets::RegistryAuth,
    Client, Reference,
};
use tokio::net::TcpListener;

/// `user:pass`
const BASIC_CREDENTIALS: &str = "Basic dXNlcjpwYXNz";
/// A JWT with an empty header and payload. The token cache only reads the payload.
const BEARER_TOKEN: &str = "e30.e30.signature";

/// The `Authorization` header received by the upload endpoint, if the endpoint was reached at
/// all. An empty string means the endpoint was reached without credentials.
type Seen = Arc<Mutex<Option<String>>>;

async fn upload_session(State(seen): State<Seen>, headers: HeaderMap) -> StatusCode {
    let authorization = match headers.get("Authorization") {
        Some(value) => value.to_str().unwrap_or("<not utf-8>").to_string(),
        None => String::new(),
    };
    *seen.lock().unwrap() = Some(authorization);
    StatusCode::ACCEPTED
}

async fn spawn(router: impl FnOnce(&str) -> Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let router = router(&address);
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    address
}

#[derive(Clone, Copy)]
enum Challenge {
    Basic,
    Bearer,
}

/// A registry which starts an upload session pointing at `location`, and which records at
/// `/upload` the credentials it receives there.
fn registry(challenge: Challenge, location: String, seen: Seen) -> Router {
    let token_endpoint = Router::new().route(
        "/token",
        get(|| async { format!(r#"{{"token":"{BEARER_TOKEN}"}}"#) }),
    );

    Router::new()
        .route(
            "/v2/",
            get(move |headers: HeaderMap| async move {
                let www_authenticate = match challenge {
                    Challenge::Basic => "Basic realm=\"registry\"".to_string(),
                    Challenge::Bearer => {
                        let host = headers.get("Host").unwrap().to_str().unwrap();
                        format!("Bearer realm=\"http://{host}/token\",service=\"registry\"")
                    }
                };
                (
                    StatusCode::UNAUTHORIZED,
                    [("WWW-Authenticate", www_authenticate)],
                )
            }),
        )
        .route(
            "/v2/repo/blobs/uploads/",
            post(|| async { (StatusCode::ACCEPTED, [("Location", location)]) }),
        )
        .route("/upload", any(upload_session))
        .merge(token_endpoint)
        .with_state(seen)
}

async fn push_to(registry: &str) {
    let client = Client::new(ClientConfig {
        protocol: ClientProtocol::Http,
        ..Default::default()
    });
    client
        .store_auth_if_needed(
            registry,
            &RegistryAuth::Basic("user".to_string(), "pass".to_string()),
        )
        .await;

    let image = Reference::try_from(format!("{registry}/repo")).unwrap();
    let blob = b"a blob the registry does not have yet".to_vec();
    // Never checked, the fake registry does not verify the digest.
    let digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    // The outcome of the push is irrelevant, what matters is what the upload endpoint saw.
    let _ = client.push_blob(&image, blob, digest).await;
}

#[tokio::test]
async fn no_basic_credentials_for_the_host_named_in_the_location() {
    let seen = Seen::default();
    let elsewhere = spawn(|_| {
        Router::new()
            .route("/upload", any(upload_session))
            .with_state(seen.clone())
    })
    .await;
    let registry_address = spawn(|_| {
        registry(
            Challenge::Basic,
            format!("http://{elsewhere}/upload"),
            Seen::default(),
        )
    })
    .await;

    push_to(&registry_address).await;

    assert_eq!(
        seen.lock().unwrap().clone(),
        Some(String::new()),
        "the host named in the Location should be reached, without credentials"
    );
}

#[tokio::test]
async fn no_bearer_token_for_the_host_named_in_the_location() {
    let seen = Seen::default();
    let elsewhere = spawn(|_| {
        Router::new()
            .route("/upload", any(upload_session))
            .with_state(seen.clone())
    })
    .await;
    let registry_address = spawn(|_| {
        registry(
            Challenge::Bearer,
            format!("http://{elsewhere}/upload"),
            Seen::default(),
        )
    })
    .await;

    push_to(&registry_address).await;

    assert_eq!(
        seen.lock().unwrap().clone(),
        Some(String::new()),
        "the host named in the Location should be reached, without a bearer token"
    );
}

#[tokio::test]
async fn basic_credentials_for_a_location_on_the_registry_itself() {
    let seen = Seen::default();
    let registry_address = spawn(|address| {
        registry(
            Challenge::Basic,
            format!("http://{address}/upload"),
            seen.clone(),
        )
    })
    .await;

    push_to(&registry_address).await;

    assert_eq!(
        seen.lock().unwrap().clone(),
        Some(BASIC_CREDENTIALS.to_string()),
        "an absolute location on the registry should still be authenticated"
    );
}

#[tokio::test]
async fn bearer_token_for_a_location_on_the_registry_itself() {
    let seen = Seen::default();
    let registry_address = spawn(|address| {
        registry(
            Challenge::Bearer,
            format!("http://{address}/upload"),
            seen.clone(),
        )
    })
    .await;

    push_to(&registry_address).await;

    assert_eq!(
        seen.lock().unwrap().clone(),
        Some(format!("Bearer {BEARER_TOKEN}")),
        "an absolute location on the registry should still be authenticated"
    );
}

#[tokio::test]
async fn credentials_for_a_relative_location() {
    let seen = Seen::default();
    let registry_address =
        spawn(|_| registry(Challenge::Basic, "/upload".to_string(), seen.clone())).await;

    push_to(&registry_address).await;

    assert_eq!(
        seen.lock().unwrap().clone(),
        Some(BASIC_CREDENTIALS.to_string()),
        "a relative location should still be authenticated"
    );
}
