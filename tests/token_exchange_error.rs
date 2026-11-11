// When the token service of a registry refuses a token request, the client must report that
// refusal. It must not go on to send the request to the registry without credentials, which
// hides the reason (a wrong password, a scope the account does not have) behind a generic 401
// from the registry.
use std::sync::{Arc, Mutex};

use axum::{
    extract::{RawQuery, State},
    http::{HeaderMap, StatusCode, Uri},
    routing::{get, post},
    Router,
};
use oci_client::{
    client::{ClientConfig, ClientProtocol},
    errors::OciDistributionError,
    secrets::RegistryAuth,
    Client, Reference,
};
use tokio::net::TcpListener;

const TOKEN_SERVICE_REASON: &str = "invalid username or password";
/// A JWT with an empty header and payload. The token cache only reads the payload.
const BEARER_TOKEN: &str = "e30.e30.signature";

/// The path and the `Authorization` header of each request the registry received, in order.
/// The `/v2/` endpoint and the token service are not recorded.
type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// Which token requests the token service refuses.
#[derive(Clone, Copy)]
enum Refuse {
    Every,
    PushScope,
}

fn challenge(headers: &HeaderMap) -> [(&'static str, String); 1] {
    let host = headers.get("Host").unwrap().to_str().unwrap();
    [(
        "WWW-Authenticate",
        format!("Bearer realm=\"http://{host}/token\",service=\"registry\""),
    )]
}

/// Records the request. Accepts it when it carries the bearer token, and challenges otherwise.
async fn resource(
    State(seen): State<Seen>,
    uri: Uri,
    headers: HeaderMap,
) -> (StatusCode, [(&'static str, String); 1], &'static str) {
    let authorization = headers
        .get("Authorization")
        .map(|value| value.to_str().unwrap_or("<not utf-8>").to_string());
    let authorized = authorization.as_deref() == Some(&format!("Bearer {BEARER_TOKEN}"));
    seen.lock()
        .unwrap()
        .push((uri.path().to_string(), authorization));
    if authorized {
        (
            StatusCode::OK,
            [("Content-Type", "application/json".to_string())],
            r#"{"name":"repo","tags":["latest"]}"#,
        )
    } else {
        (StatusCode::UNAUTHORIZED, challenge(&headers), "")
    }
}

/// A registry with bearer authentication, whose token service refuses the requests that
/// `refuse` selects.
async fn spawn(refuse: Refuse, seen: Seen) -> String {
    let token = move |RawQuery(query): RawQuery| async move {
        let push = query.unwrap_or_default().contains("push");
        match (refuse, push) {
            (Refuse::Every, _) | (Refuse::PushScope, true) => {
                (StatusCode::UNAUTHORIZED, TOKEN_SERVICE_REASON.to_string())
            }
            (Refuse::PushScope, false) => {
                (StatusCode::OK, format!(r#"{{"token":"{BEARER_TOKEN}"}}"#))
            }
        }
    };
    let router = Router::new()
        .route(
            "/v2/",
            get(
                |headers: HeaderMap| async move { (StatusCode::UNAUTHORIZED, challenge(&headers)) },
            ),
        )
        .route("/token", get(token))
        .route("/v2/repo/tags/list", get(resource))
        .route("/v2/repo/blobs/uploads/", post(resource))
        .with_state(seen);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    address
}

fn client() -> Client {
    Client::new(ClientConfig {
        protocol: ClientProtocol::Http,
        ..Default::default()
    })
}

fn assert_token_service_refusal(err: &OciDistributionError) {
    assert!(
        matches!(err, OciDistributionError::AuthenticationFailure(reason) if reason == TOKEN_SERVICE_REASON),
        "expected the refusal of the token service, got {err:?}"
    );
}

#[tokio::test]
#[ignore = "fails until the fix in the next commit"]
async fn a_refused_token_request_is_reported() {
    let seen = Seen::default();
    let registry = spawn(Refuse::Every, seen.clone()).await;
    let image = Reference::try_from(format!("{registry}/repo:latest")).unwrap();
    let auth = RegistryAuth::Basic("user".to_string(), "wrong".to_string());

    let err = client()
        .list_tags(&image, &auth, None, None)
        .await
        .unwrap_err();

    assert_token_service_refusal(&err);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![],
        "the registry should not receive the request once the token request was refused"
    );
}

#[tokio::test]
#[ignore = "fails until the fix in the next commit"]
async fn a_refused_anonymous_token_request_is_reported() {
    let seen = Seen::default();
    let registry = spawn(Refuse::Every, seen.clone()).await;
    let image = Reference::try_from(format!("{registry}/repo:latest")).unwrap();

    let err = client()
        .list_tags(&image, &RegistryAuth::Anonymous, None, None)
        .await
        .unwrap_err();

    assert_token_service_refusal(&err);
    assert_eq!(*seen.lock().unwrap(), vec![]);
}

#[tokio::test]
#[ignore = "fails until the fix in the next commit"]
async fn a_token_request_refused_for_another_scope_is_reported() {
    let seen = Seen::default();
    let registry = spawn(Refuse::PushScope, seen.clone()).await;
    let image = Reference::try_from(format!("{registry}/repo:latest")).unwrap();
    let auth = RegistryAuth::Basic("user".to_string(), "password".to_string());
    let client = client();

    // The pull token is granted, so the client holds working credentials for the registry.
    client.list_tags(&image, &auth, None, None).await.unwrap();

    let err = client
        .push_blob(&image, b"blob".to_vec(), "sha256:unused")
        .await
        .unwrap_err();

    assert_token_service_refusal(&err);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(
            "/v2/repo/tags/list".to_string(),
            Some(format!("Bearer {BEARER_TOKEN}"))
        )],
        "the registry should receive the pull request only"
    );
}
