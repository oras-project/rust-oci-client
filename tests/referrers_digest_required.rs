// The referrers API is defined on the digest of a manifest:
//
// > GET /v2/<name>/referrers/<digest>
//
// A reference by tag has no digest. The client must say so in an error that the caller can
// match on, and it must not send a request.
use std::sync::{Arc, Mutex};

use axum::{
    extract::State,
    http::{StatusCode, Uri},
    routing::get,
    Router,
};
use oci_client::{
    client::{ClientConfig, ClientProtocol},
    Client, Reference,
};
use tokio::net::TcpListener;

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const EMPTY_INDEX: &str =
    r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#;

/// The path of each request the registry received, in order.
type Seen = Arc<Mutex<Vec<String>>>;

async fn referrers(
    State(seen): State<Seen>,
    uri: Uri,
) -> (StatusCode, [(&'static str, &'static str); 1], &'static str) {
    seen.lock().unwrap().push(uri.path().to_string());
    (
        StatusCode::OK,
        [("Content-Type", "application/vnd.oci.image.index.v1+json")],
        EMPTY_INDEX,
    )
}

/// A registry which has no referrers for any manifest.
async fn spawn(seen: Seen) -> String {
    let router = Router::new()
        .route("/v2/repo/referrers/{digest}", get(referrers))
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

#[tokio::test]
#[ignore = "fails until the fix in the next commit"]
async fn the_referrers_of_a_reference_by_tag_need_a_digest() {
    let seen = Seen::default();
    let registry = spawn(seen.clone()).await;
    let image = Reference::try_from(format!("{registry}/repo:latest")).unwrap();

    let err = client().pull_referrers(&image, None).await.unwrap_err();

    assert_eq!(
        err.to_string(),
        format!("Reference {registry}/repo:latest has no digest, and this operation requires one")
    );
    assert_eq!(
        *seen.lock().unwrap(),
        Vec::<String>::new(),
        "the registry should not receive a request"
    );
}

#[tokio::test]
async fn a_reference_with_a_tag_and_a_digest_is_accepted() {
    let seen = Seen::default();
    let registry = spawn(seen.clone()).await;
    let image = Reference::try_from(format!("{registry}/repo:latest@{DIGEST}")).unwrap();

    let index = client().pull_referrers(&image, None).await.unwrap();

    assert!(index.manifests.is_empty());
    assert_eq!(
        *seen.lock().unwrap(),
        vec![format!("/v2/repo/referrers/{DIGEST}")]
    );
}
