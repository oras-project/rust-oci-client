// The distribution spec requires the registry to return a `Location` header on a successful
// manifest push, but only constrains it to be "a pullable manifest URL" -- it does not have to
// end with the digest. Registries such as Forgejo/Gitea return a URL ending with the tag that
// was pushed, not the digest:
// https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#pushing-manifests
//
// `push_manifest`/`push_manifest_raw` therefore return the digest computed locally rather than
// asking the caller to parse it out of the `Location` header. These tests pin that behavior,
// including the pre-existing fallback for registries (such as AWS ECR) that omit the `Location`
// header entirely, and the hard error raised when a registry's `Docker-Content-Digest` disagrees
// with the digest computed locally.
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    routing::put,
    Router,
};
use oci_client::{
    client::{ClientConfig, ClientProtocol},
    errors::{DigestError, OciDistributionError},
    Client, Reference,
};
use sha2::{Digest as _, Sha256};
use tokio::net::TcpListener;

const REPO: &str = "repo";
const TAG: &str = "v0.0.1";
/// Deliberately does not need to be a valid OCI manifest: the fake registry never parses it, it
/// only hashes the bytes it received.
const MANIFEST_BODY: &[u8] = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},"layers":[]}"#;
const WRONG_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const MANIFEST_CONTENT_TYPE: HeaderValue =
    HeaderValue::from_static("application/vnd.oci.image.manifest.v1+json");

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[derive(Clone, Copy)]
enum Mode {
    /// `Location` ends with the tag that was pushed, and `Docker-Content-Digest` matches the
    /// body the server received.
    TagLocationMatchingDigest,
    /// No `Location` header at all, mirroring the AWS ECR spec violation the client already
    /// works around.
    NoLocation,
    /// `Location` is present, but `Docker-Content-Digest` disagrees with the body the server
    /// received.
    MismatchedDigest,
}

async fn upload_manifest(State(mode): State<Mode>, body: Bytes) -> (StatusCode, HeaderMap) {
    let mut headers = HeaderMap::new();
    match mode {
        Mode::TagLocationMatchingDigest => {
            headers.insert(
                "Location",
                format!("/v2/{REPO}/manifests/{TAG}").parse().unwrap(),
            );
            headers.insert(
                "Docker-Content-Digest",
                sha256_digest(&body).parse().unwrap(),
            );
        }
        Mode::NoLocation => {
            // Intentionally no `Location` and no `Docker-Content-Digest` header.
        }
        Mode::MismatchedDigest => {
            headers.insert(
                "Location",
                format!("/v2/{REPO}/manifests/{TAG}").parse().unwrap(),
            );
            headers.insert("Docker-Content-Digest", WRONG_DIGEST.parse().unwrap());
        }
    }
    (StatusCode::CREATED, headers)
}

/// Starts a fake registry that only implements `PUT /v2/repo/manifests/<reference>`, and
/// returns its address together with a `Client` configured to talk to it over plain HTTP.
async fn spawn(mode: Mode) -> (String, Client) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let app = Router::new()
        .route(
            &format!("/v2/{REPO}/manifests/{{reference}}"),
            put(upload_manifest),
        )
        .with_state(mode);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = Client::new(ClientConfig {
        protocol: ClientProtocol::Http,
        ..Default::default()
    });
    (address, client)
}

#[tokio::test]
async fn tag_location_is_returned_unchanged_alongside_the_local_digest() {
    let (address, client) = spawn(Mode::TagLocationMatchingDigest).await;
    let reference: Reference = format!("{address}/{REPO}:{TAG}").parse().unwrap();

    let response = client
        .push_manifest_raw(&reference, MANIFEST_BODY, MANIFEST_CONTENT_TYPE)
        .await
        .expect("push_manifest_raw should succeed");

    assert_eq!(response.digest, sha256_digest(MANIFEST_BODY));
    assert_eq!(
        response.url,
        format!("http://{address}/v2/{REPO}/manifests/{TAG}"),
        "the tag URL returned by the registry must be passed through unchanged"
    );
}

#[tokio::test]
async fn missing_location_falls_back_to_a_digest_based_url() {
    let (address, client) = spawn(Mode::NoLocation).await;
    let reference: Reference = format!("{address}/{REPO}:{TAG}").parse().unwrap();

    let response = client
        .push_manifest_raw(&reference, MANIFEST_BODY, MANIFEST_CONTENT_TYPE)
        .await
        .expect("push_manifest_raw should fall back when Location is missing");

    let expected_digest = sha256_digest(MANIFEST_BODY);
    assert_eq!(response.digest, expected_digest);
    assert_eq!(
        response.url,
        format!("http://{address}/v2/{REPO}/manifests/{expected_digest}"),
        "without a Location header the URL must be derived from the locally computed digest"
    );
}

#[tokio::test]
async fn mismatched_docker_content_digest_is_a_hard_error() {
    let (address, client) = spawn(Mode::MismatchedDigest).await;
    let reference: Reference = format!("{address}/{REPO}:{TAG}").parse().unwrap();

    let err = client
        .push_manifest_raw(&reference, MANIFEST_BODY, MANIFEST_CONTENT_TYPE)
        .await
        .expect_err(
            "a Docker-Content-Digest that disagrees with the local digest must be rejected",
        );

    match err {
        OciDistributionError::DigestError(DigestError::VerificationError { expected, actual }) => {
            assert_eq!(expected, sha256_digest(MANIFEST_BODY));
            assert_eq!(actual, WRONG_DIGEST);
        }
        other => panic!("expected a digest verification error, got {other:?}"),
    }
}
