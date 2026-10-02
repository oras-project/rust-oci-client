//! HTTP regressions for the registry's advertised minimum upload chunk length.
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{patch, post},
    Router,
};
use futures_util::stream;
use oci_client::{
    client::{ClientConfig, ClientProtocol},
    errors::{OciDistributionError, Result},
    Client, Reference,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

const MIB: usize = 1024 * 1024;
const UPLOAD: &str = "/v2/example/image/blobs/uploads/session";
#[derive(Default)]
struct UploadState {
    minimum: Option<String>,
    bytes: Vec<u8>,
    chunks: Vec<usize>,
    completed: bool,
}
type Shared = Arc<Mutex<UploadState>>;
struct Registry {
    image: Reference,
    state: Shared,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Registry {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Registry {
    async fn new(minimum: Option<&str>) -> Self {
        let state = Arc::new(Mutex::new(UploadState {
            minimum: minimum.map(str::to_owned),
            ..Default::default()
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/v2/example/image/blobs/uploads/", post(begin))
            .route(UPLOAD, patch(upload).put(finish))
            .layer(DefaultBodyLimit::disable())
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            image: format!("{address}/example/image:fixture").parse().unwrap(),
            state,
            server,
        }
    }
    fn assert_upload(&self, bytes: &[u8], chunks: &[usize]) {
        let state = self.state.lock().unwrap();
        assert!(state.completed, "upload must complete with a PUT");
        assert_eq!(state.bytes, bytes, "all payload bytes must be preserved");
        assert_eq!(state.chunks, chunks);
    }
}
async fn begin(State(state): State<Shared>) -> Response {
    let state = state.lock().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(header::LOCATION, UPLOAD.parse().unwrap());
    if let Some(minimum) = &state.minimum {
        headers.insert("OCI-Chunk-Min-Length", minimum.parse().unwrap());
    }
    (StatusCode::ACCEPTED, headers).into_response()
}
async fn upload(State(state): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let mut state = state.lock().unwrap();
    let minimum = state
        .minimum
        .as_deref()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1);
    // A short PATCH may be the final chunk. Reject it only if another PATCH follows.
    if state
        .chunks
        .last()
        .is_some_and(|previous| *previous < minimum)
    {
        return StatusCode::RANGE_NOT_SATISFIABLE.into_response();
    }
    let expected = format!(
        "{}-{}",
        state.bytes.len(),
        state.bytes.len() + body.len() - 1
    );
    if headers.get("Content-Range").and_then(|v| v.to_str().ok()) != Some(&expected) {
        return StatusCode::RANGE_NOT_SATISFIABLE.into_response();
    }
    state.bytes.extend_from_slice(&body);
    state.chunks.push(body.len());
    (
        StatusCode::ACCEPTED,
        [
            (header::LOCATION, UPLOAD.to_owned()),
            (header::RANGE, format!("0-{}", state.bytes.len() - 1)),
        ],
    )
        .into_response()
}
async fn finish(
    State(state): State<Shared>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let mut state = state.lock().unwrap();
    if query.get("digest") != Some(&digest(&state.bytes)) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    state.completed = true;
    (
        StatusCode::CREATED,
        [(
            header::LOCATION,
            format!("/v2/example/image/blobs/{}", digest(&state.bytes)),
        )],
    )
        .into_response()
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn client() -> Client {
    Client::new(ClientConfig {
        protocol: ClientProtocol::Http,
        ..Default::default()
    })
}
fn small_fragments(
    bytes: Bytes,
) -> impl futures_util::Stream<Item = Result<Bytes>> + Send + 'static {
    // Input stream boundaries deliberately do not match the registry's chunk size.
    stream::iter(
        (0..bytes.len())
            .step_by(128 * 1024)
            .map(move |start| Ok(bytes.slice(start..(start + 128 * 1024).min(bytes.len())))),
    )
}
#[tokio::test]
async fn buffered_upload_honors_minimum_and_final_short_chunk() {
    let registry = Registry::new(Some("5242880")).await;
    let bytes = Bytes::from(vec![0x3b; 11 * MIB + 17]);
    client()
        .push_blob(&registry.image, bytes.clone(), &digest(&bytes))
        .await
        .unwrap();
    registry.assert_upload(&bytes, &[5 * MIB, 5 * MIB, MIB + 17]);
}
#[tokio::test]
async fn streamed_upload_coalesces_short_input_fragments() {
    let registry = Registry::new(Some("5242880")).await;
    let bytes = Bytes::from(vec![0x3c; 11 * MIB + 17]);
    client()
        .push_blob_stream(
            &registry.image,
            small_fragments(bytes.clone()),
            &digest(&bytes),
            None,
        )
        .await
        .unwrap();
    registry.assert_upload(&bytes, &[5 * MIB, 5 * MIB, MIB + 17]);
}
#[tokio::test]
async fn streamed_upload_computes_digest_after_coalescing_fragments() {
    let registry = Registry::new(Some("5242880")).await;
    let bytes = Bytes::from(vec![0x3d; 11 * MIB + 17]);
    let receipt = client()
        .push_blob_stream_chunked(&registry.image, small_fragments(bytes.clone()))
        .await
        .unwrap();
    assert_eq!(receipt.blob_digest, digest(&bytes));
    assert_eq!(receipt.size, bytes.len() as u64);
    registry.assert_upload(&bytes, &[5 * MIB, 5 * MIB, MIB + 17]);
}
#[tokio::test]
async fn absent_or_smaller_minimum_retains_default_chunk_size() {
    let c = client();
    for minimum in [None, Some("1024")] {
        let registry = Registry::new(minimum).await;
        let bytes = Bytes::from(vec![0x3e; 5 * MIB + 17]);
        c.push_blob(&registry.image, bytes.clone(), &digest(&bytes))
            .await
            .unwrap();
        registry.assert_upload(&bytes, &[4 * MIB, MIB + 17]);
    }
}
#[tokio::test]
async fn a_single_final_chunk_can_be_smaller_than_minimum() {
    for mode in 0..3 {
        let registry = Registry::new(Some("5242880")).await;
        let bytes = Bytes::from_static(b"final short chunk");
        let c = client();
        match mode {
            0 => {
                c.push_blob(&registry.image, bytes.clone(), &digest(&bytes))
                    .await
                    .unwrap();
            }
            1 => {
                c.push_blob_stream(
                    &registry.image,
                    small_fragments(bytes.clone()),
                    &digest(&bytes),
                    None,
                )
                .await
                .unwrap();
            }
            _ => {
                c.push_blob_stream_chunked(&registry.image, small_fragments(bytes.clone()))
                    .await
                    .unwrap();
            }
        }
        registry.assert_upload(&bytes, &[bytes.len()]);
    }
}
#[tokio::test]
async fn invalid_minimum_is_rejected_before_polling_stream_or_sending_payload() {
    for minimum in ["0", "-1", "invalid-private-value", "184467440737095516160"] {
        let registry = Registry::new(Some(minimum)).await;
        let unread = stream::poll_fn(|_| -> std::task::Poll<Option<Result<Bytes>>> {
            panic!("invalid header must fail before consuming input")
        });
        let error = client()
            .push_blob_stream(&registry.image, unread, &digest(b"payload"), None)
            .await
            .unwrap_err();
        assert!(matches!(error, OciDistributionError::GenericError(_)));
        assert!(!error.to_string().contains(minimum));
        let state = registry.state.lock().unwrap();
        assert!(state.bytes.is_empty());
        assert!(!state.completed);
    }
}
#[tokio::test]
async fn negotiated_minimum_does_not_change_shared_client_default() {
    let c = client();
    let bytes = Bytes::from(vec![0x3f; 6 * MIB]);
    let first = Registry::new(Some("5242880")).await;
    c.push_blob(&first.image, bytes.clone(), &digest(&bytes))
        .await
        .unwrap();
    first.assert_upload(&bytes, &[5 * MIB, MIB]);
    let second = Registry::new(None).await;
    c.push_blob(&second.image, bytes.clone(), &digest(&bytes))
        .await
        .unwrap();
    second.assert_upload(&bytes, &[4 * MIB, 2 * MIB]);
}

#[tokio::test]
async fn streamed_upload_accepts_large_fragments_and_empty_fragments() {
    let registry = Registry::new(Some("5242880")).await;
    let bytes = Bytes::from(vec![0x40; 11 * MIB + 17]);
    let fragments = stream::iter([
        Ok(Bytes::new()),
        Ok(bytes.slice(..7 * MIB)),
        Ok(Bytes::new()),
        Ok(bytes.slice(7 * MIB..)),
    ]);
    client()
        .push_blob_stream(&registry.image, fragments, &digest(&bytes), None)
        .await
        .unwrap();
    registry.assert_upload(&bytes, &[5 * MIB, 5 * MIB, MIB + 17]);
}

#[tokio::test]
async fn input_error_does_not_commit_pending_bytes_or_complete_upload() {
    let registry = Registry::new(Some("5242880")).await;
    let fragments = stream::iter([
        Ok(Bytes::from(vec![0x41; MIB])),
        Err(OciDistributionError::GenericError(Some(
            "input failed".into(),
        ))),
    ]);
    let error = client()
        .push_blob_stream(&registry.image, fragments, &digest(b"unused"), None)
        .await
        .unwrap_err();
    assert!(matches!(error, OciDistributionError::GenericError(_)));
    let state = registry.state.lock().unwrap();
    assert!(state.bytes.is_empty());
    assert!(!state.completed);
}
