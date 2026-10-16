//! HTTP regressions for the registry's advertised minimum upload chunk length.
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{patch, post},
    Router,
};
use futures_util::{stream, StreamExt};
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
    patch_calls: usize,
    put_calls: usize,
    reject_patch: bool,
    begin_status: Option<StatusCode>,
    omit_location: bool,
    received: Arc<tokio::sync::Notify>,
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
    if !state.omit_location {
        headers.insert(header::LOCATION, UPLOAD.parse().unwrap());
    }
    if let Some(minimum) = &state.minimum {
        headers.insert("OCI-Chunk-Min-Length", minimum.parse().unwrap());
    }
    (state.begin_status.unwrap_or(StatusCode::ACCEPTED), headers).into_response()
}
async fn upload(State(state): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let mut state = state.lock().unwrap();
    state.patch_calls += 1;
    if state.reject_patch {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
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
    state.received.notify_one();
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
    state.put_calls += 1;
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
// Each eight-byte position has a distinct value, exposing reordered or duplicated fragments.
fn payload(len: usize) -> Bytes {
    Bytes::from(
        (0u64..)
            .flat_map(u64::to_le_bytes)
            .take(len)
            .collect::<Vec<_>>(),
    )
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
    let bytes = payload(11 * MIB + 17);
    client()
        .push_blob(&registry.image, bytes.clone(), &digest(&bytes))
        .await
        .unwrap();
    registry.assert_upload(&bytes, &[5 * MIB, 5 * MIB, MIB + 17]);
}
#[tokio::test]
async fn streamed_upload_coalesces_short_input_fragments() {
    let registry = Registry::new(Some("5242880")).await;
    let bytes = payload(11 * MIB + 17);
    push_stream(
        StreamApi::KnownDigest,
        &client(),
        &registry.image,
        small_fragments(bytes.clone()),
        &bytes,
    )
    .await
    .unwrap();
    registry.assert_upload(&bytes, &[5 * MIB, 5 * MIB, MIB + 17]);
}
#[tokio::test]
async fn streamed_upload_computes_digest_after_coalescing_fragments() {
    let registry = Registry::new(Some("5242880")).await;
    let bytes = payload(11 * MIB + 17);
    push_stream(
        StreamApi::ComputedDigest,
        &client(),
        &registry.image,
        small_fragments(bytes.clone()),
        &bytes,
    )
    .await
    .unwrap();
    registry.assert_upload(&bytes, &[5 * MIB, 5 * MIB, MIB + 17]);
}
#[tokio::test]
async fn absent_or_smaller_minimum_retains_default_chunk_size() {
    let c = client();
    for minimum in [None, Some("1024")] {
        let registry = Registry::new(minimum).await;
        let bytes = payload(5 * MIB + 17);
        c.push_blob(&registry.image, bytes.clone(), &digest(&bytes))
            .await
            .unwrap();
        registry.assert_upload(&bytes, &[4 * MIB, MIB + 17]);
    }
}
#[tokio::test]
async fn a_single_final_chunk_can_be_smaller_than_minimum() {
    let bytes = Bytes::from_static(b"final short chunk");
    let c = client();
    let registry = Registry::new(Some("5242880")).await;
    c.push_blob(&registry.image, bytes.clone(), &digest(&bytes))
        .await
        .unwrap();
    registry.assert_upload(&bytes, &[bytes.len()]);
    for api in [StreamApi::KnownDigest, StreamApi::ComputedDigest] {
        let registry = Registry::new(Some("5242880")).await;
        push_stream(
            api,
            &c,
            &registry.image,
            small_fragments(bytes.clone()),
            &bytes,
        )
        .await
        .unwrap();
        registry.assert_upload(&bytes, &[bytes.len()]);
    }
}
#[tokio::test]
async fn invalid_minimum_is_rejected_before_polling_stream_or_sending_payload() {
    for minimum in ["-1", "invalid-private-value", "184467440737095516160"] {
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
    let bytes = payload(6 * MIB);
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
    let bytes = payload(11 * MIB + 17);
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
        Ok(payload(MIB)),
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

#[derive(Clone, Copy, Debug)]
enum StreamApi {
    KnownDigest,
    ComputedDigest,
}

async fn push_stream(
    api: StreamApi,
    c: &Client,
    image: &Reference,
    input: impl futures_util::Stream<Item = Result<Bytes>> + Send + 'static,
    bytes: &[u8],
) -> Result<()> {
    match api {
        StreamApi::KnownDigest => c
            .push_blob_stream(image, input, &digest(bytes), None)
            .await
            .map(|_| ()),
        StreamApi::ComputedDigest => {
            let receipt = c.push_blob_stream_chunked(image, input).await?;
            assert_eq!(receipt.blob_digest, digest(bytes));
            assert_eq!(receipt.size, bytes.len() as u64);
            Ok(())
        }
    }
}

async fn assert_prompt_upload(minimum: Option<&str>, api: StreamApi) {
    let registry = Registry::new(minimum).await;
    let first = payload(128 * 1024);
    let last = payload(128 * 1024 + 17);
    let bytes = [first.as_ref(), last.as_ref()].concat();
    let received = registry.state.lock().unwrap().received.clone();
    // The producer waits for the first PATCH before supplying the rest of the blob.
    let input = stream::once(async move { Ok(first) }).chain(stream::once(async move {
        received.notified().await;
        Ok(last)
    }));
    let c = client();
    let upload = push_stream(api, &c, &registry.image, input, &bytes);
    tokio::time::timeout(std::time::Duration::from_secs(5), upload)
        .await
        .expect("first PATCH must precede the next input fragment")
        .unwrap();
    registry.assert_upload(&bytes, &[128 * 1024, 128 * 1024 + 17]);
}

#[tokio::test]
async fn known_digest_stream_sends_eligible_fragments_without_waiting() {
    for minimum in [None, Some("0"), Some("1024")] {
        assert_prompt_upload(minimum, StreamApi::KnownDigest).await;
    }
}

#[tokio::test]
async fn computed_digest_stream_sends_eligible_fragments_without_waiting() {
    for minimum in [None, Some("0"), Some("1024")] {
        assert_prompt_upload(minimum, StreamApi::ComputedDigest).await;
    }
}

#[rstest::rstest]
#[case(StreamApi::KnownDigest)]
#[case(StreamApi::ComputedDigest)]
#[tokio::test]
async fn oversized_minimum_is_rejected_before_polling_stream(#[case] api: StreamApi) {
    for minimum in ["67108865", "1073741824"] {
        let registry = Registry::new(Some(minimum)).await;
        let unread = stream::poll_fn(|_| -> std::task::Poll<Option<Result<Bytes>>> {
            panic!("oversized minimum must fail before consuming input")
        });
        let error = push_stream(api, &client(), &registry.image, unread, b"unused")
            .await
            .unwrap_err();
        assert!(matches!(error, OciDistributionError::GenericError(_)));
        assert!(error.to_string().contains("exceeds"));
        let state = registry.state.lock().unwrap();
        assert_eq!(state.patch_calls, 0);
        assert_eq!(state.put_calls, 0);
    }
}

#[tokio::test]
async fn oversized_minimum_is_rejected_before_sending_buffered_payload() {
    let registry = Registry::new(Some("67108865")).await;
    let bytes = payload(17);
    let error = client()
        .push_blob(&registry.image, bytes.clone(), &digest(&bytes))
        .await
        .unwrap_err();
    assert!(matches!(error, OciDistributionError::GenericError(_)));
    assert!(error.to_string().contains("exceeds"));
    let state = registry.state.lock().unwrap();
    assert_eq!(state.patch_calls, 0);
    assert_eq!(state.put_calls, 0);
}

#[tokio::test]
async fn maximum_supported_minimum_allows_a_short_final_chunk() {
    let bytes = payload(17);
    let registry = Registry::new(Some("67108864")).await;
    let c = client();
    c.push_blob(&registry.image, bytes.clone(), &digest(&bytes))
        .await
        .unwrap();
    registry.assert_upload(&bytes, &[bytes.len()]);
    for api in [StreamApi::KnownDigest, StreamApi::ComputedDigest] {
        let registry = Registry::new(Some("67108864")).await;
        push_stream(
            api,
            &c,
            &registry.image,
            small_fragments(bytes.clone()),
            &bytes,
        )
        .await
        .unwrap();
        registry.assert_upload(&bytes, &[bytes.len()]);
    }
}

#[rstest::rstest]
#[case(StreamApi::KnownDigest)]
#[case(StreamApi::ComputedDigest)]
#[tokio::test]
async fn input_error_after_a_sent_chunk_does_not_flush_or_commit(#[case] api: StreamApi) {
    let registry = Registry::new(Some("1024")).await;
    let bytes = payload(1041);
    let input = stream::iter([
        Ok(bytes.slice(..1024)),
        Ok(bytes.slice(1024..)),
        Err(OciDistributionError::GenericError(Some(
            "input failed".into(),
        ))),
    ]);
    let error = push_stream(api, &client(), &registry.image, input, &bytes)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("input failed"));
    let state = registry.state.lock().unwrap();
    assert_eq!(state.bytes, bytes[..1024]);
    assert_eq!(state.patch_calls, 1);
    assert_eq!(state.put_calls, 0);
}

#[rstest::rstest]
#[case(StreamApi::KnownDigest)]
#[case(StreamApi::ComputedDigest)]
#[tokio::test]
async fn patch_error_stops_polling_and_does_not_commit(#[case] api: StreamApi) {
    let registry = Registry::new(Some("1024")).await;
    registry.state.lock().unwrap().reject_patch = true;
    let input = stream::iter([Ok(payload(512)), Ok(payload(512))]).chain(stream::poll_fn(
        |_| -> std::task::Poll<Option<Result<Bytes>>> {
            panic!("failed PATCH must stop consuming input")
        },
    ));
    let error = push_stream(api, &client(), &registry.image, input, b"unused")
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        OciDistributionError::ServerError { code: 500, .. }
    ));
    let state = registry.state.lock().unwrap();
    assert_eq!(state.patch_calls, 1);
    assert_eq!(state.put_calls, 0);
}

#[tokio::test]
async fn session_status_and_location_errors_take_precedence_over_minimum() {
    for status_error in [true, false] {
        let registry = Registry::new(Some("invalid")).await;
        {
            let mut state = registry.state.lock().unwrap();
            if status_error {
                state.begin_status = Some(StatusCode::BAD_REQUEST);
            } else {
                state.omit_location = true;
            }
        }
        let unread = stream::poll_fn(|_| -> std::task::Poll<Option<Result<Bytes>>> {
            panic!("failed session must not consume input")
        });
        let error = client()
            .push_blob_stream(&registry.image, unread, &digest(b"unused"), None)
            .await
            .unwrap_err();
        if status_error {
            assert!(matches!(
                error,
                OciDistributionError::ServerError { code: 400, .. }
            ));
        } else {
            assert!(matches!(
                error,
                OciDistributionError::RegistryNoLocationError
            ));
        }
        let state = registry.state.lock().unwrap();
        assert_eq!(state.patch_calls, 0);
        assert_eq!(state.put_calls, 0);
    }
}
