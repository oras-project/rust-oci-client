use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use axum::extract::Path;
use axum::response::{IntoResponse, Redirect};
use axum::{routing::get, Router};
use bytes::Bytes;
use http::header::{AUTHORIZATION, USER_AGENT};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::errors::OciDistributionError;
use oci_client::secrets::RegistryAuth;
use oci_client::transport::EffectiveUrl;
use oci_client::{transport, Client, Reference};
use rstest::rstest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tower::util::BoxCloneSyncService;
use tower::{service_fn, ServiceBuilder, ServiceExt};
use tower_http::follow_redirect::{FollowRedirectLayer, RequestUri};

const BEARER_TOKEN: &str = "test-token";
const BLOB: &[u8] = b"blob content";
const BLOB_DIGEST: &str = "sha256:7b24cf3d897fd680e0258c1c7c23db50a5428581ed1785c08de505c381b4c4b5";
/// A digest that the storage server answers with a `500`, see
/// [`spawn_redirecting_registry`].
const FAILING_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// A hyper client, used as a transport for [`Client::new_with_transport`].
///
/// The hyper client does not follow redirects. As a result, the stack must
/// include `FollowRedirectLayer`.
fn hyper_transport() -> transport::Transport {
    let client = HyperClient::builder(TokioExecutor::new()).build_http::<transport::Body>();
    let service = ServiceBuilder::new()
        .map_err(transport::BoxError::from)
        // After it calls the inner service below, `FollowRedirectLayer`
        // writes the final URL into a `RequestUri` extension. This layer
        // runs after `FollowRedirectLayer`, so it copies that URL into the
        // `EffectiveUrl` extension. The client reads `EffectiveUrl` for its
        // error messages.
        .map_response(|mut response: http::Response<transport::Body>| {
            if let Some(uri) = response.extensions().get::<RequestUri>().cloned() {
                response.extensions_mut().insert(EffectiveUrl(uri.0));
            }
            response
        })
        .layer(FollowRedirectLayer::new())
        .map_response(|response: http::Response<hyper::body::Incoming>| {
            response.map(transport::Body::wrap)
        })
        .service(client);
    BoxCloneSyncService::new(service)
}

/// A registry that redirects blob downloads to a storage server on another
/// port. Registries that use a CDN or an object store do the same.
///
/// The storage server answers [`BLOB_DIGEST`] with [`BLOB`], and
/// [`FAILING_DIGEST`] with a `500`.
struct RedirectingRegistry {
    /// The address of the registry.
    address: String,
    /// The address of the storage server.
    storage_address: String,
    /// The `Authorization` header of each request that the registry receives.
    registry_authorizations: Arc<Mutex<Vec<Option<HeaderValue>>>>,
    /// The `Authorization` header of each request that the storage server receives.
    storage_authorizations: Arc<Mutex<Vec<Option<HeaderValue>>>>,
}

async fn spawn_redirecting_registry() -> RedirectingRegistry {
    let registry_authorizations = Arc::new(Mutex::new(Vec::new()));
    let storage_authorizations = Arc::new(Mutex::new(Vec::new()));

    let storage_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let storage_address = storage_listener.local_addr().unwrap();
    let seen = Arc::clone(&storage_authorizations);
    let storage = Router::new().route(
        "/storage/{digest}",
        get(move |Path(digest): Path<String>, headers: HeaderMap| {
            let seen = Arc::clone(&seen);
            async move {
                seen.lock()
                    .unwrap()
                    .push(headers.get(AUTHORIZATION).cloned());
                if digest == FAILING_DIGEST {
                    (StatusCode::INTERNAL_SERVER_ERROR, "server error").into_response()
                } else {
                    BLOB.into_response()
                }
            }
        }),
    );
    tokio::spawn(async move { axum::serve(storage_listener, storage).await.unwrap() });

    let registry_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let registry_address = registry_listener.local_addr().unwrap();
    let seen = Arc::clone(&registry_authorizations);
    let registry = Router::new().route(
        "/v2/repo/blobs/{digest}",
        get(move |Path(digest): Path<String>, headers: HeaderMap| {
            let seen = Arc::clone(&seen);
            async move {
                seen.lock()
                    .unwrap()
                    .push(headers.get(AUTHORIZATION).cloned());
                Redirect::temporary(&format!("http://{storage_address}/storage/{digest}"))
            }
        }),
    );
    tokio::spawn(async move { axum::serve(registry_listener, registry).await.unwrap() });

    RedirectingRegistry {
        address: registry_address.to_string(),
        storage_address: storage_address.to_string(),
        registry_authorizations,
        storage_authorizations,
    }
}

/// The transports that must follow the redirects of a registry.
#[derive(Debug)]
enum TransportKind {
    /// The reqwest client that the crate builds by default.
    Default,
    /// A hyper client with `FollowRedirectLayer`. Refer to [`hyper_transport`].
    Hyper,
}

/// Creates a client that uses the transport of `kind` and plain HTTP.
fn client_with(kind: TransportKind) -> Client {
    let config = ClientConfig {
        protocol: ClientProtocol::Http,
        ..Default::default()
    };
    match kind {
        TransportKind::Default => Client::new(config),
        TransportKind::Hyper => Client::new_with_transport(config, hyper_transport()),
    }
}

/// Reads one HTTP request from `stream`, up to the end of its headers.
async fn read_request_head(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0; 1024];
    while !request.ends_with(b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await.unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(request).unwrap()
}

#[tokio::test]
async fn default_transport_sends_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let registry = listener.local_addr().unwrap().to_string();
    let router = Router::new().route(
        "/v2/repo/tags/list",
        get(|| async { r#"{"name":"repo","tags":["latest"]}"# }),
    );
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let client = Client::new(ClientConfig {
        protocol: ClientProtocol::Http,
        ..Default::default()
    });
    let reference = Reference::try_from(format!("{registry}/repo:latest")).unwrap();

    let response = client
        .list_tags(
            &reference,
            &RegistryAuth::Bearer(BEARER_TOKEN.to_string()),
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(response.tags, vec!["latest"]);
}

/// Pulls a blob from a [`RedirectingRegistry`].
///
/// Makes sure that the transport follows the redirect, and that the storage
/// server does not get the registry credentials.
#[rstest]
#[case::default_transport(TransportKind::Default)]
#[case::hyper_transport(TransportKind::Hyper)]
#[tokio::test]
async fn transport_follows_blob_redirects(#[case] kind: TransportKind) {
    let registry = spawn_redirecting_registry().await;
    let client = client_with(kind);
    let reference = Reference::try_from(format!("{}/repo:latest", registry.address)).unwrap();
    client
        .store_auth_if_needed(
            reference.resolve_registry(),
            &RegistryAuth::Bearer(BEARER_TOKEN.to_string()),
        )
        .await;

    let mut blob = Vec::new();
    client
        .pull_blob(&reference, BLOB_DIGEST, &mut blob)
        .await
        .unwrap();

    assert_eq!(blob, BLOB);
    assert_eq!(
        *registry.registry_authorizations.lock().unwrap(),
        vec![Some(HeaderValue::from_static("Bearer test-token"))]
    );
    assert_eq!(*registry.storage_authorizations.lock().unwrap(), vec![None]);
}

/// A failed blob download is reported with the URL of the server that
/// answered it. This is the storage server, not the registry it was
/// redirected from.
#[rstest]
#[case::default_transport(TransportKind::Default)]
#[case::hyper_transport(TransportKind::Hyper)]
#[tokio::test]
async fn failed_redirected_blob_names_the_storage_url(#[case] kind: TransportKind) {
    let registry = spawn_redirecting_registry().await;
    let client = client_with(kind);
    let reference = Reference::try_from(format!("{}/repo:latest", registry.address)).unwrap();

    let error = client
        .pull_blob(&reference, FAILING_DIGEST, &mut Vec::new())
        .await
        .unwrap_err();

    match error {
        OciDistributionError::ServerError { url, code, .. } => {
            assert_eq!(code, 500);
            assert!(
                url.contains(&registry.storage_address),
                "the error should name the storage server: {url}"
            );
            assert!(
                !url.contains(&registry.address),
                "the error should not name the registry: {url}"
            );
        }
        other => panic!("expected a ServerError, got {other:?}"),
    }
}

#[tokio::test]
async fn transport_not_following_redirects_is_reported() {
    let registry = spawn_redirecting_registry().await;
    // A bare hyper client does not follow redirects.
    let client = Client::new_with_transport(
        ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        },
        HyperClient::builder(TokioExecutor::new())
            .build_http::<transport::Body>()
            .map_response(|response: http::Response<hyper::body::Incoming>| {
                response.map(transport::Body::wrap)
            }),
    );
    let reference = Reference::try_from(format!("{}/repo:latest", registry.address)).unwrap();

    let error = client
        .pull_blob(&reference, BLOB_DIGEST, &mut Vec::new())
        .await
        .unwrap_err();

    assert!(
        matches!(
            &error,
            OciDistributionError::ServerError { code: 307, message, .. }
                if message.contains("did not follow the redirect")
        ),
        "{error:?}"
    );
}

/// When a transport puts an `EffectiveUrl` extension on its response, the
/// client reports that URL in its error, not the URL it requested.
///
/// This is the contract that [`hyper_transport`] relies on: a transport that
/// follows redirects records the URL it ended on as an `EffectiveUrl`.
#[tokio::test]
async fn effective_url_extension_names_the_response_in_errors() {
    let service = service_fn(|_: transport::Request| async {
        let mut response = http::Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(transport::Body::empty())
            .unwrap();
        response.extensions_mut().insert(EffectiveUrl(
            "https://storage.example/blob".parse().unwrap(),
        ));
        Ok::<_, TestTransportError>(response)
    });
    let client = Client::new_with_transport(ClientConfig::default(), service);
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    let error = client
        .list_tags(
            &reference,
            &RegistryAuth::Bearer(BEARER_TOKEN.to_string()),
            None,
            None,
        )
        .await
        .unwrap_err();

    match error {
        OciDistributionError::ServerError { url, code, .. } => {
            assert_eq!(code, 500);
            assert_eq!(url, "https://storage.example/blob");
        }
        other => panic!("expected a ServerError, got {other:?}"),
    }
}

#[tokio::test]
#[cfg(any(
    feature = "native-tls",
    feature = "rustls-tls",
    feature = "rustls-tls-no-provider"
))]
async fn configured_user_agent_is_sent_on_https_proxy_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let proxy = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request_head(&mut stream).await
    });

    let client = Client::new(ClientConfig {
        user_agent: "proxy-connect-agent",
        https_proxy: Some(format!("http://{proxy_address}")),
        ..Default::default()
    });
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    client
        .list_tags(
            &reference,
            &RegistryAuth::Bearer(BEARER_TOKEN.to_string()),
            None,
            None,
        )
        .await
        .expect_err("the probe proxy closes before establishing the tunnel");

    let connect_request = proxy.await.unwrap().to_ascii_lowercase();
    assert!(connect_request.starts_with("connect registry.example:443 http/1.1\r\n"));
    assert!(connect_request.contains("\r\nuser-agent: proxy-connect-agent\r\n"));
}

#[tokio::test]
async fn empty_get_and_head_bodies_do_not_emit_content_length() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for response in [
            concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: application/json\r\n",
                "Content-Length: 33\r\n",
                "Connection: close\r\n",
                "\r\n",
                r#"{"name":"repo","tags":["latest"]}"#
            ),
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
        ] {
            let (mut stream, _) = listener.accept().await.unwrap();
            requests.push(read_request_head(&mut stream).await);
            stream.write_all(response.as_bytes()).await.unwrap();
        }
        requests
    });

    let client = Client::new_with_transport(
        ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        },
        hyper_transport(),
    );
    let reference = Reference::try_from(format!("{server_address}/repo:latest")).unwrap();

    let tags = client
        .list_tags(
            &reference,
            &RegistryAuth::Bearer(BEARER_TOKEN.to_string()),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(tags.tags, vec!["latest"]);
    assert!(client.blob_exists(&reference, "sha256:abc").await.unwrap());

    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert!(!request.to_ascii_lowercase().contains("\r\ncontent-length:"));
    }
}

/// A transport can stream a response body with no known length, for example
/// the browser transport. When this happens, the client takes the length of
/// the stream from the `Content-Length` header.
#[tokio::test]
async fn content_length_falls_back_to_the_header() {
    let service = service_fn(|_: transport::Request| async {
        let stream = futures_util::stream::once(async {
            Ok::<_, transport::BoxError>(http_body::Frame::data(Bytes::from_static(BLOB)))
        });
        let body = transport::Body::wrap(http_body_util::StreamBody::new(stream));
        Ok::<_, Infallible>(
            http::Response::builder()
                .header(http::header::CONTENT_LENGTH, BLOB.len())
                .body(body)
                .unwrap(),
        )
    });
    let client = Client::new_with_transport(ClientConfig::default(), service);
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    let stream = client
        .pull_blob_stream(&reference, BLOB_DIGEST)
        .await
        .unwrap();

    assert_eq!(stream.content_length, Some(BLOB.len() as u64));
}

#[tokio::test]
async fn custom_transport_receives_registry_operations() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    let service = service_fn(move |request: transport::Request| {
        let seen = Arc::clone(&seen);
        async move {
            let method = request.method().clone();
            let path = request.uri().path().to_string();
            seen.lock().unwrap().push((method.clone(), path.clone()));

            let response = match (method, path.as_str()) {
                (Method::GET, "/v2/repo/tags/list") => http::Response::builder()
                    .status(StatusCode::OK)
                    .body(transport::Body::from(
                        r#"{"name":"repo","tags":["latest"]}"#,
                    ))
                    .unwrap(),
                (Method::HEAD, "/v2/repo/blobs/sha256:abc") => http::Response::builder()
                    .status(StatusCode::OK)
                    .body(transport::Body::empty())
                    .unwrap(),
                (Method::PUT, "/v2/repo/manifests/latest") => http::Response::builder()
                    .status(StatusCode::CREATED)
                    .header("Location", "/v2/repo/manifests/sha256:manifest")
                    .body(transport::Body::empty())
                    .unwrap(),
                _ => http::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(transport::Body::empty())
                    .unwrap(),
            };
            Ok::<_, Infallible>(response)
        }
    });

    let client = Client::new_with_transport(ClientConfig::default(), service);
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();
    let auth = RegistryAuth::Bearer(BEARER_TOKEN.to_string());

    client
        .list_tags(&reference, &auth, None, None)
        .await
        .unwrap();
    assert!(client.blob_exists(&reference, "sha256:abc").await.unwrap());
    client
        .push_manifest_raw(
            &reference,
            b"{}".as_slice(),
            "application/vnd.oci.image.manifest.v1+json"
                .parse()
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        *requests.lock().unwrap(),
        vec![
            (Method::GET, "/v2/repo/tags/list".to_string()),
            (Method::HEAD, "/v2/repo/blobs/sha256:abc".to_string()),
            (Method::PUT, "/v2/repo/manifests/latest".to_string()),
        ]
    );
}

#[tokio::test]
async fn custom_transport_receives_token_and_registry_requests() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    let service = service_fn(move |request: transport::Request| {
        let seen = Arc::clone(&seen);
        async move {
            let target = format!(
                "{}{}",
                request.uri().authority().map(|a| a.as_str()).unwrap_or(""),
                request.uri().path()
            );
            let authorization = request
                .headers()
                .get(AUTHORIZATION)
                .map(|value| (value.is_sensitive(), format!("{value:?}")));
            seen.lock().unwrap().push((target.clone(), authorization));

            let response = match target.as_str() {
                "registry.example/v2/" => http::Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header(
                        "WWW-Authenticate",
                        r#"Bearer realm="https://auth.example/token",service="registry.example""#,
                    )
                    .body(transport::Body::empty())
                    .unwrap(),
                "auth.example/token" => http::Response::builder()
                    .status(StatusCode::OK)
                    .body(transport::Body::from(r#"{"token":"transport-token"}"#))
                    .unwrap(),
                "registry.example/v2/repo/tags/list" => http::Response::builder()
                    .status(StatusCode::OK)
                    .body(transport::Body::from(
                        r#"{"name":"repo","tags":["latest"]}"#,
                    ))
                    .unwrap(),
                _ => unreachable!("unexpected request target: {target}"),
            };
            Ok::<_, Infallible>(response)
        }
    });

    let client = Client::new_with_transport(ClientConfig::default(), service);
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    client
        .list_tags(
            &reference,
            &RegistryAuth::Basic("user".to_string(), "password".to_string()),
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        *requests.lock().unwrap(),
        vec![
            ("registry.example/v2/".to_string(), None),
            (
                "auth.example/token".to_string(),
                Some((true, "Sensitive".to_string())),
            ),
            (
                "registry.example/v2/repo/tags/list".to_string(),
                Some((true, "Sensitive".to_string())),
            ),
        ]
    );
}

#[tokio::test]
async fn custom_constructor_applies_config_without_building_reqwest() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    let service = service_fn(move |request: transport::Request| {
        let seen = Arc::clone(&seen);
        async move {
            seen.lock().unwrap().push((
                request.uri().scheme_str().map(str::to_string),
                request.headers().get(USER_AGENT).cloned(),
            ));
            let body = if request.uri().path() == "/v2/repo/tags/list" {
                transport::Body::from(r#"{"name":"repo","tags":["latest"]}"#)
            } else {
                transport::Body::empty()
            };
            Ok::<_, Infallible>(http::Response::new(body))
        }
    });
    let config = ClientConfig {
        protocol: ClientProtocol::Http,
        user_agent: "custom-transport-agent",
        https_proxy: Some("not a valid reqwest proxy URL".to_string()),
        ..Default::default()
    };
    let client = Client::new_with_transport(config, service);
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    let response = client
        .list_tags(&reference, &RegistryAuth::Anonymous, None, None)
        .await
        .unwrap();

    assert_eq!(response.tags, vec!["latest"]);
    assert_eq!(
        *requests.lock().unwrap(),
        vec![
            (
                Some("http".to_string()),
                Some(HeaderValue::from_static("custom-transport-agent")),
            ),
            (
                Some("http".to_string()),
                Some(HeaderValue::from_static("custom-transport-agent")),
            ),
        ]
    );
}

#[derive(Debug)]
struct TestTransportError;

impl std::fmt::Display for TestTransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("custom transport failed")
    }
}

impl std::error::Error for TestTransportError {}

#[tokio::test]
async fn custom_transport_errors_propagate() {
    let service = service_fn(|_: transport::Request| async {
        Err::<transport::Response, _>(TestTransportError)
    });
    let client = Client::new_with_transport(ClientConfig::default(), service);
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    let error = client
        .list_tags(
            &reference,
            &RegistryAuth::Bearer(BEARER_TOKEN.to_string()),
            None,
            None,
        )
        .await
        .unwrap_err();

    assert!(matches!(error, OciDistributionError::TransportError(source)
            if source.to_string().contains("custom transport failed")));
}

#[test]
fn public_transport_types_and_client_futures_are_send() {
    fn assert_send<T: Send>(_: T) {}
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<Client>();
    assert_send_sync::<transport::Transport>();
    assert_send(transport::Body::empty());

    let client = Client::default();
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();
    let auth = RegistryAuth::Bearer(BEARER_TOKEN.to_string());
    assert_send(async move {
        client
            .list_tags(&reference, &auth, None, None)
            .await
            .unwrap();
    });
}

/// A response body split across more than one frame. A consumer that
/// reads the body sees more than one chunk arrive over time. A real
/// registry's TCP stream splits a body this way. A plain in-memory body
/// does not.
#[cfg(feature = "blocking")]
fn multi_frame_body(chunks: Vec<&'static [u8]>) -> transport::Body {
    let stream = futures_util::stream::iter(chunks.into_iter().map(|chunk| {
        Ok::<_, transport::BoxError>(http_body::Frame::data(Bytes::from_static(chunk)))
    }));
    transport::Body::wrap(http_body_util::StreamBody::new(stream))
}

/// [`Client::pull_blob`] streams a blob to the caller's [`std::io::Write`]
/// as the blob arrives. It does not buffer the whole blob in memory
/// first. This test sends the blob as more than one frame. It checks
/// that the writer gets more than one `write` call, and that the bytes
/// and the digest are still correct.
#[test]
#[cfg(feature = "blocking")]
fn blocking_pull_blob_streams_to_the_writer() {
    use std::io::Write;

    let service = tower::service_fn(|request: transport::Request| async move {
        assert_eq!(request.method(), Method::GET);
        Ok::<_, Infallible>(
            http::Response::builder()
                .status(StatusCode::OK)
                .body(multi_frame_body(vec![&BLOB[..4], &BLOB[4..]]))
                .unwrap(),
        )
    });
    let client = oci_client::blocking::Client::new_with_transport(
        ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        },
        service,
    );
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    #[derive(Default)]
    struct CountingWriter {
        buf: Vec<u8>,
        writes: usize,
    }
    impl Write for CountingWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            self.buf.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut writer = CountingWriter::default();
    client
        .pull_blob(&reference, BLOB_DIGEST, &mut writer)
        .expect("failed to pull blob");

    assert_eq!(writer.buf, BLOB);
    assert!(
        writer.writes >= 2,
        "expected the blob to arrive in more than one write call, got {}",
        writer.writes
    );
}

/// When the caller's [`std::io::Write`] fails partway through,
/// [`Client::pull_blob`] reports that error. It does not hang, even
/// though more of the blob is still waiting to be read.
#[test]
#[cfg(feature = "blocking")]
fn blocking_pull_blob_propagates_writer_errors() {
    use std::io::Write;

    let service = tower::service_fn(|request: transport::Request| async move {
        assert_eq!(request.method(), Method::GET);
        Ok::<_, Infallible>(
            http::Response::builder()
                .status(StatusCode::OK)
                .body(multi_frame_body(vec![&BLOB[..4], &BLOB[4..]]))
                .unwrap(),
        )
    });
    let client = oci_client::blocking::Client::new_with_transport(
        ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        },
        service,
    );
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    struct FailingWriter {
        calls: usize,
    }
    impl Write for FailingWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if self.calls == 1 {
                Ok(data.len())
            } else {
                Err(std::io::Error::other("write boom"))
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let error = client
        .pull_blob(&reference, BLOB_DIGEST, &mut FailingWriter { calls: 0 })
        .expect_err("expected the writer's error to be reported");

    assert!(
        matches!(error, OciDistributionError::IoError(_)),
        "{error:?}"
    );
}

/// When the caller's [`std::io::Read`] fails partway through,
/// [`Client::push_blob_from_read`] reports that error. It does not hang,
/// even though the background thread still drives the chunked upload.
#[test]
#[cfg(feature = "blocking")]
fn blocking_push_blob_from_read_propagates_reader_errors() {
    let service = tower::service_fn(|request: transport::Request| async move {
        let response = match *request.method() {
            Method::POST | Method::PATCH => http::Response::builder()
                .status(StatusCode::ACCEPTED)
                .header(
                    "Location",
                    "http://registry.example/v2/repo/blobs/uploads/session",
                )
                .body(transport::Body::empty())
                .unwrap(),
            _ => http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(transport::Body::empty())
                .unwrap(),
        };
        Ok::<_, Infallible>(response)
    });
    let client = oci_client::blocking::Client::new_with_transport(ClientConfig::default(), service);
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    struct FailingReader {
        yielded: bool,
    }
    impl std::io::Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.yielded {
                self.yielded = true;
                let n = BLOB.len().min(buf.len());
                buf[..n].copy_from_slice(&BLOB[..n]);
                Ok(n)
            } else {
                Err(std::io::Error::other("read boom"))
            }
        }
    }

    let error = client
        .push_blob_from_read(
            &reference,
            FailingReader { yielded: false },
            BLOB_DIGEST,
            None,
        )
        .expect_err("expected the reader's error to be reported");

    assert!(
        matches!(error, OciDistributionError::IoError(_)),
        "{error:?}"
    );
}

/// When the client uses monolithic push and `size` is `None`,
/// [`Client::push_blob_from_read`] returns an error at once. It does not
/// read from the reader. It does not send a request to the registry.
#[test]
#[cfg(feature = "blocking")]
fn blocking_push_blob_from_read_monolithic_without_size_does_not_read() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let requests = Arc::new(AtomicUsize::new(0));
    let counter = requests.clone();
    let service = tower::service_fn(move |_request: transport::Request| {
        counter.fetch_add(1, Ordering::SeqCst);
        async move {
            Ok::<_, Infallible>(
                http::Response::builder()
                    .status(StatusCode::ACCEPTED)
                    .header(
                        "Location",
                        "http://registry.example/v2/repo/blobs/uploads/session",
                    )
                    .body(transport::Body::empty())
                    .unwrap(),
            )
        }
    });
    let client = oci_client::blocking::Client::new_with_transport(
        ClientConfig {
            use_monolithic_push: true,
            ..Default::default()
        },
        service,
    );
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    struct NeverRead;
    impl std::io::Read for NeverRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("push_blob_from_read must not read the reader when size is None and use_monolithic_push is set")
        }
    }

    let error = client
        .push_blob_from_read(&reference, NeverRead, BLOB_DIGEST, None)
        .expect_err("expected a missing size error");

    assert!(
        matches!(&error, OciDistributionError::GenericError(Some(m)) if m == "size must be provided when use_monolithic_push is enabled"),
        "{error:?}"
    );
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

/// [`Client::pull_blob_read`] reports `content_length` before the first
/// byte. It then returns the blob across more than one `read` call, as
/// the data arrives in more than one piece.
#[test]
#[cfg(feature = "blocking")]
fn blocking_pull_blob_read_exposes_content_length_and_streams() {
    let service = tower::service_fn(|request: transport::Request| async move {
        assert_eq!(request.method(), Method::GET);
        Ok::<_, Infallible>(
            http::Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_LENGTH, BLOB.len())
                .body(multi_frame_body(vec![&BLOB[..4], &BLOB[4..]]))
                .unwrap(),
        )
    });
    let client = oci_client::blocking::Client::new_with_transport(
        ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        },
        service,
    );
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    let mut reader = client
        .pull_blob_read(&reference, BLOB_DIGEST)
        .expect("failed to open the blob");
    assert_eq!(reader.content_length, Some(BLOB.len() as u64));

    // Read one byte at a time. A 1-byte buffer forces one `read` call
    // per byte of `BLOB`, which checks that `BlobReader` hands out a
    // chunk across more than one call, not just as a single copy.
    let mut out = Vec::new();
    let mut reads = 0;
    let mut buf = [0u8; 1];
    loop {
        let n = std::io::Read::read(&mut reader, &mut buf).expect("failed to read the blob");
        if n == 0 {
            break;
        }
        reads += 1;
        out.extend_from_slice(&buf[..n]);
    }

    assert_eq!(out, BLOB);
    assert_eq!(reads, BLOB.len());
}

/// Reading a [`BlobReader`] again after it already reached the end of
/// the blob returns `Ok(0)` again. It must not poll the response body
/// a second time: the registry's digest-verifying stream finalizes its
/// digest on every `None` it returns, so polling it again after it
/// already finished would check the blob's digest against the digest
/// of an empty body, and report a false mismatch.
#[test]
#[cfg(feature = "blocking")]
fn blocking_pull_blob_read_returns_eof_again_after_the_blob() {
    let service = tower::service_fn(|request: transport::Request| async move {
        assert_eq!(request.method(), Method::GET);
        Ok::<_, Infallible>(
            http::Response::builder()
                .status(StatusCode::OK)
                .body(multi_frame_body(vec![&BLOB[..4], &BLOB[4..]]))
                .unwrap(),
        )
    });
    let client = oci_client::blocking::Client::new_with_transport(
        ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        },
        service,
    );
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    let mut reader = client
        .pull_blob_read(&reference, BLOB_DIGEST)
        .expect("failed to open the blob");
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut out).expect("failed to read the blob");
    assert_eq!(out, BLOB);

    let mut buf = [0u8; 4];
    assert_eq!(
        std::io::Read::read(&mut reader, &mut buf).expect("expected Ok(0), not a digest error"),
        0
    );
}

/// A failed open, for example a `404` response, is reported by
/// [`Client::pull_blob_read`] itself. The caller does not have to call
/// `read` to see it.
#[test]
#[cfg(feature = "blocking")]
fn blocking_pull_blob_read_reports_open_errors_before_reading() {
    let service = tower::service_fn(|_: transport::Request| async {
        Ok::<_, Infallible>(
            http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(transport::Body::empty())
                .unwrap(),
        )
    });
    let client = oci_client::blocking::Client::new_with_transport(
        ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        },
        service,
    );
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    let error = client
        .pull_blob_read(&reference, BLOB_DIGEST)
        .expect_err("expected the 404 to be reported");

    assert!(
        matches!(error, OciDistributionError::ServerError { code: 404, .. }),
        "{error:?}"
    );
}

/// A digest mismatch is reported as [`OciDistributionError::DigestError`],
/// by [`Client::pull_blob`] and by the last `read` of
/// [`Client::pull_blob_read`]. Both clients report the same error
/// variant, instead of the generic [`OciDistributionError::IoError`] that
/// a plain [`std::io::Error`] would become.
#[test]
#[cfg(feature = "blocking")]
fn blocking_pull_blob_reports_digest_mismatch_as_a_digest_error() {
    let service = tower::service_fn(|request: transport::Request| async move {
        assert_eq!(request.method(), Method::GET);
        Ok::<_, Infallible>(
            http::Response::builder()
                .status(StatusCode::OK)
                .body(transport::Body::from(b"wrong content".as_slice()))
                .unwrap(),
        )
    });
    let client = oci_client::blocking::Client::new_with_transport(
        ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        },
        service,
    );
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    let error = client
        .pull_blob(&reference, BLOB_DIGEST, &mut Vec::new())
        .expect_err("expected the digest mismatch to be reported");
    assert!(
        matches!(error, OciDistributionError::DigestError(_)),
        "{error:?}"
    );

    let mut reader = client
        .pull_blob_read(&reference, BLOB_DIGEST)
        .expect("failed to open the blob");
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut out).expect_err("expected a read error");
}

/// A [`oci_client::blocking::BlobReader`] can outlive the
/// [`oci_client::blocking::Client`] that created it. Dropping every
/// clone of the client while a read is still in progress must not stop
/// the pull or panic the reader.
#[test]
#[cfg(feature = "blocking")]
fn blocking_pull_blob_read_outlives_its_client() {
    // Sends the blob one byte at a time, through a Tokio task that
    // `tower::service_fn` spawns onto whatever runtime drives the
    // request. That is the background runtime of the blocking client.
    // The task waits on `release` right after the first byte, so the
    // test can drop the client first. If `BlobReader` did not hold its
    // own clone of the background runtime, dropping the last client
    // clone would shut that runtime down at this point, and the
    // runtime would drop this task before it sent the rest of the
    // blob. `notify_one` stores its permit even with no task waiting
    // yet, so this works regardless of how far the task has progressed
    // by the time the test calls it; no sleep or polling is needed.
    let release = Arc::new(tokio::sync::Notify::new());
    let release_for_service = Arc::clone(&release);
    let service = tower::service_fn(move |request: transport::Request| {
        let release = Arc::clone(&release_for_service);
        async move {
            assert_eq!(request.method(), Method::GET);
            let (tx, rx) = tokio::sync::mpsc::channel::<
                Result<http_body::Frame<Bytes>, transport::BoxError>,
            >(1);
            tokio::spawn(async move {
                for index in 0..BLOB.len() {
                    if index == 1 {
                        release.notified().await;
                    }
                    let frame =
                        http_body::Frame::data(Bytes::copy_from_slice(&BLOB[index..index + 1]));
                    if tx.send(Ok(frame)).await.is_err() {
                        break;
                    }
                }
            });
            let stream = futures_util::stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|item| (item, rx))
            });
            Ok::<_, Infallible>(
                http::Response::builder()
                    .status(StatusCode::OK)
                    .body(transport::Body::wrap(http_body_util::StreamBody::new(
                        stream,
                    )))
                    .unwrap(),
            )
        }
    });
    let client = oci_client::blocking::Client::new_with_transport(
        ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        },
        service,
    );
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    let mut reader = client
        .pull_blob_read(&reference, BLOB_DIGEST)
        .expect("failed to open the blob");
    let mut first_byte = [0u8; 1];
    std::io::Read::read(&mut reader, &mut first_byte).expect("failed to read the first byte");

    drop(client);
    release.notify_one();

    let mut rest = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut rest).expect("failed to read the rest");

    let mut out = first_byte.to_vec();
    out.extend_from_slice(&rest);
    assert_eq!(out, BLOB);
}

/// Dropping a [`BlobReader`] releases the response body at once, even
/// when the registry never sends the next chunk. The reader owns the
/// body stream, so dropping the reader drops the stream. No other task
/// holds the stream, and nothing waits for the registry.
#[test]
#[cfg(feature = "blocking")]
fn blocking_pull_blob_read_drop_releases_a_stalled_download() {
    // Sends a value when the response stream drops. The test waits on
    // this, with a timeout, instead of guessing how long "stalled"
    // needs to be.
    struct DropSignal(std::sync::mpsc::Sender<()>);
    impl Drop for DropSignal {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    let (dropped_tx, dropped_rx) = std::sync::mpsc::channel::<()>();
    let service = tower::service_fn(move |request: transport::Request| {
        let dropped_tx = dropped_tx.clone();
        async move {
            assert_eq!(request.method(), Method::GET);
            let stream = futures_util::stream::unfold(
                (false, DropSignal(dropped_tx)),
                |(sent_first, guard)| async move {
                    if !sent_first {
                        return Some((
                            Ok::<_, transport::BoxError>(http_body::Frame::data(
                                Bytes::copy_from_slice(&BLOB[..1]),
                            )),
                            (true, guard),
                        ));
                    }
                    // The registry stalls here, forever. It already
                    // sent the first frame, and never sends the next
                    // one or closes the connection.
                    std::future::pending::<()>().await;
                    unreachable!("the stall above never resolves");
                },
            );
            Ok::<_, Infallible>(
                http::Response::builder()
                    .status(StatusCode::OK)
                    .body(transport::Body::wrap(http_body_util::StreamBody::new(
                        stream,
                    )))
                    .unwrap(),
            )
        }
    });
    let client = oci_client::blocking::Client::new_with_transport(
        ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        },
        service,
    );
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

    let mut reader = client
        .pull_blob_read(&reference, BLOB_DIGEST)
        .expect("failed to open the blob");
    let mut buf = [0u8; 1];
    std::io::Read::read(&mut reader, &mut buf).expect("failed to read the first byte");
    drop(reader);

    dropped_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the response stream did not drop after the reader dropped");
}

/// With [`ClientConfig::read_timeout`] set, a `read` on a
/// [`oci_client::blocking::BlobReader`] fails when the registry stalls
/// between chunks. The default transport applies the timeout with a
/// Tokio timer inside the body. The reader polls that body on the
/// calling thread, so this test also checks that the timer finds a
/// runtime there. [`oci_client::blocking::Client::pull_blob`] reports
/// the error as [`OciDistributionError::IoError`].
#[test]
#[cfg(feature = "blocking")]
fn blocking_pull_blob_read_times_out_when_the_registry_stalls() {
    use std::io::Write;

    /// A raw HTTP server on a background thread. It answers each
    /// request with the headers and the first byte of the blob, then
    /// keeps the connection open and never sends the rest.
    ///
    /// Dropping this stops the thread: it sets a flag the thread checks
    /// after each `accept`, opens one throwaway connection to wake the
    /// blocking `accept` call, then joins the thread. This runs during
    /// unwinding too, so a failing assertion earlier in the test does
    /// not leave the thread blocked in `accept` with its listener and
    /// connections alive for the rest of the test process.
    struct StallingServer {
        address: String,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl StallingServer {
        fn start() -> Self {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let shutdown_for_server = Arc::clone(&shutdown);
            let handle = std::thread::spawn(move || {
                let mut connections = Vec::new();
                for connection in listener.incoming() {
                    // The throwaway connection that `Drop` opens only
                    // exists to wake up the blocking `accept` call.
                    // Check the flag before reading from it; it never
                    // sends a request head.
                    if shutdown_for_server.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    let mut connection = connection.unwrap();
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if std::io::Read::read(&mut connection, &mut byte).unwrap() == 0 {
                            break;
                        }
                        head.push(byte[0]);
                    }
                    write!(
                        connection,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                        BLOB.len()
                    )
                    .unwrap();
                    connection.write_all(&BLOB[..1]).unwrap();
                    connection.flush().unwrap();
                    // Keep the connection open, so the client sees a
                    // stall and not a closed connection.
                    connections.push(connection);
                }
            });
            Self {
                address,
                shutdown,
                handle: Some(handle),
            }
        }
    }

    impl Drop for StallingServer {
        fn drop(&mut self) {
            self.shutdown
                .store(true, std::sync::atomic::Ordering::SeqCst);
            // `accept` blocks with no timeout; connecting once more is
            // what wakes it up to see the flag.
            let _ = std::net::TcpStream::connect(&self.address);
            if let Some(handle) = self.handle.take() {
                let result = handle.join();
                // A second panic during unwinding aborts the process
                // and hides the test's real failure. Only treat a
                // server panic as a test failure on the happy path.
                if !std::thread::panicking() {
                    result.expect("the server thread panicked");
                }
            }
        }
    }

    // Declared first, so it drops last: the client's connections close
    // before this stops and joins the server thread, on the happy path
    // and while unwinding from a panic alike.
    let server = StallingServer::start();

    let client = oci_client::blocking::Client::new(ClientConfig {
        protocol: ClientProtocol::Http,
        read_timeout: Some(std::time::Duration::from_millis(100)),
        ..Default::default()
    });
    let reference = Reference::try_from(format!("{}/repo:latest", server.address)).unwrap();

    let mut reader = client
        .pull_blob_read(&reference, BLOB_DIGEST)
        .expect("failed to open the blob");
    let mut buf = [0u8; 1];
    std::io::Read::read(&mut reader, &mut buf).expect("failed to read the first byte");
    std::io::Read::read(&mut reader, &mut buf).expect_err("expected the second read to time out");

    let error = client
        .pull_blob(&reference, BLOB_DIGEST, &mut Vec::new())
        .expect_err("expected the pull to time out");
    assert!(
        matches!(error, OciDistributionError::IoError(_)),
        "{error:?}"
    );
}
