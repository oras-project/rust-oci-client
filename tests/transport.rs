use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use axum::extract::Path;
use axum::response::Redirect;
use axum::{routing::get, Router};
use http::header::{AUTHORIZATION, USER_AGENT};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::errors::OciDistributionError;
use oci_client::secrets::RegistryAuth;
use oci_client::{transport, Client, Reference};
use rstest::rstest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tower::util::BoxCloneSyncService;
use tower::{service_fn, ServiceBuilder, ServiceExt};
use tower_http::follow_redirect::FollowRedirectLayer;

const BEARER_TOKEN: &str = "test-token";
const BLOB: &[u8] = b"blob content";
const BLOB_DIGEST: &str = "sha256:7b24cf3d897fd680e0258c1c7c23db50a5428581ed1785c08de505c381b4c4b5";

/// A hyper client, used as a transport for [`Client::new_with_transport`].
///
/// The hyper client does not follow redirects. As a result, the stack must
/// include `FollowRedirectLayer`.
fn hyper_transport() -> transport::Transport {
    let client = HyperClient::builder(TokioExecutor::new()).build_http::<transport::Body>();
    let service = ServiceBuilder::new()
        .map_err(transport::BoxError::from)
        .layer(FollowRedirectLayer::new())
        .map_response(|response: http::Response<hyper::body::Incoming>| {
            response.map(transport::Body::wrap)
        })
        .service(client);
    BoxCloneSyncService::new(service)
}

/// A registry that redirects blob downloads to a storage server on another
/// port. Registries that use a CDN or an object store do the same.
struct RedirectingRegistry {
    /// The address of the registry.
    address: String,
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
        get(move |headers: HeaderMap| {
            let seen = Arc::clone(&seen);
            async move {
                seen.lock()
                    .unwrap()
                    .push(headers.get(AUTHORIZATION).cloned());
                BLOB
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
