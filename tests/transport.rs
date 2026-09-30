use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use axum::{routing::get, Router};
use http::header::{AUTHORIZATION, USER_AGENT};
use http::{Method, StatusCode};
use hyper_util::rt::TokioIo;
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::errors::OciDistributionError;
use oci_client::secrets::RegistryAuth;
use oci_client::{transport, Client, Reference};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::service_fn;

const BEARER_TOKEN: &str = "test-token";

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

#[tokio::test]
async fn configured_user_agent_is_sent_on_https_proxy_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let proxy = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
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
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            requests.push(String::from_utf8(request).unwrap());
            stream.write_all(response.as_bytes()).await.unwrap();
        }
        requests
    });

    let transport = service_fn(move |request: transport::Request| async move {
        let stream = tokio::net::TcpStream::connect(server_address).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            connection
                .await
                .expect("raw test server should complete the HTTP/1 connection");
        });
        let response = sender.send_request(request).await?;
        let (parts, body) = response.into_parts();
        Ok::<_, transport::BoxError>(http::Response::from_parts(
            parts,
            transport::Body::streaming(body),
        ))
    });
    let client = Client::default().with_transport(transport);
    let reference = Reference::try_from("registry.example/repo:latest").unwrap();

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
                    .body(transport::body(r#"{"name":"repo","tags":["latest"]}"#))
                    .unwrap(),
                (Method::HEAD, "/v2/repo/blobs/sha256:abc") => http::Response::builder()
                    .status(StatusCode::OK)
                    .body(transport::body(&[][..]))
                    .unwrap(),
                (Method::PUT, "/v2/repo/manifests/latest") => http::Response::builder()
                    .status(StatusCode::CREATED)
                    .header("Location", "/v2/repo/manifests/sha256:manifest")
                    .body(transport::body(&[][..]))
                    .unwrap(),
                _ => http::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(transport::body(&[][..]))
                    .unwrap(),
            };
            Ok::<_, Infallible>(response)
        }
    });

    let client = Client::default().with_transport(service);
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
    let service =
        service_fn(move |request: transport::Request| {
            let seen = Arc::clone(&seen);
            async move {
                let authority = request
                    .uri()
                    .authority()
                    .map(|authority| authority.as_str())
                    .unwrap_or_default();
                let target = format!("{authority}{}", request.uri().path());
                let authorization = request
                    .headers()
                    .get(AUTHORIZATION)
                    .map(|value| (value.is_sensitive(), format!("{value:?}")));
                seen.lock().unwrap().push((target, authorization));

                let response = match (authority, request.uri().path()) {
                ("registry.example", "/v2/") => http::Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header(
                        "WWW-Authenticate",
                        r#"Bearer realm="https://auth.example/token",service="registry.example""#,
                    )
                    .body(transport::body(&[][..]))
                    .unwrap(),
                ("auth.example", "/token") => http::Response::builder()
                    .status(StatusCode::OK)
                    .body(transport::body(r#"{"token":"transport-token"}"#))
                    .unwrap(),
                ("registry.example", "/v2/repo/tags/list") => http::Response::builder()
                    .status(StatusCode::OK)
                    .body(transport::body(r#"{"name":"repo","tags":["latest"]}"#))
                    .unwrap(),
                _ => unreachable!("unexpected request target: {authority}{}", request.uri().path()),
            };
                Ok::<_, Infallible>(response)
            }
        });

    let client = Client::default().with_transport(service);
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
                transport::body(r#"{"name":"repo","tags":["latest"]}"#)
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
                Some(http::HeaderValue::from_static("custom-transport-agent")),
            ),
            (
                Some("http".to_string()),
                Some(http::HeaderValue::from_static("custom-transport-agent")),
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
    let client = Client::default().with_transport(service);
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
fn public_transport_types_and_client_futures_are_send_sync() {
    fn assert_send<T: Send>(_: T) {}
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<Client>();
    assert_send_sync::<transport::Body>();
    assert_send_sync::<transport::Transport>();

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
