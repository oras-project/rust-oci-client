//! The HTTP transport that [`crate::Client`] uses to send requests to registries.
//!
//! A transport is a cloneable [`tower::Service`]. It takes an HTTP
//! [`Request`] and returns an HTTP [`Response`]. By default, the client sends
//! its requests with a `reqwest::Client` that it builds from [`ClientConfig`].
//! An application can have an HTTP stack of its own, for example for a TLS
//! policy, observability or traffic shaping. Such an application can give its
//! stack to the client with
//! [`Client::new_with_transport`](crate::Client::new_with_transport).
//!
//! # Contract
//!
//! The client prepares each request fully: the URL, the method, the headers
//! and the body. The headers include `User-Agent` and the registry credentials.
//! The transport controls all the network work: connections, TLS, proxies,
//! timeouts and retries.
//!
//! The transport must also follow HTTP redirects. Registries
//! often redirect blob downloads to a CDN or to an object store. As a result,
//! a transport that does not follow redirects cannot pull images.
//!
//! The default transport follows redirects with the default policy of reqwest.
//! A transport built on hyper can use
//! [`tower_http::follow_redirect::FollowRedirectLayer`](https://docs.rs/tower-http/latest/tower_http/follow_redirect/struct.FollowRedirectLayer.html).
//! Reqwest uses this layer internally. If a redirect goes to a different origin
//! (scheme, host and port), the two remove the `Authorization` header.
//!
//! # Configuration
//!
//! [`Client::new_with_transport`](crate::Client::new_with_transport) does not
//! build a reqwest client or a TLS backend. Some fields of
//! [`ClientConfig`] only configure the default transport: the TLS fields, the
//! proxies and the timeouts. With a custom transport, the client ignores them.
//! The client uses all the other fields, for example `protocol` and
//! `user_agent`.
//!
//! # WebAssembly
//!
//! On `wasm32-unknown-unknown`, the default transport uses the Fetch API of
//! the browser. The browser controls TLS, proxies, timeouts and redirects, so
//! the client ignores the related fields of [`ClientConfig`]. The browser can
//! also remove the `User-Agent` header, because Fetch forbids it. The transport
//! reads each request body into memory before it sends the request.
//!
//! # Errors
//!
//! The client returns transport errors as
//! [`OciDistributionError::TransportError`]. It returns the errors of the
//! default transport as [`OciDistributionError::RequestError`].
//!
//! # Example
//!
//! This example builds a transport from hyper, rustls and tower layers. It
//! uses these crates: `hyper`, `hyper-util`, `hyper-rustls`, `rustls`, `tower`
//! and `tower-http`.
//!
//! ```no_run
//! use hyper_rustls::HttpsConnectorBuilder;
//! use hyper_util::client::legacy::Client as HyperClient;
//! use hyper_util::rt::TokioExecutor;
//! use oci_client::client::ClientConfig;
//! use oci_client::{transport, Client};
//! use tower::ServiceBuilder;
//! use tower_http::follow_redirect::FollowRedirectLayer;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // The transport supplies TLS. This code gives the crypto provider to
//! // rustls. If an application includes more than one rustls provider,
//! // rustls cannot select one.
//! let https = HttpsConnectorBuilder::new()
//!     .with_provider_and_native_roots(rustls::crypto::aws_lc_rs::default_provider())?
//!     .https_or_http()
//!     .enable_http1()
//!     .build();
//! let hyper_client =
//!     HyperClient::builder(TokioExecutor::new()).build::<_, transport::Body>(https);
//!
//! let service = ServiceBuilder::new()
//!     // The client needs the transport errors as `BoxError`.
//!     .map_err(transport::BoxError::from)
//!     // The transport must follow redirects.
//!     .layer(FollowRedirectLayer::new())
//!     // The client needs responses with a `transport::Body`.
//!     .map_response(|response: http::Response<hyper::body::Incoming>| {
//!         response.map(transport::Body::wrap)
//!     })
//!     .service(hyper_client);
//!
//! let client = Client::new_with_transport(ClientConfig::default(), service);
//! # Ok(())
//! # }
//! ```
//!
//! The [`custom-transport` example](https://github.com/oras-project/rust-oci-client/blob/main/examples/custom-transport/main.rs)
//! adds a trace layer to this stack and pulls an image. Run it with this
//! command:
//!
//! ```text
//! cargo run --example custom-transport -- --verbose docker.io/library/hello-world:latest
//! ```

use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http_body::{Body as HttpBody, Frame};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt};
use tower::util::BoxCloneSyncService;

use crate::client::ClientConfig;
use crate::errors::OciDistributionError;

/// The error type of transports and of transport bodies.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The type of the requests that a transport receives.
pub type Request = http::Request<Body>;

/// The type of the responses that a transport returns.
pub type Response = http::Response<Body>;

/// The boxed service that a [`crate::Client`] sends its requests through.
pub type Transport = BoxCloneSyncService<Request, Response, BoxError>;

/// The body of transport requests and responses.
///
/// A body is buffered or streamed:
///
/// - A buffered body keeps all its bytes in memory. [`Body::from_bytes`],
///   [`Body::empty`] and the `From` conversions make buffered bodies.
/// - A streamed body reads its bytes from another [`http_body::Body`].
///   [`Body::wrap`] makes streamed bodies.
///
/// If the registry redirects a request, the default transport can send a
/// buffered body again. The transport can read a streamed body only one time.
pub struct Body(BodyKind);

enum BodyKind {
    Buffered(Bytes),
    Streaming(UnsyncBoxBody<Bytes, BoxError>),
}

impl Body {
    /// Creates an empty body.
    pub fn empty() -> Self {
        Self::from_bytes(Bytes::new())
    }

    /// Creates a buffered body, which keeps all its bytes in memory.
    pub fn from_bytes(data: impl Into<Bytes>) -> Self {
        Self(BodyKind::Buffered(data.into()))
    }

    /// Creates a streamed body, which reads its bytes from another
    /// [`http_body::Body`].
    pub fn wrap<B>(body: B) -> Self
    where
        B: HttpBody<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        Self(BodyKind::Streaming(body.map_err(Into::into).boxed_unsync()))
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Bytes> for Body {
    fn from(data: Bytes) -> Self {
        Self::from_bytes(data)
    }
}

impl From<Vec<u8>> for Body {
    fn from(data: Vec<u8>) -> Self {
        Self::from_bytes(data)
    }
}

impl From<&'static [u8]> for Body {
    fn from(data: &'static [u8]) -> Self {
        Self::from_bytes(data)
    }
}

impl From<String> for Body {
    fn from(data: String) -> Self {
        Self::from_bytes(data)
    }
}

impl From<&'static str> for Body {
    fn from(data: &'static str) -> Self {
        Self::from_bytes(data)
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            BodyKind::Buffered(bytes) => formatter
                .debug_struct("Body")
                .field("kind", &"buffered")
                .field("remaining", &bytes.len())
                .finish(),
            BodyKind::Streaming(_) => formatter
                .debug_struct("Body")
                .field("kind", &"streaming")
                .finish_non_exhaustive(),
        }
    }
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match &mut self.get_mut().0 {
            BodyKind::Buffered(bytes) => {
                if bytes.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(Frame::data(std::mem::take(bytes)))))
                }
            }
            BodyKind::Streaming(body) => Pin::new(body).poll_frame(context),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.0 {
            BodyKind::Buffered(bytes) => bytes.is_empty(),
            BodyKind::Streaming(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match &self.0 {
            BodyKind::Buffered(bytes) => http_body::SizeHint::with_exact(bytes.len() as u64),
            BodyKind::Streaming(body) => body.size_hint(),
        }
    }
}

/// Creates a streamed body from a stream of byte chunks.
pub(crate) fn stream_body<S, E>(stream: S) -> Body
where
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: Into<BoxError> + 'static,
{
    Body::wrap(http_body_util::StreamBody::new(
        stream.map(|chunk| chunk.map(Frame::data).map_err(Into::into)),
    ))
}

/// Reads all the bytes of a body into memory.
pub(crate) async fn collect(body: Body) -> Result<Bytes, OciDistributionError> {
    Ok(body.collect().await.map_err(into_oci_error)?.to_bytes())
}

/// Converts an error of a transport, or of a transport body, into an
/// [`OciDistributionError`].
pub(crate) fn into_oci_error(error: BoxError) -> OciDistributionError {
    match error.downcast::<reqwest::Error>() {
        Ok(error) => OciDistributionError::RequestError(*error),
        Err(error) => OciDistributionError::TransportError(error),
    }
}

/// Builds the default transport. This function does not use a client configuration.
pub(crate) fn default_transport() -> Transport {
    #[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
    {
        native::default_transport()
    }
    #[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
    {
        browser::default_transport()
    }
}

/// Builds the default transport from a client configuration.
pub(crate) fn configured_transport(
    config: &ClientConfig,
) -> Result<Transport, OciDistributionError> {
    #[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
    {
        native::configured_transport(config)
    }
    #[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
    {
        browser::configured_transport(config)
    }
}

/// The default transport on native targets: a reqwest client.
#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
mod native {
    use super::{Body, BodyKind, BoxError, Request, Transport};
    use crate::client::ClientConfig;
    use crate::errors::OciDistributionError;
    use http_body_util::BodyExt;
    use tower::util::BoxCloneSyncService;

    /// Builds the default transport. This function does not use a client configuration.
    pub(super) fn default_transport() -> Transport {
        from_reqwest(reqwest::Client::new())
    }

    /// Builds the default transport from a client configuration.
    pub(super) fn configured_transport(
        config: &ClientConfig,
    ) -> Result<Transport, OciDistributionError> {
        let mut client_builder = reqwest::Client::builder().user_agent(config.user_agent);

        #[cfg(any(
            feature = "native-tls",
            feature = "rustls-tls",
            feature = "rustls-tls-no-provider"
        ))]
        {
            client_builder =
                client_builder.danger_accept_invalid_certs(config.accept_invalid_certificates);

            #[cfg(feature = "native-tls")]
            {
                client_builder =
                    client_builder.danger_accept_invalid_hostnames(config.accept_invalid_hostnames);
            }

            if !config.tls_certs_only.is_empty() {
                client_builder =
                    client_builder.tls_certs_only(convert_certificates(&config.tls_certs_only)?);
            }
            client_builder = client_builder
                .tls_certs_merge(convert_certificates(&config.extra_root_certificates)?);
        }

        if let Some(timeout) = config.read_timeout {
            client_builder = client_builder.read_timeout(timeout);
        }
        if let Some(timeout) = config.connect_timeout {
            client_builder = client_builder.connect_timeout(timeout);
        }

        if let Some(proxy_addr) = &config.https_proxy {
            let no_proxy = config
                .no_proxy
                .as_ref()
                .and_then(|no_proxy| reqwest::NoProxy::from_string(no_proxy));
            let proxy = reqwest::Proxy::https(proxy_addr)?.no_proxy(no_proxy);
            client_builder = client_builder.proxy(proxy);
        }

        if let Some(proxy_addr) = &config.http_proxy {
            let no_proxy = config
                .no_proxy
                .as_ref()
                .and_then(|no_proxy| reqwest::NoProxy::from_string(no_proxy));
            let proxy = reqwest::Proxy::http(proxy_addr)?.no_proxy(no_proxy);
            client_builder = client_builder.proxy(proxy);
        }

        Ok(from_reqwest(client_builder.build()?))
    }

    #[cfg(any(
        feature = "native-tls",
        feature = "rustls-tls",
        feature = "rustls-tls-no-provider"
    ))]
    fn convert_certificates(
        certs: &[crate::client::Certificate],
    ) -> Result<Vec<reqwest::Certificate>, OciDistributionError> {
        certs.iter().map(reqwest::Certificate::try_from).collect()
    }

    /// Puts a `reqwest::Client` in a [`Transport`].
    ///
    /// The reqwest client keeps its own redirect policy. As a result, the
    /// transport follows redirects as reqwest does. If a redirect goes to a
    /// different origin, reqwest removes the credentials from the request.
    fn from_reqwest(client: reqwest::Client) -> Transport {
        BoxCloneSyncService::new(tower::service_fn(move |request: Request| {
            let client = client.clone();
            async move {
                let request = reqwest::Request::try_from(request)?;
                let response = client.execute(request).await?;
                Ok::<_, BoxError>(http::Response::from(response).map(Body::wrap))
            }
        }))
    }

    impl From<Body> for reqwest::Body {
        fn from(body: Body) -> Self {
            match body.0 {
                // If the registry redirects the request, reqwest can send a
                // buffered body again.
                BodyKind::Buffered(bytes) => Self::from(bytes),
                BodyKind::Streaming(body) => Self::wrap_stream(body.into_data_stream()),
            }
        }
    }
}

/// The default transport on `wasm32-unknown-unknown`: the Fetch API of the
/// browser, through the wasm backend of reqwest.
///
/// The browser controls TLS, proxies, timeouts and redirects. As a result,
/// `ClientConfig` cannot configure them, and the transport ignores those
/// fields. The browser can also remove the `User-Agent` header, because
/// Fetch forbids it.
///
/// The transport reads each request body into memory before it sends the
/// request, because Fetch cannot stream a request body on all browsers.
///
/// The futures of the Fetch API are not `Send`. The transport runs the
/// request in a local task, and gets the response back through a channel. In
/// this way the service and its future are `Send`, as [`Transport`] requires.
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
mod browser {
    use super::{stream_body, BoxError, Request, Response, Transport};
    use crate::client::ClientConfig;
    use crate::errors::OciDistributionError;
    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use http_body_util::BodyExt;
    use tower::util::BoxCloneSyncService;

    /// Builds the default transport. This function does not use a client configuration.
    pub(super) fn default_transport() -> Transport {
        from_reqwest(reqwest::Client::new())
    }

    /// Builds the default transport from a client configuration.
    ///
    /// The browser controls TLS, proxies and timeouts, so this function only
    /// uses `user_agent`.
    pub(super) fn configured_transport(
        config: &ClientConfig,
    ) -> Result<Transport, OciDistributionError> {
        let client = reqwest::Client::builder()
            .user_agent(config.user_agent)
            .build()?;
        Ok(from_reqwest(client))
    }

    /// Puts a `reqwest::Client` in a [`Transport`].
    fn from_reqwest(client: reqwest::Client) -> Transport {
        BoxCloneSyncService::new(tower::service_fn(move |request: Request| {
            let client = client.clone();
            async move {
                let (parts, body) = request.into_parts();
                let body = body.collect().await?.to_bytes();
                let (sender, receiver) = futures_channel::oneshot::channel();
                wasm_bindgen_futures::spawn_local(async move {
                    let result = execute(client, parts, body).await;
                    let _ = sender.send(result);
                });
                receiver.await.map_err(|_| {
                    BoxError::from(std::io::Error::other(
                        "the browser request task was cancelled",
                    ))
                })?
            }
        }))
    }

    /// Sends one request with the Fetch API and converts the response.
    ///
    /// The body of the response is a stream. A local task reads the stream
    /// of the browser and forwards each chunk through a channel.
    async fn execute(
        client: reqwest::Client,
        parts: http::request::Parts,
        body: Bytes,
    ) -> Result<Response, BoxError> {
        let response = client
            .request(parts.method, parts.uri.to_string())
            .headers(parts.headers)
            .body(body)
            .send()
            .await?;
        let status = response.status();
        let headers = response.headers().clone();

        let (mut sender, receiver) = futures_channel::mpsc::channel(1);
        wasm_bindgen_futures::spawn_local(async move {
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                if sender.send(chunk.map_err(BoxError::from)).await.is_err() {
                    break;
                }
            }
        });

        let mut response = http::Response::builder().status(status);
        if let Some(response_headers) = response.headers_mut() {
            response_headers.extend(headers);
        }
        response.body(stream_body(receiver)).map_err(BoxError::from)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::Method;
    use http_body::Body as _;
    use http_body_util::BodyExt;

    use crate::errors::OciDistributionError;

    use super::{stream_body, Body};

    #[test]
    fn empty_body_is_immediately_at_end_stream() {
        let body = Body::empty();

        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
    }

    #[tokio::test]
    async fn buffered_body_yields_its_bytes_then_ends() {
        let mut body = Body::from("payload");
        assert!(!body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(7));

        let frame = body
            .frame()
            .await
            .expect("buffered body should yield one frame")
            .expect("buffered body frame should be valid");
        assert_eq!(
            frame.into_data().expect("frame should carry data"),
            Bytes::from_static(b"payload")
        );
        assert!(body.is_end_stream());
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn streamed_body_forwards_every_chunk() {
        let body = stream_body(futures_util::stream::iter([
            Ok::<_, OciDistributionError>(Bytes::from_static(b"pay")),
            Ok(Bytes::from_static(b"load")),
        ]));
        assert_eq!(body.size_hint().exact(), None);

        let collected = body.collect().await.unwrap().to_bytes();
        assert_eq!(collected, Bytes::from_static(b"payload"));
    }

    #[test]
    fn default_transport_keeps_buffered_requests_replayable() {
        for (method, body) in [
            (Method::GET, Body::empty()),
            (Method::HEAD, Body::empty()),
            (Method::PUT, Body::from("payload")),
        ] {
            let request = http::Request::builder()
                .method(method)
                .uri("https://registry.example/v2/")
                .body(body)
                .unwrap();
            let request = reqwest::Request::try_from(request).unwrap();

            assert!(request.try_clone().is_some());
        }
    }

    #[test]
    fn default_transport_keeps_streamed_requests_single_use() {
        let body = stream_body(futures_util::stream::once(async {
            Ok::<_, OciDistributionError>(Bytes::from_static(b"payload"))
        }));
        let request = http::Request::builder()
            .method(Method::PUT)
            .uri("https://registry.example/v2/")
            .body(body)
            .unwrap();
        let request = reqwest::Request::try_from(request).unwrap();

        assert!(request.try_clone().is_none());
    }
}
