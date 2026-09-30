//! HTTP transport types used by [`crate::Client`].
//!
//! A transport is a cloneable [`tower::Service`] that accepts an HTTP request
//! and returns an HTTP response. Callers can replace the default reqwest-backed
//! transport with [`crate::Client::with_transport`] to apply their own TLS,
//! observability, proxy, or traffic-shaping policy.

use std::fmt;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http_body::{Body as HttpBody, Frame};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use tower::util::BoxCloneSyncService;
#[cfg(not(target_arch = "wasm32"))]
use tower::ServiceExt;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::wasm_bindgen;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, JsValue};

#[cfg(not(target_arch = "wasm32"))]
use crate::client::Certificate;
use crate::client::ClientConfig;
use crate::errors::OciDistributionError;

/// Error type returned by transports and transport bodies.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Body type used by transport requests and responses.
///
/// Bodies created with [`body`] or [`Body::empty`] retain their bytes and can
/// be replayed by redirect handling or custom retry layers. Bodies created with
/// [`Body::streaming`] are consumed once and cannot be replayed.
pub struct Body {
    inner: BodyInner,
}

enum BodyInner {
    Replayable { bytes: Bytes, sent: bool },
    Streaming(BoxBody<Bytes, BoxError>),
}

impl Body {
    /// Creates an empty replayable body.
    pub fn empty() -> Self {
        Self::from_bytes(Bytes::new())
    }

    /// Creates a replayable body from in-memory bytes.
    pub fn from_bytes(data: impl Into<Bytes>) -> Self {
        Self {
            inner: BodyInner::Replayable {
                bytes: data.into(),
                sent: false,
            },
        }
    }

    /// Creates a non-replayable streaming body.
    pub fn streaming<B, E>(body: B) -> Self
    where
        B: HttpBody<Data = Bytes, Error = E> + Send + Sync + 'static,
        E: Into<BoxError> + 'static,
    {
        Self {
            inner: BodyInner::Streaming(body.map_err(Into::into).boxed()),
        }
    }

    /// Returns whether this body can be cloned for another request attempt.
    pub fn is_replayable(&self) -> bool {
        matches!(self.inner, BodyInner::Replayable { .. })
    }

    /// Clones this body when its content is replayable.
    ///
    /// Streaming bodies return `None`. Retry layers should call this before the
    /// first attempt and retain the original request as their replay template.
    pub fn try_clone(&self) -> Option<Self> {
        match &self.inner {
            BodyInner::Replayable { bytes, sent } => Some(Self {
                inner: BodyInner::Replayable {
                    bytes: bytes.clone(),
                    sent: *sent,
                },
            }),
            BodyInner::Streaming(_) => None,
        }
    }

    /// Returns the remaining in-memory bytes, or `None` for a streaming body.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.inner {
            BodyInner::Replayable { bytes, sent: false } => Some(bytes.as_ref()),
            BodyInner::Replayable { sent: true, .. } => Some(&[]),
            BodyInner::Streaming(_) => None,
        }
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            BodyInner::Replayable { bytes, sent } => formatter
                .debug_struct("Body")
                .field("kind", &"replayable")
                .field("remaining", &if *sent { 0 } else { bytes.len() })
                .finish(),
            BodyInner::Streaming(_) => formatter
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
        match &mut self.get_mut().inner {
            BodyInner::Replayable { bytes, sent } => {
                if *sent || bytes.is_empty() {
                    *sent = true;
                    Poll::Ready(None)
                } else {
                    *sent = true;
                    Poll::Ready(Some(Ok(Frame::data(bytes.clone()))))
                }
            }
            BodyInner::Streaming(body) => Pin::new(body).poll_frame(context),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            BodyInner::Replayable { bytes, sent } => *sent || bytes.is_empty(),
            BodyInner::Streaming(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match &self.inner {
            BodyInner::Replayable { bytes, sent: false } => {
                http_body::SizeHint::with_exact(bytes.len() as u64)
            }
            BodyInner::Replayable { sent: true, .. } => http_body::SizeHint::with_exact(0),
            BodyInner::Streaming(body) => body.size_hint(),
        }
    }
}

/// Request type accepted by an OCI client transport.
pub type Request = http::Request<Body>;

/// Response type returned by an OCI client transport.
pub type Response = http::Response<Body>;

/// Boxed transport used by an OCI client.
pub type Transport = BoxCloneSyncService<Request, Response, BoxError>;

#[derive(Debug, thiserror::Error)]
#[error(
    "browser Fetch concealed the redirect response for {url}; its status and Location header are not observable"
)]
struct BrowserRedirectError {
    url: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, thiserror::Error)]
#[error("browser Fetch failed while attempting to {operation}: {message}")]
struct BrowserFetchError {
    operation: &'static str,
    message: String,
}

/// Creates a transport body from in-memory bytes.
pub fn body(data: impl Into<Bytes>) -> Body {
    Body::from_bytes(data)
}

type BoxByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, BoxError>> + Send>>;

struct SyncStreamBody {
    stream: Mutex<BoxByteStream>,
}

impl HttpBody for SyncStreamBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.get_mut()
            .stream
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
            .poll_next(context)
            .map(|item| item.map(|result| result.map(Frame::data)))
    }
}

pub(crate) fn stream_body<S, E>(stream: S) -> Body
where
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: Into<BoxError> + 'static,
{
    let stream = stream.map(|result| result.map_err(Into::into));
    Body::streaming(SyncStreamBody {
        stream: Mutex::new(Box::pin(stream)),
    })
}

/// Builds the default transport without applying client configuration.
pub(crate) fn default_transport() -> Transport {
    #[cfg(not(target_arch = "wasm32"))]
    {
        from_reqwest(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("the default reqwest client configuration is valid"),
        )
    }
    #[cfg(target_arch = "wasm32")]
    {
        browser_transport()
    }
}

/// Builds the default transport using the supplied client configuration.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn configured_transport(
    config: &ClientConfig,
) -> Result<Transport, OciDistributionError> {
    let mut client_builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(config.user_agent)
        .danger_accept_invalid_certs(config.accept_invalid_certificates);

    client_builder = match () {
        #[cfg(feature = "native-tls")]
        () => client_builder.danger_accept_invalid_hostnames(config.accept_invalid_hostnames),
        #[cfg(not(feature = "native-tls"))]
        () => client_builder,
    };

    if !config.tls_certs_only.is_empty() {
        client_builder =
            client_builder.tls_certs_only(convert_certificates(&config.tls_certs_only)?);
    }
    client_builder =
        client_builder.tls_certs_merge(convert_certificates(&config.extra_root_certificates)?);

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

/// Builds the browser Fetch-backed transport.
///
/// TLS certificates, proxies, connection timeouts, and the `User-Agent` header
/// are controlled by the browser on wasm32 and therefore cannot be configured
/// by `ClientConfig`. Redirects are requested in manual mode so Fetch cannot
/// bypass the client's redirect policy.
#[cfg(target_arch = "wasm32")]
pub(crate) fn configured_transport(
    _config: &ClientConfig,
) -> Result<Transport, OciDistributionError> {
    Ok(browser_transport())
}

#[cfg(not(target_arch = "wasm32"))]
fn convert_certificates(
    certs: &[Certificate],
) -> Result<Vec<reqwest::Certificate>, OciDistributionError> {
    certs.iter().map(reqwest::Certificate::try_from).collect()
}

/// Wraps a reqwest client as a transport.
#[cfg(not(target_arch = "wasm32"))]
fn from_reqwest(client: reqwest::Client) -> Transport {
    BoxCloneSyncService::new(tower::service_fn(move |request: Request| {
        let client = client.clone();
        async move {
            let request = reqwest::Request::try_from(request)?;
            let response = client.oneshot(request).await?;
            Ok::<_, BoxError>(http::Response::from(response).map(from_reqwest_body))
        }
    }))
}

#[cfg(not(target_arch = "wasm32"))]
impl From<Body> for reqwest::Body {
    fn from(body: Body) -> Self {
        match body.inner {
            BodyInner::Replayable { bytes, sent: false } => Self::from(bytes),
            BodyInner::Replayable { sent: true, .. } => Self::from(Bytes::new()),
            BodyInner::Streaming(body) => Self::wrap(body),
        }
    }
}

/// Uses browser Fetch while keeping it behind the same transport selected by
/// `Client`.
///
/// JavaScript futures are `!Send`, so the Fetch operation runs locally and
/// sends only the transport response back to the Send Tower future.
#[cfg(target_arch = "wasm32")]
fn browser_transport() -> Transport {
    BoxCloneSyncService::new(tower::service_fn(move |request: Request| async move {
        let (parts, body) = request.into_parts();
        let body = body.collect().await?.to_bytes();
        let (sender, receiver) = futures_channel::oneshot::channel();
        wasm_bindgen_futures::spawn_local(async move {
            let result = execute_browser_request(parts, body).await;
            let _ = sender.send(result);
        });
        receiver
            .await
            .map_err(|_| browser_fetch_error("receive the response", "task was cancelled"))?
    }))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = fetch)]
    fn fetch_with_request(input: &web_sys::Request) -> js_sys::Promise;
}

#[cfg(target_arch = "wasm32")]
async fn execute_browser_request(
    parts: http::request::Parts,
    body: Bytes,
) -> Result<Response, BoxError> {
    let url = parts.uri.to_string();
    let headers = web_sys::Headers::new()
        .map_err(|error| browser_fetch_js_error("create request headers", error))?;
    for (name, value) in &parts.headers {
        headers
            .append(name.as_str(), value.to_str().map_err(BoxError::from)?)
            .map_err(|error| browser_fetch_js_error("set a request header", error))?;
    }

    let init = web_sys::RequestInit::new();
    init.set_method(parts.method.as_str());
    init.set_headers(headers.as_ref());
    init.set_redirect(web_sys::RequestRedirect::Manual);
    let body = (!body.is_empty()).then(|| js_sys::Uint8Array::from(body.as_ref()));
    if let Some(body) = body.as_ref() {
        init.set_body(body.as_ref());
    }

    let request = web_sys::Request::new_with_str_and_init(&url, &init)
        .map_err(|error| browser_fetch_js_error("construct the request", error))?;
    let response = wasm_bindgen_futures::JsFuture::from(fetch_with_request(&request))
        .await
        .map_err(|error| browser_fetch_js_error("send the request", error))?
        .dyn_into::<web_sys::Response>()
        .map_err(|error| browser_fetch_js_error("read the response", error))?;

    if response.type_() == web_sys::ResponseType::Opaqueredirect {
        return Err(Box::new(BrowserRedirectError { url }));
    }

    let mut response_builder = http::Response::builder().status(response.status());
    for item in response.headers().entries() {
        let item = item.map_err(|error| browser_fetch_js_error("read response headers", error))?;
        let pair = item
            .dyn_into::<js_sys::Array>()
            .map_err(|error| browser_fetch_js_error("read a response header", error))?;
        let name = pair
            .get(0)
            .as_string()
            .ok_or_else(|| browser_fetch_error("read a response header", "name is not a string"))?;
        let value = pair.get(1).as_string().ok_or_else(|| {
            browser_fetch_error("read a response header", "value is not a string")
        })?;
        response_builder = response_builder.header(name, value);
    }

    let buffer = response
        .array_buffer()
        .map_err(|error| browser_fetch_js_error("read the response body", error))?;
    let buffer = wasm_bindgen_futures::JsFuture::from(buffer)
        .await
        .map_err(|error| browser_fetch_js_error("read the response body", error))?;
    let bytes = js_sys::Uint8Array::new(&buffer);
    let mut body = vec![0; bytes.length() as usize];
    bytes.copy_to(&mut body);

    response_builder
        .body(crate::transport::body(body))
        .map_err(BoxError::from)
}

#[cfg(target_arch = "wasm32")]
fn browser_fetch_js_error(operation: &'static str, error: JsValue) -> BoxError {
    browser_fetch_error(operation, format!("{error:?}"))
}

#[cfg(target_arch = "wasm32")]
fn browser_fetch_error(operation: &'static str, message: impl Into<String>) -> BoxError {
    Box::new(BrowserFetchError {
        operation,
        message: message.into(),
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn from_reqwest_body(body: reqwest::Body) -> Body {
    Body::streaming(body)
}

pub(crate) async fn collect(body: Body) -> Result<Bytes, OciDistributionError> {
    Ok(body.collect().await.map_err(into_oci_error)?.to_bytes())
}

pub(crate) fn into_oci_error(error: BoxError) -> OciDistributionError {
    match error.downcast::<reqwest::Error>() {
        Ok(error) => OciDistributionError::RequestError(*error),
        Err(error) => match error.downcast::<BrowserRedirectError>() {
            Ok(error) => OciDistributionError::BrowserRedirectNotObservable { url: error.url },
            Err(error) => OciDistributionError::TransportError(error),
        },
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    #[cfg(not(target_arch = "wasm32"))]
    use http::Method;
    use http_body::Body as _;
    use http_body_util::BodyExt;

    use crate::errors::OciDistributionError;

    use super::{body, into_oci_error, stream_body, Body, BrowserRedirectError};

    #[test]
    fn browser_redirect_maps_to_typed_client_error() {
        let error = into_oci_error(Box::new(BrowserRedirectError {
            url: "https://registry.example/blob".to_string(),
        }));

        assert!(matches!(
            error,
            OciDistributionError::BrowserRedirectNotObservable { url }
                if url == "https://registry.example/blob"
        ));
    }

    #[test]
    fn buffered_body_is_replayable() {
        let body = body("payload");
        let cloned = body
            .try_clone()
            .expect("buffered body should be replayable");

        assert_eq!(cloned.as_bytes(), Some("payload".as_bytes()));
    }

    #[test]
    fn empty_replayable_body_is_immediately_at_end_stream() {
        assert!(Body::empty().is_end_stream());
    }

    #[tokio::test]
    async fn nonempty_replayable_body_reaches_end_stream_after_consumption() {
        let mut body = body("payload");
        assert!(!body.is_end_stream());

        assert_eq!(
            body.frame()
                .await
                .expect("buffered body should yield one frame")
                .expect("buffered body frame should be valid")
                .into_data()
                .expect("buffered body should yield data"),
            Bytes::from_static(b"payload")
        );
        assert!(body.is_end_stream());
    }

    #[test]
    fn streaming_body_is_not_replayable() {
        let body = stream_body(futures_util::stream::once(async {
            Ok::<_, OciDistributionError>(Bytes::from_static(b"payload"))
        }));

        assert!(!body.is_replayable());
        assert!(body.try_clone().is_none());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn default_adapter_keeps_empty_and_buffered_requests_cloneable() {
        for (method, body) in [
            (Method::GET, Body::empty()),
            (Method::HEAD, Body::empty()),
            (Method::PUT, body("payload")),
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

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn default_adapter_keeps_streaming_requests_non_replayable() {
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
