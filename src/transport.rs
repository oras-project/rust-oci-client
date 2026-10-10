//! The HTTP transport used to talk to registries.
//!
//! Requests are sent through a [`tower::Service`] that takes an
//! [`http::Request`] and returns an [`http::Response`], rather than through
//! `reqwest` directly. For now the only transport is the `reqwest::Client`
//! built from [`crate::client::ClientConfig`].

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use tower::util::BoxCloneSyncService;
use tower::ServiceExt;

use crate::errors::OciDistributionError;

/// Error type produced by a [`Transport`] and by its bodies.
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Body of the requests sent and of the responses received by a [`Transport`].
pub(crate) type Body = BoxBody<Bytes, BoxError>;

/// The service every registry request is sent through.
pub(crate) type Transport =
    BoxCloneSyncService<http::Request<Body>, http::Response<Body>, BoxError>;

/// Wraps a `reqwest::Client` into a [`Transport`].
///
/// Requests go through `reqwest::Client`'s own `tower::Service`
/// implementation, so everything the client was configured with (TLS,
/// proxies, timeouts, user agent, redirect policy) keeps applying.
pub(crate) fn from_reqwest(client: reqwest::Client) -> Transport {
    BoxCloneSyncService::new(tower::service_fn(move |request: http::Request<Body>| {
        let client = client.clone();
        async move {
            let request = reqwest::Request::try_from(request.map(reqwest::Body::wrap))?;
            let response = client.oneshot(request).await?;
            Ok::<_, BoxError>(http::Response::from(response).map(from_reqwest_body))
        }
    }))
}

/// Converts a `reqwest::Body` into a transport [`Body`].
pub(crate) fn from_reqwest_body(body: reqwest::Body) -> Body {
    body.map_err(BoxError::from).boxed()
}

/// Reads the whole body into memory.
pub(crate) async fn collect(body: Body) -> Result<Bytes, OciDistributionError> {
    Ok(body.collect().await.map_err(into_oci_error)?.to_bytes())
}

/// Converts an error raised by a [`Transport`] into an [`OciDistributionError`].
///
/// Errors coming from `reqwest` keep being reported as
/// [`OciDistributionError::RequestError`].
pub(crate) fn into_oci_error(error: BoxError) -> OciDistributionError {
    match error.downcast::<reqwest::Error>() {
        Ok(error) => OciDistributionError::RequestError(*error),
        Err(error) => OciDistributionError::GenericError(Some(error.to_string())),
    }
}
