# Rust OCI Client

Formerly known as `oci-distribution`

[![oci-client documentation](https://docs.rs/oci-client/badge.svg)](https://docs.rs/oci-client)

This Rust library implements the
[OCI Distribution specification](https://github.com/opencontainers/distribution-spec/blob/master/spec.md),
which is the protocol that Docker Hub and other container registries use.

## TLS backends

This crate offers three Cargo features for TLS, you must enable exactly one of them.

- `rustls-tls` (default): Uses the `rustls` library with its built-in `aws-lc-rs` crypto provider.
- `rustls-tls-no-provider`: Uses `rustls`, but leaves the crypto provider to you. Before you build a `Client`, install one, for example with `rustls::crypto::ring::default_provider().install_default()`. Choose this feature when your application already picks a crypto provider and you want to avoid `aws-lc-rs`.
- `native-tls`: Uses the TLS library of your operating system instead of `rustls`.

## Custom HTTP transport

By default, `Client` sends requests with the reqwest client configured by
`ClientConfig`. Applications that need their own TLS, observability, proxy, or
traffic-shaping policy can replace it with a cloneable Tower service:

```rust
use std::convert::Infallible;

use oci_client::client::ClientConfig;
use oci_client::{transport, Client};
use tower::service_fn;

let transport = service_fn(|_request: transport::Request| async move {
    // Forward the request with your HTTP stack and return its response.
    Ok::<_, Infallible>(http::Response::new(transport::Body::empty()))
});

let client = Client::new_with_transport(ClientConfig::default(), transport);
```

The service receives every registry and authentication request after the OCI
client has applied headers, credentials, and request bodies. It should execute
one HTTP exchange and return redirect responses unchanged: the OCI client owns
redirect handling, including its redirect limit, body replay rules, and removal
of credentials when a redirect crosses an origin. Transport-level retries are
the service's responsibility. [`transport::Body`](https://docs.rs/oci-client/latest/oci_client/transport/struct.Body.html)
reports whether a body is replayable and can clone buffered bodies for retry
layers; streaming bodies are intentionally single-use.

`Client::new_with_transport` stores the supplied `ClientConfig` without
constructing reqwest or a default TLS backend. This is useful with
`rustls-tls-no-provider` when the custom transport manages TLS itself. Reqwest-
specific config fields such as proxy URLs and root certificates are not
validated or applied on this path.

On `wasm32-unknown-unknown`, the default transport uses browser Fetch with
`redirect: "manual"` so the browser cannot silently follow or replay a request.
TLS certificates, proxies, and connection timeouts are browser-controlled.
The OCI client prepares the configured `User-Agent` header, but the browser may
filter or replace it according to Fetch rules.
The Fetch API exposes a manual redirect only as an `opaqueredirect` response:
the redirect status and `Location` header are hidden from WebAssembly. The
client therefore refuses the redirect with
`OciDistributionError::BrowserRedirectNotObservable`; browser redirects cannot
provide the same behavior as native transports. Request bodies, including
streaming bodies, are buffered before Fetch sends them, but are never replayed
by the default browser transport.

## Code of Conduct

This project has adopted the [CNCF Code of
Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).
