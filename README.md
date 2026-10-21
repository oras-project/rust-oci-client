# Rust OCI Client

Formerly known as `oci-distribution`

[![oci-client documentation](https://docs.rs/oci-client/badge.svg)](https://docs.rs/oci-client)

This Rust library implements the
[OCI Distribution specification](https://github.com/opencontainers/distribution-spec/blob/master/spec.md),
which is the protocol that Docker Hub and other container registries use.

## TLS backends

This crate has three Cargo features for TLS. If you use the default HTTP
transport, you must enable exactly one of them.

- `rustls-tls` (default): Uses the `rustls` library with its built-in `aws-lc-rs` crypto provider.
- `rustls-tls-no-provider`: Uses `rustls`, but leaves the crypto provider to you. Before you build a `Client`, install one, for example with `rustls::crypto::ring::default_provider().install_default()`. Choose this feature when your application already picks a crypto provider and you want to avoid `aws-lc-rs`.
- `native-tls`: Uses the TLS library of your operating system instead of `rustls`.

You do not have to enable a TLS feature in two cases:

- You give the client your own HTTP transport. The transport supplies TLS.
- You build for `wasm32-unknown-unknown`. The browser supplies TLS. The features have no effect.

The next section explains how to use a custom transport.

## Custom HTTP transport

By default, `Client` sends its requests with a reqwest client that it builds
from `ClientConfig`. An application can have an HTTP stack of its own, for
example for a TLS policy, observability or traffic shaping. Such an
application can give its stack to `Client::new_with_transport` as a
cloneable Tower service.

The client prepares each request fully: the URL, the method, the headers and
the body. The headers include `User-Agent` and the registry credentials. Then
the client gives the request to the transport. The transport controls all the
network work: connections, TLS, proxies, timeouts and retries.

The transport must also follow redirects. A redirect is a response that tells
the client to send the request to a different URL. Registries often redirect
blob downloads to a CDN or to an object store. As a result, a transport that
does not follow redirects cannot pull images.

A transport that follows a redirect can record the URL it ended on in a
`transport::EffectiveUrl` extension of the response. The client reads this
URL for its error messages. A transport built on
`tower_http::follow_redirect::FollowRedirectLayer` must copy the final URL
from that layer's own extension into an `EffectiveUrl`, as the
[`custom-transport`](examples/custom-transport/main.rs) example shows.

On `wasm32-unknown-unknown`, the default transport uses the Fetch API of the
browser. The browser controls TLS, proxies, timeouts and redirects, so the
client ignores the related fields of `ClientConfig`.

The [`custom-transport`](examples/custom-transport/main.rs) example builds a
transport from hyper, rustls and tower layers. Run it with this command:

```sh
cargo run --example custom-transport -- docker.io/library/hello-world:latest
```

To see a trace of each HTTP exchange, add `--verbose`. The trace also shows
the blob download that the registry redirects.

`Client::new_with_transport` does not build a reqwest client or a TLS backend.
Some fields of `ClientConfig` only configure the default transport: the TLS
fields, the proxies and the timeouts. With a custom transport, the client
ignores them. The client uses all the other fields, for example `protocol` and
`user_agent`.

## Blocking client

`oci_client::blocking::Client` mirrors `Client` for synchronous Rust code.
The `blocking` feature enables it.

Each method runs the matching call on an async `Client`. It runs that
call on one background thread. Then it waits for the result.
`reqwest::blocking` uses the same approach on top of `reqwest`.

As a result, the blocking client accepts a custom transport, the same
way the async client does. Use `blocking::Client::new_with_transport` to
set it.

The blocking client has no version of `pull_blob_stream_partial`. That
method needs an async runtime to run its response body.

`blocking::Client::pull_blob_read` covers `pull_blob_stream`. It returns
a type that implements `Read`, with the content length and the digest
header ready before the first byte. `blocking::Client::pull_blob` is
`std::io::copy` over that type, for a simpler `Write`-based call. The
[`blocking-pull-layer`](examples/blocking-pull-layer/main.rs) example
uses `pull_blob_read` to show progress against the content length while
it writes a layer to a file. Run it with this command:

```sh
cargo run --features blocking --example blocking-pull-layer -- docker.io/library/hello-world:latest
```

`blocking::Client::push_blob_from_read` covers `push_blob_stream`. It
reads a plain `Read` on the calling thread, instead of a `Stream`.

None of these three methods buffers the whole blob in memory. A
`BlobReader` polls the response body on the calling thread, the way
`reqwest::blocking::Response` does. The push methods send chunks to the
background thread through a bounded channel. `ClientConfig::read_timeout`
and `connect_timeout` work as they do for the async client.

Do not call this client from async code. Like `reqwest::blocking`, each
method call blocks one OS thread until the request finishes.

## Code of Conduct

This project has adopted the [CNCF Code of
Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).
