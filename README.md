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

If you use your own HTTP transport, you do not have to enable a TLS feature.
In that case, your transport supplies TLS. The next section gives more
information.

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

## Code of Conduct

This project has adopted the [CNCF Code of
Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).
