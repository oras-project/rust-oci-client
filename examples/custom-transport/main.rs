//! Pulls an image manifest and its configuration through a custom HTTP transport.
//!
//! By default, `oci_client::Client` sends its requests with a reqwest client.
//! This example gives the client a different HTTP stack, built from hyper and
//! tower layers. An application that already has an HTTP stack, for example
//! for a TLS policy, observability or traffic shaping, can do the same.
//!
//! The transport controls all the network work. As a result, it must have its
//! own TLS, and it must follow HTTP redirects. A redirect is a response that
//! tells the client to send the request to a different URL. Registries often
//! redirect blob downloads to a CDN or to an object store.
//!
//! Run the example with this command:
//!
//! ```text
//! cargo run --example custom-transport -- docker.io/library/hello-world:latest
//! ```
//!
//! To see a trace of each HTTP exchange, add `--verbose`. The blob download
//! shows as two exchanges. The registry returns a `307` redirect, then the
//! storage returns a `200`.
//!
//! This example does only anonymous pulls, so that it shows only the
//! transport. The `get-manifest` example shows how to use docker credentials.

use clap::Parser;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::secrets::RegistryAuth;
use oci_client::{transport, Client, Reference};
use tower::util::BoxCloneSyncService;
use tower::ServiceBuilder;
use tower_http::follow_redirect::FollowRedirectLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

/// Pull an image manifest and its configuration through a hyper HTTP transport
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Show a trace of each HTTP exchange of the transport
    #[clap(short, long)]
    verbose: bool,

    /// Pull the image from the registry with HTTP, not HTTPS
    #[clap(short, long)]
    insecure: bool,

    /// The name of the image to pull
    image: String,
}

/// Builds the HTTP transport that the OCI client sends its requests through.
fn hyper_transport() -> anyhow::Result<transport::Transport> {
    // The transport has its own TLS. This code gives the crypto provider to
    // rustls. The dependencies of this crate include two rustls providers,
    // and in that case rustls cannot select one.
    let https = HttpsConnectorBuilder::new()
        .with_provider_and_native_roots(rustls::crypto::aws_lc_rs::default_provider())?
        .https_or_http()
        .enable_http1()
        .build();
    let client = HyperClient::builder(TokioExecutor::new()).build::<_, transport::Body>(https);

    let service = ServiceBuilder::new()
        // The OCI client needs the transport errors as `BoxError`.
        .map_err(transport::BoxError::from)
        // The transport must follow redirects. If a redirect goes to a
        // different origin, this layer removes the `Authorization` header, as
        // reqwest does. As a result, the CDN does not get the registry
        // credentials.
        .layer(FollowRedirectLayer::new())
        // The OCI client needs responses with a `transport::Body`. This layer
        // must be outside `TraceLayer`, because `TraceLayer` changes the body
        // type of the responses.
        .map_response(|response: http::Response<_>| response.map(transport::Body::wrap))
        // You can add any tower middleware to the stack. This layer is an
        // example of the observability layers of an application. It is inside
        // `FollowRedirectLayer`, so it shows each redirect as a separate trace.
        .layer(TraceLayer::new_for_http())
        .service(client);

    Ok(BoxCloneSyncService::new(service))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        "info,oci_client=debug,tower_http=debug"
    } else {
        "info"
    };
    tracing_subscriber::registry()
        .with(EnvFilter::new(filter))
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    let reference: Reference = cli.image.parse()?;
    let config = ClientConfig {
        protocol: if cli.insecure {
            ClientProtocol::Http
        } else {
            ClientProtocol::Https
        },
        ..Default::default()
    };
    let client = Client::new_with_transport(config, hyper_transport()?);

    // To pull the configuration, the client sends all the request types: a
    // token request, the manifest requests and a blob download. Registries
    // usually redirect the blob download.
    let (manifest, digest, config) = client
        .pull_manifest_and_config(&reference, &RegistryAuth::Anonymous)
        .await?;

    println!("Manifest digest: {digest}");
    println!("Manifest:\n{manifest}");
    println!("Config:\n{config}");

    Ok(())
}
