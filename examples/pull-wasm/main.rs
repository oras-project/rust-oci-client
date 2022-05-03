extern crate oci_distribution;
use oci_distribution::{manifest, secrets::RegistryAuth, Client, Reference};

use clap::Parser;
use docker_credential::{CredentialRetrievalError, DockerCredential};
use tracing::{debug, info, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

/// Pull a WebAssembly module from a OCI container registry
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Enable verbose mode
    #[clap(short, long)]
    verbose: bool,

    /// Perform anonymous operation, by default the tool tries to reuse the docker credentials read
    /// from the default docker file
    #[clap(short, long)]
    anonymous: bool,

    /// Pull image from registry using HTTP instead of HTTPS
    #[clap(short, long)]
    insecure: bool,

    /// Write contents to file
    #[clap(short, long)]
    output: String,

    /// Name of the image to pull
    image: String,
}

fn build_auth(reference: &Reference, cli: &Cli) -> RegistryAuth {
    let server = reference
        .resolve_registry()
        .strip_suffix("/")
        .unwrap_or_else(|| reference.resolve_registry());

    if cli.anonymous {
        return RegistryAuth::Anonymous;
    }

    match docker_credential::get_credential(server) {
        Err(CredentialRetrievalError::ConfigNotFound) => RegistryAuth::Anonymous,
        Err(e) => panic!("Error handling docker configuration file: {}", e),
        Ok(DockerCredential::UsernamePassword(username, password)) => {
            debug!("Found docker credentials");
            RegistryAuth::Basic(username, password)
        }
        Ok(DockerCredential::IdentityToken(_)) => {
            warn!("Cannot use contents of docker config, identity token not supported. Using anonymous auth");
            RegistryAuth::Anonymous
        }
    }
}

fn build_client_config(cli: &Cli) -> oci_distribution::client::ClientConfig {
    let protocol = if cli.insecure {
        oci_distribution::client::ClientProtocol::Http
    } else {
        oci_distribution::client::ClientProtocol::Https
    };

    oci_distribution::client::ClientConfig {
        protocol,
        ..Default::default()
    }
}

#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();

    // setup logging
    let level_filter = if cli.verbose { "debug" } else { "info" };
    let filter_layer = EnvFilter::new(level_filter);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    let client_config = build_client_config(&cli);
    let mut client = Client::new(client_config);

    let reference: Reference = cli.image.parse().expect("Not a valid image reference");
    info!(?reference, "fetching wasm module");

    let auth = build_auth(&reference, &cli);

    let image_content = client
        .pull(&reference, &auth, vec![manifest::WASM_LAYER_MEDIA_TYPE])
        .await
        .expect("Cannot pull Wasm module")
        .layers
        .into_iter()
        .next()
        .map(|layer| layer.data)
        .expect("No data found");

    std::fs::write(&cli.output, image_content).expect("Cannot write to file");
    println!("Wasm module successfully written to {}", &cli.output);
}
