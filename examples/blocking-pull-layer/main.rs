//! Pulls one or more layers of an image, through the blocking client's
//! `Read` API.
//!
//! `oci_client::blocking::Client::pull_blob_read` returns `BlobReader`, a
//! type that implements `std::io::Read`. Its `content_length` and
//! `digest_header_value` fields are ready before the first byte of the
//! body, so a caller can show progress against a known total before it
//! reads anything. A plain `Write`-based call, like
//! `blocking::Client::pull_blob`, cannot do that: it only returns once
//! the whole layer is in `out`.
//!
//! This example streams each layer straight to a file. It never holds
//! the whole layer in memory.
//!
//! Run the example with this command:
//!
//! ```text
//! cargo run --features blocking --example blocking-pull-layer -- docker.io/library/hello-world:latest
//! ```
//!
//! The example writes the first layer to the current directory, under a
//! name built from its digest. Use `--output-dir` to pick a different
//! directory, `--layer <N>` to pull one layer by its index in the
//! manifest, or `--all` to pull every layer. Add `--verbose` to see the
//! HTTP exchanges.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use docker_credential::{CredentialRetrievalError, DockerCredential};
use oci_client::blocking::{Client, ClientConfig, ClientProtocol};
use oci_client::manifest::OciDescriptor;
use oci_client::{secrets::RegistryAuth, Reference};
use tracing::{debug, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

/// Pulls one or more layers of an image, through the blocking client's `Read` API
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

    /// Pull the image from the registry with HTTP, not HTTPS
    #[clap(short, long)]
    insecure: bool,

    /// Directory to write the layers into
    #[clap(short, long, default_value = ".")]
    output_dir: PathBuf,

    /// Index of the one layer to pull, in the order the manifest lists them
    #[clap(short, long, default_value_t = 0, conflicts_with = "all")]
    layer: usize,

    /// Pull every layer, instead of just the one `--layer` names
    #[clap(long)]
    all: bool,

    /// Name of the image to pull
    image: String,
}

fn build_auth(reference: &Reference, cli: &Cli) -> RegistryAuth {
    let server = reference
        .resolve_registry()
        .strip_suffix('/')
        .unwrap_or_else(|| reference.resolve_registry());

    if cli.anonymous {
        return RegistryAuth::Anonymous;
    }

    match docker_credential::get_credential(server) {
        Err(CredentialRetrievalError::ConfigNotFound) => RegistryAuth::Anonymous,
        Err(CredentialRetrievalError::NoCredentialConfigured) => RegistryAuth::Anonymous,
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

/// A `Read` that counts the bytes it passes through, and prints progress
/// to stderr as that count grows.
///
/// This is the part a `Write`-based call cannot offer: `pull_blob_read`
/// gives `total` before the first byte arrives, so this wrapper can show
/// a percentage from the start, instead of only a running byte count.
struct Progress<R> {
    inner: R,
    read: u64,
    total: Option<u64>,
    last_reported_mib: u64,
}

impl<R: Read> Read for Progress<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read += n as u64;
        let mib = self.read / (1024 * 1024);
        if mib > self.last_reported_mib || n == 0 {
            self.last_reported_mib = mib;
            match self.total {
                Some(total) if total > 0 => {
                    let percent = self.read * 100 / total;
                    eprint!("\r  {} / {total} bytes ({percent}%)", self.read);
                }
                _ => eprint!("\r  {} bytes", self.read),
            }
            if n == 0 {
                eprintln!();
            }
        }
        Ok(n)
    }
}

/// Pulls `layer` from `image`, and writes it to `output_dir`.
///
/// Writes to a `.part` file first, and renames it to its final name only
/// once the whole layer arrives and its digest checks out. A read that
/// stops partway through, for example on a digest mismatch, leaves no
/// file under the final name; the next run starts over.
fn pull_layer(
    client: &Client,
    image: &Reference,
    layer: &OciDescriptor,
    output_dir: &Path,
) -> Result<()> {
    println!("Layer {}", layer.digest);
    println!("  media type: {}", layer.media_type);

    // `pull_blob_read` returns once the registry opens the response. At
    // this point, no byte of the body has arrived yet.
    let reader = client
        .pull_blob_read(image, layer)
        .with_context(|| format!("failed to open layer {}", layer.digest))?;

    println!(
        "  content length: {}",
        reader
            .content_length
            .map(|n| n.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    if let Some(digest) = &reader.digest_header_value {
        println!("  registry digest header: {digest}");
    }

    let mut reader = Progress {
        total: reader.content_length,
        read: 0,
        last_reported_mib: 0,
        inner: reader,
    };

    let file_name = layer.digest.replace(':', "-");
    let part_path = output_dir.join(format!("{file_name}.part"));
    let final_path = output_dir.join(&file_name);

    let mut file = File::create(&part_path)
        .with_context(|| format!("failed to create {}", part_path.display()))?;

    // The digest check happens on the network, as the last bytes of the
    // layer arrive. A mismatch surfaces here, from `std::io::copy`, as
    // an `io::Error` whose `source()` is the `DigestError`. Anyhow's
    // default error report prints that source as a "Caused by" line.
    let copy_result = std::io::copy(&mut reader, &mut file).and_then(|_| file.flush());
    if let Err(error) = copy_result {
        drop(file);
        let _ = std::fs::remove_file(&part_path);
        return Err(error).with_context(|| format!("failed to read layer {}", layer.digest));
    }
    drop(file);

    std::fs::rename(&part_path, &final_path)
        .with_context(|| format!("failed to rename {} to its final name", part_path.display()))?;
    println!("  saved to {}", final_path.display());

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let level_filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::registry()
        .with(EnvFilter::new(level_filter))
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    let reference: Reference = cli.image.parse().context("not a valid image reference")?;
    let auth = build_auth(&reference, &cli);

    let config = ClientConfig {
        protocol: if cli.insecure {
            ClientProtocol::Http
        } else {
            ClientProtocol::Https
        },
        ..Default::default()
    };
    let client = Client::new(config);

    let (manifest, _) = client
        .pull_image_manifest(&reference, &auth)
        .context("failed to pull the image manifest")?;

    if manifest.layers.is_empty() {
        anyhow::bail!("the image has no layers");
    }

    std::fs::create_dir_all(&cli.output_dir)
        .with_context(|| format!("failed to create {}", cli.output_dir.display()))?;

    let layers: Vec<&OciDescriptor> = if cli.all {
        manifest.layers.iter().collect()
    } else {
        let layer = manifest.layers.get(cli.layer).with_context(|| {
            format!(
                "the image has {} layer(s); there is no layer {}",
                manifest.layers.len(),
                cli.layer
            )
        })?;
        vec![layer]
    };

    for layer in layers {
        pull_layer(&client, &reference, layer, &cli.output_dir)?;
    }

    Ok(())
}
