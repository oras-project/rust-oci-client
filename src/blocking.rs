//! A synchronous (blocking) OCI Distribution client.
//!
//! [`Client`] mirrors [`crate::Client`], the asynchronous client, for use
//! from synchronous Rust code. It requires the `blocking` feature.
//!
//! # How it works
//!
//! Each [`Client`] method builds the matching call on an asynchronous
//! [`crate::Client`]. It runs that call to completion on one background
//! thread. Then it blocks the calling thread for the result.
//!
//! `reqwest::blocking` uses the same approach on top of `reqwest`. Because
//! of this, [`Client`] gets the asynchronous client's own [`ClientConfig`]
//! and HTTP transport for free. [`Client::new_with_transport`] takes the
//! same transport as [`crate::Client::new_with_transport`].
//!
//! See the [`crate::transport`] module for the contract a transport must
//! obey.
//!
//! Do not call this client from async code. Like `reqwest::blocking`, each
//! method call blocks an OS thread until the request completes. This
//! includes any redirects or retries that the transport does.
//!
//! # Streaming
//!
//! [`Client::pull_blob_read`] is the blocking form of
//! [`crate::Client::pull_blob_stream`]. It returns [`BlobReader`], which
//! implements [`std::io::Read`]. [`Client::pull_blob`] is
//! [`std::io::copy`] over a [`BlobReader`].
//!
//! [`BlobReader`] owns the response body stream. Each `read` call polls
//! that stream on the calling thread, the same way
//! `reqwest::blocking::Response` reads its body. No chunk crosses a
//! channel, and the transport reads from the network only when the
//! reader asks for the next chunk.
//!
//! [`Client::push_blob_from_read`] is the blocking form of
//! [`crate::Client::push_blob_stream`]. It reads a plain
//! [`std::io::Read`] on the calling thread, instead of a
//! [`futures_util::Stream`].
//!
//! [`Client::push_blob_from_read_chunked`] is the same kind of wrapper
//! around [`crate::Client::push_blob_stream_chunked`]. It computes the
//! digest while it reads, instead of needing the digest up front.
//!
//! For both push methods, a bounded channel carries blob chunks from the
//! calling thread to the background thread. At most a few chunks sit in
//! memory at once.
//!
//! This client has no version of [`crate::Client::pull_blob_stream_partial`].
//! That API can return a partial response, and a partial response does
//! not fit [`BlobReader`] the way a full response does.
//!
//! # Timeouts
//!
//! [`ClientConfig::read_timeout`] and [`ClientConfig::connect_timeout`]
//! work as they do for the asynchronous client. The transport applies
//! them. On a [`BlobReader`], a `read` call that waits longer than
//! `read_timeout` for the next chunk returns an error.
//! [`Client::pull_blob`] reports that error as
//! [`OciDistributionError::IoError`].

use std::convert::TryFrom;
use std::io::{Read, Write};

use bytes::Bytes;
use http::HeaderValue;
use tokio::sync::mpsc;
use tower::Service;

pub use crate::client::{
    current_platform_resolver, linux_amd64_resolver, windows_amd64_resolver, Certificate,
    CertificateEncoding, ClientConfig, ClientProtocol,
};
pub use crate::types::*;
pub use crate::{
    DEFAULT_MAX_CONCURRENT_DOWNLOAD, DEFAULT_MAX_CONCURRENT_UPLOAD, DEFAULT_TOKEN_EXPIRATION_SECS,
};

use crate::errors::*;
use crate::manifest::{OciImageIndex, OciImageManifest, OciManifest};
use crate::secrets::RegistryAuth;
use crate::token_cache::RegistryOperation;
#[cfg(test)]
use crate::token_cache::RegistryTokenType;
use crate::transport;
use crate::Reference;

mod background_runtime;
use background_runtime::BackgroundRuntime;

mod blob_io;
pub use blob_io::BlobReader;

mod wait;

/// A synchronous OCI Distribution client.
///
/// See the [module documentation](self) for how this client relates to
/// [`crate::Client`], the asynchronous client it wraps.
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: crate::client::Client,
    rt: BackgroundRuntime,
}

impl Default for Client {
    fn default() -> Self {
        Self::new(ClientConfig::default())
    }
}

/// A source that can provide a `ClientConfig`.
/// If you are using this crate in your own application, you can implement this
/// trait on your configuration type so that it can be passed to `Client::from_source`.
pub trait ClientConfigSource {
    /// Provides a `ClientConfig`.
    fn client_config(&self) -> ClientConfig;
}

impl TryFrom<ClientConfig> for Client {
    type Error = OciDistributionError;

    fn try_from(config: ClientConfig) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            inner: crate::client::Client::try_from(config)?,
            rt: BackgroundRuntime::new().map_err(|error| {
                OciDistributionError::GenericError(Some(format!(
                    "failed to start the background thread of the blocking client: {error}"
                )))
            })?,
        })
    }
}

impl Client {
    /// Create a new client with the supplied config
    pub fn new(config: ClientConfig) -> Self {
        Self {
            inner: crate::client::Client::new(config),
            rt: BackgroundRuntime::new()
                .expect("failed to start the background thread of the blocking client"),
        }
    }

    /// Create a new client with the supplied config
    pub fn from_source(config_source: &impl ClientConfigSource) -> Self {
        Self::new(config_source.client_config())
    }

    /// Creates a client that sends its requests through `transport`, not
    /// through the default reqwest client.
    ///
    /// This mirrors [`crate::Client::new_with_transport`]. See that
    /// constructor and the [`crate::transport`] module for the contract the
    /// transport must obey.
    pub fn new_with_transport<T, E>(config: ClientConfig, transport: T) -> Self
    where
        T: Service<transport::Request, Response = transport::Response, Error = E>
            + Clone
            + Send
            + Sync
            + 'static,
        T::Future: Send + 'static,
        E: Into<transport::BoxError> + 'static,
    {
        Self {
            inner: crate::client::Client::new_with_transport(config, transport),
            rt: BackgroundRuntime::new()
                .expect("failed to start the background thread of the blocking client"),
        }
    }

    /// Runs `future` to completion on the background thread of this client.
    /// Then it blocks the calling thread for the result.
    fn block_on<F>(&self, future: F) -> F::Output
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.rt.block_on(future)
    }

    /// Store the authentication information for this registry if it's not already stored in the client.
    ///
    /// Most of the time, you don't need to call this method directly. It's called by other
    /// methods (where you have to provide the authentication information as parameter).
    ///
    /// But if you want to pull/push a blob without calling any of the other methods first, which would
    /// store the authentication information, you can call this method to store the authentication
    /// information manually.
    pub fn store_auth_if_needed(&self, registry: &str, auth: &RegistryAuth) {
        let (registry, auth, inner) = (registry.to_string(), auth.clone(), self.inner.clone());
        self.block_on(async move { inner.store_auth_if_needed(&registry, &auth).await })
    }

    /// Fetches the available Tags for the given Reference
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    pub fn list_tags(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<TagResponse> {
        let (image, auth, last, inner) = (
            image.clone(),
            auth.clone(),
            last.map(str::to_owned),
            self.inner.clone(),
        );
        self.block_on(async move { inner.list_tags(&image, &auth, n, last.as_deref()).await })
    }

    /// Pull an image and return the bytes
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    pub fn pull(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
        accepted_media_types: Vec<&str>,
    ) -> Result<ImageData> {
        let (image, auth, inner) = (image.clone(), auth.clone(), self.inner.clone());
        let accepted_media_types: Vec<String> =
            accepted_media_types.iter().map(|s| s.to_string()).collect();
        self.block_on(async move {
            let accepted_media_types: Vec<&str> =
                accepted_media_types.iter().map(String::as_str).collect();
            inner.pull(&image, &auth, accepted_media_types).await
        })
    }

    /// Checks if a blob exists in the remote registry
    pub fn blob_exists(&self, image: &Reference, digest: &str) -> Result<bool> {
        let (image, digest, inner) = (image.clone(), digest.to_string(), self.inner.clone());
        self.block_on(async move { inner.blob_exists(&image, &digest).await })
    }

    /// Push an image and return the uploaded URL of the image
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// If a manifest is not provided, the client will attempt to generate
    /// it from the provided image and config data.
    ///
    /// Returns pullable URL for the image
    pub fn push(
        &self,
        image_ref: &Reference,
        layers: &[ImageLayer],
        config: Config,
        auth: &RegistryAuth,
        manifest: Option<OciImageManifest>,
    ) -> Result<PushResponse> {
        let (image_ref, layers, auth, inner) = (
            image_ref.clone(),
            layers.to_vec(),
            auth.clone(),
            self.inner.clone(),
        );
        self.block_on(async move {
            inner
                .push(&image_ref, &layers, config, &auth, manifest)
                .await
        })
    }

    /// Pushes a blob to the registry
    pub fn push_blob(
        &self,
        image_ref: &Reference,
        data: impl Into<bytes::Bytes>,
        digest: &str,
    ) -> Result<String> {
        let (image_ref, data, digest, inner) = (
            image_ref.clone(),
            data.into(),
            digest.to_string(),
            self.inner.clone(),
        );
        self.block_on(async move { inner.push_blob(&image_ref, data, &digest).await })
    }

    /// Pushes a blob to the registry. It reads the blob from `reader`
    /// instead of needing the whole blob in memory first.
    ///
    /// This method wraps [`crate::Client::push_blob_stream`]. `reader`
    /// runs on the calling thread. The method reads it in fixed-size
    /// chunks, then sends each chunk to the background thread. The
    /// background thread sends each chunk to the registry. At most a few
    /// chunks sit in memory at once. See the [module documentation](self)
    /// for details.
    ///
    /// `size` must be `Some` when the client's
    /// [`ClientConfig::use_monolithic_push`] is set. A monolithic push
    /// needs the `Content-Length` header up front, and `reader` cannot
    /// run twice. If `size` is `None` in that case, this method returns
    /// an error, and does not read from `reader`. Unlike
    /// [`Client::push_blob`], this method does not fall back to a
    /// monolithic push when the chunked path returns a
    /// `SpecViolationError`, for the same reason.
    ///
    /// Returns the pullable location of the blob.
    pub fn push_blob_from_read<R: Read>(
        &self,
        image_ref: &Reference,
        reader: R,
        digest: &str,
        size: Option<u64>,
    ) -> Result<String> {
        // Select the mode here, on the calling thread, before any code reads
        // `reader`. A missing `size` fails here. The background task never
        // starts, so this thread never blocks on a read from a pipe or a
        // socket.
        let mode = self.inner.push_mode(size)?;
        let (image_ref, digest, inner) =
            (image_ref.clone(), digest.to_string(), self.inner.clone());
        let (tx, rx) = mpsc::channel::<Result<Bytes>>(blob_io::BLOB_CHANNEL_CAPACITY);
        let handle = self.rt.spawn(async move {
            inner
                .push_blob_stream_with_mode(&image_ref, blob_io::receiver_stream(rx), &digest, mode)
                .await
        });
        blob_io::feed_reader_to_channel(reader, tx);
        handle.wait()
    }

    /// Pushes a blob to the registry. It reads the blob from `reader` and
    /// computes the digest while it reads.
    ///
    /// This method wraps [`crate::Client::push_blob_stream_chunked`]. See
    /// [`Client::push_blob_from_read`] for how `reader` connects to the
    /// background thread. This method always sends the blob as a series
    /// of chunked PATCH requests. It ignores the client's
    /// `use_monolithic_push` setting.
    ///
    /// Returns the pullable location of the blob, the computed digest,
    /// and the blob size.
    pub fn push_blob_from_read_chunked<R: Read>(
        &self,
        image_ref: &Reference,
        reader: R,
    ) -> Result<PushBlobStreamChunkedResponse> {
        let (image_ref, inner) = (image_ref.clone(), self.inner.clone());
        let (tx, rx) = mpsc::channel::<Result<Bytes>>(blob_io::BLOB_CHANNEL_CAPACITY);
        let handle = self.rt.spawn(async move {
            inner
                .push_blob_stream_chunked(&image_ref, blob_io::receiver_stream(rx))
                .await
        });
        blob_io::feed_reader_to_channel(reader, tx);
        handle.wait()
    }

    /// Perform an OAuth v2 auth request if necessary.
    ///
    /// This performs authorization and then stores the token internally to be used
    /// on other requests.
    pub fn auth(
        &self,
        image: &Reference,
        authentication: &RegistryAuth,
        operation: RegistryOperation,
    ) -> Result<Option<String>> {
        let (image, authentication, inner) =
            (image.clone(), authentication.clone(), self.inner.clone());
        self.block_on(async move { inner.auth(&image, &authentication, operation).await })
    }

    /// Fetch a manifest's digest from the remote OCI Distribution service.
    ///
    /// If the connection has already gone through authentication, this will
    /// use the bearer token. Otherwise, this will attempt an anonymous pull.
    ///
    /// Will first attempt to read the `Docker-Content-Digest` header using a
    /// HEAD request. If this header is not present, will make a second GET
    /// request and return the SHA256 of the response body.
    pub fn fetch_manifest_digest(&self, image: &Reference, auth: &RegistryAuth) -> Result<String> {
        let (image, auth, inner) = (image.clone(), auth.clone(), self.inner.clone());
        self.block_on(async move { inner.fetch_manifest_digest(&image, &auth).await })
    }

    /// Pull a manifest from the remote OCI Distribution service.
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// A Tuple is returned containing the [OciImageManifest]
    /// and the manifest content digest hash.
    ///
    /// If a multi-platform Image Index manifest is encountered, a platform-specific
    /// Image manifest will be selected using the client's default platform resolution.
    pub fn pull_image_manifest(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
    ) -> Result<(OciImageManifest, String)> {
        let (image, auth, inner) = (image.clone(), auth.clone(), self.inner.clone());
        self.block_on(async move { inner.pull_image_manifest(&image, &auth).await })
    }

    /// Pull a manifest from the remote OCI Distribution service.
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// Returns `(image_manifest, manifest_digest, Option<manifest_list_digest>)`.
    /// The manifest list digest is `Some` when the original reference pointed to
    /// an image index / manifest list; `None` when it pointed directly to a
    /// single-platform image manifest.
    ///
    /// If a multi-platform Image Index manifest is encountered, a platform-specific
    /// Image manifest will be selected using the client's default platform resolution.
    pub fn pull_image_manifest_and_list_digest(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
    ) -> Result<(OciImageManifest, String, Option<String>)> {
        let (image, auth, inner) = (image.clone(), auth.clone(), self.inner.clone());
        self.block_on(async move {
            inner
                .pull_image_manifest_and_list_digest(&image, &auth)
                .await
        })
    }

    /// Pull a manifest from the remote OCI Distribution service without parsing it.
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// A Tuple is returned containing raw byte representation of the manifest
    /// and the manifest content digest.
    pub fn pull_manifest_raw(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
        accepted_media_types: &[&str],
    ) -> Result<(Vec<u8>, String)> {
        let (image, auth, inner) = (image.clone(), auth.clone(), self.inner.clone());
        let accepted_media_types: Vec<String> =
            accepted_media_types.iter().map(|s| s.to_string()).collect();
        self.block_on(async move {
            let accepted_media_types: Vec<&str> =
                accepted_media_types.iter().map(String::as_str).collect();
            let (body, digest) = inner
                .pull_manifest_raw(&image, &auth, &accepted_media_types)
                .await?;
            Ok((body.to_vec(), digest))
        })
    }

    /// Pull a manifest from the remote OCI Distribution service.
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// A Tuple is returned containing the [Manifest](crate::manifest::OciImageManifest)
    /// and the manifest content digest hash.
    pub fn pull_manifest(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
    ) -> Result<(OciManifest, String)> {
        let (image, auth, inner) = (image.clone(), auth.clone(), self.inner.clone());
        self.block_on(async move { inner.pull_manifest(&image, &auth).await })
    }

    /// Pull a manifest and its config from the remote OCI Distribution service.
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// A Tuple is returned containing the [OciImageManifest],
    /// the manifest content digest hash and the contents of the manifests config layer
    /// as a String.
    pub fn pull_manifest_and_config(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
    ) -> Result<(OciImageManifest, String, String)> {
        let (image, auth, inner) = (image.clone(), auth.clone(), self.inner.clone());
        self.block_on(async move { inner.pull_manifest_and_config(&image, &auth).await })
    }

    /// Pull a manifest and its config from the remote OCI Distribution service.
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// Returns `(image_manifest, manifest_digest, config_json, Option<manifest_list_digest>)`.
    /// The manifest list digest is `Some` when the original reference pointed to
    /// an image index / manifest list; `None` when it pointed directly to a
    /// single-platform image manifest.
    ///
    /// If a multi-platform Image Index manifest is encountered, a platform-specific
    /// Image manifest will be selected using the client's default platform resolution.
    pub fn pull_manifest_and_config_and_list_digest(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
    ) -> Result<(OciImageManifest, String, String, Option<String>)> {
        let (image, auth, inner) = (image.clone(), auth.clone(), self.inner.clone());
        self.block_on(async move {
            inner
                .pull_manifest_and_config_and_list_digest(&image, &auth)
                .await
        })
    }

    /// Push a manifest list to an OCI registry.
    ///
    /// This pushes a manifest list to an OCI registry.
    pub fn push_manifest_list(
        &self,
        reference: &Reference,
        auth: &RegistryAuth,
        manifest: OciImageIndex,
    ) -> Result<ManifestPushResponse> {
        let (reference, auth, inner) = (reference.clone(), auth.clone(), self.inner.clone());
        self.block_on(async move { inner.push_manifest_list(&reference, &auth, manifest).await })
    }

    /// Pull a single layer from an OCI registry, as a [`std::io::Read`].
    ///
    /// This pulls the layer for a particular image that is identified by the given layer
    /// descriptor. The layer descriptor can be anything that can be referenced as a layer
    /// descriptor. The image reference is used to find the repository and the registry, but it is
    /// not used to verify that the digest is a layer inside of the image. (The manifest is used for
    /// that.)
    ///
    /// This method is the blocking form of [`crate::Client::pull_blob_stream`].
    /// It returns once the registry sends a response. [`BlobReader::content_length`]
    /// and [`BlobReader::digest_header_value`] are ready at that point, before
    /// the first byte of the body. A read error, including a digest
    /// mismatch or a read timeout, surfaces from [`std::io::Read::read`]
    /// on the returned [`BlobReader`]. See the [module documentation](self)
    /// for how each `read` call gets its data, and [`Client::pull_blob`]
    /// for a simpler, `Write`-based version.
    ///
    /// Drop the returned [`BlobReader`] to stop the pull early. The
    /// reader can outlive this `Client`; dropping every clone of the
    /// client does not cancel the pull. See [`BlobReader`] for the exact
    /// drop and lifetime behavior.
    pub fn pull_blob_read(
        &self,
        image: &Reference,
        layer: impl AsLayerDescriptor,
    ) -> Result<BlobReader> {
        let (image, layer, inner) = (
            image.clone(),
            blob_io::OwnedLayerDescriptor::new(layer),
            self.inner.clone(),
        );
        let stream = self.block_on(async move { inner.pull_blob_stream(&image, &layer).await })?;
        Ok(BlobReader {
            content_length: stream.content_length,
            digest_header_value: stream.digest_header_value,
            state: blob_io::StreamState::Open(stream.stream),
            current: Bytes::new(),
            runtime: self.rt.clone(),
        })
    }

    /// Pull a single layer from an OCI registry.
    ///
    /// This pulls the layer for a particular image that is identified by the given layer
    /// descriptor. The layer descriptor can be anything that can be referenced as a layer
    /// descriptor. The image reference is used to find the repository and the registry, but it is
    /// not used to verify that the digest is a layer inside of the image. (The manifest is used for
    /// that.)
    ///
    /// This method streams the blob to `out` as the blob arrives over the
    /// network. It does not buffer the whole blob in memory; see
    /// [`Client::pull_blob_read`], which this method wraps. Because of
    /// this, some bytes can already be in `out` when this method returns
    /// a digest-mismatch error or a read-timeout error. If you need
    /// all-or-nothing behavior, write to a temporary file. Rename the
    /// file into place only after this method returns `Ok`.
    pub fn pull_blob<T: Write>(
        &self,
        image: &Reference,
        layer: impl AsLayerDescriptor,
        mut out: T,
    ) -> Result<()> {
        let mut reader = self.pull_blob_read(image, layer)?;
        std::io::copy(&mut reader, &mut out).map_err(blob_io::io_error_to_oci)?;
        out.flush()?;
        Ok(())
    }

    /// Mounts a blob to the provided reference, from the given source
    pub fn mount_blob(&self, image: &Reference, source: &Reference, digest: &str) -> Result<()> {
        let (image, source, digest, inner) = (
            image.clone(),
            source.clone(),
            digest.to_string(),
            self.inner.clone(),
        );
        self.block_on(async move { inner.mount_blob(&image, &source, &digest).await })
    }

    /// Pushes the manifest for a specified image
    ///
    /// Returns the pullable manifest URL and the locally computed digest of
    /// the manifest that was sent.
    pub fn push_manifest(
        &self,
        image: &Reference,
        manifest: &OciManifest,
    ) -> Result<ManifestPushResponse> {
        let (image, manifest, inner) = (image.clone(), manifest.clone(), self.inner.clone());
        self.block_on(async move { inner.push_manifest(&image, &manifest).await })
    }

    /// Pushes the manifest, provided as raw bytes, for a specified image
    ///
    /// Returns the pullable manifest URL and the locally computed digest of
    /// the manifest that was sent.
    pub fn push_manifest_raw(
        &self,
        image: &Reference,
        body: impl Into<bytes::Bytes>,
        content_type: HeaderValue,
    ) -> Result<ManifestPushResponse> {
        let (image, body, inner) = (image.clone(), body.into(), self.inner.clone());
        self.block_on(async move { inner.push_manifest_raw(&image, body, content_type).await })
    }

    /// Pulls the referrers for the given image filtering by the optionally provided artifact type.
    pub fn pull_referrers(
        &self,
        image: &Reference,
        artifact_type: Option<&str>,
    ) -> Result<OciImageIndex> {
        let (image, artifact_type, inner) = (
            image.clone(),
            artifact_type.map(str::to_owned),
            self.inner.clone(),
        );
        self.block_on(async move { inner.pull_referrers(&image, artifact_type.as_deref()).await })
    }

    /// Lists available repositories in the registry.
    ///
    /// Implements the OCI Distribution Spec catalog endpoint (`/v2/_catalog`).
    /// Supports pagination via `n` (page size) and `last` (last repo from
    /// previous page).
    pub fn catalog(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<CatalogResponse> {
        let (image, auth, last, inner) = (
            image.clone(),
            auth.clone(),
            last.map(str::to_owned),
            self.inner.clone(),
        );
        self.block_on(async move { inner.catalog(&image, &auth, n, last.as_deref()).await })
    }
}

/// Test-only methods for functionality of the asynchronous client that is
/// not part of its public API. The test harness in `client::test` uses
/// these methods. It runs the same test bodies against both clients.
#[cfg(test)]
impl Client {
    pub(crate) fn block_on_for_test<F>(&self, future: F) -> F::Output
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.block_on(future)
    }

    pub(crate) fn store_auth(&self, registry: &str, auth: RegistryAuth) {
        let (registry, inner) = (registry.to_string(), self.inner.clone());
        self.block_on(async move { inner.store_auth(&registry, auth).await })
    }

    pub(crate) fn insert_token(
        &self,
        reference: &Reference,
        op: RegistryOperation,
        token: RegistryTokenType,
    ) {
        let (reference, inner) = (reference.clone(), self.inner.clone());
        self.block_on(async move { inner.tokens.insert(&reference, op, token).await })
    }

    pub(crate) fn cached_token(
        &self,
        reference: &Reference,
        op: RegistryOperation,
    ) -> Option<RegistryTokenType> {
        let (reference, inner) = (reference.clone(), self.inner.clone());
        self.block_on(async move { inner.tokens.get(&reference, op).await })
    }

    pub(crate) fn set_push_chunk_size(&mut self, size: usize) {
        self.inner.set_push_chunk_size(size);
    }

    pub(crate) fn _pull_image_manifest(
        &self,
        image: &Reference,
    ) -> Result<(OciImageManifest, String)> {
        let (image, inner) = (image.clone(), self.inner.clone());
        self.block_on(async move { inner._pull_image_manifest(&image).await })
    }

    pub(crate) fn push_blob_chunked(
        &self,
        image: &Reference,
        data: impl Into<bytes::Bytes>,
        digest: &str,
    ) -> Result<String> {
        let (image, data, digest, inner) = (
            image.clone(),
            data.into(),
            digest.to_string(),
            self.inner.clone(),
        );
        self.block_on(async move { inner.push_blob_chunked(&image, data, &digest).await })
    }

    pub(crate) fn begin_push_chunked_session(&self, image: &Reference) -> Result<String> {
        let (image, inner) = (image.clone(), self.inner.clone());
        self.block_on(async move { inner.begin_push_chunked_session(&image).await })
    }

    pub(crate) fn push_chunk(
        &self,
        location: &str,
        image: &Reference,
        data: impl Into<bytes::Bytes>,
        start_byte: usize,
    ) -> Result<(String, usize)> {
        let (location, image, data, inner) = (
            location.to_string(),
            image.clone(),
            data.into(),
            self.inner.clone(),
        );
        self.block_on(async move { inner.push_chunk(&location, &image, data, start_byte).await })
    }

    pub(crate) fn end_push_chunked_session(
        &self,
        location: &str,
        image: &Reference,
        digest: &str,
    ) -> Result<String> {
        let (location, image, digest, inner) = (
            location.to_string(),
            image.clone(),
            digest.to_string(),
            self.inner.clone(),
        );
        self.block_on(async move {
            inner
                .end_push_chunked_session(&location, &image, &digest)
                .await
        })
    }
}
