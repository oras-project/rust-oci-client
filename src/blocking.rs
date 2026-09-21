//! Blocking OCI distribution client for fetching oci images from an OCI compliant remote store
//!
//! This module mirrors [`crate::client`] but uses `reqwest::blocking`, so it can
//! be used from synchronous Rust code. It is enabled by the `blocking` feature.
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::Write;

use http::header::RANGE;
use http::HeaderValue;
use olpc_cjson::CanonicalFormatter;
use reqwest::blocking::{RequestBuilder, Response};
use reqwest::header::HeaderMap;
use reqwest::{NoProxy, Proxy, Url};
use serde::Serialize;
use tracing::{debug, trace, warn};

pub use crate::client::{
    current_platform_resolver, linux_amd64_resolver, windows_amd64_resolver, Certificate,
    CertificateEncoding, ClientConfig, ClientProtocol,
};
pub use crate::types::*;
pub use crate::{
    DEFAULT_MAX_CONCURRENT_DOWNLOAD, DEFAULT_MAX_CONCURRENT_UPLOAD, DEFAULT_TOKEN_EXPIRATION_SECS,
};

use crate::client::{convert_certificates, validate_registry_response, BearerChallenge};
use crate::digest::{digest_header_value, validate_digest, Digest, Digester};
use crate::errors::*;
use crate::manifest::{
    OciImageIndex, OciImageManifest, OciManifest, Versioned, IMAGE_MANIFEST_LIST_MEDIA_TYPE,
    IMAGE_MANIFEST_MEDIA_TYPE, OCI_IMAGE_INDEX_MEDIA_TYPE, OCI_IMAGE_MEDIA_TYPE,
};
use crate::secrets::RegistryAuth;
use crate::secrets::*;
use crate::sha256_digest;
use crate::token_cache::{RegistryOperation, RegistryToken, RegistryTokenType, SyncTokenCache};
use crate::Reference;
use crate::{MIME_TYPES_DISTRIBUTION_MANIFEST, PUSH_CHUNK_MAX_SIZE};

/// The OCI client connects to an OCI registry and fetches OCI images.
///
/// An OCI registry is a container registry that adheres to the OCI Distribution
/// specification. DockerHub is one example, as are ACR and GCR. This client
/// provides a native Rust implementation for pulling OCI images.
///
/// Some OCI registries support completely anonymous access. But most require
/// at least an Oauth2 handshake. Typically, you will want to create a new
/// client, and then run the `auth()` method, which will attempt to get
/// a read-only bearer token. From there, pulling images can be done with
/// the `pull_*` functions.
///
/// For true anonymous access, you can skip `auth()`. This is not recommended
/// unless you are sure that the remote registry does not require Oauth2.
pub struct Client {
    config: ClientConfig,
    // Registry -> RegistryAuth
    auth_store: HashMap<String, RegistryAuth>,
    pub(crate) tokens: SyncTokenCache,
    client: reqwest::blocking::Client,
    pub(crate) push_chunk_size: usize,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            config: ClientConfig::default(),
            auth_store: HashMap::new(),
            tokens: SyncTokenCache::new(DEFAULT_TOKEN_EXPIRATION_SECS),
            client: reqwest::blocking::Client::default(),
            push_chunk_size: PUSH_CHUNK_MAX_SIZE,
        }
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
        #[allow(unused_mut)]
        let mut client_builder = reqwest::blocking::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let mut client_builder =
            client_builder.danger_accept_invalid_certs(config.accept_invalid_certificates);

        client_builder = match () {
            #[cfg(all(feature = "native-tls", not(target_arch = "wasm32")))]
            () => client_builder.danger_accept_invalid_hostnames(config.accept_invalid_hostnames),
            #[cfg(any(not(feature = "native-tls"), target_arch = "wasm32"))]
            () => client_builder,
        };

        #[cfg(not(target_arch = "wasm32"))]
        {
            if !config.tls_certs_only.is_empty() {
                client_builder =
                    client_builder.tls_certs_only(convert_certificates(&config.tls_certs_only)?);
            }
            client_builder = client_builder
                .tls_certs_merge(convert_certificates(&config.extra_root_certificates)?);
        }

        // `reqwest::blocking::ClientBuilder` has no per-read timeout; `timeout`
        // bounds the whole request instead.
        if let Some(timeout) = config.read_timeout {
            client_builder = client_builder.timeout(timeout);
        }
        if let Some(timeout) = config.connect_timeout {
            client_builder = client_builder.connect_timeout(timeout);
        }

        client_builder = client_builder.user_agent(config.user_agent);

        if let Some(proxy_addr) = &config.https_proxy {
            let no_proxy = config
                .no_proxy
                .as_ref()
                .and_then(|no_proxy| NoProxy::from_string(no_proxy));
            let proxy = Proxy::https(proxy_addr)?.no_proxy(no_proxy);
            client_builder = client_builder.proxy(proxy);
        }

        if let Some(proxy_addr) = &config.http_proxy {
            let no_proxy = config
                .no_proxy
                .as_ref()
                .and_then(|no_proxy| NoProxy::from_string(no_proxy));
            let proxy = Proxy::http(proxy_addr)?.no_proxy(no_proxy);
            client_builder = client_builder.proxy(proxy);
        }

        let default_token_expiration_secs = config.default_token_expiration_secs;
        Ok(Self {
            config,
            tokens: SyncTokenCache::new(default_token_expiration_secs),
            client: client_builder.build()?,
            push_chunk_size: PUSH_CHUNK_MAX_SIZE,
            ..Default::default()
        })
    }
}

impl Client {
    /// Create a new client with the supplied config
    pub fn new(config: ClientConfig) -> Self {
        let default_token_expiration_secs = config.default_token_expiration_secs;
        Client::try_from(config).unwrap_or_else(|err| {
            warn!("Cannot create OCI client from config: {:?}", err);
            warn!("Creating client with default configuration");
            Self {
                tokens: SyncTokenCache::new(default_token_expiration_secs),
                push_chunk_size: PUSH_CHUNK_MAX_SIZE,
                ..Default::default()
            }
        })
    }

    /// Create a new client with the supplied config
    pub fn from_source(config_source: &impl ClientConfigSource) -> Self {
        Self::new(config_source.client_config())
    }

    pub(crate) fn store_auth(&mut self, registry: &str, auth: RegistryAuth) {
        self.auth_store.insert(registry.to_string(), auth);
    }

    fn is_stored_auth(&self, registry: &str) -> bool {
        self.auth_store.contains_key(registry)
    }

    /// Store the authentication information for this registry if it's not already stored in the client.
    ///
    /// Most of the time, you don't need to call this method directly. It's called by other
    /// methods (where you have to provide the authentication information as parameter).
    ///
    /// But if you want to pull/push a blob without calling any of the other methods first, which would
    /// store the authentication information, you can call this method to store the authentication
    /// information manually.
    pub fn store_auth_if_needed(&mut self, registry: &str, auth: &RegistryAuth) {
        if !self.is_stored_auth(registry) {
            self.store_auth(registry, auth.clone());
        }
    }

    /// Checks if we got a token, if we don't - create it and store it in cache.
    fn get_auth_token(
        &mut self,
        reference: &Reference,
        op: RegistryOperation,
    ) -> Option<RegistryTokenType> {
        let registry = reference.resolve_registry();
        let auth = self.auth_store.get(registry)?.clone();
        match self.tokens.get(reference, op) {
            Some(token) => Some(token),
            None => {
                let token = self._auth(reference, &auth, op).ok()??;
                self.tokens.insert(reference, op, token.clone());
                Some(token)
            }
        }
    }

    /// Fetches the available Tags for the given Reference
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    pub fn list_tags(
        &mut self,
        image: &Reference,
        auth: &RegistryAuth,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<TagResponse> {
        let op = RegistryOperation::Pull;
        let url = self.config.to_list_tags_url(image);

        self.store_auth_if_needed(image.resolve_registry(), auth);

        let request = self.client.get(&url);
        let request = if let Some(num) = n {
            request.query(&[("n", num)])
        } else {
            request
        };
        let request = if let Some(l) = last {
            request.query(&[("last", l)])
        } else {
            request
        };
        let mut request = RequestBuilderWrapper {
            client: self,
            request_builder: request,
        };
        let res = request
            .apply_auth(image, op)?
            .into_request_builder()
            .send()?;
        let status = res.status();
        let body = res.bytes()?;

        validate_registry_response(status, &body, &url)?;

        Ok(serde_json::from_str(std::str::from_utf8(&body)?)?)
    }

    /// Pull an image and return the bytes
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    pub fn pull(
        &mut self,
        image: &Reference,
        auth: &RegistryAuth,
        accepted_media_types: Vec<&str>,
    ) -> Result<ImageData> {
        debug!("Pulling image: {:?}", image);
        self.store_auth_if_needed(image.resolve_registry(), auth);

        let (manifest, digest, config) = self._pull_manifest_and_config(image)?;

        self.validate_layers(&manifest, accepted_media_types)?;

        let layers = manifest.layers.iter().try_fold(vec![], |mut acc, layer| {
            let mut out: Vec<u8> = Vec::new();
            debug!("Pulling image layer");
            match self.pull_blob(image, layer, &mut out) {
                Ok(_) => {
                    acc.push(ImageLayer::new(
                        out,
                        layer.media_type.clone(),
                        layer.annotations.clone(),
                    ));
                    Ok(acc)
                }
                Err(e) => {
                    warn!(error = ?e, "Failed to pull image layer");
                    Err(e)
                }
            }
        })?;

        Ok(ImageData {
            layers,
            manifest: Some(manifest),
            config,
            digest: Some(digest),
        })
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
        &mut self,
        image_ref: &Reference,
        layers: &[ImageLayer],
        config: Config,
        auth: &RegistryAuth,
        manifest: Option<OciImageManifest>,
    ) -> Result<PushResponse> {
        debug!("Pushing image: {:?}", image_ref);
        self.store_auth_if_needed(image_ref.resolve_registry(), auth);

        let manifest: OciImageManifest = match manifest {
            Some(m) => m,
            None => OciImageManifest::build(layers, &config, None),
        };

        // Upload layers
        layers.iter().try_for_each(|layer| {
            let digest = layer.sha256_digest();
            self.push_blob(image_ref, &layer.data, &digest)?;
            Result::Ok(())
        })?;

        let config_url = self.push_blob(image_ref, &config.data, &manifest.config.digest)?;
        let manifest_url = self.push_manifest(image_ref, &manifest.into())?;

        Ok(PushResponse {
            config_url,
            manifest_url,
        })
    }

    /// Pushes a blob to the registry
    pub fn push_blob(
        &mut self,
        image_ref: &Reference,
        data: &[u8],
        digest: &str,
    ) -> Result<String> {
        if self.config.use_monolithic_push {
            return self.push_blob_monolithically(image_ref, data, digest);
        }

        match self.push_blob_chunked(image_ref, data, digest) {
            Ok(url) => Ok(url),
            Err(OciDistributionError::SpecViolationError(violation)) => {
                warn!(?violation, "Registry is not respecting the OCI Distribution Specification when doing chunked push operations");
                warn!("Attempting monolithic push");
                self.push_blob_monolithically(image_ref, data, digest)
            }
            Err(e) => Err(e),
        }
    }

    /// Pushes a blob to the registry as a monolith
    ///
    /// Returns the pullable location of the blob
    fn push_blob_monolithically(
        &mut self,
        image: &Reference,
        blob_data: &[u8],
        blob_digest: &str,
    ) -> Result<String> {
        let location = self.begin_push_monolithical_session(image)?;
        self.push_monolithically(&location, image, blob_data, blob_digest)
    }

    /// Pushes a blob to the registry as a series of chunks
    ///
    /// Returns the pullable location of the blob
    pub(crate) fn push_blob_chunked(
        &mut self,
        image: &Reference,
        blob_data: &[u8],
        blob_digest: &str,
    ) -> Result<String> {
        let mut location = self.begin_push_chunked_session(image)?;
        let mut start: usize = 0;
        loop {
            (location, start) = self.push_chunk(&location, image, blob_data, start)?;
            if start >= blob_data.len() {
                break;
            }
        }
        self.end_push_chunked_session(&location, image, blob_digest)
    }

    /// Perform an OAuth v2 auth request if necessary.
    ///
    /// This performs authorization and then stores the token internally to be used
    /// on other requests.
    pub fn auth(
        &mut self,
        image: &Reference,
        authentication: &RegistryAuth,
        operation: RegistryOperation,
    ) -> Result<Option<String>> {
        self.store_auth_if_needed(image.resolve_registry(), authentication);
        // preserve old caching behavior
        match self._auth(image, authentication, operation) {
            Ok(Some(RegistryTokenType::Bearer(token))) => {
                self.tokens
                    .insert(image, operation, RegistryTokenType::Bearer(token.clone()));
                Ok(Some(token.token().to_string()))
            }
            Ok(Some(RegistryTokenType::Basic(username, password))) => {
                self.tokens.insert(
                    image,
                    operation,
                    RegistryTokenType::Basic(username, password),
                );
                Ok(None)
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Internal auth that retrieves token.
    fn _auth(
        &self,
        image: &Reference,
        authentication: &RegistryAuth,
        operation: RegistryOperation,
    ) -> Result<Option<RegistryTokenType>> {
        debug!("Authorizing for image: {:?}", image);
        // The version request will tell us where to go.
        let url = format!(
            "{}://{}/v2/",
            self.config.protocol.scheme_for(image.resolve_registry()),
            image.resolve_registry()
        );
        debug!(?url);
        let res = self.client.get(&url).send()?;
        let dist_hdr = match res.headers().get(reqwest::header::WWW_AUTHENTICATE) {
            Some(h) => h,
            None => return Ok(None),
        };

        let challenge = match BearerChallenge::try_from(dist_hdr) {
            Ok(c) => c,
            Err(e) => {
                debug!(error = ?e, "Falling back to HTTP Basic Auth");
                if let RegistryAuth::Basic(username, password) = authentication {
                    return Ok(Some(RegistryTokenType::Basic(
                        username.to_string(),
                        password.to_string(),
                    )));
                }
                return Ok(None);
            }
        };

        // Allow for either push or pull authentication
        let scope = match operation {
            RegistryOperation::Pull => format!("repository:{}:pull", image.repository()),
            RegistryOperation::Push => format!("repository:{}:pull,push", image.repository()),
        };

        let realm = challenge.realm.as_ref();
        let service = challenge.service.as_ref();
        let mut query = vec![("scope", &scope)];

        if let Some(s) = service {
            query.push(("service", s))
        }

        // TODO: At some point in the future, we should support sending a secret to the
        // server for auth. This particular workflow is for read-only public auth.
        debug!(?realm, ?service, ?scope, "Making authentication call");

        let auth_res = self
            .client
            .get(realm)
            .query(&query)
            .apply_authentication(authentication)
            .send()?;

        match auth_res.status() {
            reqwest::StatusCode::OK => {
                let text = auth_res.text()?;
                debug!("Received response from auth request: {}", text);
                let token: RegistryToken = serde_json::from_str(&text)
                    .map_err(|e| OciDistributionError::RegistryTokenDecodeError(e.to_string()))?;
                debug!("Successfully authorized for image '{:?}'", image);
                Ok(Some(RegistryTokenType::Bearer(token)))
            }
            _ => {
                let reason = auth_res.text()?;
                debug!("Failed to authenticate for image '{:?}': {}", image, reason);
                Err(OciDistributionError::AuthenticationFailure(reason))
            }
        }
    }

    /// Fetch a manifest's digest from the remote OCI Distribution service.
    ///
    /// If the connection has already gone through authentication, this will
    /// use the bearer token. Otherwise, this will attempt an anonymous pull.
    ///
    /// Will first attempt to read the `Docker-Content-Digest` header using a
    /// HEAD request. If this header is not present, will make a second GET
    /// request and return the SHA256 of the response body.
    pub fn fetch_manifest_digest(
        &mut self,
        image: &Reference,
        auth: &RegistryAuth,
    ) -> Result<String> {
        self.store_auth_if_needed(image.resolve_registry(), auth);

        let url = self.config.to_v2_manifest_url(image);
        debug!("HEAD image manifest from {}", url);
        let res = RequestBuilderWrapper::from_client(self, |client| client.head(&url))
            .apply_accept(MIME_TYPES_DISTRIBUTION_MANIFEST)?
            .apply_auth(image, RegistryOperation::Pull)?
            .into_request_builder()
            .send()?;

        if let Some(digest) = digest_header_value(res.headers().clone())? {
            let status = res.status();
            let body = res.bytes()?;
            validate_registry_response(status, &body, &url)?;

            // If the reference has a digest and the digest header has a matching algorithm, compare
            // them and return an error if they don't match.
            if let Some(img_digest) = image.digest() {
                let header_digest = Digest::new(&digest)?;
                let image_digest = Digest::new(img_digest)?;
                if header_digest.algorithm == image_digest.algorithm
                    && header_digest != image_digest
                {
                    return Err(DigestError::VerificationError {
                        expected: img_digest.to_string(),
                        actual: digest,
                    }
                    .into());
                }
            }

            Ok(digest)
        } else {
            debug!("GET image manifest from {}", url);
            let res = RequestBuilderWrapper::from_client(self, |client| client.get(&url))
                .apply_accept(MIME_TYPES_DISTRIBUTION_MANIFEST)?
                .apply_auth(image, RegistryOperation::Pull)?
                .into_request_builder()
                .send()?;
            let status = res.status();
            trace!(headers = ?res.headers(), "Got Headers");
            let headers = res.headers().clone();
            let body = res.bytes()?;
            validate_registry_response(status, &body, &url)?;

            validate_digest(&body, digest_header_value(headers)?, image.digest())
                .map_err(OciDistributionError::from)
        }
    }

    fn validate_layers(
        &self,
        manifest: &OciImageManifest,
        accepted_media_types: Vec<&str>,
    ) -> Result<()> {
        if manifest.layers.is_empty() {
            return Err(OciDistributionError::PullNoLayersError);
        }

        for layer in &manifest.layers {
            if !accepted_media_types.iter().any(|i| i.eq(&layer.media_type)) {
                return Err(OciDistributionError::IncompatibleLayerMediaTypeError(
                    layer.media_type.clone(),
                ));
            }
        }

        Ok(())
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
        &mut self,
        image: &Reference,
        auth: &RegistryAuth,
    ) -> Result<(OciImageManifest, String)> {
        self.store_auth_if_needed(image.resolve_registry(), auth);

        self._pull_image_manifest(image)
    }

    /// Pull a manifest from the remote OCI Distribution service without parsing it.
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// A Tuple is returned containing raw byte representation of the manifest
    /// and the manifest content digest.
    pub fn pull_manifest_raw(
        &mut self,
        image: &Reference,
        auth: &RegistryAuth,
        accepted_media_types: &[&str],
    ) -> Result<(Vec<u8>, String)> {
        self.store_auth_if_needed(image.resolve_registry(), auth);

        self._pull_manifest_raw(image, accepted_media_types)
    }

    /// Pull a manifest from the remote OCI Distribution service.
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// A Tuple is returned containing the [Manifest](crate::manifest::OciImageManifest)
    /// and the manifest content digest hash.
    pub fn pull_manifest(
        &mut self,
        image: &Reference,
        auth: &RegistryAuth,
    ) -> Result<(OciManifest, String)> {
        self.store_auth_if_needed(image.resolve_registry(), auth);

        self._pull_manifest(image)
    }

    /// Pull an image manifest from the remote OCI Distribution service.
    ///
    /// If the connection has already gone through authentication, this will
    /// use the bearer token. Otherwise, this will attempt an anonymous pull.
    ///
    /// If a multi-platform Image Index manifest is encountered, a platform-specific
    /// Image manifest will be selected using the client's default platform resolution.
    pub(crate) fn _pull_image_manifest(
        &mut self,
        image: &Reference,
    ) -> Result<(OciImageManifest, String)> {
        let (manifest, digest) = self._pull_manifest(image)?;
        match manifest {
            OciManifest::Image(image_manifest) => Ok((image_manifest, digest)),
            OciManifest::ImageIndex(image_index_manifest) => {
                debug!("Inspecting Image Index Manifest");
                let digest = if let Some(resolver) = &self.config.platform_resolver {
                    resolver(&image_index_manifest.manifests)
                } else {
                    return Err(OciDistributionError::ImageIndexParsingNoPlatformResolverError);
                };

                match digest {
                    Some(digest) => {
                        debug!("Selected manifest entry with digest: {}", digest);
                        let manifest_entry_reference = image.clone_with_digest(digest.clone());
                        self._pull_manifest(&manifest_entry_reference).and_then(
                            |(manifest, _digest)| match manifest {
                                OciManifest::Image(manifest) => Ok((manifest, digest)),
                                OciManifest::ImageIndex(_) => {
                                    Err(OciDistributionError::ImageManifestNotFoundError(
                                        "received Image Index manifest instead".to_string(),
                                    ))
                                }
                            },
                        )
                    }
                    None => Err(OciDistributionError::ImageManifestNotFoundError(
                        "no entry found in image index manifest matching client's default platform"
                            .to_string(),
                    )),
                }
            }
        }
    }

    /// Pull a manifest from the remote OCI Distribution service without parsing it.
    ///
    /// If the connection has already gone through authentication, this will
    /// use the bearer token. Otherwise, this will attempt an anonymous pull.
    fn _pull_manifest_raw(
        &mut self,
        image: &Reference,
        accepted_media_types: &[&str],
    ) -> Result<(Vec<u8>, String)> {
        let url = self.config.to_v2_manifest_url(image);
        debug!("Pulling image manifest from {}", url);

        let res = RequestBuilderWrapper::from_client(self, |client| client.get(&url))
            .apply_accept(accepted_media_types)?
            .apply_auth(image, RegistryOperation::Pull)?
            .into_request_builder()
            .send()?;
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.bytes()?;

        validate_registry_response(status, &body, &url)?;

        let digest_header = digest_header_value(headers)?;
        let digest = validate_digest(&body, digest_header, image.digest())?;

        Ok((body.to_vec(), digest))
    }

    /// Pull a manifest from the remote OCI Distribution service.
    ///
    /// If the connection has already gone through authentication, this will
    /// use the bearer token. Otherwise, this will attempt an anonymous pull.
    fn _pull_manifest(&mut self, image: &Reference) -> Result<(OciManifest, String)> {
        let (body, digest) = self._pull_manifest_raw(image, MIME_TYPES_DISTRIBUTION_MANIFEST)?;

        self.validate_image_manifest(&body)?;

        debug!("Parsing response as Manifest");
        let manifest = serde_json::from_slice(&body)
            .map_err(|e| OciDistributionError::ManifestParsingError(e.to_string()))?;
        Ok((manifest, digest))
    }

    fn validate_image_manifest(&self, body: &[u8]) -> Result<()> {
        let versioned: Versioned = serde_json::from_slice(body)
            .map_err(|e| OciDistributionError::VersionedParsingError(e.to_string()))?;
        debug!(?versioned, "validating manifest");
        if versioned.schema_version != 2 {
            return Err(OciDistributionError::UnsupportedSchemaVersionError(
                versioned.schema_version,
            ));
        }
        if let Some(media_type) = versioned.media_type {
            if media_type != IMAGE_MANIFEST_MEDIA_TYPE
                && media_type != OCI_IMAGE_MEDIA_TYPE
                && media_type != IMAGE_MANIFEST_LIST_MEDIA_TYPE
                && media_type != OCI_IMAGE_INDEX_MEDIA_TYPE
            {
                return Err(OciDistributionError::UnsupportedMediaTypeError(media_type));
            }
        }

        Ok(())
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
        &mut self,
        image: &Reference,
        auth: &RegistryAuth,
    ) -> Result<(OciImageManifest, String, String)> {
        self.store_auth_if_needed(image.resolve_registry(), auth);

        self._pull_manifest_and_config(image)
            .and_then(|(manifest, digest, config)| {
                Ok((
                    manifest,
                    digest,
                    String::from_utf8(config.data.into()).map_err(|e| {
                        OciDistributionError::GenericError(Some(format!(
                            "Cannot parse config as UTF-8 string: {e}"
                        )))
                    })?,
                ))
            })
    }

    fn _pull_manifest_and_config(
        &mut self,
        image: &Reference,
    ) -> Result<(OciImageManifest, String, Config)> {
        let (manifest, digest) = self._pull_image_manifest(image)?;

        let mut out: Vec<u8> = Vec::new();
        debug!("Pulling config layer");
        self.pull_blob(image, &manifest.config, &mut out)?;
        let media_type = manifest.config.media_type.clone();
        let annotations = manifest.annotations.clone();
        Ok((manifest, digest, Config::new(out, media_type, annotations)))
    }

    /// Push a manifest list to an OCI registry.
    ///
    /// This pushes a manifest list to an OCI registry.
    pub fn push_manifest_list(
        &mut self,
        reference: &Reference,
        auth: &RegistryAuth,
        manifest: OciImageIndex,
    ) -> Result<String> {
        self.store_auth_if_needed(reference.resolve_registry(), auth);
        self.push_manifest(reference, &OciManifest::ImageIndex(manifest))
    }

    /// Pull a single layer from an OCI registry.
    ///
    /// This pulls the layer for a particular image that is identified by the given layer
    /// descriptor. The layer descriptor can be anything that can be referenced as a layer
    /// descriptor. The image reference is used to find the repository and the registry, but it is
    /// not used to verify that the digest is a layer inside of the image. (The manifest is used for
    /// that.)
    pub fn pull_blob<T: Write + Unpin>(
        &mut self,
        image: &Reference,
        layer: impl AsLayerDescriptor,
        mut out: T,
    ) -> Result<()> {
        let response = self.pull_blob_response(image, &layer, None, None)?;

        let mut maybe_header_digester = digest_header_value(response.headers().clone())?
            .map(|digest| Digester::new(&digest).map(|d| (d, digest)))
            .transpose()?;

        // With a blob pull, we need to use the digest from the layer and not the image
        let layer_digest = layer.as_layer_descriptor().digest.to_string();
        let mut layer_digester = Digester::new(&layer_digest)?;

        let bytes = response.error_for_status()?.bytes()?;
        if let Some((ref mut digester, _)) = maybe_header_digester.as_mut() {
            digester.update(&bytes);
        }
        layer_digester.update(&bytes);
        out.write_all(&bytes)?;

        if let Some((mut digester, expected)) = maybe_header_digester.take() {
            let digest = digester.finalize();

            if digest != expected {
                return Err(DigestError::VerificationError {
                    expected,
                    actual: digest,
                }
                .into());
            }
        }

        let digest = layer_digester.finalize();
        if digest != layer_digest {
            return Err(DigestError::VerificationError {
                expected: layer_digest,
                actual: digest,
            }
            .into());
        }

        Ok(())
    }

    /// Pull a single layer from an OCI registry.
    fn pull_blob_response(
        &mut self,
        image: &Reference,
        layer: impl AsLayerDescriptor,
        offset: Option<u64>,
        length: Option<u64>,
    ) -> Result<Response> {
        let layer = layer.as_layer_descriptor();
        let url = self.config.to_v2_blob_url(image, layer.digest);

        let mut request = RequestBuilderWrapper::from_client(self, |client| client.get(&url))
            .apply_accept(MIME_TYPES_DISTRIBUTION_MANIFEST)?
            .apply_auth(image, RegistryOperation::Pull)?
            .into_request_builder();
        if let (Some(off), Some(len)) = (offset, length) {
            let end = (off + len).saturating_sub(1);
            request = request.header(
                RANGE,
                HeaderValue::from_str(&format!("bytes={off}-{end}")).unwrap(),
            );
        } else if let Some(offset) = offset {
            request = request.header(
                RANGE,
                HeaderValue::from_str(&format!("bytes={offset}-")).unwrap(),
            );
        }
        let mut response = request.send()?;

        if let Some(urls) = &layer.urls {
            for url in urls {
                if response.error_for_status_ref().is_ok() {
                    break;
                }

                let url = Url::parse(url)
                    .map_err(|e| OciDistributionError::UrlParseError(e.to_string()))?;

                if url.scheme() == "http" || url.scheme() == "https" {
                    // NOTE: we must not authenticate on additional URLs as those
                    // can be abused to leak credentials or tokens.  Please
                    // refer to CVE-2020-15157 for more information.
                    request =
                        RequestBuilderWrapper::from_client(self, |client| client.get(url.clone()))
                            .apply_accept(MIME_TYPES_DISTRIBUTION_MANIFEST)?
                            .into_request_builder();
                    if let Some(offset) = offset {
                        request = request.header(
                            RANGE,
                            HeaderValue::from_str(&format!("bytes={offset}-")).unwrap(),
                        );
                    }
                    response = request.send()?
                }
            }
        }

        Ok(response)
    }

    /// Begins a session to push an image to registry in a monolithical way
    ///
    /// Returns URL with session UUID
    fn begin_push_monolithical_session(&mut self, image: &Reference) -> Result<String> {
        let url = &self.config.to_v2_blob_upload_url(image);
        debug!(?url, "begin_push_monolithical_session");
        let res = RequestBuilderWrapper::from_client(self, |client| client.post(url))
            .apply_auth(image, RegistryOperation::Push)?
            .into_request_builder()
            // We set "Content-Length" to 0 here even though the OCI Distribution
            // spec does not strictly require that. In practice we have seen that
            // certain registries require "Content-Length" to be present for all
            // types of push sessions.
            .header("Content-Length", 0)
            .send()?;

        // OCI spec requires the status code be 202 Accepted to successfully begin the push process
        self.extract_location_header(image, res, &reqwest::StatusCode::ACCEPTED)
    }

    /// Begins a session to push an image to registry as a series of chunks
    ///
    /// Returns URL with session UUID
    pub(crate) fn begin_push_chunked_session(&mut self, image: &Reference) -> Result<String> {
        let url = &self.config.to_v2_blob_upload_url(image);
        debug!(?url, "begin_push_session");
        let res = RequestBuilderWrapper::from_client(self, |client| client.post(url))
            .apply_auth(image, RegistryOperation::Push)?
            .into_request_builder()
            .header("Content-Length", 0)
            .send()?;

        // OCI spec requires the status code be 202 Accepted to successfully begin the push process
        self.extract_location_header(image, res, &reqwest::StatusCode::ACCEPTED)
    }

    /// Closes the chunked push session
    ///
    /// Returns the pullable URL for the image
    pub(crate) fn end_push_chunked_session(
        &mut self,
        location: &str,
        image: &Reference,
        digest: &str,
    ) -> Result<String> {
        let url = Url::parse_with_params(location, &[("digest", digest)])
            .map_err(|e| OciDistributionError::GenericError(Some(e.to_string())))?;
        let res = RequestBuilderWrapper::from_client(self, |client| client.put(url.clone()))
            .apply_auth(image, RegistryOperation::Push)?
            .into_request_builder()
            .header("Content-Length", 0)
            .send()?;
        self.extract_location_header(image, res, &reqwest::StatusCode::CREATED)
    }

    /// Pushes a layer to a registry as a monolithical blob.
    ///
    /// Returns the URL location for the next layer
    fn push_monolithically(
        &mut self,
        location: &str,
        image: &Reference,
        layer: &[u8],
        blob_digest: &str,
    ) -> Result<String> {
        let mut url = Url::parse(location).unwrap();
        url.query_pairs_mut().append_pair("digest", blob_digest);
        let url = url.to_string();

        debug!(size = layer.len(), location = ?url, "Pushing monolithically");
        if layer.is_empty() {
            return Err(OciDistributionError::PushNoDataError);
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Length",
            format!("{}", layer.len()).parse().unwrap(),
        );
        headers.insert("Content-Type", "application/octet-stream".parse().unwrap());

        let res = RequestBuilderWrapper::from_client(self, |client| client.put(&url))
            .apply_auth(image, RegistryOperation::Push)?
            .into_request_builder()
            .headers(headers)
            .body(layer.to_vec())
            .send()?;

        // Returns location
        self.extract_location_header(image, res, &reqwest::StatusCode::CREATED)
    }

    /// Pushes a single chunk of a blob to a registry,
    /// as part of a chunked blob upload.
    ///
    /// Returns the URL location for the next chunk
    pub(crate) fn push_chunk(
        &mut self,
        location: &str,
        image: &Reference,
        blob_data: &[u8],
        start_byte: usize,
    ) -> Result<(String, usize)> {
        if blob_data.is_empty() {
            return Err(OciDistributionError::PushNoDataError);
        };
        let end_byte = if (start_byte + self.push_chunk_size) < blob_data.len() {
            start_byte + self.push_chunk_size - 1
        } else {
            blob_data.len() - 1
        };
        let body = blob_data[start_byte..end_byte + 1].to_vec();
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Range",
            format!("{}-{}", start_byte, end_byte).parse().unwrap(),
        );
        headers.insert("Content-Length", format!("{}", body.len()).parse().unwrap());
        headers.insert("Content-Type", "application/octet-stream".parse().unwrap());

        debug!(
            ?start_byte,
            ?end_byte,
            blob_data_len = blob_data.len(),
            body_len = body.len(),
            ?location,
            ?headers,
            "Pushing chunk"
        );

        let res = RequestBuilderWrapper::from_client(self, |client| client.patch(location))
            .apply_auth(image, RegistryOperation::Push)?
            .into_request_builder()
            .headers(headers)
            .body(body)
            .send()?;

        // Returns location for next chunk and the start byte for the next range
        Ok((
            self.extract_location_header(image, res, &reqwest::StatusCode::ACCEPTED)?,
            end_byte + 1,
        ))
    }

    /// Mounts a blob to the provided reference, from the given source
    pub fn mount_blob(
        &mut self,
        image: &Reference,
        source: &Reference,
        digest: &str,
    ) -> Result<()> {
        let base_url = self.config.to_v2_blob_upload_url(image);
        let url = Url::parse_with_params(
            &base_url,
            &[("mount", digest), ("from", source.repository())],
        )
        .map_err(|e| OciDistributionError::UrlParseError(e.to_string()))?;

        let res = RequestBuilderWrapper::from_client(self, |client| client.post(url.clone()))
            .apply_auth(image, RegistryOperation::Push)?
            .into_request_builder()
            .send()?;

        self.extract_location_header(image, res, &reqwest::StatusCode::CREATED)?;

        Ok(())
    }

    /// Pushes the manifest for a specified image
    ///
    /// Returns pullable manifest URL
    pub fn push_manifest(&mut self, image: &Reference, manifest: &OciManifest) -> Result<String> {
        let mut headers = HeaderMap::new();
        let content_type = manifest.content_type();
        headers.insert("Content-Type", content_type.parse().unwrap());

        // Serialize the manifest with a canonical json formatter, as described at
        // https://github.com/opencontainers/image-spec/blob/main/considerations.md#json
        let mut body = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut body, CanonicalFormatter::new());
        manifest.serialize(&mut ser).unwrap();

        self.push_manifest_raw(image, body, manifest.content_type().parse().unwrap())
    }

    /// Pushes the manifest, provided as raw bytes, for a specified image
    ///
    /// Returns pullable manifest url
    pub fn push_manifest_raw(
        &mut self,
        image: &Reference,
        body: Vec<u8>,
        content_type: HeaderValue,
    ) -> Result<String> {
        let url = self.config.to_v2_manifest_url(image);
        debug!(?url, ?content_type, "push manifest");

        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", content_type);

        // Calculate the digest of the manifest, this is useful
        // if the remote registry is violating the OCI Distribution Specification.
        // See below for more details.
        let manifest_hash = sha256_digest(&body);

        let res = RequestBuilderWrapper::from_client(self, |client| client.put(url.clone()))
            .apply_auth(image, RegistryOperation::Push)?
            .into_request_builder()
            .headers(headers)
            .body(body)
            .send()?;

        let ret = self.extract_location_header(image, res, &reqwest::StatusCode::CREATED);

        if matches!(ret, Err(OciDistributionError::RegistryNoLocationError)) {
            // The registry is violating the OCI Distribution Spec, BUT the OCI
            // image/artifact has been uploaded successfully.
            // The `Location` header contains the sha256 digest of the manifest,
            // we can reuse the value we calculated before.
            // The workaround is there because repositories such as
            // AWS ECR are violating this aspect of the spec. This at least let the
            // oci-distribution users interact with these registries.
            warn!("Registry is not respecting the OCI Distribution Specification: it didn't return the Location of the uploaded Manifest inside of the response headers. Working around this issue...");

            let url_base = url
                .strip_suffix(image.tag().unwrap_or("latest"))
                .expect("The manifest URL always ends with the image tag suffix");
            let url_by_digest = format!("{}{}", url_base, manifest_hash);

            return Ok(url_by_digest);
        }

        ret
    }

    /// Pulls the referrers for the given image filtering by the optionally provided artifact type.
    pub fn pull_referrers(
        &mut self,
        image: &Reference,
        artifact_type: Option<&str>,
    ) -> Result<OciImageIndex> {
        let url = self.config.to_v2_referrers_url(image, artifact_type)?;
        debug!("Pulling referrers from {}", url);

        let res = RequestBuilderWrapper::from_client(self, |client| client.get(&url))
            .apply_accept(MIME_TYPES_DISTRIBUTION_MANIFEST)?
            .apply_auth(image, RegistryOperation::Pull)?
            .into_request_builder()
            .send()?;
        let status = res.status();
        let body = res.bytes()?;

        validate_registry_response(status, &body, &url)?;
        let manifest = serde_json::from_slice(&body)
            .map_err(|e| OciDistributionError::ManifestParsingError(e.to_string()))?;

        Ok(manifest)
    }

    fn extract_location_header(
        &self,
        image: &Reference,
        res: reqwest::blocking::Response,
        expected_status: &reqwest::StatusCode,
    ) -> Result<String> {
        debug!(expected_status_code=?expected_status.as_u16(),
            status_code=?res.status().as_u16(),
            "extract location header");
        if res.status().eq(expected_status) {
            let location_header = res.headers().get("Location");
            debug!(location=?location_header, "Location header");
            match location_header {
                None => Err(OciDistributionError::RegistryNoLocationError),
                Some(lh) => self.config.location_header_to_url(image, lh),
            }
        } else if res.status().is_success() && expected_status.is_success() {
            Err(OciDistributionError::SpecViolationError(format!(
                "Expected HTTP Status {}, got {} instead",
                expected_status,
                res.status(),
            )))
        } else {
            let url = res.url().to_string();
            let code = res.status().as_u16();
            let message = res.text()?;
            Err(OciDistributionError::ServerError { url, code, message })
        }
    }
}

/// The request builder wrapper allows to be instantiated from a
/// `Client` and allows composable operations on the request builder,
/// to produce a `RequestBuilder` object that can be executed.
pub(crate) struct RequestBuilderWrapper<'a> {
    client: &'a mut Client,
    request_builder: RequestBuilder,
}

// RequestBuilderWrapper type management
impl<'a> RequestBuilderWrapper<'a> {
    /// Create a `RequestBuilderWrapper` from a `Client` instance, by
    /// instantiating the internal `RequestBuilder` with the provided
    /// function `f`.
    pub(crate) fn from_client(
        client: &'a mut Client,
        f: impl Fn(&reqwest::blocking::Client) -> RequestBuilder,
    ) -> RequestBuilderWrapper<'a> {
        let request_builder = f(&client.client);
        RequestBuilderWrapper {
            client,
            request_builder,
        }
    }

    // Produces a final `RequestBuilder` out of this `RequestBuilderWrapper`
    pub(crate) fn into_request_builder(self) -> RequestBuilder {
        self.request_builder
    }
}

// Composable functions applicable to a `RequestBuilderWrapper`
impl RequestBuilderWrapper<'_> {
    /// Returns a clone of the inner `RequestBuilder`.
    ///
    /// Cloning fails if the request has a streaming body, which is never the
    /// case here since bodies are attached after the wrapper is consumed.
    fn cloned_request_builder(&self) -> Result<RequestBuilder> {
        self.request_builder.try_clone().ok_or_else(|| {
            OciDistributionError::GenericError(Some("could not clone request builder".to_string()))
        })
    }

    pub(crate) fn apply_accept(&mut self, accept: &[&str]) -> Result<RequestBuilderWrapper<'_>> {
        let request_builder = self
            .cloned_request_builder()?
            .header("Accept", Vec::from(accept).join(", "));

        Ok(RequestBuilderWrapper {
            client: self.client,
            request_builder,
        })
    }

    /// Returns whether the request being built is addressed to the registry the
    /// credentials of `image` belong to. See [`ClientConfig::targets_credential_registry`].
    fn targets_credential_registry(&self, image: &Reference) -> Result<bool> {
        let request = self.cloned_request_builder()?.build()?;
        self.client
            .config
            .targets_credential_registry(request.url(), image)
    }

    /// Updates request as necessary for authentication.
    ///
    /// If the struct has Some(bearer), this will insert the bearer token in an
    /// Authorization header. It will also set the Accept header, which must
    /// be set on all OCI Registry requests. If the struct has HTTP Basic Auth
    /// credentials, these will be configured.
    pub(crate) fn apply_auth(
        &mut self,
        image: &Reference,
        op: RegistryOperation,
    ) -> Result<RequestBuilderWrapper<'_>> {
        // NOTE: we must not authenticate requests addressed outside of the
        // registry, as those can be abused to leak credentials or tokens.
        // Please refer to CVE-2020-15157 for more information.
        if !self.targets_credential_registry(image)? {
            debug!(
                registry = image.resolve_registry(),
                "Not authenticating a request addressed outside of the registry"
            );
            let request_builder = self.cloned_request_builder()?;
            return Ok(RequestBuilderWrapper {
                client: self.client,
                request_builder,
            });
        }

        let mut headers = HeaderMap::new();
        if let Some(token) = self.client.get_auth_token(image, op) {
            match token {
                RegistryTokenType::Bearer(token) => {
                    debug!("Using bearer token authentication.");
                    headers.insert("Authorization", token.bearer_token().parse().unwrap());
                }
                RegistryTokenType::Basic(username, password) => {
                    debug!("Using HTTP basic authentication.");
                    let request_builder = self
                        .cloned_request_builder()?
                        .headers(headers)
                        .basic_auth(username.to_string(), Some(password.to_string()));
                    return Ok(RequestBuilderWrapper {
                        client: self.client,
                        request_builder,
                    });
                }
            }
        }
        let request_builder = self.cloned_request_builder()?.headers(headers);
        Ok(RequestBuilderWrapper {
            client: self.client,
            request_builder,
        })
    }
}
