//! Node.js NAPI bindings for rust-oci-client
//!
//! This module provides a pure, precise JavaScript API mirror of the native oci-client library.
//! All function signatures match the native Rust functions exactly.

use napi::bindgen_prelude::*;
use napi_derive::napi;

use oci_client::client::{
    Certificate as NativeCertificate, CertificateEncoding as NativeCertificateEncoding,
    ClientConfig as NativeClientConfig, ClientProtocol as NativeClientProtocol,
    Config as NativeConfig, ImageData as NativeImageData, ImageLayer as NativeImageLayer,
    PushResponse as NativePushResponse,
};
use oci_client::manifest::{
    ImageIndexEntry, OciDescriptor, OciImageIndex, OciImageManifest, OciManifest, Platform,
};
use oci_client::secrets::RegistryAuth as NativeRegistryAuth;
use oci_client::{Client, Reference};
use oci_spec::image::{Arch, Os};

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

fn format_error_chain(err: &dyn std::error::Error) -> String {
    let mut msg = err.to_string();
    let mut current = err.source();
    while let Some(source) = current {
        msg.push_str(": ");
        msg.push_str(&source.to_string());
        current = source.source();
    }
    msg
}

fn oci_error(context: &str, err: oci_client::errors::OciDistributionError) -> Error {
    Error::from_reason(format!("{}: {}", context, format_error_chain(&err)))
}

// ============================================================================
// Authentication Types - Mirror RegistryAuth exactly
// ============================================================================

/// Authentication method for registry access.
/// Mirrors the native RegistryAuth enum exactly.
#[napi(string_enum)]
pub enum RegistryAuthType {
    /// Access the registry anonymously
    Anonymous,
    /// Access the registry using HTTP Basic authentication
    Basic,
    /// Access the registry using Bearer token authentication
    Bearer,
}

/// Registry authentication configuration.
/// Use `auth_type` to specify the authentication method.
#[napi(object)]
pub struct RegistryAuth {
    /// The type of authentication to use
    pub auth_type: RegistryAuthType,
    /// Username for Basic auth (required when auth_type is Basic)
    pub username: Option<String>,
    /// Password for Basic auth (required when auth_type is Basic)
    pub password: Option<String>,
    /// Token for Bearer auth (required when auth_type is Bearer)
    pub token: Option<String>,
}

impl RegistryAuth {
    fn to_native(&self) -> Result<NativeRegistryAuth> {
        match self.auth_type {
            RegistryAuthType::Anonymous => Ok(NativeRegistryAuth::Anonymous),
            RegistryAuthType::Basic => {
                let username = self
                    .username
                    .clone()
                    .ok_or_else(|| Error::from_reason("username required for Basic auth"))?;
                let password = self
                    .password
                    .clone()
                    .ok_or_else(|| Error::from_reason("password required for Basic auth"))?;
                Ok(NativeRegistryAuth::Basic(username, password))
            }
            RegistryAuthType::Bearer => {
                let token = self
                    .token
                    .clone()
                    .ok_or_else(|| Error::from_reason("token required for Bearer auth"))?;
                Ok(NativeRegistryAuth::Bearer(token))
            }
        }
    }
}

// ============================================================================
// Client Configuration Types - Mirror ClientConfig exactly
// ============================================================================

/// Protocol configuration for the client.
/// Mirrors the native ClientProtocol enum.
#[napi(string_enum)]
pub enum ClientProtocol {
    /// Use HTTP (insecure)
    Http,
    /// Use HTTPS (secure, default)
    Https,
    /// Use HTTPS except for specified registries
    HttpsExcept,
}

/// Certificate encoding format.
/// Mirrors the native CertificateEncoding enum.
#[napi(string_enum)]
pub enum CertificateEncoding {
    /// DER encoded certificate
    Der,
    /// PEM encoded certificate
    Pem,
}

/// A x509 certificate for TLS.
/// Mirrors the native Certificate struct.
#[napi(object)]
pub struct Certificate {
    /// Which encoding is used by the certificate
    pub encoding: CertificateEncoding,
    /// Certificate data as bytes
    pub data: Buffer,
}

impl Certificate {
    fn to_native(&self) -> NativeCertificate {
        NativeCertificate {
            encoding: match self.encoding {
                CertificateEncoding::Der => NativeCertificateEncoding::Der,
                CertificateEncoding::Pem => NativeCertificateEncoding::Pem,
            },
            data: self.data.to_vec(),
        }
    }
}

/// Platform filter for selecting a specific platform from multi-platform images.
/// When set, the client will automatically select the matching platform from Image Index manifests.
#[napi(object)]
pub struct PlatformFilter {
    /// Operating system (e.g., "linux", "windows", "darwin")
    pub os: String,
    /// CPU architecture (e.g., "amd64", "arm64", "arm")
    pub architecture: String,
    /// Optional variant (e.g., "v7" for arm/v7)
    pub variant: Option<String>,
}

/// Client configuration options.
/// Mirrors the native ClientConfig struct with all available options.
#[napi(object)]
pub struct ClientConfig {
    /// Which protocol the client should use (default: Https)
    pub protocol: Option<ClientProtocol>,
    /// List of registries to exclude from HTTPS (used with HttpsExcept protocol)
    pub https_except_registries: Option<Vec<String>>,
    /// Accept invalid certificates (default: false)
    pub accept_invalid_certificates: Option<bool>,
    /// Use monolithic push for pushing blobs (default: false)
    pub use_monolithic_push: Option<bool>,
    /// Extra root certificates to trust (for self-signed certificates)
    pub extra_root_certificates: Option<Vec<Certificate>>,
    /// Maximum number of concurrent uploads during push (default: 16)
    pub max_concurrent_upload: Option<u32>,
    /// Maximum number of concurrent downloads during pull (default: 16)
    pub max_concurrent_download: Option<u32>,
    /// Default token expiration in seconds (default: 60)
    pub default_token_expiration_secs: Option<u32>,
    /// Read timeout in milliseconds
    pub read_timeout_ms: Option<u32>,
    /// Connect timeout in milliseconds
    pub connect_timeout_ms: Option<u32>,
    /// HTTPS proxy URL
    pub https_proxy: Option<String>,
    /// HTTP proxy URL
    pub http_proxy: Option<String>,
    /// No proxy list (comma-separated)
    pub no_proxy: Option<String>,
    /// Platform filter for multi-platform image selection.
    /// When set, automatically selects the matching platform from Image Index manifests.
    pub platform: Option<PlatformFilter>,
}

impl ClientConfig {
    fn to_native(&self) -> NativeClientConfig {
        let mut config = NativeClientConfig::default();

        if let Some(protocol) = &self.protocol {
            config.protocol = match protocol {
                ClientProtocol::Http => NativeClientProtocol::Http,
                ClientProtocol::Https => NativeClientProtocol::Https,
                ClientProtocol::HttpsExcept => {
                    let registries = self.https_except_registries.clone().unwrap_or_default();
                    NativeClientProtocol::HttpsExcept(registries)
                }
            };
        }

        if let Some(accept) = self.accept_invalid_certificates {
            config.accept_invalid_certificates = accept;
        }

        if let Some(monolithic) = self.use_monolithic_push {
            config.use_monolithic_push = monolithic;
        }

        if let Some(certs) = &self.extra_root_certificates {
            config.extra_root_certificates = certs.iter().map(|c| c.to_native()).collect();
        }

        if let Some(max) = self.max_concurrent_upload {
            config.max_concurrent_upload = max as usize;
        }

        if let Some(max) = self.max_concurrent_download {
            config.max_concurrent_download = max as usize;
        }

        if let Some(secs) = self.default_token_expiration_secs {
            config.default_token_expiration_secs = secs as usize;
        }

        if let Some(ms) = self.read_timeout_ms {
            config.read_timeout = Some(Duration::from_millis(ms as u64));
        }

        if let Some(ms) = self.connect_timeout_ms {
            config.connect_timeout = Some(Duration::from_millis(ms as u64));
        }

        if let Some(proxy) = &self.https_proxy {
            config.https_proxy = Some(proxy.clone());
        }

        if let Some(proxy) = &self.http_proxy {
            config.http_proxy = Some(proxy.clone());
        }

        if let Some(no_proxy) = &self.no_proxy {
            config.no_proxy = Some(no_proxy.clone());
        }

        if let Some(p) = &self.platform {
            let os = Os::from(p.os.as_str());
            let arch = Arch::from(p.architecture.as_str());
            let variant = p.variant.clone();
            config.platform_resolver = Some(Box::new(move |manifests| {
                manifests
                    .iter()
                    .find(|e| {
                        e.platform.as_ref().is_some_and(|plat| {
                            plat.os == os
                                && plat.architecture == arch
                                && (variant.is_none() || plat.variant == variant)
                        })
                    })
                    .map(|e| e.digest.clone())
            }));
        }

        config
    }
}

// ============================================================================
// Data Types - Mirror ImageLayer, Config, ImageData, PushResponse exactly
// ============================================================================

/// An image layer with data and metadata.
/// Mirrors the native ImageLayer struct.
#[napi(object)]
pub struct ImageLayer {
    /// The layer data as raw bytes
    pub data: Buffer,
    /// The media type of this layer
    pub media_type: String,
    /// Optional annotations for this layer
    pub annotations: Option<BTreeMap<String, String>>,
}

impl ImageLayer {
    fn from_native(layer: NativeImageLayer) -> Self {
        ImageLayer {
            data: Buffer::from(layer.data.to_vec()),
            media_type: layer.media_type,
            annotations: layer.annotations,
        }
    }

    fn to_native(&self) -> NativeImageLayer {
        NativeImageLayer::new(
            self.data.to_vec(),
            self.media_type.clone(),
            self.annotations.clone(),
        )
    }
}

/// Configuration object for an image.
/// Mirrors the native Config struct.
#[napi(object)]
pub struct Config {
    /// The config data as raw bytes
    pub data: Buffer,
    /// The media type of this config
    pub media_type: String,
    /// Optional annotations for this config
    pub annotations: Option<BTreeMap<String, String>>,
}

impl Config {
    fn from_native(config: NativeConfig) -> Self {
        Config {
            data: Buffer::from(config.data.to_vec()),
            media_type: config.media_type,
            annotations: config.annotations,
        }
    }

    fn to_native(&self) -> NativeConfig {
        NativeConfig::new(
            self.data.to_vec(),
            self.media_type.clone(),
            self.annotations.clone(),
        )
    }
}

/// Data returned from pulling an image.
/// Mirrors the native ImageData struct.
#[napi(object)]
pub struct ImageData {
    /// The layers of the image
    pub layers: Vec<ImageLayer>,
    /// The digest of the image (if available)
    pub digest: Option<String>,
    /// The configuration object of the image
    pub config: Config,
    /// The manifest (if available)
    pub manifest: Option<ImageManifest>,
}

impl ImageData {
    fn from_native(data: NativeImageData) -> Self {
        ImageData {
            layers: data
                .layers
                .into_iter()
                .map(ImageLayer::from_native)
                .collect(),
            digest: data.digest,
            config: Config::from_native(data.config),
            manifest: data.manifest.map(|m| m.into()),
        }
    }
}

/// Response from pushing an image.
/// Mirrors the native PushResponse struct.
#[napi(object)]
pub struct PushResponse {
    /// Pullable URL for the config
    pub config_url: String,
    /// Pullable URL for the manifest
    pub manifest_url: String,
}

impl From<NativePushResponse> for PushResponse {
    fn from(resp: NativePushResponse) -> Self {
        PushResponse {
            config_url: resp.config_url,
            manifest_url: resp.manifest_url,
        }
    }
}

// ============================================================================
// Manifest Types - For structured manifest handling
// ============================================================================

/// OCI Descriptor - describes a content addressable resource.
#[napi(object)]
pub struct Descriptor {
    /// The media type of the referenced content
    pub media_type: String,
    /// The digest of the targeted content
    pub digest: String,
    /// The size in bytes of the targeted content
    pub size: i64,
    /// Optional list of URLs from which this object may be downloaded
    pub urls: Option<Vec<String>>,
    /// Optional annotations for this descriptor
    pub annotations: Option<BTreeMap<String, String>>,
}

impl From<OciDescriptor> for Descriptor {
    fn from(d: OciDescriptor) -> Self {
        Descriptor {
            media_type: d.media_type,
            digest: d.digest,
            size: d.size,
            urls: d.urls,
            annotations: d.annotations,
        }
    }
}

impl From<Descriptor> for OciDescriptor {
    fn from(d: Descriptor) -> Self {
        OciDescriptor {
            media_type: d.media_type,
            digest: d.digest,
            size: d.size,
            urls: d.urls,
            annotations: d.annotations,
        }
    }
}

/// Platform specification for an image.
#[napi(object)]
pub struct PlatformSpec {
    /// CPU architecture
    pub architecture: String,
    /// Operating system
    pub os: String,
    /// OS version
    pub os_version: Option<String>,
    /// OS features
    pub os_features: Option<Vec<String>>,
    /// CPU variant
    pub variant: Option<String>,
    /// Additional features
    pub features: Option<Vec<String>>,
}

impl From<Platform> for PlatformSpec {
    fn from(p: Platform) -> Self {
        PlatformSpec {
            architecture: p.architecture.to_string(),
            os: p.os.to_string(),
            os_version: p.os_version,
            os_features: p.os_features,
            variant: p.variant,
            features: p.features,
        }
    }
}

impl From<PlatformSpec> for Platform {
    fn from(p: PlatformSpec) -> Self {
        Platform {
            architecture: Arch::from(p.architecture.as_str()),
            os: Os::from(p.os.as_str()),
            os_version: p.os_version,
            os_features: p.os_features,
            variant: p.variant,
            features: p.features,
        }
    }
}

/// An entry in an image index manifest.
#[napi(object)]
pub struct ManifestEntry {
    /// Media type of the manifest
    pub media_type: String,
    /// Digest of the manifest
    pub digest: String,
    /// Size in bytes
    pub size: i64,
    /// Platform specification
    pub platform: Option<PlatformSpec>,
    /// Annotations
    pub annotations: Option<BTreeMap<String, String>>,
}

impl From<ImageIndexEntry> for ManifestEntry {
    fn from(e: ImageIndexEntry) -> Self {
        ManifestEntry {
            media_type: e.media_type,
            digest: e.digest,
            size: e.size,
            platform: e.platform.map(|p| p.into()),
            annotations: e.annotations,
        }
    }
}

impl From<ManifestEntry> for ImageIndexEntry {
    fn from(e: ManifestEntry) -> Self {
        ImageIndexEntry {
            media_type: e.media_type,
            digest: e.digest,
            size: e.size,
            platform: e.platform.map(|p| p.into()),
            annotations: e.annotations,
        }
    }
}

/// OCI Image Index (manifest list).
#[napi(object)]
pub struct ImageIndex {
    /// Schema version (always 2)
    pub schema_version: u8,
    /// Media type of this manifest
    pub media_type: Option<String>,
    /// List of manifests for specific platforms
    pub manifests: Vec<ManifestEntry>,
    /// Artifact type
    pub artifact_type: Option<String>,
    /// Annotations
    pub annotations: Option<BTreeMap<String, String>>,
}

impl From<OciImageIndex> for ImageIndex {
    fn from(idx: OciImageIndex) -> Self {
        ImageIndex {
            schema_version: idx.schema_version,
            media_type: idx.media_type,
            manifests: idx.manifests.into_iter().map(|m| m.into()).collect(),
            artifact_type: idx.artifact_type,
            annotations: idx.annotations,
        }
    }
}

impl From<ImageIndex> for OciImageIndex {
    fn from(idx: ImageIndex) -> Self {
        OciImageIndex {
            schema_version: idx.schema_version,
            media_type: idx.media_type,
            manifests: idx.manifests.into_iter().map(|m| m.into()).collect(),
            artifact_type: idx.artifact_type,
            annotations: idx.annotations,
        }
    }
}

/// OCI Image Manifest.
#[napi(object)]
pub struct ImageManifest {
    /// Schema version (always 2)
    pub schema_version: u8,
    /// Media type of this manifest
    pub media_type: Option<String>,
    /// The image configuration descriptor
    pub config: Descriptor,
    /// The image layers
    pub layers: Vec<Descriptor>,
    /// Subject descriptor (for referrers)
    pub subject: Option<Descriptor>,
    /// Artifact type
    pub artifact_type: Option<String>,
    /// Annotations
    pub annotations: Option<BTreeMap<String, String>>,
}

impl From<OciImageManifest> for ImageManifest {
    fn from(m: OciImageManifest) -> Self {
        ImageManifest {
            schema_version: m.schema_version,
            media_type: m.media_type,
            config: m.config.into(),
            layers: m.layers.into_iter().map(|l| l.into()).collect(),
            subject: m.subject.map(|s| s.into()),
            artifact_type: m.artifact_type,
            annotations: m.annotations,
        }
    }
}

impl From<ImageManifest> for OciImageManifest {
    fn from(m: ImageManifest) -> Self {
        OciImageManifest {
            schema_version: m.schema_version,
            media_type: m.media_type,
            config: m.config.into(),
            layers: m.layers.into_iter().map(|l| l.into()).collect(),
            subject: m.subject.map(|s| s.into()),
            artifact_type: m.artifact_type,
            annotations: m.annotations,
        }
    }
}

// ============================================================================
// Union type for OciManifest (can be Image or ImageIndex)
// ============================================================================

/// Manifest type discriminator.
#[napi(string_enum)]
pub enum ManifestType {
    /// An OCI image manifest
    Image,
    /// An OCI image index (manifest list)
    ImageIndex,
}

/// OCI Manifest - can be either an Image manifest or an ImageIndex.
/// Check `manifest_type` to determine which field is populated.
#[napi(object)]
pub struct Manifest {
    /// The type of manifest
    pub manifest_type: ManifestType,
    /// The image manifest (populated when manifest_type is Image)
    pub image: Option<ImageManifest>,
    /// The image index (populated when manifest_type is ImageIndex)
    pub image_index: Option<ImageIndex>,
}

impl From<OciManifest> for Manifest {
    fn from(m: OciManifest) -> Self {
        match m {
            OciManifest::Image(img) => Manifest {
                manifest_type: ManifestType::Image,
                image: Some(img.into()),
                image_index: None,
            },
            OciManifest::ImageIndex(idx) => Manifest {
                manifest_type: ManifestType::ImageIndex,
                image: None,
                image_index: Some(idx.into()),
            },
        }
    }
}

impl TryFrom<Manifest> for OciManifest {
    type Error = String;

    fn try_from(m: Manifest) -> std::result::Result<Self, Self::Error> {
        match m.manifest_type {
            ManifestType::Image => {
                let img = m
                    .image
                    .ok_or("image field required for Image manifest type")?;
                Ok(OciManifest::Image(img.into()))
            }
            ManifestType::ImageIndex => {
                let idx = m
                    .image_index
                    .ok_or("image_index field required for ImageIndex manifest type")?;
                Ok(OciManifest::ImageIndex(idx.into()))
            }
        }
    }
}

/// Result from pull_manifest containing both manifest and digest.
#[napi(object)]
pub struct PullManifestResult {
    /// The pulled manifest
    pub manifest: Manifest,
    /// The digest of the manifest
    pub digest: String,
}

// ============================================================================
// Result Types for functions that return tuples
// ============================================================================

/// Result from pull_image_manifest containing both manifest and digest.
#[napi(object)]
pub struct PullImageManifestResult {
    /// The pulled image manifest
    pub manifest: ImageManifest,
    /// The digest of the manifest
    pub digest: String,
}

// ============================================================================
// Main Client - Mirrors the native Client
// ============================================================================

/// OCI Distribution client for interacting with OCI registries.
/// Provides pull, push, and manifest operations.
#[napi]
pub struct OciClient {
    inner: Client,
}

#[napi]
impl OciClient {
    /// Create a new OCI client with default configuration.
    #[napi(constructor)]
    pub fn new() -> Self {
        OciClient {
            inner: Client::default(),
        }
    }

    /// Create a new OCI client with custom configuration.
    #[napi(factory)]
    pub fn with_config(config: ClientConfig) -> Self {
        OciClient {
            inner: Client::new(config.to_native()),
        }
    }

    /// Pull an image from the registry.
    ///
    /// Arguments match native: `pull(image: &Reference, auth: &RegistryAuth, accepted_media_types: Vec<&str>)`
    ///
    /// Returns ImageData containing layers (as Buffers), config, and manifest.
    #[napi]
    pub async fn pull(
        &self,
        image: String,
        auth: RegistryAuth,
        accepted_media_types: Vec<String>,
    ) -> Result<ImageData> {
        let reference = Reference::from_str(&image)
            .map_err(|e| Error::from_reason(format!("Invalid image reference: {}", e)))?;
        let native_auth = auth.to_native()?;
        let media_types: Vec<&str> = accepted_media_types.iter().map(|s| s.as_str()).collect();

        let image_data = self
            .inner
            .pull(&reference, &native_auth, media_types)
            .await
            .map_err(|e| oci_error("Pull failed", e))?;

        Ok(ImageData::from_native(image_data))
    }

    /// Push an image to the registry.
    ///
    /// Arguments match native: `push(image_ref: &Reference, layers: &[ImageLayer], config: Config, auth: &RegistryAuth, manifest: Option<OciImageManifest>)`
    ///
    /// Returns PushResponse with config and manifest URLs.
    #[napi]
    pub async fn push(
        &self,
        image_ref: String,
        layers: Vec<ImageLayer>,
        config: Config,
        auth: RegistryAuth,
        manifest: Option<ImageManifest>,
    ) -> Result<PushResponse> {
        let reference = Reference::from_str(&image_ref)
            .map_err(|e| Error::from_reason(format!("Invalid image reference: {}", e)))?;
        let native_auth = auth.to_native()?;
        let native_layers: Vec<NativeImageLayer> = layers.iter().map(|l| l.to_native()).collect();
        let native_config = config.to_native();
        let native_manifest: Option<OciImageManifest> = manifest.map(|m| m.into());

        let response = self
            .inner
            .push(
                &reference,
                &native_layers,
                native_config,
                &native_auth,
                native_manifest,
            )
            .await
            .map_err(|e| oci_error("Push failed", e))?;

        Ok(response.into())
    }

    /// Pull referrers for an artifact (OCI 1.1 Referrers API).
    ///
    /// Arguments match native: `pull_referrers(image: &Reference, artifact_type: Option<&str>)`
    ///
    /// Returns an ImageIndex containing the referrers.
    #[napi]
    pub async fn pull_referrers(
        &self,
        image: String,
        artifact_type: Option<String>,
    ) -> Result<ImageIndex> {
        let reference = Reference::from_str(&image)
            .map_err(|e| Error::from_reason(format!("Invalid image reference: {}", e)))?;

        let referrers = self
            .inner
            .pull_referrers(&reference, artifact_type.as_deref())
            .await
            .map_err(|e| oci_error("Pull referrers failed", e))?;

        Ok(referrers.into())
    }

    /// Push a manifest list (image index) to the registry.
    ///
    /// Arguments match native: `push_manifest_list(reference: &Reference, auth: &RegistryAuth, manifest: OciImageIndex)`
    ///
    /// Returns the manifest URL.
    #[napi]
    pub async fn push_manifest_list(
        &self,
        reference: String,
        auth: RegistryAuth,
        manifest: ImageIndex,
    ) -> Result<String> {
        let ref_parsed = Reference::from_str(&reference)
            .map_err(|e| Error::from_reason(format!("Invalid reference: {}", e)))?;
        let native_auth = auth.to_native()?;
        let native_manifest: OciImageIndex = manifest.into();

        self.inner
            .push_manifest_list(&ref_parsed, &native_auth, native_manifest)
            .await
            .map_err(|e| oci_error("Push manifest list failed", e))
    }

    /// Pull an image manifest from the registry.
    ///
    /// Arguments match native: `pull_image_manifest(image: &Reference, auth: &RegistryAuth)`
    ///
    /// If a multi-platform Image Index manifest is encountered, a platform-specific
    /// Image manifest will be selected using the client's default platform resolution.
    ///
    /// Returns both the manifest and its digest.
    #[napi]
    pub async fn pull_image_manifest(
        &self,
        image: String,
        auth: RegistryAuth,
    ) -> Result<PullImageManifestResult> {
        let reference = Reference::from_str(&image)
            .map_err(|e| Error::from_reason(format!("Invalid image reference: {}", e)))?;
        let native_auth = auth.to_native()?;

        let (manifest, digest) = self
            .inner
            .pull_image_manifest(&reference, &native_auth)
            .await
            .map_err(|e| oci_error("Pull image manifest failed", e))?;

        Ok(PullImageManifestResult {
            manifest: manifest.into(),
            digest,
        })
    }

    // ========================================================================
    // Additional utility methods for complete API coverage
    // ========================================================================

    /// Store authentication credentials for a registry.
    /// This is useful for pre-authenticating before multiple operations.
    #[napi]
    pub async fn store_auth(&self, registry: String, auth: RegistryAuth) -> Result<()> {
        let native_auth = auth.to_native()?;
        self.inner
            .store_auth_if_needed(&registry, &native_auth)
            .await;
        Ok(())
    }

    /// Pull a manifest (either image or index) from the registry.
    /// Returns the manifest and its digest.
    #[napi]
    pub async fn pull_manifest(
        &self,
        image: String,
        auth: RegistryAuth,
    ) -> Result<PullManifestResult> {
        let reference = Reference::from_str(&image)
            .map_err(|e| Error::from_reason(format!("Invalid image reference: {}", e)))?;
        let native_auth = auth.to_native()?;

        let (manifest, digest) = self
            .inner
            .pull_manifest(&reference, &native_auth)
            .await
            .map_err(|e| oci_error("Pull manifest failed", e))?;

        Ok(PullManifestResult {
            manifest: manifest.into(),
            digest,
        })
    }

    /// Pull a manifest as raw bytes.
    #[napi]
    pub async fn pull_manifest_raw(
        &self,
        image: String,
        auth: RegistryAuth,
        accepted_media_types: Vec<String>,
    ) -> Result<Buffer> {
        let reference = Reference::from_str(&image)
            .map_err(|e| Error::from_reason(format!("Invalid image reference: {}", e)))?;
        let native_auth = auth.to_native()?;
        let media_types: Vec<&str> = accepted_media_types.iter().map(|s| s.as_str()).collect();

        let (bytes, _digest) = self
            .inner
            .pull_manifest_raw(&reference, &native_auth, &media_types)
            .await
            .map_err(|e| oci_error("Pull manifest raw failed", e))?;

        Ok(Buffer::from(bytes.to_vec()))
    }

    /// Push a manifest to the registry.
    /// Returns the manifest URL.
    #[napi]
    pub async fn push_manifest(&self, image: String, manifest: Manifest) -> Result<String> {
        let reference = Reference::from_str(&image)
            .map_err(|e| Error::from_reason(format!("Invalid image reference: {}", e)))?;

        let native_manifest: OciManifest = manifest
            .try_into()
            .map_err(|e: String| Error::from_reason(e))?;

        self.inner
            .push_manifest(&reference, &native_manifest)
            .await
            .map_err(|e| oci_error("Push manifest failed", e))
    }

    /// Push a blob to the registry.
    /// Returns the blob digest.
    #[napi]
    pub async fn push_blob(&self, image: String, data: Buffer, digest: String) -> Result<String> {
        let reference = Reference::from_str(&image)
            .map_err(|e| Error::from_reason(format!("Invalid image reference: {}", e)))?;

        self.inner
            .push_blob(&reference, data.to_vec(), &digest)
            .await
            .map_err(|e| oci_error("Push blob failed", e))
    }

    /// Pull a blob from the registry.
    /// Returns the blob data.
    #[napi]
    pub async fn pull_blob(&self, image: String, digest: String) -> Result<Buffer> {
        let reference = Reference::from_str(&image)
            .map_err(|e| Error::from_reason(format!("Invalid image reference: {}", e)))?;

        let mut data = Vec::new();
        self.inner
            .pull_blob(&reference, digest.as_str(), &mut data)
            .await
            .map_err(|e| oci_error("Pull blob failed", e))?;

        Ok(Buffer::from(data))
    }

    /// Check if a blob exists in the registry.
    #[napi]
    pub async fn blob_exists(&self, image: String, digest: String) -> Result<bool> {
        let reference = Reference::from_str(&image)
            .map_err(|e| Error::from_reason(format!("Invalid image reference: {}", e)))?;

        self.inner
            .blob_exists(&reference, &digest)
            .await
            .map_err(|e| oci_error("Blob exists check failed", e))
    }

    /// Mount a blob from another repository.
    #[napi]
    pub async fn mount_blob(&self, target: String, source: String, digest: String) -> Result<()> {
        let target_ref = Reference::from_str(&target)
            .map_err(|e| Error::from_reason(format!("Invalid target reference: {}", e)))?;
        let source_ref = Reference::from_str(&source)
            .map_err(|e| Error::from_reason(format!("Invalid source reference: {}", e)))?;

        self.inner
            .mount_blob(&target_ref, &source_ref, &digest)
            .await
            .map_err(|e| oci_error("Mount blob failed", e))
    }

    /// List tags for a repository.
    #[napi]
    pub async fn list_tags(
        &self,
        image: String,
        auth: RegistryAuth,
        n: Option<u32>,
        last: Option<String>,
    ) -> Result<Vec<String>> {
        let reference = Reference::from_str(&image)
            .map_err(|e| Error::from_reason(format!("Invalid image reference: {}", e)))?;
        let native_auth = auth.to_native()?;

        let tags = self
            .inner
            .list_tags(
                &reference,
                &native_auth,
                n.map(|v| v as usize),
                last.as_deref(),
            )
            .await
            .map_err(|e| oci_error("List tags failed", e))?;

        Ok(tags.tags)
    }

    /// Fetch manifest digest without downloading the full manifest.
    #[napi]
    pub async fn fetch_manifest_digest(&self, image: String, auth: RegistryAuth) -> Result<String> {
        let reference = Reference::from_str(&image)
            .map_err(|e| Error::from_reason(format!("Invalid image reference: {}", e)))?;
        let native_auth = auth.to_native()?;

        self.inner
            .fetch_manifest_digest(&reference, &native_auth)
            .await
            .map_err(|e| oci_error("Fetch manifest digest failed", e))
    }
}

// ============================================================================
// OCI Annotation Constants
// ============================================================================

/// Date and time on which the image was built (string, date-time as defined by RFC 3339)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_CREATED: &str = "org.opencontainers.image.created";

/// Contact details of the people or organization responsible for the image (freeform string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_AUTHORS: &str = "org.opencontainers.image.authors";

/// URL to find more information on the image (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_URL: &str = "org.opencontainers.image.url";

/// URL to get documentation on the image (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_DOCUMENTATION: &str = "org.opencontainers.image.documentation";

/// URL to get source code for building the image (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_SOURCE: &str = "org.opencontainers.image.source";

/// Version of the packaged software
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_VERSION: &str = "org.opencontainers.image.version";

/// Source control revision identifier for the packaged software
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_REVISION: &str = "org.opencontainers.image.revision";

/// Name of the distributing entity, organization or individual
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_VENDOR: &str = "org.opencontainers.image.vendor";

/// License(s) under which contained software is distributed as an SPDX License Expression
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_LICENSES: &str = "org.opencontainers.image.licenses";

/// Name of the reference for a target (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_REF_NAME: &str = "org.opencontainers.image.ref.name";

/// Human-readable title of the image (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_TITLE: &str = "org.opencontainers.image.title";

/// Human-readable description of the software packaged in the image (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_DESCRIPTION: &str = "org.opencontainers.image.description";

/// Digest of the image this image is based on (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_BASE_DIGEST: &str = "org.opencontainers.image.base.digest";

/// Image reference of the image this image is based on (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_BASE_NAME: &str = "org.opencontainers.image.base.name";

// ============================================================================
// OCI Media Type Constants
// ============================================================================

/// The mediatype for WASM layers
#[napi]
pub const WASM_LAYER_MEDIA_TYPE: &str = "application/vnd.wasm.content.layer.v1+wasm";

/// The mediatype for a WASM image config
#[napi]
pub const WASM_CONFIG_MEDIA_TYPE: &str = "application/vnd.wasm.config.v1+json";

/// The mediatype for a Docker v2 schema 2 manifest
#[napi]
pub const IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";

/// The mediatype for a Docker v2 schema 2 manifest list
#[napi]
pub const IMAGE_MANIFEST_LIST_MEDIA_TYPE: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";

/// The mediatype for an OCI image index manifest
#[napi]
pub const OCI_IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";

/// The mediatype for an OCI image manifest
#[napi]
pub const OCI_IMAGE_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// The mediatype for an image config (manifest)
#[napi]
pub const IMAGE_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";

/// The mediatype that Docker uses for image configs
#[napi]
pub const IMAGE_DOCKER_CONFIG_MEDIA_TYPE: &str = "application/vnd.docker.container.image.v1+json";

/// The mediatype for a layer
#[napi]
pub const IMAGE_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";

/// The mediatype for a layer that is gzipped
#[napi]
pub const IMAGE_LAYER_GZIP_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// The mediatype that Docker uses for a layer that is tarred
#[napi]
pub const IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE: &str = "application/vnd.docker.image.rootfs.diff.tar";

/// The mediatype that Docker uses for a layer that is gzipped
#[napi]
pub const IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE: &str =
    "application/vnd.docker.image.rootfs.diff.tar.gzip";

/// The mediatype for a layer that is nondistributable
#[napi]
pub const IMAGE_LAYER_NONDISTRIBUTABLE_MEDIA_TYPE: &str =
    "application/vnd.oci.image.layer.nondistributable.v1.tar";

/// The mediatype for a layer that is nondistributable and gzipped
#[napi]
pub const IMAGE_LAYER_NONDISTRIBUTABLE_GZIP_MEDIA_TYPE: &str =
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip";

// ============================================================================
// Helper functions
// ============================================================================

/// Create an anonymous authentication object.
#[napi]
pub fn anonymous_auth() -> RegistryAuth {
    RegistryAuth {
        auth_type: RegistryAuthType::Anonymous,
        username: None,
        password: None,
        token: None,
    }
}

/// Create a basic authentication object.
#[napi]
pub fn basic_auth(username: String, password: String) -> RegistryAuth {
    RegistryAuth {
        auth_type: RegistryAuthType::Basic,
        username: Some(username),
        password: Some(password),
        token: None,
    }
}

/// Create a bearer token authentication object.
#[napi]
pub fn bearer_auth(token: String) -> RegistryAuth {
    RegistryAuth {
        auth_type: RegistryAuthType::Bearer,
        username: None,
        password: None,
        token: Some(token),
    }
}
