use std::collections::BTreeMap;

use serde::Deserialize;

use crate::{
    config::ConfigFile,
    errors::{OciDistributionError, Result},
    manifest::{
        OciDescriptor, OciImageManifest, IMAGE_CONFIG_MEDIA_TYPE, IMAGE_LAYER_GZIP_MEDIA_TYPE,
        IMAGE_LAYER_MEDIA_TYPE,
    },
    sha256_digest,
};

/// The data for an image or module.
#[derive(Clone)]
pub struct ImageData {
    /// The layers of the image or module.
    pub layers: Vec<ImageLayer>,
    /// The digest of the image or module.
    pub digest: Option<String>,
    /// The Configuration object of the image or module.
    pub config: Config,
    /// The manifest of the image or module.
    pub manifest: Option<OciImageManifest>,
}

/// The data returned by an OCI registry after a successful push
/// operation is completed
pub struct PushResponse {
    /// Pullable url for the config
    pub config_url: String,
    /// Pullable url for the manifest
    pub manifest_url: String,
}

/// The data returned by a successful tags/list Request
#[derive(Deserialize, Debug)]
pub struct TagResponse {
    /// Repository Name
    pub name: String,
    /// List of existing Tags
    pub tags: Vec<String>,
}

/// Layer descriptor required to pull a layer
pub struct LayerDescriptor<'a> {
    /// The digest of the layer
    pub digest: &'a str,
    /// Optional list of additional URIs to pull the layer from
    pub urls: &'a Option<Vec<String>>,
}

/// A trait for converting any type into a [`LayerDescriptor`]
pub trait AsLayerDescriptor {
    /// Convert the type to a LayerDescriptor reference
    fn as_layer_descriptor(&self) -> LayerDescriptor<'_>;
}

impl<T: AsLayerDescriptor> AsLayerDescriptor for &T {
    fn as_layer_descriptor(&self) -> LayerDescriptor<'_> {
        (*self).as_layer_descriptor()
    }
}

impl AsLayerDescriptor for &str {
    fn as_layer_descriptor(&self) -> LayerDescriptor<'_> {
        LayerDescriptor {
            digest: self,
            urls: &None,
        }
    }
}

impl AsLayerDescriptor for &OciDescriptor {
    fn as_layer_descriptor(&self) -> LayerDescriptor<'_> {
        LayerDescriptor {
            digest: &self.digest,
            urls: &self.urls,
        }
    }
}

impl AsLayerDescriptor for &LayerDescriptor<'_> {
    fn as_layer_descriptor(&self) -> LayerDescriptor<'_> {
        LayerDescriptor {
            digest: self.digest,
            urls: self.urls,
        }
    }
}

/// The data and media type for an image layer
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ImageLayer {
    /// The data of this layer
    pub data: Vec<u8>,
    /// The media type of this layer
    pub media_type: String,
    /// This OPTIONAL property contains arbitrary metadata for this descriptor.
    /// This OPTIONAL property MUST use the [annotation rules](https://github.com/opencontainers/image-spec/blob/main/annotations.md#rules)
    pub annotations: Option<BTreeMap<String, String>>,
}

impl ImageLayer {
    /// Constructs a new ImageLayer struct with provided data and media type
    pub fn new(
        data: Vec<u8>,
        media_type: String,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Self {
        ImageLayer {
            data,
            media_type,
            annotations,
        }
    }

    /// Constructs a new ImageLayer struct with provided data and
    /// media type application/vnd.oci.image.layer.v1.tar
    pub fn oci_v1(data: Vec<u8>, annotations: Option<BTreeMap<String, String>>) -> Self {
        Self::new(data, IMAGE_LAYER_MEDIA_TYPE.to_string(), annotations)
    }
    /// Constructs a new ImageLayer struct with provided data and
    /// media type application/vnd.oci.image.layer.v1.tar+gzip
    pub fn oci_v1_gzip(data: Vec<u8>, annotations: Option<BTreeMap<String, String>>) -> Self {
        Self::new(data, IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string(), annotations)
    }

    /// Helper function to compute the sha256 digest of an image layer
    pub fn sha256_digest(&self) -> String {
        sha256_digest(&self.data)
    }
}

/// The data and media type for a configuration object
#[derive(Clone)]
pub struct Config {
    /// The data of this config object
    pub data: Vec<u8>,
    /// The media type of this object
    pub media_type: String,
    /// This OPTIONAL property contains arbitrary metadata for this descriptor.
    /// This OPTIONAL property MUST use the [annotation rules](https://github.com/opencontainers/image-spec/blob/main/annotations.md#rules)
    pub annotations: Option<BTreeMap<String, String>>,
}

impl Config {
    /// Constructs a new Config struct with provided data and media type
    pub fn new(
        data: Vec<u8>,
        media_type: String,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Self {
        Config {
            data,
            media_type,
            annotations,
        }
    }

    /// Constructs a new Config struct with provided data and
    /// media type application/vnd.oci.image.config.v1+json
    pub fn oci_v1(data: Vec<u8>, annotations: Option<BTreeMap<String, String>>) -> Self {
        Self::new(data, IMAGE_CONFIG_MEDIA_TYPE.to_string(), annotations)
    }

    /// Construct a new Config struct with provided [`ConfigFile`] and
    /// media type `application/vnd.oci.image.config.v1+json`
    pub fn oci_v1_from_config_file(
        config_file: ConfigFile,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Result<Self> {
        let data = serde_json::to_vec(&config_file)?;
        Ok(Self::new(
            data,
            IMAGE_CONFIG_MEDIA_TYPE.to_string(),
            annotations,
        ))
    }

    /// Helper function to compute the sha256 digest of this config object
    pub fn sha256_digest(&self) -> String {
        sha256_digest(&self.data)
    }
}

impl TryFrom<Config> for ConfigFile {
    type Error = crate::errors::OciDistributionError;

    fn try_from(config: Config) -> Result<Self> {
        let config = String::from_utf8(config.data)
            .map_err(|e| OciDistributionError::ConfigConversionError(e.to_string()))?;
        let config_file: ConfigFile = serde_json::from_str(&config)
            .map_err(|e| OciDistributionError::ConfigConversionError(e.to_string()))?;
        Ok(config_file)
    }
}
