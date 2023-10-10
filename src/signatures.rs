//! OCI extension - signatures

/// The type of signatures that can be stored in a registry that supports the X-Registry-Supports-Signatures API extension.
pub const SIGNATURE_TYPE: &str = "atomic";
/// The header key for a returned in an OCI distribution API call to registry that supports the X-Registry-Supports-Signatures API extension.
pub const X_REGISTRY_SUPPORTS_SIGNATURES_HEADER: &str = "x-registry-supports-signatures";
/// The supported version of the X-Registry-Supports-Signatures API GET signatures response schema.
pub const SIGNATURE_SCHEMA: u8 = 2;
/// The length of the unique part of the signature name in the response returned by the GET signatures API, where the
/// name is in the format <digest>@<name_uid>.
pub const SIGANTURE_NAME_UID_LENGTH: u8 = 32;

/// The RegistrySignatures is the list of signatures associated with a digest.
///
/// This is the list of signatures returned by the X-Registry-Supports-Signatures API extension
/// GET https://<registry>/extensions/v2/<repository>/signatures/<image_digest>
/// endpoint.
#[derive(Default, Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RegistrySignatures {
    /// This is a list of all the signatures for a particular image digest stored in the registry.
    ///
    /// If there are no signatures stored in the registry for a digest, the signatures extension API will return an empty list.
    pub signatures: Vec<RegistrySignature>,
}

impl std::fmt::Display for RegistrySignatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let registry_signatures: Vec<String> =
            self.signatures.iter().map(|s| s.to_string()).collect();
        write!(f, "( signatures: '{}' )", registry_signatures.join(","),)
    }
}

/// This is a signature associated with a digest
///
/// This is a single instance of a signature in the list of signatures returned by the
/// X-Registry-Supports-Signatures API extension
/// GET https://<registry>/extensions/v2/<repository>/signatures/<image_digest>
/// endpoint.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrySignature {
    /// This is a schema version.
    ///
    /// The width of this integer is not specificed.
    /// However, the latest version of the signatures extension is `2`.
    /// So choose u8 to represent the schema version
    pub schema_version: u8,

    /// The name of the image signature.
    ///
    /// This is unique and is in the following format: `<digest>@<name>`.
    /// The name has to be 32 characters long.
    pub name: String,

    /// The type of the signature
    ///
    /// Usually type will be 'atomic'
    #[serde(rename = "type")]
    pub signature_type: String,

    /// The base64 encoded signature
    pub content: String,
}

impl Default for RegistrySignature {
    fn default() -> Self {
        RegistrySignature {
            schema_version: 2,
            name: "".to_owned(),
            signature_type: SIGNATURE_TYPE.to_owned(),
            content: "".to_owned(),
        }
    }
}

impl std::fmt::Display for RegistrySignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "( schema-version: '{}', name: '{}', type: '{}', content: '{}' )",
            self.schema_version, self.name, self.signature_type, self.content,
        )
    }
}
