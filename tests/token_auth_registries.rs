// Registries with token authentication do not agree on the scopes that they require. For the
// catalog, the distribution registry requires `registry:catalog:*` and Zot requires
// `repository::pull`. These tests run the client against both, so that the client is tested
// with the challenges that the registries really send.
//
// The token service is `cesanta/docker_auth`. It signs the tokens with a certificate that the
// test generates, and the registries verify the tokens with the same certificate.
#![cfg(feature = "test-registry")]

use std::time::Duration;

use oci_client::{
    client::{ClientConfig, ClientProtocol, Config, ImageLayer},
    secrets::RegistryAuth,
    Client, Reference,
};
use rcgen::{CertificateParams, KeyPair, RsaKeySize, PKCS_RSA_SHA256};
use testcontainers::{
    core::IntoContainerPort, runners::AsyncRunner, ContainerAsync, CopyTargetOptions, GenericImage,
    ImageExt,
};

const USERNAME: &str = "testuser";
const PASSWORD: &str = "testpassword";
/// The bcrypt hash of [`PASSWORD`].
const PASSWORD_HASH: &str = "$2y$05$8/q2bfRcX74EuxGf0qOcSuhWDQJXrgWiy6Fi73/JM2tKC66qSrLve";

const ISSUER: &str = "oci-client test token service";
const SERVICE: &str = "oci-client-test";
const CERTIFICATE_PATH: &str = "/certs/token.crt";
const KEY_PATH: &str = "/certs/token.key";

const TOKEN_SERVICE_PORT: u16 = 5001;
const REGISTRY_PORT: u16 = 5000;

/// A running token service, which grants every scope to [`USERNAME`].
struct TokenService {
    _container: ContainerAsync<GenericImage>,
    /// The URL that the registries name in their challenges. The client requests the tokens
    /// there, so it is an address on the host.
    realm: String,
    /// The certificate that verifies the tokens, in PEM format.
    certificate: String,
}

/// A file that every user of a container can read. The containers do not run as root.
fn readable(path: &str) -> CopyTargetOptions {
    CopyTargetOptions::new(path).with_mode(0o644)
}

async fn start_token_service() -> TokenService {
    // The key is an RSA key: docker_auth 1.14.0 computes a wrong key ID for an EC key.
    let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)
        .expect("Failed to generate the key that signs the tokens");
    let certificate = CertificateParams::new(Vec::<String>::new())
        .and_then(|params| params.self_signed(&key))
        .expect("Failed to generate the certificate that verifies the tokens")
        .pem();

    let config = format!(
        r#"server:
  addr: ":{TOKEN_SERVICE_PORT}"
token:
  issuer: "{ISSUER}"
  expiration: 900
  certificate: "{CERTIFICATE_PATH}"
  key: "{KEY_PATH}"
  disable_legacy_key_id: true
users:
  "{USERNAME}":
    password: "{PASSWORD_HASH}"
acl:
  - match: {{account: "{USERNAME}"}}
    actions: ["*"]
"#
    );
    let container = GenericImage::new("docker.io/cesanta/docker_auth", "1.14.0")
        .with_exposed_port(TOKEN_SERVICE_PORT.tcp())
        .with_cmd(["--logtostderr", "/config/auth_config.yml"])
        .with_copy_to(readable("/config/auth_config.yml"), config.into_bytes())
        .with_copy_to(readable(CERTIFICATE_PATH), certificate.clone().into_bytes())
        .with_copy_to(readable(KEY_PATH), key.serialize_pem().into_bytes())
        .start()
        .await
        .expect("Failed to start the token service container");
    let port = container
        .get_host_port_ipv4(TOKEN_SERVICE_PORT)
        .await
        .expect("Failed to get the port of the token service");
    let realm = format!("http://localhost:{port}/auth");
    wait_for_unauthorized(&realm).await;

    TokenService {
        _container: container,
        realm,
        certificate,
    }
}

/// Starts a registry container with its configuration file at `config_path`, and returns the
/// container and the address of the registry.
async fn start_registry(
    name: &str,
    tag: &str,
    config_path: &str,
    config: String,
    token_service: &TokenService,
) -> (ContainerAsync<GenericImage>, String) {
    let container = GenericImage::new(name, tag)
        .with_exposed_port(REGISTRY_PORT.tcp())
        .with_copy_to(readable(config_path), config.into_bytes())
        .with_copy_to(
            readable(CERTIFICATE_PATH),
            token_service.certificate.clone().into_bytes(),
        )
        .start()
        .await
        .expect("Failed to start the registry container");
    let port = container
        .get_host_port_ipv4(REGISTRY_PORT)
        .await
        .expect("Failed to get the port of the registry");
    let registry = format!("localhost:{port}");
    wait_for_unauthorized(&format!("http://{registry}/v2/")).await;
    (container, registry)
}

/// Waits until `url` answers `401 Unauthorized`: the server is up, and it requires
/// authentication.
async fn wait_for_unauthorized(url: &str) {
    for _ in 0..150 {
        if let Ok(response) = reqwest::get(url).await {
            if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("{url} did not answer 401 Unauthorized in 30 seconds");
}

/// Lists the catalog, pushes an image, and lists the tags and the catalog again, all with
/// one client. The requests need tokens for different scopes.
async fn push_and_list(registry: &str) {
    let client = Client::new(ClientConfig {
        protocol: ClientProtocol::Http,
        ..Default::default()
    });
    let auth = RegistryAuth::Basic(USERNAME.to_string(), PASSWORD.to_string());
    let image = Reference::try_from(format!("{registry}/test/hello:v1")).unwrap();

    let catalog = client
        .catalog(&image, &auth, None, None)
        .await
        .expect("Failed to list the catalog of the empty registry");
    assert!(catalog.repositories.is_empty());

    let layer = ImageLayer::new(
        b"hello".to_vec(),
        "application/vnd.oci.image.layer.v1.tar".to_string(),
        None,
    );
    let config = Config::new(
        b"{}".to_vec(),
        "application/vnd.oci.image.config.v1+json".to_string(),
        None,
    );
    client
        .push(&image, &[layer], config, &auth, None)
        .await
        .expect("Failed to push the image");

    let tags = client
        .list_tags(&image, &auth, None, None)
        .await
        .expect("Failed to list the tags");
    assert_eq!(tags.tags, vec!["v1"]);

    let catalog = client
        .catalog(&image, &auth, None, None)
        .await
        .expect("Failed to list the catalog");
    assert_eq!(catalog.repositories, vec!["test/hello"]);
}

#[tokio::test]
async fn distribution_registry_with_token_authentication() {
    let token_service = start_token_service().await;
    let config = format!(
        r#"version: 0.1
storage:
  filesystem:
    rootdirectory: /var/lib/registry
http:
  addr: :{REGISTRY_PORT}
auth:
  token:
    realm: {realm}
    service: {SERVICE}
    issuer: "{ISSUER}"
    rootcertbundle: {CERTIFICATE_PATH}
"#,
        realm = token_service.realm
    );
    let (_container, registry) = start_registry(
        "docker.io/library/registry",
        "3.1.2",
        "/etc/distribution/config.yml",
        config,
        &token_service,
    )
    .await;

    push_and_list(&registry).await;
}

#[tokio::test]
async fn zot_with_token_authentication() {
    let token_service = start_token_service().await;
    let config = format!(
        r#"{{
  "distSpecVersion": "1.1.1",
  "storage": {{ "rootDirectory": "/var/lib/registry" }},
  "http": {{
    "address": "0.0.0.0",
    "port": "{REGISTRY_PORT}",
    "auth": {{
      "bearer": {{
        "realm": "{realm}",
        "service": "{SERVICE}",
        "cert": "{CERTIFICATE_PATH}"
      }}
    }}
  }}
}}"#,
        realm = token_service.realm
    );
    let (_container, registry) = start_registry(
        "ghcr.io/project-zot/zot-minimal-linux-amd64",
        "v2.1.22",
        "/etc/zot/config.json",
        config,
        &token_service,
    )
    .await;

    push_and_list(&registry).await;
}
