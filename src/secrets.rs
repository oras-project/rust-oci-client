//! Types for working with registry access secrets

use serde::Deserialize;

use base64;
use dirs;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::process::{Command, Stdio};
use std::str;
use tracing::debug;

/// A method for authenticating to a registry
pub enum RegistryAuth {
    /// Access the registry anonymously
    Anonymous,

    /// Access the registry using HTTP Basic authentication
    Basic(String, String),

    /// Access the registry using credentials configured in the Docker config file
    Default,
}

pub(crate) trait Authenticable {
    fn apply_authentication(self, registry: &str, auth: &RegistryAuth) -> Self;
}

impl Authenticable for reqwest::RequestBuilder {
    fn apply_authentication(self, registry: &str, auth: &RegistryAuth) -> Self {
        match auth {
            RegistryAuth::Anonymous => self,
            RegistryAuth::Basic(username, password) => self.basic_auth(username, Some(password)),
            RegistryAuth::Default => match docker_auth(registry) {
                Ok(userpass) => self.basic_auth(userpass.0, Some(userpass.1)),
                Err(e) => {
                    // This effectively falls back to anonymous, instead of raising the error.
                    // TODO: Raise this error so clients can *require* Docker config auth.
                    debug!("failed to get credentials: {}", e);
                    self
                }
            },
        }
    }
}

fn docker_auth(registry: &str) -> Result<(String, String), anyhow::Error> {
    let cfg = get_docker_config()?;

    // TODO: Check any per-repo configured auth, instead of just per-registry.

    let mut acr = cfg.auths.get(registry);
    // For historical purposes, this key is also accepted for DockerHub.
    if acr.is_none() && registry == "index.docker.io" {
        acr = cfg.auths.get("https://index.docker.io/v1/")
    }
    if !acr.is_none() {
        let ac = acr.unwrap();

        if ac.auth != "" {
            // base64-decode the auth to get username and password.
            let dec = &base64::decode(&ac.auth)?;
            let vec = str::from_utf8(dec)?.split(":").collect::<Vec<_>>();
            assert_eq!(vec.len(), 2);
            let username = vec[0];
            let password = vec[1];
            return Ok((username.to_string(), password.to_string()));
        }
        if ac.username != "" && ac.password != "" {
            return Ok((ac.username.to_string(), ac.password.to_string()));
        }
        if ac.identity_token != "" {
            return Ok(("<token>".to_string(), ac.identity_token.to_string()));
        }
        // TODO: bearer auth if RegistryToken is found.
    }

    // If a cred helper is configured, execute it, passing the registry to stdin and parsing its stdout as JSON.
    let chr = cfg.cred_helpers.get(registry);
    if !chr.is_none() {
        let ch = chr.unwrap();
        let out = Command::new(format!("docker-credential-{}", ch))
            .args(["get"])
            .stdin(Stdio::null()) // TODO: pass registry to stdin.
            .output()?
            .stdout
            .to_vec();

        let resp: CredHelperResponse = serde_json::from_slice(out.as_slice())?;
        let username = resp.username;
        let password = resp.secret;
        return Ok((username, password));
    }

    // TODO: credsStores

    Err(anyhow::Error::msg("no matching credentials"))
}

fn get_docker_config() -> Result<DockerConfig, anyhow::Error> {
    // TODO: Also check for Podman auth configured in $XDG_RUNTIME_DIR/containers/auth.json
    let cfg = env::var("DOCKER_CONFIG")
        .unwrap_or(
            dirs::home_dir()
                .unwrap_or_default()
                .join(".docker")
                .to_str()
                .unwrap_or_default()
                .to_string(),
        )
        .to_string();
    let file = File::open(Path::new(&cfg).join("config.json"))?;
    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}

#[derive(Deserialize, Debug)]
struct DockerConfig {
    auths: HashMap<String, AuthConfig>,
    #[serde(rename(deserialize = "credHelpers"))]
    cred_helpers: HashMap<String, String>,
}

#[derive(Deserialize, Debug)]
struct AuthConfig {
    auth: String, // base64-encoded username:password
    username: String,
    password: String,
    #[serde(rename(deserialize = "identitytoken"))]
    identity_token: String,
}

#[derive(Deserialize, Debug)]
struct CredHelperResponse {
    #[serde(rename(deserialize = "Username"))]
    username: String,
    #[serde(rename(deserialize = "Secret"))]
    secret: String,
}