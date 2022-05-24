use oci_distribution::{
    client::{Config, ImageLayer},
    manifest,
    secrets::RegistryAuth,
    Client, Reference,
};
use tracing::info;

pub(crate) async fn push_wasm(
    client: &mut Client,
    auth: &RegistryAuth,
    reference: &Reference,
    module: &str,
) {
    info!(?reference, ?module, "pushing wasm module");

    let data = async_std::fs::read(module)
        .await
        .expect("Cannot read Wasm module from disk");

    let layers = vec![ImageLayer::new(
        data,
        manifest::WASM_LAYER_MEDIA_TYPE.to_string(),
    )];

    let config = Config {
        data: b"{}".to_vec(),
        media_type: manifest::WASM_CONFIG_MEDIA_TYPE.to_string(),
    };

    let response = client
        .push(&reference, &layers, config, &auth, None)
        .await
        .map(|push_response| push_response.manifest_url)
        .expect("Cannot push Wasm module");

    println!("Wasm module successfully pushed {:?}", response);
}
