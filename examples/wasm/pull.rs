use oci_distribution::{manifest, secrets::RegistryAuth, Client, Reference};
use tracing::info;

pub(crate) async fn pull_wasm(
    client: &mut Client,
    auth: &RegistryAuth,
    reference: &Reference,
    output: &str,
) {
    info!(?reference, ?output, "pulling wasm module");

    let image_content = client
        .pull(reference, auth, vec![manifest::WASM_LAYER_MEDIA_TYPE])
        .await
        .expect("Cannot pull Wasm module")
        .layers
        .into_iter()
        .next()
        .map(|layer| layer.data)
        .expect("No data found");

    std::fs::write(output, image_content).expect("Cannot write to file");
    println!("Wasm module successfully written to {}", output);
}
