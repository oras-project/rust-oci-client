use std::env;

extern crate oci_distribution;

#[tokio::main]
pub async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Image ref not provided");
        std::process::exit(1);
    }

    let reference: oci_distribution::Reference =
        args[1].parse().expect("Not a valid OCI image reference");
    let anon_auth = oci_distribution::secrets::RegistryAuth::Anonymous;

    let mut client = oci_distribution::Client::default();
    let (manifest, _) = client
        .pull_manifest(&reference, &anon_auth)
        .await
        .expect("Cannot pull manifest");

    println!("{}", manifest);
}
