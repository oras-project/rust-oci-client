// The distribution specification lets a registry ignore the `artifactType` filter of the
// referrers API:
//
// > If filtering is requested and applied, the response MUST include a header
// > `OCI-Filters-Applied: artifactType` denoting that an `artifactType` filter was applied.
//
// https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#listing-referrers
//
// When the registry does not report the filter, the client must apply it. Version 1.1.0-rc1
// of the specification reported the filter in an annotation of the index, which the client
// also accepts.
use std::collections::HashMap;

use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    routing::get,
    Router,
};
use oci_client::{
    client::{ClientConfig, ClientProtocol},
    Client, Reference,
};
use tokio::net::TcpListener;

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const SBOM: &str = "application/vnd.example.sbom.v1";
const SIGNATURE: &str = "application/vnd.example.signature.v1";

/// How the registry reports the filters it applied.
#[derive(Clone, Copy)]
enum Report {
    Nothing,
    Header(&'static str),
    Annotation(&'static str),
}

/// An image index with one SBOM referrer and one signature referrer: the registry did not
/// filter, whatever it reports.
fn unfiltered_index(report: Report) -> String {
    let manifests: Vec<_> = [SBOM, SIGNATURE]
        .iter()
        .enumerate()
        .map(|(i, artifact_type)| {
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "size": 1,
                "digest": format!("sha256:{:064x}", i + 1),
                "artifactType": artifact_type,
            })
        })
        .collect();
    let mut index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": INDEX_MEDIA_TYPE,
        "manifests": manifests,
    });
    if let Report::Annotation(filters) = report {
        index["annotations"] =
            serde_json::json!({ "org.opencontainers.referrers.filtersApplied": filters });
    }
    index.to_string()
}

/// A registry whose referrers endpoint answers with both referrers and reports its filters
/// as `report` says. It refuses a request that does not ask for the SBOM artifact type.
async fn spawn(report: Report) -> String {
    let router = Router::new().route(
        &format!("/v2/repo/referrers/{DIGEST}"),
        get(
            move |Query(query): Query<HashMap<String, String>>| async move {
                if query.get("artifactType").map(String::as_str) != Some(SBOM) {
                    return Err(StatusCode::BAD_REQUEST);
                }
                let mut headers = HeaderMap::new();
                headers.insert("Content-Type", INDEX_MEDIA_TYPE.parse().unwrap());
                if let Report::Header(filters) = report {
                    headers.insert("OCI-Filters-Applied", filters.parse().unwrap());
                }
                Ok((headers, unfiltered_index(report)))
            },
        ),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    address
}

/// The artifact types of the SBOM referrers that the client returns.
async fn sbom_referrers(report: Report) -> Vec<Option<String>> {
    let registry = spawn(report).await;
    let client = Client::new(ClientConfig {
        protocol: ClientProtocol::Http,
        ..Default::default()
    });
    let subject = Reference::try_from(format!("{registry}/repo@{DIGEST}")).unwrap();
    client
        .pull_referrers(&subject, Some(SBOM))
        .await
        .unwrap()
        .manifests
        .into_iter()
        .map(|entry| entry.artifact_type)
        .collect()
}

fn only_sbom() -> Vec<Option<String>> {
    vec![Some(SBOM.to_string())]
}

fn as_the_registry_sent_it() -> Vec<Option<String>> {
    vec![Some(SBOM.to_string()), Some(SIGNATURE.to_string())]
}

#[tokio::test]
#[ignore = "fails until the fix in the next commit"]
async fn filters_when_the_registry_reports_no_filter() {
    assert_eq!(sbom_referrers(Report::Nothing).await, only_sbom());
}

#[tokio::test]
#[ignore = "fails until the fix in the next commit"]
async fn filters_when_the_registry_reports_another_filter() {
    assert_eq!(sbom_referrers(Report::Header("digest")).await, only_sbom());
}

// The registry did not filter in the two tests below, so they show that the client reads
// the report of the registry, and does not filter a second time.

#[tokio::test]
async fn trusts_the_header_of_a_registry_that_applied_the_filter() {
    assert_eq!(
        sbom_referrers(Report::Header("digest,artifactType")).await,
        as_the_registry_sent_it()
    );
}

#[tokio::test]
async fn trusts_the_annotation_of_a_registry_that_applied_the_filter() {
    assert_eq!(
        sbom_referrers(Report::Annotation("artifactType")).await,
        as_the_registry_sent_it()
    );
}
