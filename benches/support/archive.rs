#![allow(dead_code)]

#[cfg(feature = "encrypted-keys")]
use ed25519_dalek::pkcs8::EncodePrivateKey;
#[cfg(feature = "encrypted-keys")]
use pkcs8::LineEnding;
use std::fs;
#[cfg(feature = "encrypted-keys")]
use treetop_bundle::SigningKey;
use treetop_bundle::{BundleArchive, BundleBuilder};

pub fn unsigned_archive() -> BundleArchive {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let policies = (0..128)
        .map(|index| {
            format!(
                r#"@id("bench.policy-{index}")
permit(
    principal is Example::User,
    action == Example::Action::"read",
    resource is Example::Resource
);
"#
            )
        })
        .collect::<String>();
    fs::write(root.join("policies.cedar"), policies).unwrap();
    fs::write(
        root.join("treetop-module.toml"),
        r#"format_version = 1
name = "bench"
namespace = "Example"
policies = ["policies.cedar"]
"#,
    )
    .unwrap();
    fs::write(
        root.join("treetop-bundle.toml"),
        r#"format_version = 1
name = "benchmark"

[[modules]]
manifest = "treetop-module.toml"
"#,
    )
    .unwrap();
    BundleBuilder::from_manifest(root.join("treetop-bundle.toml"))
        .unwrap()
        .build(None)
        .unwrap()
}

#[cfg(feature = "encrypted-keys")]
pub struct ResignFixture {
    pub archive: BundleArchive,
    pub key: SigningKey,
}

#[cfg(feature = "encrypted-keys")]
pub fn resign_fixture() -> ResignFixture {
    let pem = ed25519_dalek::SigningKey::from_bytes(&[42; 32])
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap();
    ResignFixture {
        archive: unsigned_archive(),
        key: SigningKey::from_pkcs8_pem(pem.as_str()).unwrap(),
    }
}
