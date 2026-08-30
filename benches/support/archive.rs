#![allow(dead_code)]

#[cfg(feature = "encrypted-keys")]
use ed25519_dalek::pkcs8::EncodePrivateKey;
#[cfg(feature = "encrypted-keys")]
use pkcs8::LineEnding;
use std::fs;
#[cfg(feature = "encrypted-keys")]
use treetop_bundle::SigningKey;
use treetop_bundle::{
    ArchiveLimits, BundleArchive, BundleBuilder, SignaturePolicy, TrustStore, ValidatedBundle,
};

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

pub fn validated_policy_store_bundle() -> ValidatedBundle {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let mut module_entries = String::new();
    for store_index in 0..8 {
        let module_name = format!("store{store_index}");
        let namespace = format!("Example::Store{store_index}");
        let policies = (0..16)
            .map(|policy_index| {
                format!(
                    r#"@id("{module_name}.read-{policy_index}")
permit(
    principal,
    action == {namespace}::Action::"read-{policy_index}",
    resource is {namespace}::Resource
);
"#
                )
            })
            .collect::<String>();
        fs::write(root.join(format!("{module_name}.cedar")), policies).unwrap();
        fs::write(
            root.join(format!("{module_name}.toml")),
            format!(
                "format_version = 1\nname = {module_name:?}\nnamespace = {namespace:?}\npolicies = [{:?}]\n",
                format!("{module_name}.cedar")
            ),
        )
        .unwrap();
        module_entries.push_str(&format!(
            "\n[[modules]]\nmanifest = {:?}\n",
            format!("{module_name}.toml")
        ));
    }
    fs::write(
        root.join("global.cedar"),
        r#"@id("global.blocked")
forbid(principal == Example::User::"blocked", action, resource);
"#,
    )
    .unwrap();
    fs::write(
        root.join("global.toml"),
        r#"format_version = 1
name = "global"
namespace = "Example::Global"
policies = ["global.cedar"]
"#,
    )
    .unwrap();
    module_entries.push_str("\n[[modules]]\nmanifest = \"global.toml\"\nrole = \"global\"\n");
    fs::write(
        root.join("treetop-bundle.toml"),
        format!("format_version = 1\nname = \"policy-store-benchmark\"\n{module_entries}"),
    )
    .unwrap();

    BundleBuilder::from_manifest(root.join("treetop-bundle.toml"))
        .unwrap()
        .build(None)
        .unwrap()
        .validate(
            SignaturePolicy::AllowUnsigned,
            &TrustStore::new(),
            ArchiveLimits::default(),
        )
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
