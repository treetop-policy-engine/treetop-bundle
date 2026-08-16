use ed25519_dalek::pkcs8::EncodePrivateKey;
use gungraun::{library_benchmark, library_benchmark_group, main};
use pkcs8::LineEnding;
use std::fs;
use treetop_bundle::{
    ArchiveLimits, BundleArchive, BundleBuilder, SignaturePolicy, SigningKey, TrustStore,
};

fn unsigned_archive() -> BundleArchive {
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

#[library_benchmark(setup = unsigned_archive)]
fn validate_archive(archive: BundleArchive) {
    let _ = archive
        .validate(
            SignaturePolicy::AllowUnsigned,
            &TrustStore::new(),
            ArchiveLimits::default(),
        )
        .unwrap();
}

struct ResignFixture {
    archive: BundleArchive,
    key: SigningKey,
}

fn resign_fixture() -> ResignFixture {
    let pem = ed25519_dalek::SigningKey::from_bytes(&[42; 32])
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap();
    ResignFixture {
        archive: unsigned_archive(),
        key: SigningKey::from_pkcs8_pem(pem.as_str()).unwrap(),
    }
}

#[library_benchmark(setup = resign_fixture)]
fn resign_archive(fixture: ResignFixture) {
    let _ = fixture
        .archive
        .resign(&fixture.key, ArchiveLimits::default())
        .unwrap();
}

library_benchmark_group!(
    name = archive;
    benchmarks = validate_archive, resign_archive
);

main!(library_benchmark_groups = archive);
