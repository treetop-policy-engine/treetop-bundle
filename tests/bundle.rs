use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use flate2::bufread::GzDecoder;
use flate2::{Compression, GzBuilder};
#[cfg(feature = "encrypted-keys")]
use pkcs8::{LineEnding, PrivateKeyInfoRef};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use tar::{Archive, Builder, EntryType, Header};
use tempfile::TempDir;
use treetop_bundle::{
    ArchiveLimits, BundleArchive, BundleBuilder, BundleError, BundleManifest, LabelSet,
    SignaturePolicy, SigningKey, TrustStore, TrustedKey,
};

struct Fixture {
    _temporary: TempDir,
    bundle_manifest: PathBuf,
}

impl Fixture {
    fn valid() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        write(
            root.join("policy.cedar"),
            r#"
@id("dns.read")
permit (
    principal is ExampleCo::DNS::User,
    action == ExampleCo::DNS::Action::"read",
    resource is ExampleCo::DNS::Host
);
"#,
        );
        write(
            root.join("schema.cedarschema"),
            r#"
namespace ExampleCo::DNS {
    entity User;
    entity Host = {
        name: String,
        labels: Set<String>,
    };
    action "read" appliesTo {
        principal: User,
        resource: Host,
    };
}
"#,
        );
        write(
            root.join("labels.json"),
            r#"[
  {
    "kind": "ExampleCo::DNS::Host",
    "field": "name",
    "output": "labels",
    "patterns": [{"name": "production", "regex": "^prod-"}]
  }
]"#,
        );
        write(
            root.join("treetop-module.toml"),
            r#"
format_version = 1
name = "dns"
namespace = "ExampleCo::DNS"
imports = []
policies = ["policy.cedar"]
schemas = ["schema.cedarschema"]
labels = ["labels.json"]
"#,
        );
        let bundle_manifest = root.join("treetop-bundle.toml");
        write(
            &bundle_manifest,
            r#"
format_version = 1
name = "production"

[[modules]]
manifest = "treetop-module.toml"
role = "ordinary"
"#,
        );
        Self {
            _temporary: temporary,
            bundle_manifest,
        }
    }
}

#[test]
fn builds_byte_identical_archives() {
    let fixture = Fixture::valid();
    let builder = BundleBuilder::from_manifest(&fixture.bundle_manifest).unwrap();
    let first = builder.build(None).unwrap();
    let second = builder.build(None).unwrap();

    assert_eq!(first.as_bytes(), second.as_bytes());
    let validated = first
        .validate(
            SignaturePolicy::AllowUnsigned,
            &TrustStore::new(),
            ArchiveLimits::default(),
        )
        .unwrap();
    assert_eq!(validated.name(), "production");
    assert_eq!(validated.policy_ids(), &["dns.read"]);
    validated.prepare_engine().unwrap();
}

#[test]
fn signed_archives_are_deterministic_and_require_trust() {
    let fixture = Fixture::valid();
    let (signing_key, trusted_key) = key_pair(7);
    let builder = BundleBuilder::from_manifest(&fixture.bundle_manifest).unwrap();
    let first = builder.build(Some(&signing_key)).unwrap();
    let second = builder.build(Some(&signing_key)).unwrap();
    assert_eq!(first.as_bytes(), second.as_bytes());

    let error = first
        .validate(
            SignaturePolicy::AllowUnsigned,
            &TrustStore::new(),
            ArchiveLimits::default(),
        )
        .err()
        .unwrap();
    assert!(error.to_string().contains("untrusted_key"));

    let trust = TrustStore::from_keys([trusted_key]).unwrap();
    let validated = first
        .validate(SignaturePolicy::Required, &trust, ArchiveLimits::default())
        .unwrap();
    assert!(validated.verified_signature().is_signed());
    assert_eq!(
        validated.verified_signature().key_id(),
        Some(signing_key.key_id().as_str())
    );
}

#[test]
fn resigning_rotates_key_without_changing_bundle_id() {
    let fixture = Fixture::valid();
    let (first_key, first_trusted) = key_pair(1);
    let (second_key, second_trusted) = key_pair(2);
    let original = BundleBuilder::from_manifest(&fixture.bundle_manifest)
        .unwrap()
        .build(Some(&first_key))
        .unwrap();
    let rotated = original
        .resign(&second_key, ArchiveLimits::default())
        .unwrap();
    assert_ne!(original.sha256(), rotated.sha256());

    let original = original
        .validate(
            SignaturePolicy::Required,
            &TrustStore::from_keys([first_trusted]).unwrap(),
            ArchiveLimits::default(),
        )
        .unwrap();
    let rotated = rotated
        .validate(
            SignaturePolicy::Required,
            &TrustStore::from_keys([second_trusted]).unwrap(),
            ArchiveLimits::default(),
        )
        .unwrap();
    assert_eq!(original.bundle_id(), rotated.bundle_id());
}

#[test]
fn required_policy_rejects_unsigned_archive() {
    let fixture = Fixture::valid();
    let archive = BundleBuilder::from_manifest(&fixture.bundle_manifest)
        .unwrap()
        .build(None)
        .unwrap();
    let error = archive
        .validate(
            SignaturePolicy::Required,
            &TrustStore::new(),
            ArchiveLimits::default(),
        )
        .err()
        .unwrap();
    assert!(error.to_string().contains("signature_missing"));
}

#[test]
fn signed_manifest_tampering_fails_signature_before_manifest_identity() {
    let fixture = Fixture::valid();
    let (signing_key, trusted_key) = key_pair(11);
    let archive = BundleBuilder::from_manifest(&fixture.bundle_manifest)
        .unwrap()
        .build(Some(&signing_key))
        .unwrap();
    let tampered = rewrite_entry(&archive, "manifest.json", |contents| {
        String::from_utf8(contents.to_vec())
            .unwrap()
            .replace("production", "xroduction")
            .into_bytes()
    });

    let error = tampered
        .validate(
            SignaturePolicy::Required,
            &TrustStore::from_keys([trusted_key]).unwrap(),
            ArchiveLimits::default(),
        )
        .err()
        .unwrap();

    assert!(error.to_string().contains("invalid_signature"));
}

#[test]
fn signed_artifact_tampering_fails_the_authenticated_hash() {
    let fixture = Fixture::valid();
    let (signing_key, trusted_key) = key_pair(12);
    let archive = BundleBuilder::from_manifest(&fixture.bundle_manifest)
        .unwrap()
        .build(Some(&signing_key))
        .unwrap();
    let tampered = rewrite_entry(&archive, "policies.cedar", |contents| {
        String::from_utf8(contents.to_vec())
            .unwrap()
            .replace("dns.read", "dns.reed")
            .into_bytes()
    });

    let error = tampered
        .validate(
            SignaturePolicy::Required,
            &TrustStore::from_keys([trusted_key]).unwrap(),
            ArchiveLimits::default(),
        )
        .err()
        .unwrap();

    assert!(error.to_string().contains("artifact hash or size mismatch"));
}

#[test]
fn concatenated_gzip_members_are_rejected() {
    let fixture = Fixture::valid();
    let archive = BundleBuilder::from_manifest(&fixture.bundle_manifest)
        .unwrap()
        .build(None)
        .unwrap();
    let mut concatenated = archive.as_bytes().to_vec();
    concatenated.extend_from_slice(archive.as_bytes());

    let error = BundleArchive::from_bytes(concatenated)
        .validate(
            SignaturePolicy::AllowUnsigned,
            &TrustStore::new(),
            ArchiveLimits::default(),
        )
        .err()
        .unwrap();

    assert!(error.to_string().contains("concatenated gzip members"));
}

#[test]
fn global_policy_scope_is_not_confined_to_its_module_namespace() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    write(
        root.join("policy.cedar"),
        r#"
@id("platform.global")
permit (
    principal is External::User,
    action,
    resource is External::Resource
);
"#,
    );
    write(
        root.join("treetop-module.toml"),
        r#"
format_version = 1
name = "platform"
namespace = "ExampleCo::Platform"
policies = ["policy.cedar"]
"#,
    );
    let manifest = root.join("treetop-bundle.toml");
    write(
        &manifest,
        r#"
format_version = 1
name = "global-test"

[[modules]]
manifest = "treetop-module.toml"
role = "global"
"#,
    );

    BundleBuilder::from_manifest(manifest)
        .unwrap()
        .build(None)
        .unwrap();
}

#[test]
fn ordinary_policies_must_constrain_owned_actions() {
    let temporary = tempfile::tempdir().unwrap();
    let manifest = write_single_module(
        temporary.path(),
        "ordinary",
        r#"
@id("dns.any")
permit(principal, action, resource);
"#,
    );

    let error = BundleBuilder::from_manifest(manifest)
        .unwrap()
        .build(None)
        .err()
        .unwrap();

    assert!(
        error
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "policy.action_unconstrained")
    );
}

#[test]
fn deployable_templates_are_rejected() {
    let temporary = tempfile::tempdir().unwrap();
    let manifest = write_single_module(
        temporary.path(),
        "ordinary",
        r#"
@id("dns.template")
permit(
    principal == ?principal,
    action == ExampleCo::DNS::Action::"read",
    resource
);
"#,
    );

    let error = BundleBuilder::from_manifest(manifest)
        .unwrap()
        .build(None)
        .err()
        .unwrap();

    assert!(
        error
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "policy.templates_unsupported")
    );
}

#[test]
fn module_namespaces_must_be_segment_prefix_disjoint() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    for (name, namespace) in [
        ("parent", "ExampleCo::DNS"),
        ("child", "ExampleCo::DNS::Zone"),
    ] {
        let directory = root.join(name);
        fs::create_dir(&directory).unwrap();
        write(
            directory.join("treetop-module.toml"),
            &format!("format_version = 1\nname = {name:?}\nnamespace = {namespace:?}\n"),
        );
    }
    let manifest = root.join("treetop-bundle.toml");
    write(
        &manifest,
        r#"
format_version = 1
name = "overlap"

[[modules]]
manifest = "parent/treetop-module.toml"

[[modules]]
manifest = "child/treetop-module.toml"
"#,
    );

    let error = BundleManifest::from_path(manifest).err().unwrap();

    assert!(
        error
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "manifest.overlapping_namespaces")
    );
}

#[test]
fn imports_must_exactly_match_a_selected_namespace() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    write(
        root.join("treetop-module.toml"),
        r#"
format_version = 1
name = "dns"
namespace = "ExampleCo::DNS"
imports = ["ExampleCo::Identity"]
"#,
    );
    let manifest = root.join("treetop-bundle.toml");
    write(
        &manifest,
        r#"
format_version = 1
name = "imports"

[[modules]]
manifest = "treetop-module.toml"
"#,
    );

    let error = BundleManifest::from_path(manifest).err().unwrap();

    assert!(
        error
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "manifest.unresolved_import")
    );
}

#[cfg(unix)]
#[test]
fn module_inputs_may_not_escape_through_symlinks() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let module = root.join("module");
    fs::create_dir(&module).unwrap();
    write(
        root.join("outside.cedar"),
        "permit(principal, action, resource);\n",
    );
    symlink(root.join("outside.cedar"), module.join("policy.cedar")).unwrap();
    write(
        module.join("treetop-module.toml"),
        r#"
format_version = 1
name = "dns"
namespace = "ExampleCo::DNS"
policies = ["policy.cedar"]
"#,
    );

    let error = treetop_bundle::ModuleManifest::from_path(module.join("treetop-module.toml"))
        .err()
        .unwrap();

    assert!(
        error
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "manifest.input_escape")
    );
}

#[test]
fn compressed_limit_is_enforced_before_decoding() {
    let archive = BundleArchive::from_bytes(vec![0; 16]);
    let error = archive
        .validate(
            SignaturePolicy::AllowUnsigned,
            &TrustStore::new(),
            ArchiveLimits::new(8, 1024).unwrap(),
        )
        .err()
        .unwrap();
    assert!(matches!(
        error,
        BundleError::SizeLimit {
            kind: "compressed",
            limit: 8
        }
    ));
}

#[test]
fn compressed_file_limit_is_enforced_while_reading() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("oversized.tar.gz");
    fs::write(&path, [0; 16]).unwrap();

    let error = BundleArchive::read(&path, 8).unwrap_err();

    assert!(matches!(
        error,
        BundleError::SizeLimit {
            kind: "compressed",
            limit: 8
        }
    ));
}

#[test]
fn label_destinations_are_unique() {
    let error = LabelSet::from_json_str(
        r#"[
          {"kind":"App::Host","field":"name","output":"labels","patterns":[{"name":"a","regex":"a"}]},
          {"kind":"App::Host","field":"fqdn","output":"labels","patterns":[{"name":"b","regex":"b"}]}
        ]"#,
    )
    .unwrap_err();
    assert!(
        error
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "labels.duplicate_destination")
    );
}

#[cfg(unix)]
#[test]
fn private_key_file_permissions_are_enforced() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().unwrap();
    let dalek = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let pem = pem("PRIVATE KEY", dalek.to_pkcs8_der().unwrap().as_bytes());
    let path = temporary.path().join("private.pem");
    write(&path, &pem);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(SigningKey::from_pkcs8_pem_file(&path).is_err());
}

#[test]
fn weak_public_keys_are_rejected() {
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.push(1);
    der.extend([0; 31]);
    let weak = pem("PUBLIC KEY", &der);

    let error = TrustedKey::from_spki_pem(&weak).unwrap_err();

    assert!(error.to_string().contains("weak Ed25519 public key"));
}

#[test]
#[cfg(feature = "encrypted-keys")]
fn encrypted_private_keys_require_and_accept_the_correct_password() {
    let dalek = ed25519_dalek::SigningKey::from_bytes(&[10; 32]);
    let encrypted = encrypted_pem(&dalek, b"correct horse", 1);
    let encrypted = format!("Bag Attributes\n    friendlyName: signing-key\n{encrypted}");

    let error = SigningKey::from_pkcs8_pem(&encrypted).err().unwrap();
    assert!(matches!(error, BundleError::SigningKeyPasswordRequired));

    let loaded = SigningKey::from_pkcs8_pem_with_password(&encrypted, b"correct horse").unwrap();
    assert_eq!(loaded.key_id(), key_id_for(&dalek));

    let unencrypted = pem("PRIVATE KEY", dalek.to_pkcs8_der().unwrap().as_bytes());
    let loaded =
        SigningKey::from_pkcs8_pem_with_password(&unencrypted, b"unused password").unwrap();
    assert_eq!(loaded.key_id(), key_id_for(&dalek));
    let error = SigningKey::from_pkcs8_encrypted_pem(&unencrypted, b"unused password")
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("expected \"ENCRYPTED PRIVATE KEY\"")
    );

    let error = SigningKey::from_pkcs8_encrypted_pem(&encrypted, b"wrong")
        .err()
        .unwrap();
    assert!(error.to_string().contains("invalid encrypted PKCS#8"));
}

#[test]
#[cfg(feature = "encrypted-keys")]
fn encrypted_private_keys_can_be_loaded_from_a_file() {
    let temporary = tempfile::tempdir().unwrap();
    let dalek = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let encrypted = encrypted_pem(&dalek, b"vault secret", 2);
    let path = temporary.path().join("private.pem");
    write(&path, &encrypted);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let loaded = SigningKey::from_pkcs8_pem_file_with_password(&path, b"vault secret").unwrap();
    assert_eq!(loaded.key_id(), key_id_for(&dalek));
}

fn key_pair(seed: u8) -> (SigningKey, TrustedKey) {
    let dalek = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let private_pem = pem("PRIVATE KEY", dalek.to_pkcs8_der().unwrap().as_bytes());
    let public_der = dalek.verifying_key().to_public_key_der().unwrap();
    let public_pem = pem("PUBLIC KEY", public_der.as_bytes());
    (
        SigningKey::from_pkcs8_pem(&private_pem).unwrap(),
        TrustedKey::from_spki_pem(&public_pem).unwrap(),
    )
}

#[cfg(feature = "encrypted-keys")]
fn key_id_for(key: &ed25519_dalek::SigningKey) -> String {
    let public_der = key.verifying_key().to_public_key_der().unwrap();
    let public_pem = pem("PUBLIC KEY", public_der.as_bytes());
    TrustedKey::from_spki_pem(&public_pem)
        .unwrap()
        .key_id()
        .to_string()
}

#[cfg(feature = "encrypted-keys")]
fn encrypted_pem(key: &ed25519_dalek::SigningKey, password: &[u8], seed: u8) -> String {
    let der = key.to_pkcs8_der().unwrap();
    let private_key = PrivateKeyInfoRef::try_from(der.as_bytes()).unwrap();
    let salt = [seed; 16];
    let iv = [seed.wrapping_add(1); 16];
    let parameters =
        pkcs8::pkcs5::pbes2::Parameters::generate_pbkdf2_sha256_aes256cbc(2, &salt, iv).unwrap();
    private_key
        .encrypt_with_params(parameters, password)
        .unwrap()
        .to_pem("ENCRYPTED PRIVATE KEY", LineEnding::LF)
        .unwrap()
        .to_string()
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

fn write(path: impl AsRef<Path>, contents: &str) {
    fs::write(path, contents).unwrap();
}

fn write_single_module(root: &Path, role: &str, policy: &str) -> PathBuf {
    write(root.join("policy.cedar"), policy);
    write(
        root.join("treetop-module.toml"),
        r#"
format_version = 1
name = "dns"
namespace = "ExampleCo::DNS"
policies = ["policy.cedar"]
"#,
    );
    let manifest = root.join("treetop-bundle.toml");
    write(
        &manifest,
        &format!(
            r#"
format_version = 1
name = "single"

[[modules]]
manifest = "treetop-module.toml"
role = {role:?}
"#
        ),
    );
    manifest
}

fn rewrite_entry(
    archive: &BundleArchive,
    target: &str,
    rewrite: impl FnOnce(&[u8]) -> Vec<u8>,
) -> BundleArchive {
    let mut decoder = GzDecoder::new(Cursor::new(archive.as_bytes()));
    let mut tar_bytes = Vec::new();
    decoder.read_to_end(&mut tar_bytes).unwrap();
    let mut input = Archive::new(Cursor::new(tar_bytes));
    let mut entries = Vec::new();
    let mut rewrite = Some(rewrite);
    for entry in input.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().into_owned();
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents).unwrap();
        if path == target {
            contents = rewrite.take().unwrap()(&contents);
        }
        entries.push((path, contents));
    }
    assert!(rewrite.is_none(), "target entry was not found");

    let mut rebuilt_tar = Vec::new();
    {
        let mut builder = Builder::new(&mut rebuilt_tar);
        for (path, contents) in entries {
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::Regular);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(contents.len() as u64);
            header.set_cksum();
            builder
                .append_data(&mut header, path, Cursor::new(contents))
                .unwrap();
        }
        builder.finish().unwrap();
    }
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    encoder.write_all(&rebuilt_tar).unwrap();
    BundleArchive::from_bytes(encoder.finish().unwrap())
}
