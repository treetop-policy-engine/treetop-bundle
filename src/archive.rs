use crate::signing::{BundleSignature, SignaturePolicy, SigningKey, TrustStore};
use crate::validation::{BundleParts, ModuleRecord, validate_archive_parts};
use crate::{
    BundleError, CEDAR_VERSION, Diagnostic, FORMAT_VERSION, LabelSet, Result, TREETOP_CORE_VERSION,
};
use flate2::bufread::GzDecoder;
use flate2::{Compression, GzBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path};
use tar::{Archive, Builder, EntryType, Header};
use treetop_core::{LabelRegistryBuilder, PolicyEngine};

const MANIFEST_PATH: &str = "manifest.json";
const SIGNATURE_PATH: &str = "signature.json";
const POLICIES_PATH: &str = "policies.cedar";
const SCHEMA_PATH: &str = "schema.json";
const LABELS_PATH: &str = "labels.json";

/// Default and configured archive limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveLimits {
    max_compressed_bytes: usize,
    max_uncompressed_bytes: usize,
}

impl ArchiveLimits {
    pub const DEFAULT_MAX_COMPRESSED_BYTES: usize = 10 * 1024 * 1024;
    pub const DEFAULT_MAX_UNCOMPRESSED_BYTES: usize = 50 * 1024 * 1024;

    pub fn new(max_compressed_bytes: usize, max_uncompressed_bytes: usize) -> Result<Self> {
        if max_compressed_bytes == 0 || max_uncompressed_bytes == 0 {
            return Err(BundleError::Archive(
                "archive size limits must be greater than zero".to_string(),
            ));
        }
        Ok(Self {
            max_compressed_bytes,
            max_uncompressed_bytes,
        })
    }

    pub fn max_compressed_bytes(&self) -> usize {
        self.max_compressed_bytes
    }

    pub fn max_uncompressed_bytes(&self) -> usize {
        self.max_uncompressed_bytes
    }
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_compressed_bytes: Self::DEFAULT_MAX_COMPRESSED_BYTES,
            max_uncompressed_bytes: Self::DEFAULT_MAX_UNCOMPRESSED_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratorRecord {
    treetop_bundle: String,
    treetop_core: String,
    cedar: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactRecord {
    path: String,
    size: usize,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveManifest {
    format_version: u32,
    bundle_id: String,
    name: String,
    generator: GeneratorRecord,
    modules: Vec<ModuleRecord>,
    policy_ids: Vec<String>,
    artifacts: Vec<ArtifactRecord>,
}

/// Signature verification details for a validated bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedSignature {
    signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
}

impl VerifiedSignature {
    pub fn is_signed(&self) -> bool {
        self.signed
    }

    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }
}

/// A decoded bundle whose signatures, hashes, Cedar, schema, and labels are valid.
pub struct ValidatedBundle {
    format_version: u32,
    bundle_id: String,
    name: String,
    modules: Vec<ModuleRecord>,
    policies: String,
    schema_json: Option<Value>,
    labels: LabelSet,
    policy_ids: Vec<String>,
    diagnostics: Vec<Diagnostic>,
    archive_sha256: String,
    compressed_size: usize,
    signature: VerifiedSignature,
}

impl ValidatedBundle {
    pub fn format_version(&self) -> u32 {
        self.format_version
    }

    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    pub fn policies(&self) -> &str {
        &self.policies
    }

    pub fn schema_json(&self) -> Option<&Value> {
        self.schema_json.as_ref()
    }

    pub fn schema_json_string(&self) -> Result<Option<String>> {
        self.schema_json
            .as_ref()
            .map(canonical_json_bytes)
            .transpose()
            .and_then(|value| {
                value
                    .map(|bytes| {
                        String::from_utf8(bytes)
                            .map_err(|error| BundleError::Serialization(error.to_string()))
                    })
                    .transpose()
            })
    }

    pub fn labels(&self) -> &LabelSet {
        &self.labels
    }

    pub fn labels_json(&self) -> Result<String> {
        let bytes = canonical_json_bytes(&self.labels)?;
        String::from_utf8(bytes).map_err(|error| BundleError::Serialization(error.to_string()))
    }

    pub fn policy_ids(&self) -> &[String] {
        &self.policy_ids
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn archive_sha256(&self) -> &str {
        &self.archive_sha256
    }

    pub fn compressed_size(&self) -> usize {
        self.compressed_size
    }

    pub fn verified_signature(&self) -> &VerifiedSignature {
        &self.signature
    }

    /// Build a complete engine without modifying any application state.
    pub fn prepare_engine(&self) -> Result<PolicyEngine> {
        let mut engine = match &self.schema_json {
            Some(schema) => {
                let schema =
                    cedar_policy::Schema::from_json_value(schema.clone()).map_err(|error| {
                        BundleError::Validation(vec![Diagnostic::error(
                            "schema.aggregate_invalid",
                            error.to_string(),
                        )])
                    })?;
                PolicyEngine::new_from_str_with_schema(&self.policies, schema).map_err(|error| {
                    BundleError::Validation(vec![Diagnostic::error(
                        "policy.engine_prepare",
                        error.to_string(),
                    )])
                })?
            }
            None => PolicyEngine::new_from_str(&self.policies).map_err(|error| {
                BundleError::Validation(vec![Diagnostic::error(
                    "policy.engine_prepare",
                    error.to_string(),
                )])
            })?,
        };
        let labelers = self.labels.to_labelers();
        if !labelers.is_empty() {
            let mut builder = LabelRegistryBuilder::new();
            for labeler in labelers {
                builder = builder.add_labeler(labeler);
            }
            engine = engine.with_label_registry(builder.build());
        }
        Ok(engine)
    }
}

/// An in-memory gzip-compressed Treetop bundle archive.
#[derive(Debug, Clone)]
pub struct BundleArchive {
    bytes: Vec<u8>,
}

impl BundleArchive {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn read(path: impl AsRef<Path>, max_compressed_bytes: usize) -> Result<Self> {
        let path = path.as_ref();
        let metadata = fs::metadata(path).map_err(|error| BundleError::io(path, error))?;
        if metadata.len() > max_compressed_bytes as u64 {
            return Err(BundleError::SizeLimit {
                kind: "compressed",
                limit: max_compressed_bytes,
            });
        }
        let bytes = fs::read(path).map_err(|error| BundleError::io(path, error))?;
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn sha256(&self) -> String {
        sha256_hex(&self.bytes)
    }

    pub fn validate(
        &self,
        signature_policy: SignaturePolicy,
        trust_store: &TrustStore,
        limits: ArchiveLimits,
    ) -> Result<ValidatedBundle> {
        self.validate_inner(signature_policy, trust_store, limits, true)
    }

    /// Validate and re-sign an archive, replacing its existing signature.
    pub fn resign(&self, key: &SigningKey, limits: ArchiveLimits) -> Result<Self> {
        let decoded = decode_archive(&self.bytes, limits)?;
        let (manifest, _, _) = validate_decoded(
            &decoded,
            SignaturePolicy::AllowUnsigned,
            &TrustStore::new(),
            false,
        )?;
        let signature = key.sign_manifest(&decoded.manifest);
        let signature_bytes = canonical_json_bytes(&signature)?;
        let artifacts = artifact_entries(&decoded);
        let bytes = encode_archive(&decoded.manifest, Some(&signature_bytes), &artifacts)?;
        let rebuilt = Self { bytes };

        // Preserve the logical identity by construction and guard it explicitly.
        let rebuilt_decoded = decode_archive(&rebuilt.bytes, limits)?;
        let rebuilt_manifest: ArchiveManifest =
            parse_json(MANIFEST_PATH, &rebuilt_decoded.manifest)?;
        if rebuilt_manifest.bundle_id != manifest.bundle_id {
            return Err(BundleError::Archive(
                "re-signing changed the logical bundle ID".to_string(),
            ));
        }
        Ok(rebuilt)
    }

    fn validate_inner(
        &self,
        signature_policy: SignaturePolicy,
        trust_store: &TrustStore,
        limits: ArchiveLimits,
        verify_signature: bool,
    ) -> Result<ValidatedBundle> {
        let decoded = decode_archive(&self.bytes, limits)?;
        let (manifest, signature, parts) =
            validate_decoded(&decoded, signature_policy, trust_store, verify_signature)?;
        Ok(ValidatedBundle {
            format_version: manifest.format_version,
            bundle_id: manifest.bundle_id,
            name: parts.name,
            modules: parts.modules,
            policies: parts.policies,
            schema_json: parts.schema_json,
            labels: parts.labels,
            policy_ids: parts.policy_ids,
            diagnostics: parts.diagnostics,
            archive_sha256: sha256_hex(&self.bytes),
            compressed_size: self.bytes.len(),
            signature,
        })
    }

    pub(crate) fn build(parts: BundleParts, key: Option<&SigningKey>) -> Result<Self> {
        let policies = parts.policies.as_bytes().to_vec();
        let schema = parts
            .schema_json
            .as_ref()
            .map(canonical_json_bytes)
            .transpose()?;
        let labels = canonical_json_bytes(&parts.labels)?;

        let mut artifact_data = vec![(POLICIES_PATH.to_string(), policies)];
        if let Some(schema) = schema {
            artifact_data.push((SCHEMA_PATH.to_string(), schema));
        }
        artifact_data.push((LABELS_PATH.to_string(), labels));
        let artifacts = artifact_data
            .iter()
            .map(|(path, bytes)| ArtifactRecord {
                path: path.clone(),
                size: bytes.len(),
                sha256: sha256_hex(bytes),
            })
            .collect();
        let mut manifest = ArchiveManifest {
            format_version: FORMAT_VERSION,
            bundle_id: String::new(),
            name: parts.name,
            generator: GeneratorRecord {
                treetop_bundle: env!("CARGO_PKG_VERSION").to_string(),
                treetop_core: TREETOP_CORE_VERSION.to_string(),
                cedar: CEDAR_VERSION.to_string(),
            },
            modules: parts.modules,
            policy_ids: parts.policy_ids,
            artifacts,
        };
        manifest.bundle_id = compute_bundle_id(&manifest)?;
        let manifest_bytes = canonical_json_bytes(&manifest)?;
        let signature_bytes = key
            .map(|key| canonical_json_bytes(&key.sign_manifest(&manifest_bytes)))
            .transpose()?;
        let bytes = encode_archive(&manifest_bytes, signature_bytes.as_deref(), &artifact_data)?;
        Ok(Self { bytes })
    }
}

struct DecodedArchive {
    manifest: Vec<u8>,
    signature: Option<Vec<u8>>,
    policies: Vec<u8>,
    schema: Option<Vec<u8>>,
    labels: Vec<u8>,
}

fn decode_archive(bytes: &[u8], limits: ArchiveLimits) -> Result<DecodedArchive> {
    if bytes.len() > limits.max_compressed_bytes {
        return Err(BundleError::SizeLimit {
            kind: "compressed",
            limit: limits.max_compressed_bytes,
        });
    }
    let cursor = Cursor::new(bytes);
    let mut decoder = GzDecoder::new(cursor);
    let mut uncompressed = Vec::new();
    decoder
        .by_ref()
        .take((limits.max_uncompressed_bytes as u64) + 1)
        .read_to_end(&mut uncompressed)
        .map_err(|error| BundleError::Archive(format!("gzip decoding failed: {error}")))?;
    if uncompressed.len() > limits.max_uncompressed_bytes {
        return Err(BundleError::SizeLimit {
            kind: "uncompressed",
            limit: limits.max_uncompressed_bytes,
        });
    }
    let cursor = decoder.into_inner();
    if cursor.position() != bytes.len() as u64 {
        return Err(BundleError::Archive(
            "concatenated gzip members or trailing bytes are not allowed".to_string(),
        ));
    }

    let mut archive = Archive::new(Cursor::new(uncompressed));
    let mut entries = Vec::new();
    let archive_entries = archive
        .entries()
        .map_err(|error| BundleError::Archive(format!("tar decoding failed: {error}")))?;
    for entry in archive_entries {
        let mut entry = entry
            .map_err(|error| BundleError::Archive(format!("tar entry is invalid: {error}")))?;
        if entries.len() == 5 {
            return Err(BundleError::Archive(
                "bundle archive contains more than five entries".to_string(),
            ));
        }
        if entry.header().entry_type() != EntryType::Regular {
            return Err(BundleError::Archive(
                "only regular tar entries are allowed".to_string(),
            ));
        }
        let path = entry
            .path()
            .map_err(|error| BundleError::Archive(format!("invalid tar path: {error}")))?
            .into_owned();
        if path.is_absolute()
            || path.components().count() != 1
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(BundleError::Archive(format!(
                "unsafe tar entry path {}",
                path.display()
            )));
        }
        let name = path
            .to_str()
            .ok_or_else(|| BundleError::Archive("tar path is not UTF-8".to_string()))?
            .to_string();
        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .map_err(|error| BundleError::Archive(format!("cannot read tar entry: {error}")))?;
        entries.push((name, contents));
    }

    let names = entries
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();
    let valid = matches!(
        names.as_slice(),
        [MANIFEST_PATH, POLICIES_PATH, LABELS_PATH]
            | [MANIFEST_PATH, POLICIES_PATH, SCHEMA_PATH, LABELS_PATH]
            | [MANIFEST_PATH, SIGNATURE_PATH, POLICIES_PATH, LABELS_PATH]
            | [
                MANIFEST_PATH,
                SIGNATURE_PATH,
                POLICIES_PATH,
                SCHEMA_PATH,
                LABELS_PATH
            ]
    );
    if !valid {
        return Err(BundleError::Archive(format!(
            "archive entries are missing, unknown, duplicated, or out of order: {names:?}"
        )));
    }

    let mut by_name = entries
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    Ok(DecodedArchive {
        manifest: by_name
            .remove(MANIFEST_PATH)
            .expect("validated entry order includes manifest"),
        signature: by_name.remove(SIGNATURE_PATH),
        policies: by_name
            .remove(POLICIES_PATH)
            .expect("validated entry order includes policies"),
        schema: by_name.remove(SCHEMA_PATH),
        labels: by_name
            .remove(LABELS_PATH)
            .expect("validated entry order includes labels"),
    })
}

fn validate_decoded(
    decoded: &DecodedArchive,
    signature_policy: SignaturePolicy,
    trust_store: &TrustStore,
    verify_signature: bool,
) -> Result<(ArchiveManifest, VerifiedSignature, BundleParts)> {
    let manifest: ArchiveManifest = parse_json(MANIFEST_PATH, &decoded.manifest)?;
    let signature: Option<BundleSignature> = decoded
        .signature
        .as_ref()
        .map(|bytes| parse_json(SIGNATURE_PATH, bytes))
        .transpose()?;
    if let Some(signature) = &signature {
        signature.validate_format()?;
    }

    let verified_signature = match signature {
        Some(signature) if verify_signature => VerifiedSignature {
            signed: true,
            key_id: Some(trust_store.verify(&decoded.manifest, &signature)?),
        },
        Some(signature) => VerifiedSignature {
            signed: true,
            key_id: Some(signature.key_id().to_string()),
        },
        None if signature_policy == SignaturePolicy::Required => {
            return Err(BundleError::Archive("signature_missing".to_string()));
        }
        None => VerifiedSignature {
            signed: false,
            key_id: None,
        },
    };

    validate_manifest(&manifest)?;

    let expected = artifact_entries(decoded);
    if manifest.artifacts.len() != expected.len() {
        return Err(BundleError::Archive(
            "manifest artifact list does not match archive entries".to_string(),
        ));
    }
    for (record, (path, contents)) in manifest.artifacts.iter().zip(&expected) {
        if record.path != *path
            || record.size != contents.len()
            || record.sha256 != sha256_hex(contents)
        {
            return Err(BundleError::Archive(format!(
                "artifact hash or size mismatch for {path}"
            )));
        }
    }
    if manifest.bundle_id != compute_bundle_id(&manifest)? {
        return Err(BundleError::Archive(
            "manifest bundle_id does not match its canonical payload".to_string(),
        ));
    }

    let policies = utf8(POLICIES_PATH, &decoded.policies)?;
    let schema_json = decoded
        .schema
        .as_ref()
        .map(|bytes| parse_json(SCHEMA_PATH, bytes))
        .transpose()?;
    let labels_source = utf8(LABELS_PATH, &decoded.labels)?;
    let labels = LabelSet::from_json_str(&labels_source)?;
    let parts = validate_archive_parts(
        manifest.name.clone(),
        manifest.modules.clone(),
        policies,
        schema_json,
        labels,
        &manifest.policy_ids,
    )?;
    Ok((manifest, verified_signature, parts))
}

fn validate_manifest(manifest: &ArchiveManifest) -> Result<()> {
    if manifest.format_version != FORMAT_VERSION {
        return Err(BundleError::Archive(format!(
            "unsupported bundle format version {}",
            manifest.format_version
        )));
    }
    if manifest.name.trim().is_empty() {
        return Err(BundleError::Archive(
            "bundle manifest name must not be empty".to_string(),
        ));
    }
    if manifest.generator.treetop_bundle != env!("CARGO_PKG_VERSION")
        || manifest.generator.treetop_core != TREETOP_CORE_VERSION
        || manifest.generator.cedar != CEDAR_VERSION
    {
        return Err(BundleError::Archive(
            "bundle generator dependency versions are unsupported".to_string(),
        ));
    }
    let mut module_names = HashSet::new();
    let mut namespaces: Vec<&str> = Vec::new();
    let mut assigned_policy_ids = HashSet::new();
    if manifest.modules.is_empty() {
        return Err(BundleError::Archive(
            "manifest must contain at least one module".to_string(),
        ));
    }
    if !manifest
        .modules
        .windows(2)
        .all(|pair| pair[0].name < pair[1].name)
    {
        return Err(BundleError::Archive(
            "manifest modules are not ordered by name".to_string(),
        ));
    }
    if !manifest.policy_ids.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(BundleError::Archive(
            "manifest policy IDs must be sorted and unique".to_string(),
        ));
    }
    let selected_namespaces = manifest
        .modules
        .iter()
        .map(|module| module.namespace.as_str())
        .collect::<HashSet<_>>();
    for module in &manifest.modules {
        if module.name.trim().is_empty()
            || module.namespace.trim().is_empty()
            || module
                .namespace
                .parse::<cedar_policy::EntityTypeName>()
                .is_err()
        {
            return Err(BundleError::Archive(
                "manifest contains an invalid module name or namespace".to_string(),
            ));
        }
        if !module_names.insert(module.name.as_str()) {
            return Err(BundleError::Archive(
                "manifest contains duplicate module names".to_string(),
            ));
        }
        for existing in &namespaces {
            if crate::manifest::namespace_owns(existing, &module.namespace)
                || crate::manifest::namespace_owns(&module.namespace, existing)
            {
                return Err(BundleError::Archive(
                    "manifest contains overlapping module namespaces".to_string(),
                ));
            }
        }
        namespaces.push(module.namespace.as_str());
        let mut imports = HashSet::new();
        if module.imports.iter().any(|import| {
            !selected_namespaces.contains(import.as_str())
                || import == &module.namespace
                || !imports.insert(import)
        }) {
            return Err(BundleError::Archive(
                "manifest contains an unresolved, self, or duplicate module import".to_string(),
            ));
        }
        if module
            .policy_ids
            .iter()
            .any(|policy_id| !assigned_policy_ids.insert(policy_id.as_str()))
        {
            return Err(BundleError::Archive(
                "manifest assigns a policy ID more than once".to_string(),
            ));
        }
    }
    if assigned_policy_ids
        != manifest
            .policy_ids
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>()
    {
        return Err(BundleError::Archive(
            "manifest module policy assignments do not match policy_ids".to_string(),
        ));
    }
    Ok(())
}

fn artifact_entries(decoded: &DecodedArchive) -> Vec<(String, Vec<u8>)> {
    let mut entries = vec![(POLICIES_PATH.to_string(), decoded.policies.clone())];
    if let Some(schema) = &decoded.schema {
        entries.push((SCHEMA_PATH.to_string(), schema.clone()));
    }
    entries.push((LABELS_PATH.to_string(), decoded.labels.clone()));
    entries
}

fn encode_archive(
    manifest: &[u8],
    signature: Option<&[u8]>,
    artifacts: &[(String, Vec<u8>)],
) -> Result<Vec<u8>> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_bytes);
        append_tar_file(&mut builder, MANIFEST_PATH, manifest)?;
        if let Some(signature) = signature {
            append_tar_file(&mut builder, SIGNATURE_PATH, signature)?;
        }
        for (path, contents) in artifacts {
            append_tar_file(&mut builder, path, contents)?;
        }
        builder
            .finish()
            .map_err(|error| BundleError::Archive(format!("tar encoding failed: {error}")))?;
    }
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    encoder
        .write_all(&tar_bytes)
        .map_err(|error| BundleError::Archive(format!("gzip encoding failed: {error}")))?;
    encoder
        .finish()
        .map_err(|error| BundleError::Archive(format!("gzip encoding failed: {error}")))
}

fn append_tar_file(builder: &mut Builder<&mut Vec<u8>>, path: &str, contents: &[u8]) -> Result<()> {
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
        .map_err(|error| BundleError::Archive(format!("tar encoding failed: {error}")))
}

fn compute_bundle_id(manifest: &ArchiveManifest) -> Result<String> {
    let mut payload = serde_json::to_value(manifest)
        .map_err(|error| BundleError::Serialization(error.to_string()))?;
    payload
        .as_object_mut()
        .expect("ArchiveManifest always serializes as an object")
        .remove("bundle_id");
    Ok(sha256_hex(&canonical_json_bytes(&payload)?))
}

pub(crate) fn canonical_json_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)
        .map_err(|error| BundleError::Serialization(error.to_string()))?;
    let value = sort_json(value);
    let mut bytes = serde_json::to_vec(&value)
        .map_err(|error| BundleError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted = object
                .into_iter()
                .map(|(key, value)| (key, sort_json(value)))
                .collect::<std::collections::BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect::<Map<_, _>>())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        other => other,
    }
}

fn parse_json<T: for<'de> Deserialize<'de>>(path: &str, bytes: &[u8]) -> Result<T> {
    let source = std::str::from_utf8(bytes)
        .map_err(|error| BundleError::Archive(format!("{path} is not UTF-8: {error}")))?;
    serde_json::from_str(source)
        .map_err(|error| BundleError::Archive(format!("{path} is invalid JSON: {error}")))
}

fn utf8(path: &str, bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec())
        .map_err(|error| BundleError::Archive(format!("{path} is not UTF-8: {error}")))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
