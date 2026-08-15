use crate::{BundleError, FORMAT_VERSION, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::str::FromStr;

const SIGNATURE_DOMAIN: &[u8] = b"treetop-bundle-signature-v1\0";

/// Signature requirements applied while opening an archive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignaturePolicy {
    #[default]
    AllowUnsigned,
    Required,
}

impl FromStr for SignaturePolicy {
    type Err = BundleError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "allow-unsigned" => Ok(Self::AllowUnsigned),
            "required" => Ok(Self::Required),
            _ => Err(BundleError::Key(format!(
                "unknown signature policy {value:?}; expected allow-unsigned or required"
            ))),
        }
    }
}

/// Detached signature metadata stored in `signature.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSignature {
    format_version: u32,
    algorithm: String,
    key_id: String,
    signature: String,
}

impl BundleSignature {
    pub fn format_version(&self) -> u32 {
        self.format_version
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }

    pub(crate) fn validate_format(&self) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            return Err(BundleError::Archive(format!(
                "unsupported signature format version {}",
                self.format_version
            )));
        }
        if self.algorithm != "ed25519" {
            return Err(BundleError::Archive(format!(
                "unsupported signature algorithm {:?}",
                self.algorithm
            )));
        }
        let decoded = STANDARD.decode(&self.signature).map_err(|error| {
            BundleError::Archive(format!("signature is not standard base64: {error}"))
        })?;
        Signature::from_slice(&decoded).map_err(|error| {
            BundleError::Archive(format!("malformed Ed25519 signature: {error}"))
        })?;
        Ok(())
    }
}

/// An Ed25519 private signing key loaded from unencrypted PKCS#8 PEM.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// Load a private key and, on Unix, reject group/other-accessible files.
    pub fn from_pkcs8_pem_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let metadata = fs::metadata(path).map_err(|error| BundleError::io(path, error))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(BundleError::Key(format!(
                    "private key file {} is accessible by group or others",
                    path.display()
                )));
            }
        }
        let pem = fs::read_to_string(path).map_err(|error| BundleError::io(path, error))?;
        Self::from_pkcs8_pem(&pem)
    }

    /// Decode an unencrypted PKCS#8 PEM private key.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
            .map(Self)
            .map_err(|error| {
                BundleError::Key(format!("invalid PKCS#8 Ed25519 private key: {error}"))
            })
    }

    pub fn key_id(&self) -> String {
        key_id(&self.0.verifying_key())
    }

    pub(crate) fn sign_manifest(&self, manifest: &[u8]) -> BundleSignature {
        let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + manifest.len());
        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.extend_from_slice(manifest);
        let signature = self.0.sign(&message);
        BundleSignature {
            format_version: FORMAT_VERSION,
            algorithm: "ed25519".to_string(),
            key_id: self.key_id(),
            signature: STANDARD.encode(signature.to_bytes()),
        }
    }
}

/// A trusted Ed25519 public key loaded from SPKI PEM.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    key_id: String,
    key: VerifyingKey,
}

impl TrustedKey {
    pub fn from_spki_pem_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let pem = fs::read_to_string(path).map_err(|error| BundleError::io(path, error))?;
        Self::from_spki_pem(&pem)
    }

    pub fn from_spki_pem(pem: &str) -> Result<Self> {
        let key = VerifyingKey::from_public_key_pem(pem).map_err(|error| {
            BundleError::Key(format!("invalid SPKI Ed25519 public key: {error}"))
        })?;
        Ok(Self {
            key_id: key_id(&key),
            key,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    fn raw_key(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    fn verify(&self, manifest: &[u8], signature: &Signature) -> Result<()> {
        let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + manifest.len());
        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.extend_from_slice(manifest);
        self.key
            .verify(&message, signature)
            .map_err(|_| BundleError::Archive("invalid_signature".to_string()))
    }
}

/// Trusted public keys indexed by their content-derived key IDs.
#[derive(Debug, Clone, Default)]
pub struct TrustStore(BTreeMap<String, TrustedKey>);

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_keys(keys: impl IntoIterator<Item = TrustedKey>) -> Result<Self> {
        let mut store = Self::new();
        for key in keys {
            store.insert(key)?;
        }
        Ok(store)
    }

    pub fn insert(&mut self, key: TrustedKey) -> Result<()> {
        if let Some(existing) = self.0.get(key.key_id()) {
            if existing.raw_key() != key.raw_key() {
                return Err(BundleError::Key(format!(
                    "duplicate key ID {} has different public key bytes",
                    key.key_id()
                )));
            }
            return Ok(());
        }
        self.0.insert(key.key_id.clone(), key);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn verify(&self, manifest: &[u8], signature: &BundleSignature) -> Result<String> {
        signature.validate_format()?;
        let key = self
            .0
            .get(signature.key_id())
            .ok_or_else(|| BundleError::Archive("untrusted_key".to_string()))?;
        let bytes = STANDARD.decode(signature.signature()).map_err(|error| {
            BundleError::Archive(format!("signature is not standard base64: {error}"))
        })?;
        let signature = Signature::from_slice(&bytes).map_err(|error| {
            BundleError::Archive(format!("malformed Ed25519 signature: {error}"))
        })?;
        key.verify(manifest, &signature)?;
        Ok(key.key_id.clone())
    }
}

fn key_id(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.to_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
