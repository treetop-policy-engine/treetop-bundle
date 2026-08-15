use crate::validation::compile_manifest;
use crate::{
    BundleArchive, BundleError, BundleManifest, DiagnosticSeverity, PolicyCheck, Result, SigningKey,
};
use std::path::Path;

/// Compiler entry point for an organization bundle manifest.
pub struct BundleBuilder {
    manifest: BundleManifest,
    deny_warnings: bool,
}

impl BundleBuilder {
    pub fn from_manifest(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            manifest: BundleManifest::from_path(path)?,
            deny_warnings: false,
        })
    }

    pub fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }

    pub fn deny_warnings(mut self, deny: bool) -> Self {
        self.deny_warnings = deny;
        self
    }

    /// Validate the complete source bundle without emitting an archive.
    pub fn check(&self) -> Result<PolicyCheck> {
        let parts = compile_manifest(&self.manifest)?;
        if self.deny_warnings
            && parts
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Warning)
        {
            return Err(BundleError::Validation(parts.diagnostics));
        }
        Ok(PolicyCheck {
            diagnostics: parts.diagnostics,
        })
    }

    /// Validate and compile a deterministic archive, optionally signing it.
    pub fn build(&self, signing_key: Option<&SigningKey>) -> Result<BundleArchive> {
        let parts = compile_manifest(&self.manifest)?;
        if self.deny_warnings
            && parts
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Warning)
        {
            return Err(BundleError::Validation(parts.diagnostics));
        }
        BundleArchive::build(parts, signing_key)
    }
}
