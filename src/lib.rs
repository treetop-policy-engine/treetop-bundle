//! Compile, validate, sign, and load deterministic Treetop policy bundles.

mod archive;
mod builder;
mod diagnostic;
mod engine;
mod error;
mod labels;
mod manifest;
mod signing;
mod validation;

pub use archive::{ArchiveLimits, BundleArchive, ValidatedBundle, VerifiedSignature};
pub use builder::BundleBuilder;
pub use diagnostic::{Diagnostic, DiagnosticSeverity};
pub use engine::{PreparedEngine, PreparedEvaluationSession};
pub use error::{BundleError, Result};
pub use labels::{LabelPattern, LabelRule, LabelSet};
pub use manifest::{BundleManifest, ModuleManifest, ModuleRole, ModuleSelection};
pub use signing::{BundleSignature, SignaturePolicy, SigningKey, TrustStore, TrustedKey};
pub use validation::{PolicyCheck, check_module, check_policy};

/// The archive format emitted and accepted by this crate.
pub const FORMAT_VERSION: u32 = 1;

/// The exact Cedar version used to compile bundles.
pub const CEDAR_VERSION: &str = "4.12.0";

/// The exact Treetop core version used to prepare policy engines.
pub const TREETOP_CORE_VERSION: &str = "0.0.24";
