use crate::Diagnostic;
use std::path::PathBuf;

/// Errors produced while compiling or decoding a bundle.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BundleError {
    /// The input was readable but failed content validation.
    #[error("bundle validation failed")]
    Validation(Vec<Diagnostic>),
    /// A manifest could not be decoded.
    #[error("failed to parse manifest {path}: {message}")]
    Manifest { path: PathBuf, message: String },
    /// JSON input could not be decoded.
    #[error("failed to parse JSON {path}: {message}")]
    Json { path: String, message: String },
    /// A filesystem operation failed.
    #[error("filesystem error for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A key could not be loaded or decoded.
    #[error("key error: {0}")]
    Key(String),
    /// Archive framing or structure is invalid.
    #[error("invalid bundle archive: {0}")]
    Archive(String),
    /// A configured size limit was exceeded.
    #[error("bundle {kind} size exceeds the configured limit of {limit} bytes")]
    SizeLimit { kind: &'static str, limit: usize },
    /// Serialization of an internally validated value failed.
    #[error("serialization failed: {0}")]
    Serialization(String),
}

impl BundleError {
    /// Whether this error represents invalid user-controlled bundle content.
    pub fn is_validation(&self) -> bool {
        matches!(
            self,
            Self::Validation(_)
                | Self::Manifest { .. }
                | Self::Json { .. }
                | Self::Archive(_)
                | Self::SizeLimit { .. }
        )
    }

    /// Return structured diagnostics when available.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        match self {
            Self::Validation(diagnostics) => diagnostics,
            _ => &[],
        }
    }

    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, BundleError>;
