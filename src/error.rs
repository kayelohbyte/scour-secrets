//! Unified error types for the sanitization engine.
//!
//! All fallible operations in the crate return [`Result<T>`], which is an
//! alias for `std::result::Result<T, SanitizeError>`.
//!
//! Errors are categorised by subsystem (`IoError`, `SecretsError`,
//! `ArchiveError`, …) so callers can match on the variant to decide
//! whether to retry, skip, or abort. The [`thiserror`] derive keeps
//! display messages actionable and grep-friendly.

use thiserror::Error;

/// All errors that can occur within the sanitization engine.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SanitizeError {
    #[error("replacement store capacity exceeded: {current} mappings (limit: {limit})")]
    CapacityExceeded { current: usize, limit: usize },

    #[error("invalid seed length: expected 32 bytes, got {0}")]
    InvalidSeedLength(usize),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("parse error ({format}): {message}")]
    ParseError { format: String, message: String },

    #[error("recursion depth exceeded: {0}")]
    RecursionDepthExceeded(String),

    #[error("input too large: {size} bytes (limit: {limit})")]
    InputTooLarge { size: usize, limit: usize },

    #[error("pattern compilation error: {0}")]
    PatternCompileError(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("secrets: empty password")]
    SecretsEmptyPassword,

    #[error("secrets: encrypted file too short (corrupt or truncated)")]
    SecretsTooShort,

    #[error("secrets: not a recognized encrypted secrets file (bad magic or unsupported version)")]
    SecretsUnrecognizedFormat,

    #[error("secrets: decryption failed — wrong password or corrupted file")]
    SecretsDecryptFailed,

    #[error("secrets: cipher error: {0}")]
    SecretsCipherError(String),

    #[error("secrets: {format} error: {message}")]
    SecretsFormatError { format: String, message: String },

    #[error("secrets: invalid UTF-8: {0}")]
    SecretsInvalidUtf8(String),

    #[error("secrets: no password provided — file appears encrypted but --encrypted-secrets was not specified")]
    SecretsPasswordRequired,

    #[error("archive error: {0}")]
    ArchiveError(String),
}

pub type Result<T> = std::result::Result<T, SanitizeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_io_error_wraps_message() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = SanitizeError::from(io_err);
        assert!(matches!(err, SanitizeError::IoError(_)));
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn io_error_exposes_kind() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        if let SanitizeError::IoError(inner) = SanitizeError::from(io_err) {
            assert_eq!(inner.kind(), std::io::ErrorKind::PermissionDenied);
        } else {
            panic!("expected IoError");
        }
    }

    #[test]
    fn display_variants_are_actionable() {
        assert!(SanitizeError::CapacityExceeded {
            current: 5,
            limit: 3
        }
        .to_string()
        .contains('5'));
        assert!(SanitizeError::InputTooLarge {
            size: 100,
            limit: 50
        }
        .to_string()
        .contains("100"));
        assert!(SanitizeError::RecursionDepthExceeded("too deep".into())
            .to_string()
            .contains("too deep"));
        assert!(SanitizeError::SecretsEmptyPassword
            .to_string()
            .contains("empty"));
        assert!(SanitizeError::SecretsDecryptFailed
            .to_string()
            .contains("wrong password"));
    }
}
