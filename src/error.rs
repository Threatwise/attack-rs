//! Error types for ATT&CK operations
//!
//! This module provides comprehensive error handling for ATT&CK operations
//! including loading, validation, and parsing.

use thiserror::Error;

/// Main error type for ATT&CK operations
#[derive(Debug, Error)]
pub enum AttackError {
    /// I/O error when reading files
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// JSON serialization/deserialization error
    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Network error when fetching remote data
    #[error("network error: {0}")]
    NetworkError(#[from] reqwest::Error),

    /// Invalid ATT&CK ID format
    #[error("invalid ATT&CK ID: {0}")]
    InvalidId(String),

    /// Missing required field
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Object not found
    #[error("object not found: {0}")]
    NotFound(String),

    /// Validation error
    #[error("validation error: {0}")]
    ValidationError(String),
}

/// Specialized Result type for ATT&CK operations
pub type Result<T> = std::result::Result<T, AttackError>;
