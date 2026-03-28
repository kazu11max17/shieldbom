use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum ShieldBomError {
    #[error("Unsupported SBOM format: {0}")]
    UnsupportedFormat(String),

    #[error("Failed to parse SBOM: {0}")]
    ParseError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("File not found: {0}")]
    FileNotFound(String),
}
