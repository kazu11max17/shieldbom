use thiserror::Error;

#[derive(Error, Debug)]
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

    #[error("Input file too large: {0} bytes (max 50 MB)")]
    InputTooLarge(u64),

    #[error("Too many components: {0} (max 100,000)")]
    TooManyComponents(usize),

    #[error("Potentially malicious XML: {0}")]
    MaliciousXml(String),
}
