mod cyclonedx;
mod spdx;

use std::path::Path;

use anyhow::{Context, Result};

use crate::errors::ShieldBomError;
use crate::models::{ParsedSbom, SourceFormat};

/// Maximum allowed file size: 50 MB.
const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024;

/// Maximum number of components allowed in a single SBOM.
const MAX_COMPONENT_COUNT: usize = 100_000;

/// Parse an SBOM file, auto-detecting format
pub fn parse_sbom(path: &Path) -> Result<ParsedSbom> {
    // Check file size before reading into memory
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to read metadata: {}", path.display()))?;
    if metadata.len() > MAX_FILE_SIZE {
        return Err(ShieldBomError::InputTooLarge(metadata.len()).into());
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;

    let format = detect_format(path, &content)?;

    let sbom = match format {
        SourceFormat::Spdx23Json => spdx::parse_json(&content),
        SourceFormat::Spdx23TagValue => spdx::parse_tag_value(&content),
        SourceFormat::CycloneDx14Json | SourceFormat::CycloneDx15Json => {
            cyclonedx::parse_json(&content)
        }
        SourceFormat::CycloneDx14Xml | SourceFormat::CycloneDx15Xml => {
            cyclonedx::parse_xml(&content)
        }
        _ => Err(ShieldBomError::UnsupportedFormat(format.to_string()).into()),
    }?;

    // Validate component count after parsing
    if sbom.components.len() > MAX_COMPONENT_COUNT {
        return Err(ShieldBomError::TooManyComponents(sbom.components.len()).into());
    }

    Ok(sbom)
}

/// Sanitize a component name by removing path traversal sequences.
///
/// - Removes `../` and `..\` sequences (looped until stable to prevent bypass via `....//`)
/// - Strips leading `/` or `\`
pub fn sanitize_component_name(name: &str) -> String {
    let mut result = name.to_string();
    // Loop until no more traversal sequences remain (prevents bypass patterns like `....//`)
    loop {
        let next = result.replace("../", "").replace("..\\", "");
        if next == result {
            break;
        }
        result = next;
    }
    // Strip leading path separators
    while result.starts_with('/') || result.starts_with('\\') {
        result = result[1..].to_string();
    }
    result
}

fn detect_format(path: &Path, content: &str) -> Result<SourceFormat> {
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Try by file extension first
    if filename.ends_with(".spdx.json") {
        return Ok(SourceFormat::Spdx23Json);
    }
    if filename.ends_with(".spdx") || filename.ends_with(".spdx.tv") {
        return Ok(SourceFormat::Spdx23TagValue);
    }
    if filename.ends_with(".cdx.json") || filename.ends_with(".bom.json") {
        return Ok(detect_cdx_json_version(content));
    }
    if filename.ends_with(".cdx.xml") || filename.ends_with(".bom.xml") {
        return Ok(detect_cdx_xml_version(content));
    }

    // Try content-based detection
    let trimmed = content.trim_start();
    if trimmed.starts_with('{') {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if value.get("spdxVersion").is_some() {
                return Ok(SourceFormat::Spdx23Json);
            }
            if value.get("bomFormat").is_some() {
                return Ok(detect_cdx_json_version(content));
            }
        }
    }

    if trimmed.starts_with("SPDXVersion:") {
        return Ok(SourceFormat::Spdx23TagValue);
    }

    if trimmed.starts_with('<') && trimmed.contains("cyclonedx") {
        return Ok(detect_cdx_xml_version(content));
    }

    Err(ShieldBomError::UnsupportedFormat(format!(
        "Could not detect format for: {}",
        path.display()
    ))
    .into())
}

fn detect_cdx_json_version(content: &str) -> SourceFormat {
    if content.contains("\"specVersion\"")
        && (content.contains("\"1.5\"") || content.contains("\"1.6\""))
    {
        return SourceFormat::CycloneDx15Json;
    }
    SourceFormat::CycloneDx14Json
}

fn detect_cdx_xml_version(content: &str) -> SourceFormat {
    if content.contains("specVersion=\"1.5\"") || content.contains("specVersion=\"1.6\"") {
        return SourceFormat::CycloneDx15Xml;
    }
    SourceFormat::CycloneDx14Xml
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_component_name_removes_traversal() {
        assert_eq!(sanitize_component_name("../etc/passwd"), "etc/passwd");
        assert_eq!(
            sanitize_component_name("..\\windows\\system32"),
            "windows\\system32"
        );
        assert_eq!(sanitize_component_name("foo/../bar"), "foo/bar");
        assert_eq!(sanitize_component_name("/absolute/path"), "absolute/path");
        assert_eq!(sanitize_component_name("\\\\unc\\share"), "unc\\share");
    }

    #[test]
    fn test_sanitize_component_name_bypass_patterns() {
        // `....//` collapses to `../` after first pass — loop prevents bypass
        assert_eq!(sanitize_component_name("....//etc/passwd"), "etc/passwd");
        // `..././` similarly collapses
        assert_eq!(sanitize_component_name("..././etc/passwd"), "etc/passwd");
        // Deeply nested bypass attempt
        assert_eq!(
            sanitize_component_name("....//....//....//etc/passwd"),
            "etc/passwd"
        );
    }

    #[test]
    fn test_sanitize_component_name_preserves_normal() {
        assert_eq!(sanitize_component_name("openssl"), "openssl");
        assert_eq!(sanitize_component_name("my-package"), "my-package");
        assert_eq!(
            sanitize_component_name("org.apache.log4j"),
            "org.apache.log4j"
        );
    }
}
