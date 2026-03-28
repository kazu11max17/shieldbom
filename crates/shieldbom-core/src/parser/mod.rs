mod cyclonedx;
mod spdx;

use std::path::Path;

use anyhow::{Context, Result};

use crate::errors::ShieldBomError;
use crate::models::{ParsedSbom, SourceFormat};

/// Parse an SBOM file, auto-detecting format
pub fn parse_sbom(path: &Path) -> Result<ParsedSbom> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;

    let format = detect_format(path, &content)?;

    match format {
        SourceFormat::Spdx23Json => spdx::parse_json(&content),
        SourceFormat::Spdx23TagValue => spdx::parse_tag_value(&content),
        SourceFormat::CycloneDx14Json | SourceFormat::CycloneDx15Json => {
            cyclonedx::parse_json(&content)
        }
        SourceFormat::CycloneDx14Xml | SourceFormat::CycloneDx15Xml => {
            cyclonedx::parse_xml(&content)
        }
        _ => Err(ShieldBomError::UnsupportedFormat(format.to_string()).into()),
    }
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
