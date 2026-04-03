use anyhow::Result;
use serde::Deserialize;

use crate::models::{Component, Hash, ParsedSbom, SourceFormat};

/// CycloneDX JSON document structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxDocument {
    #[allow(dead_code)]
    bom_format: Option<String>,
    spec_version: Option<String>,
    #[serde(default)]
    components: Vec<CdxComponent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxComponent {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    supplier: Option<CdxSupplier>,
    #[serde(default)]
    purl: Option<String>,
    #[serde(default)]
    cpe: Option<String>,
    #[serde(default)]
    licenses: Vec<CdxLicenseChoice>,
    #[serde(default)]
    hashes: Vec<CdxHash>,
}

#[derive(Debug, Deserialize)]
struct CdxSupplier {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CdxLicenseChoice {
    license: Option<CdxLicense>,
    expression: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CdxLicense {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CdxHash {
    alg: Option<String>,
    content: Option<String>,
}

const MAX_SBOM_SIZE: usize = 50 * 1024 * 1024; // 50MB

pub fn parse_json(content: &str) -> Result<ParsedSbom> {
    if content.len() > MAX_SBOM_SIZE {
        return Err(crate::errors::ShieldBomError::ParseError(
            "SBOM file exceeds maximum size of 50MB".to_string(),
        )
        .into());
    }

    let doc: CdxDocument = serde_json::from_str(content)
        .map_err(|e| crate::errors::ShieldBomError::ParseError(format!("CycloneDX JSON: {e}")))?;

    let format = match doc.spec_version.as_deref() {
        Some("1.5") | Some("1.6") => SourceFormat::CycloneDx15Json,
        _ => SourceFormat::CycloneDx14Json,
    };

    let components = doc
        .components
        .into_iter()
        .map(|c| convert_cdx_component(c, format))
        .collect();

    Ok(ParsedSbom {
        format_detected: format,
        components,
    })
}

pub fn parse_xml(content: &str) -> Result<ParsedSbom> {
    // Security: quick-xml 0.36 does not support DTD processing or external entity
    // expansion, making it inherently safe against XXE and Billion Laughs attacks.
    // As defense-in-depth we also reject documents containing DOCTYPE declarations
    // and enforce a maximum input size.

    if content.len() > MAX_SBOM_SIZE {
        return Err(crate::errors::ShieldBomError::ParseError(
            "SBOM file exceeds maximum size of 50MB".to_string(),
        )
        .into());
    }

    // Defense-in-depth: reject any input that contains a DOCTYPE or ENTITY declaration.
    // Even though quick-xml ignores DTDs, blocking them outright prevents future
    // regressions or parser-swap surprises.
    fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
    }
    if contains_ci(content.as_bytes(), b"<!DOCTYPE") || contains_ci(content.as_bytes(), b"<!ENTITY")
    {
        return Err(crate::errors::ShieldBomError::ParseError(
            "XML DOCTYPE/ENTITY declarations are not allowed for security reasons".to_string(),
        )
        .into());
    }

    let doc: CdxXmlDocument = quick_xml::de::from_str(content)
        .map_err(|e| crate::errors::ShieldBomError::ParseError(format!("CycloneDX XML: {e}")))?;

    let format = match doc.spec_version.as_deref() {
        Some("1.5") | Some("1.6") => SourceFormat::CycloneDx15Xml,
        _ => SourceFormat::CycloneDx14Xml,
    };

    let components = doc
        .components
        .map(|c| c.component)
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let licenses = c
                .licenses
                .map(|l| l.license)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|l| l.id.or(l.name))
                .collect();

            Component {
                name: c.name,
                version: c.version.unwrap_or_default(),
                supplier: c.supplier.and_then(|s| s.name),
                cpe: c.cpe,
                purl: c.purl,
                licenses,
                hashes: Vec::new(),
                source_format: format,
            }
        })
        .collect();

    Ok(ParsedSbom {
        format_detected: format,
        components,
    })
}

fn convert_cdx_component(c: CdxComponent, format: SourceFormat) -> Component {
    let licenses: Vec<String> = c
        .licenses
        .into_iter()
        .filter_map(|lc| {
            if let Some(expr) = lc.expression {
                Some(expr)
            } else if let Some(lic) = lc.license {
                lic.id.or(lic.name)
            } else {
                None
            }
        })
        .collect();

    let hashes = c
        .hashes
        .into_iter()
        .filter_map(|h| {
            Some(Hash {
                algorithm: h.alg?,
                value: h.content?,
            })
        })
        .collect();

    Component {
        name: c.name,
        version: c.version.unwrap_or_default(),
        supplier: c.supplier.and_then(|s| s.name),
        cpe: c.cpe,
        purl: c.purl,
        licenses,
        hashes,
        source_format: format,
    }
}

// XML deserialization structs (quick-xml)
#[derive(Debug, Deserialize)]
#[serde(rename = "bom")]
struct CdxXmlDocument {
    #[serde(rename = "@specVersion")]
    spec_version: Option<String>,
    components: Option<CdxXmlComponents>,
}

#[derive(Debug, Deserialize)]
struct CdxXmlComponents {
    #[serde(default)]
    component: Vec<CdxXmlComponent>,
}

#[derive(Debug, Deserialize)]
struct CdxXmlComponent {
    #[serde(default)]
    name: String,
    version: Option<String>,
    supplier: Option<CdxXmlSupplier>,
    purl: Option<String>,
    cpe: Option<String>,
    licenses: Option<CdxXmlLicenses>,
}

#[derive(Debug, Deserialize)]
struct CdxXmlSupplier {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CdxXmlLicenses {
    #[serde(default)]
    license: Vec<CdxXmlLicense>,
}

#[derive(Debug, Deserialize)]
struct CdxXmlLicense {
    id: Option<String>,
    name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xml_rejects_doctype() {
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE bom [<!ENTITY xxe "test">]>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4">
  <components/>
</bom>"#;
        let err = parse_xml(xml).unwrap_err();
        assert!(err.to_string().contains("DOCTYPE/ENTITY"));
    }

    #[test]
    fn parse_xml_rejects_entity() {
        let xml = r#"<?xml version="1.0"?>
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<bom xmlns="http://cyclonedx.org/schema/bom/1.4">
  <components/>
</bom>"#;
        let err = parse_xml(xml).unwrap_err();
        assert!(err.to_string().contains("DOCTYPE/ENTITY"));
    }

    #[test]
    fn parse_xml_rejects_doctype_mixed_case() {
        let xml = "<!DocType foo><bom></bom>";
        let err = parse_xml(xml).unwrap_err();
        assert!(err.to_string().contains("DOCTYPE/ENTITY"));
    }

    #[test]
    fn parse_xml_rejects_oversized_input() {
        let big = "x".repeat(51 * 1024 * 1024);
        let err = parse_xml(&big).unwrap_err();
        assert!(err.to_string().contains("50MB"));
    }

    #[test]
    fn parse_json_rejects_oversized_input() {
        let big = "x".repeat(51 * 1024 * 1024);
        let err = parse_json(&big).unwrap_err();
        assert!(err.to_string().contains("50MB"));
    }
}
