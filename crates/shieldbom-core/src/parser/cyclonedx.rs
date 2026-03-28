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

pub fn parse_json(content: &str) -> Result<ParsedSbom> {
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
    // For XML, we use a simplified approach: deserialize via quick-xml
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
