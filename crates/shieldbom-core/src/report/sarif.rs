//! SARIF 2.1.0 (Static Analysis Results Interchange Format) output.
//!
//! Specification: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>
//! Schema: <https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json>

use std::collections::HashMap;

use anyhow::Result;
use serde::Serialize;

use super::truncate_str;
use crate::models::{AnalysisReport, Severity, VulnMatch};

const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const TOOL_NAME: &str = "ShieldBOM";
const TOOL_URI: &str = "https://github.com/kazu11max17/shieldbom";

/// Render an `AnalysisReport` as SARIF 2.1.0 JSON to stdout.
pub(super) fn render_sarif(report: &AnalysisReport) -> Result<()> {
    let sarif = SarifLog::from_analysis(report);
    let json = serde_json::to_string_pretty(&sarif)?;
    println!("{json}");
    Ok(())
}

/// Produce a SARIF JSON string from an `AnalysisReport` (useful for tests / programmatic use).
#[cfg(test)]
pub fn to_sarif_string(report: &AnalysisReport) -> Result<String> {
    let sarif = SarifLog::from_analysis(report);
    Ok(serde_json::to_string_pretty(&sarif)?)
}

// ---------------------------------------------------------------------------
// SARIF 2.1.0 data model
// ---------------------------------------------------------------------------

/// Top-level SARIF log object (sarifLog).
#[derive(Debug, Serialize, PartialEq)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

/// A single run of a tool.
#[derive(Debug, Serialize, PartialEq)]
struct SarifRun {
    tool: SarifTool,
    /// Artifacts (SBOM files) that were analysed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    artifacts: Vec<SarifArtifact>,
    results: Vec<SarifResult>,
    /// Run-level properties (disclaimer, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifRunPropertyBag>,
}

/// Property bag for run-level metadata.
#[derive(Debug, Serialize, PartialEq)]
struct SarifRunPropertyBag {
    disclaimer: String,
}

#[derive(Debug, Serialize, PartialEq)]
struct SarifTool {
    driver: SarifToolComponent,
}

/// The `toolComponent` object describing the driver.
#[derive(Debug, Serialize, PartialEq)]
struct SarifToolComponent {
    name: String,
    version: String,
    #[serde(rename = "semanticVersion")]
    semantic_version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<SarifReportingDescriptor>,
}

/// A `reportingDescriptor` – one per unique CVE/rule.
#[derive(Debug, Serialize, PartialEq)]
struct SarifReportingDescriptor {
    /// CVE ID (e.g. "CVE-2023-12345").
    id: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMultiformatMessageString,
    #[serde(rename = "fullDescription")]
    full_description: SarifMultiformatMessageString,
    /// Link to NVD/OSV detail page.
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    help_uri: Option<String>,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifReportingConfiguration,
    /// Custom properties (CVSS score, severity label, source).
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifPropertyBag>,
}

#[derive(Debug, Serialize, PartialEq)]
struct SarifReportingConfiguration {
    level: String,
}

#[derive(Debug, Serialize, PartialEq)]
struct SarifMultiformatMessageString {
    text: String,
}

/// A single result (finding).
#[derive(Debug, Serialize, PartialEq)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    /// Index into the `rules` array for this result.
    #[serde(rename = "ruleIndex")]
    rule_index: usize,
    level: String,
    message: SarifMessage,
    /// Where the issue was found (component as logical location).
    locations: Vec<SarifLocation>,
    /// Custom properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifPropertyBag>,
}

#[derive(Debug, Serialize, PartialEq)]
struct SarifMessage {
    text: String,
}

#[derive(Debug, Serialize, PartialEq)]
struct SarifLocation {
    #[serde(rename = "physicalLocation", skip_serializing_if = "Option::is_none")]
    physical_location: Option<SarifPhysicalLocation>,
    #[serde(rename = "logicalLocations", skip_serializing_if = "Vec::is_empty")]
    logical_locations: Vec<SarifLogicalLocation>,
}

#[derive(Debug, Serialize, PartialEq)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Serialize, PartialEq)]
struct SarifArtifactLocation {
    uri: String,
    #[serde(rename = "uriBaseId", skip_serializing_if = "Option::is_none")]
    uri_base_id: Option<String>,
}

/// Logical location — represents a component name/version.
#[derive(Debug, Serialize, PartialEq)]
struct SarifLogicalLocation {
    /// Fully-qualified logical name, e.g. "openssl@1.1.1k"
    #[serde(rename = "fullyQualifiedName")]
    fully_qualified_name: String,
    kind: String,
}

/// An artifact that was scanned (the SBOM file itself).
#[derive(Debug, Serialize, PartialEq)]
struct SarifArtifact {
    location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<SarifMultiformatMessageString>,
}

/// Generic property bag for extension data.
#[derive(Debug, Serialize, PartialEq)]
struct SarifPropertyBag {
    #[serde(rename = "cvssScore", skip_serializing_if = "Option::is_none")]
    cvss_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(rename = "affectedVersions", skip_serializing_if = "Option::is_none")]
    affected_versions: Option<String>,
    #[serde(rename = "fixedVersion", skip_serializing_if = "Option::is_none")]
    fixed_version: Option<String>,
    #[serde(rename = "componentName", skip_serializing_if = "Option::is_none")]
    component_name: Option<String>,
    #[serde(rename = "componentVersion", skip_serializing_if = "Option::is_none")]
    component_version: Option<String>,
}

// ---------------------------------------------------------------------------
// Conversion from AnalysisReport
// ---------------------------------------------------------------------------

fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::None | Severity::Unknown => "note",
    }
}

fn cve_help_uri(cve_id: &str) -> Option<String> {
    if cve_id.starts_with("CVE-") {
        Some(format!("https://nvd.nist.gov/vuln/detail/{cve_id}"))
    } else if cve_id.starts_with("GHSA-") {
        Some(format!("https://github.com/advisories/{cve_id}"))
    } else {
        None
    }
}

impl SarifLog {
    fn from_analysis(report: &AnalysisReport) -> Self {
        // De-duplicate rules by CVE ID.  Multiple VulnMatch entries can share
        // the same CVE (affecting different components), but SARIF expects one
        // rule per unique ID.
        let mut rule_index_map: HashMap<String, usize> = HashMap::new();
        let mut rules: Vec<SarifReportingDescriptor> = Vec::new();

        for vuln in &report.vulnerabilities {
            if rule_index_map.contains_key(&vuln.cve_id) {
                continue;
            }
            let idx = rules.len();
            rule_index_map.insert(vuln.cve_id.clone(), idx);

            let short = truncate_str(&vuln.description, 120);

            rules.push(SarifReportingDescriptor {
                id: vuln.cve_id.clone(),
                short_description: SarifMultiformatMessageString { text: short },
                full_description: SarifMultiformatMessageString {
                    text: vuln.description.clone(),
                },
                help_uri: cve_help_uri(&vuln.cve_id),
                default_configuration: SarifReportingConfiguration {
                    level: severity_to_sarif_level(&vuln.severity).to_string(),
                },
                properties: Some(SarifPropertyBag {
                    cvss_score: vuln.cvss_score,
                    severity: Some(vuln.severity.to_string()),
                    source: Some(vuln.source.to_string()),
                    affected_versions: None,
                    fixed_version: None,
                    component_name: None,
                    component_version: None,
                }),
            });
        }

        // Build results
        let results: Vec<SarifResult> = report
            .vulnerabilities
            .iter()
            .map(|vuln| build_result(vuln, &rule_index_map, report))
            .collect();

        // Artifact: the SBOM file that was scanned
        let sbom_uri = report.sbom_file.display().to_string();
        let artifacts = vec![SarifArtifact {
            location: SarifArtifactLocation {
                uri: sbom_uri.clone(),
                uri_base_id: None,
            },
            description: Some(SarifMultiformatMessageString {
                text: format!("{} SBOM file", report.format_detected),
            }),
        }];

        SarifLog {
            schema: SARIF_SCHEMA.to_string(),
            version: SARIF_VERSION.to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifToolComponent {
                        name: TOOL_NAME.to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        semantic_version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: TOOL_URI.to_string(),
                        rules,
                    },
                },
                artifacts,
                results,
                properties: Some(SarifRunPropertyBag {
                    disclaimer: report.disclaimer.clone(),
                }),
            }],
        }
    }
}

fn build_result(
    vuln: &VulnMatch,
    rule_index_map: &HashMap<String, usize>,
    report: &AnalysisReport,
) -> SarifResult {
    let rule_index = *rule_index_map.get(&vuln.cve_id).unwrap_or(&0);
    let level = severity_to_sarif_level(&vuln.severity);

    let message_text = if let Some(ref fixed) = vuln.fixed_version {
        format!(
            "{} affects {} @ {}. Upgrade to {} to fix.",
            vuln.cve_id, vuln.component_name, vuln.component_version, fixed
        )
    } else {
        format!(
            "{} affects {} @ {}.",
            vuln.cve_id, vuln.component_name, vuln.component_version
        )
    };

    // Physical location points to the SBOM file
    let sbom_uri = report.sbom_file.display().to_string();

    SarifResult {
        rule_id: vuln.cve_id.clone(),
        rule_index,
        level: level.to_string(),
        message: SarifMessage { text: message_text },
        locations: vec![SarifLocation {
            physical_location: Some(SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: sbom_uri,
                    uri_base_id: None,
                },
            }),
            logical_locations: vec![SarifLogicalLocation {
                fully_qualified_name: format!("{}@{}", vuln.component_name, vuln.component_version),
                kind: "module".to_string(),
            }],
        }],
        properties: Some(SarifPropertyBag {
            cvss_score: vuln.cvss_score,
            severity: Some(vuln.severity.to_string()),
            source: Some(vuln.source.to_string()),
            affected_versions: if vuln.affected_versions.display.is_empty() {
                None
            } else {
                Some(vuln.affected_versions.display.clone())
            },
            fixed_version: vuln.fixed_version.clone(),
            component_name: Some(vuln.component_name.clone()),
            component_version: Some(vuln.component_version.clone()),
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AffectedVersions, AnalysisReport, Component, Hash, Severity, SourceFormat,
        VersionRangeInfo, VulnMatch, VulnSource,
    };
    use std::path::PathBuf;

    fn sample_report(vulns: Vec<VulnMatch>) -> AnalysisReport {
        let components = vec![
            Component {
                name: "openssl".to_string(),
                version: "1.1.1k".to_string(),
                supplier: None,
                cpe: None,
                purl: Some("pkg:generic/openssl@1.1.1k".to_string()),
                licenses: vec!["Apache-2.0".to_string()],
                hashes: vec![Hash {
                    algorithm: "SHA-256".to_string(),
                    value: "abc123".to_string(),
                }],
                source_format: SourceFormat::Spdx23Json,
            },
            Component {
                name: "zlib".to_string(),
                version: "1.2.11".to_string(),
                supplier: None,
                cpe: None,
                purl: None,
                licenses: vec![],
                hashes: vec![],
                source_format: SourceFormat::Spdx23Json,
            },
        ];

        AnalysisReport::new(
            PathBuf::from("test.spdx.json"),
            SourceFormat::Spdx23Json,
            components,
            vulns,
            vec![],
        )
    }

    fn critical_vuln() -> VulnMatch {
        VulnMatch {
            component_name: "openssl".to_string(),
            component_version: "1.1.1k".to_string(),
            cve_id: "CVE-2021-3711".to_string(),
            severity: Severity::Critical,
            cvss_score: Some(9.8),
            source: VulnSource::Osv,
            affected_versions: AffectedVersions {
                display: "< 1.1.1l".to_string(),
                ranges: vec![VersionRangeInfo {
                    introduced: Some("0".to_string()),
                    fixed: Some("1.1.1l".to_string()),
                }],
            },
            fixed_version: Some("1.1.1l".to_string()),
            description: "SM2 decryption buffer overflow in OpenSSL".to_string(),
            in_kev: false,
            kev_due_date: None,
        }
    }

    fn medium_vuln() -> VulnMatch {
        VulnMatch {
            component_name: "zlib".to_string(),
            component_version: "1.2.11".to_string(),
            cve_id: "CVE-2022-37434".to_string(),
            severity: Severity::Medium,
            cvss_score: Some(5.5),
            source: VulnSource::Nvd,
            affected_versions: AffectedVersions {
                display: "< 1.2.12".to_string(),
                ranges: vec![VersionRangeInfo {
                    introduced: None,
                    fixed: Some("1.2.12".to_string()),
                }],
            },
            fixed_version: Some("1.2.12".to_string()),
            description: "Heap-based buffer over-read in zlib inflate".to_string(),
            in_kev: false,
            kev_due_date: None,
        }
    }

    #[test]
    fn sarif_schema_and_version() {
        let report = sample_report(vec![critical_vuln()]);
        let sarif = SarifLog::from_analysis(&report);

        assert_eq!(sarif.schema, SARIF_SCHEMA);
        assert_eq!(sarif.version, "2.1.0");
    }

    #[test]
    fn sarif_tool_driver() {
        let report = sample_report(vec![]);
        let sarif = SarifLog::from_analysis(&report);

        let driver = &sarif.runs[0].tool.driver;
        assert_eq!(driver.name, "ShieldBOM");
        assert_eq!(driver.information_uri, TOOL_URI);
        assert!(!driver.version.is_empty());
        assert_eq!(driver.version, driver.semantic_version);
    }

    #[test]
    fn sarif_single_vuln_produces_one_rule_one_result() {
        let report = sample_report(vec![critical_vuln()]);
        let sarif = SarifLog::from_analysis(&report);
        let run = &sarif.runs[0];

        assert_eq!(run.tool.driver.rules.len(), 1);
        assert_eq!(run.results.len(), 1);

        let rule = &run.tool.driver.rules[0];
        assert_eq!(rule.id, "CVE-2021-3711");
        assert_eq!(rule.default_configuration.level, "error");
        assert_eq!(
            rule.help_uri,
            Some("https://nvd.nist.gov/vuln/detail/CVE-2021-3711".to_string())
        );

        let result = &run.results[0];
        assert_eq!(result.rule_id, "CVE-2021-3711");
        assert_eq!(result.rule_index, 0);
        assert_eq!(result.level, "error");
        assert!(result.message.text.contains("openssl"));
        assert!(result.message.text.contains("1.1.1l")); // fix version in message
    }

    #[test]
    fn sarif_severity_mapping() {
        assert_eq!(severity_to_sarif_level(&Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(&Severity::High), "error");
        assert_eq!(severity_to_sarif_level(&Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(&Severity::Low), "note");
        assert_eq!(severity_to_sarif_level(&Severity::None), "note");
        assert_eq!(severity_to_sarif_level(&Severity::Unknown), "note");
    }

    #[test]
    fn sarif_multiple_vulns_deduplicated_rules() {
        // Same CVE affecting two components should produce 1 rule, 2 results
        let vuln1 = critical_vuln();
        let mut vuln2 = critical_vuln();
        vuln2.component_name = "openssl-dev".to_string();

        let report = sample_report(vec![vuln1, vuln2]);
        let sarif = SarifLog::from_analysis(&report);
        let run = &sarif.runs[0];

        assert_eq!(run.tool.driver.rules.len(), 1, "same CVE = one rule");
        assert_eq!(
            run.results.len(),
            2,
            "two affected components = two results"
        );
        // Both results point to rule index 0
        assert_eq!(run.results[0].rule_index, 0);
        assert_eq!(run.results[1].rule_index, 0);
    }

    #[test]
    fn sarif_different_cves_produce_separate_rules() {
        let report = sample_report(vec![critical_vuln(), medium_vuln()]);
        let sarif = SarifLog::from_analysis(&report);
        let run = &sarif.runs[0];

        assert_eq!(run.tool.driver.rules.len(), 2);
        assert_eq!(run.results.len(), 2);

        // Rules are ordered by first appearance
        assert_eq!(run.tool.driver.rules[0].id, "CVE-2021-3711");
        assert_eq!(run.tool.driver.rules[1].id, "CVE-2022-37434");

        // Second result references index 1
        assert_eq!(run.results[1].rule_index, 1);
        assert_eq!(run.results[1].level, "warning"); // Medium => warning
    }

    #[test]
    fn sarif_locations_contain_component_info() {
        let report = sample_report(vec![critical_vuln()]);
        let sarif = SarifLog::from_analysis(&report);
        let result = &sarif.runs[0].results[0];

        assert_eq!(result.locations.len(), 1);
        let loc = &result.locations[0];

        // Physical location points to the SBOM file
        let phys = loc.physical_location.as_ref().unwrap();
        assert_eq!(phys.artifact_location.uri, "test.spdx.json");

        // Logical location captures the component
        assert_eq!(loc.logical_locations.len(), 1);
        assert_eq!(
            loc.logical_locations[0].fully_qualified_name,
            "openssl@1.1.1k"
        );
        assert_eq!(loc.logical_locations[0].kind, "module");
    }

    #[test]
    fn sarif_result_properties_include_cvss() {
        let report = sample_report(vec![critical_vuln()]);
        let sarif = SarifLog::from_analysis(&report);
        let props = sarif.runs[0].results[0].properties.as_ref().unwrap();

        assert_eq!(props.cvss_score, Some(9.8));
        assert_eq!(props.severity.as_deref(), Some("CRITICAL"));
        assert_eq!(props.source.as_deref(), Some("OSV"));
        assert_eq!(props.fixed_version.as_deref(), Some("1.1.1l"));
        assert_eq!(props.affected_versions.as_deref(), Some("< 1.1.1l"));
    }

    #[test]
    fn sarif_rule_properties_include_cvss() {
        let report = sample_report(vec![critical_vuln()]);
        let sarif = SarifLog::from_analysis(&report);
        let rule_props = sarif.runs[0].tool.driver.rules[0]
            .properties
            .as_ref()
            .unwrap();

        assert_eq!(rule_props.cvss_score, Some(9.8));
        assert_eq!(rule_props.severity.as_deref(), Some("CRITICAL"));
    }

    #[test]
    fn sarif_artifacts_lists_sbom_file() {
        let report = sample_report(vec![critical_vuln()]);
        let sarif = SarifLog::from_analysis(&report);
        let artifacts = &sarif.runs[0].artifacts;

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].location.uri, "test.spdx.json");
        assert!(artifacts[0]
            .description
            .as_ref()
            .unwrap()
            .text
            .contains("SPDX"));
    }

    #[test]
    fn sarif_empty_vulns_produces_empty_results() {
        let report = sample_report(vec![]);
        let sarif = SarifLog::from_analysis(&report);
        let run = &sarif.runs[0];

        assert!(run.tool.driver.rules.is_empty());
        assert!(run.results.is_empty());
        // Artifact should still be present
        assert_eq!(run.artifacts.len(), 1);
    }

    #[test]
    fn sarif_no_fixed_version_message_format() {
        let mut vuln = critical_vuln();
        vuln.fixed_version = None;

        let report = sample_report(vec![vuln]);
        let sarif = SarifLog::from_analysis(&report);
        let msg = &sarif.runs[0].results[0].message.text;

        assert!(msg.ends_with("openssl @ 1.1.1k."));
        assert!(!msg.contains("Upgrade"));
    }

    #[test]
    fn sarif_serialization_roundtrip() {
        let report = sample_report(vec![critical_vuln(), medium_vuln()]);
        let json_str = to_sarif_string(&report).unwrap();

        // Parse back as generic JSON and verify key fields
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(v["$schema"], SARIF_SCHEMA);
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "ShieldBOM");
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 2);
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        // Check that ruleIndex is present
        assert_eq!(v["runs"][0]["results"][0]["ruleIndex"], 0);
        assert_eq!(v["runs"][0]["results"][1]["ruleIndex"], 1);
    }

    #[test]
    fn sarif_ghsa_help_uri() {
        let mut vuln = critical_vuln();
        vuln.cve_id = "GHSA-xxxx-yyyy-zzzz".to_string();

        let report = sample_report(vec![vuln]);
        let sarif = SarifLog::from_analysis(&report);
        let rule = &sarif.runs[0].tool.driver.rules[0];

        assert_eq!(
            rule.help_uri,
            Some("https://github.com/advisories/GHSA-xxxx-yyyy-zzzz".to_string())
        );
    }
}
