use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::Serialize;
use tera::Tera;

use super::truncate_str;
use crate::models::{AnalysisReport, Severity};

const CRA_TEMPLATE: &str = include_str!("cra_template.html");

/// Default values for fields the user may override in the future.
const DEFAULT_PRODUCT_NAME: &str = "Product";
const DEFAULT_PRODUCT_VERSION: &str = "0.0.0";
const DEFAULT_MANUFACTURER: &str = "Manufacturer";
const DEFAULT_SUPPORT_PERIOD: &str = "To be determined by manufacturer (CRA minimum: 5 years)";
const DEFAULT_UPDATE_MECHANISM: &str =
    "To be determined by manufacturer (CRA Annex I, Part II, Sec. 8)";

/// Render a CRA compliance report as an HTML string.
pub fn render_cra(report: &AnalysisReport) -> Result<String> {
    let mut tera = Tera::default();
    tera.add_raw_template("cra.html", CRA_TEMPLATE)
        .context("Failed to parse CRA HTML template")?;

    let context = build_context(report)?;
    let html = tera
        .render("cra.html", &context)
        .context("Failed to render CRA report")?;

    Ok(html)
}

fn build_context(report: &AnalysisReport) -> Result<tera::Context> {
    let mut ctx = tera::Context::new();

    // Product identification
    ctx.insert("product_name", DEFAULT_PRODUCT_NAME);
    ctx.insert("product_version", DEFAULT_PRODUCT_VERSION);
    ctx.insert("manufacturer", DEFAULT_MANUFACTURER);
    ctx.insert(
        "product_id",
        &format!("shieldbom-scan-{}", report.timestamp.format("%Y%m%d%H%M%S")),
    );

    // File / format info
    ctx.insert("sbom_file", &report.sbom_file.display().to_string());
    ctx.insert("format_detected", &report.format_detected.to_string());
    ctx.insert(
        "timestamp",
        &report.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    );
    ctx.insert("version", env!("CARGO_PKG_VERSION"));
    ctx.insert("stats", &report.stats);

    // Security update information
    ctx.insert("support_period", DEFAULT_SUPPORT_PERIOD);
    ctx.insert("update_mechanism", DEFAULT_UPDATE_MECHANISM);

    // License breakdown
    let license_breakdown = compute_license_breakdown(report);
    ctx.insert("license_breakdown", &license_breakdown);

    // Components
    let components: Vec<TemplateComponent> = report
        .components
        .iter()
        .map(|c| TemplateComponent {
            name: c.name.clone(),
            version: c.version.clone(),
            supplier: c.supplier.clone(),
            licenses: c.licenses.clone(),
        })
        .collect();
    ctx.insert("components", &components);

    // Vulnerabilities
    let vulns: Vec<TemplateVuln> = report
        .vulnerabilities
        .iter()
        .map(|v| {
            let severity_class = match v.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::None => "none",
                Severity::Unknown => "unknown",
            };
            TemplateVuln {
                cve_id: v.cve_id.clone(),
                severity: v.severity.to_string(),
                severity_class: severity_class.to_string(),
                cvss_score: v.cvss_score.map(|s| format!("{:.1}", s)),
                component_name: v.component_name.clone(),
                component_version: v.component_version.clone(),
                description_truncated: truncate_str(&v.description, 200),
                fixed_version: v.fixed_version.clone(),
            }
        })
        .collect();
    ctx.insert("vulnerabilities", &vulns);

    // Conformity assessment checklist
    let checklist = build_checklist(report);
    ctx.insert("checklist", &checklist);

    Ok(ctx)
}

fn compute_license_breakdown(report: &AnalysisReport) -> Vec<LicenseCount> {
    let mut map: BTreeMap<String, usize> = BTreeMap::new();
    for comp in &report.components {
        if comp.licenses.is_empty() {
            *map.entry("No license specified".to_string()).or_insert(0) += 1;
        } else {
            for lic in &comp.licenses {
                *map.entry(lic.clone()).or_insert(0) += 1;
            }
        }
    }
    map.into_iter()
        .map(|(name, count)| LicenseCount { name, count })
        .collect()
}

fn build_checklist(report: &AnalysisReport) -> Vec<ChecklistItem> {
    let has_critical = report.stats.critical > 0;
    let has_high = report.stats.high > 0;
    let has_any_vuln = report.stats.total_vulns > 0;
    let all_have_licenses = report.components.iter().all(|c| !c.licenses.is_empty());
    let sbom_documented = !report.components.is_empty();

    vec![
        ChecklistItem {
            requirement: "Delivered without known exploitable vulnerabilities".to_string(),
            cra_reference: "Annex I, Part I, Sec. 1".to_string(),
            status: if !has_critical && !has_high {
                "Pass".to_string()
            } else {
                "Fail".to_string()
            },
            evidence: if has_critical || has_high {
                format!(
                    "Found {} critical and {} high severity vulnerabilities. Remediation required before market placement.",
                    report.stats.critical, report.stats.high
                )
            } else if has_any_vuln {
                format!(
                    "No critical/high vulnerabilities. {} medium/low findings noted.",
                    report.stats.medium + report.stats.low
                )
            } else {
                "No known vulnerabilities detected in SBOM components.".to_string()
            },
        },
        ChecklistItem {
            requirement: "Secure by default configuration".to_string(),
            cra_reference: "Annex I, Part I, Sec. 2(a)".to_string(),
            status: "N/A".to_string(),
            evidence: "Requires manual verification by manufacturer. Outside scope of SBOM analysis."
                .to_string(),
        },
        ChecklistItem {
            requirement: "Security updates available".to_string(),
            cra_reference: "Annex I, Part II, Sec. 8-9".to_string(),
            status: "N/A".to_string(),
            evidence:
                "Requires manufacturer to document update mechanism and support period."
                    .to_string(),
        },
        ChecklistItem {
            requirement: "Vulnerability handling process in place".to_string(),
            cra_reference: "Annex I, Part II, Sec. 1-3".to_string(),
            status: "Pass".to_string(),
            evidence: format!(
                "SBOM scanned with ShieldBOM v{}. {} components analyzed against vulnerability databases.",
                env!("CARGO_PKG_VERSION"),
                report.stats.total_components
            ),
        },
        ChecklistItem {
            requirement: "SBOM documented".to_string(),
            cra_reference: "Annex I, Part II, Sec. 1; Annex VII, Sec. 2".to_string(),
            status: if sbom_documented {
                "Pass".to_string()
            } else {
                "Fail".to_string()
            },
            evidence: if sbom_documented {
                format!(
                    "SBOM contains {} components in {} format.",
                    report.stats.total_components, report.format_detected
                )
            } else {
                "No components found in SBOM. Ensure SBOM is complete.".to_string()
            },
        },
        ChecklistItem {
            requirement: "Third-party component due diligence".to_string(),
            cra_reference: "Article 13(4)".to_string(),
            status: if all_have_licenses && !has_critical {
                "Pass".to_string()
            } else if has_critical || !all_have_licenses {
                "Fail".to_string()
            } else {
                "N/A".to_string()
            },
            evidence: if !all_have_licenses {
                format!(
                    "{} component(s) missing license information. {} license issues detected.",
                    report
                        .components
                        .iter()
                        .filter(|c| c.licenses.is_empty())
                        .count(),
                    report.stats.license_issues
                )
            } else if has_critical {
                format!(
                    "All components licensed. However, {} critical vulnerabilities require remediation.",
                    report.stats.critical
                )
            } else {
                format!(
                    "All {} components have license information. {} license issues detected.",
                    report.stats.total_components, report.stats.license_issues
                )
            },
        },
    ]
}

#[derive(Serialize)]
struct TemplateComponent {
    name: String,
    version: String,
    supplier: Option<String>,
    licenses: Vec<String>,
}

#[derive(Serialize)]
struct TemplateVuln {
    cve_id: String,
    severity: String,
    severity_class: String,
    cvss_score: Option<String>,
    component_name: String,
    component_version: String,
    description_truncated: String,
    fixed_version: Option<String>,
}

#[derive(Serialize)]
struct LicenseCount {
    name: String,
    count: usize,
}

#[derive(Serialize)]
struct ChecklistItem {
    requirement: String,
    cra_reference: String,
    status: String,
    evidence: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AnalysisReport, Component, Hash, LicenseIssue, LicenseIssueType, Severity, SourceFormat,
        VulnMatch, VulnSource,
    };
    use std::path::PathBuf;

    fn sample_report() -> AnalysisReport {
        let components = vec![
            Component {
                name: "openssl".to_string(),
                version: "1.1.1k".to_string(),
                supplier: Some("OpenSSL Project".to_string()),
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

        let vulns = vec![VulnMatch {
            component_name: "openssl".to_string(),
            component_version: "1.1.1k".to_string(),
            cve_id: "CVE-2021-3711".to_string(),
            severity: Severity::High,
            cvss_score: Some(9.8),
            source: VulnSource::Osv,
            affected_versions: "<1.1.1l".to_string(),
            fixed_version: Some("1.1.1l".to_string()),
            description: "SM2 Decryption Buffer Overflow".to_string(),
        }];

        let license_issues = vec![LicenseIssue {
            component_name: "zlib".to_string(),
            component_version: "1.2.11".to_string(),
            issue_type: LicenseIssueType::MissingLicense,
            description: "No license specified for this component".to_string(),
        }];

        AnalysisReport::new(
            PathBuf::from("test-sbom.spdx.json"),
            SourceFormat::Spdx23Json,
            components,
            vulns,
            license_issues,
        )
    }

    fn clean_report() -> AnalysisReport {
        let components = vec![Component {
            name: "libfoo".to_string(),
            version: "2.0.0".to_string(),
            supplier: Some("Foo Corp".to_string()),
            cpe: None,
            purl: Some("pkg:generic/libfoo@2.0.0".to_string()),
            licenses: vec!["MIT".to_string()],
            hashes: vec![],
            source_format: SourceFormat::CycloneDx14Json,
        }];

        AnalysisReport::new(
            PathBuf::from("clean.cdx.json"),
            SourceFormat::CycloneDx14Json,
            components,
            vec![],
            vec![],
        )
    }

    #[test]
    fn test_render_cra_produces_valid_html() {
        let report = sample_report();
        let html = render_cra(&report).unwrap();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("EU Cyber Resilience Act (CRA) Compliance Report"));
        assert!(html.contains("test-sbom.spdx.json"));
        assert!(html.contains("SPDX 2.3 (JSON)"));
    }

    #[test]
    fn test_render_cra_contains_product_identification() {
        let report = sample_report();
        let html = render_cra(&report).unwrap();

        assert!(html.contains("Product"));
        assert!(html.contains("Manufacturer"));
        assert!(html.contains("shieldbom-scan-"));
    }

    #[test]
    fn test_render_cra_contains_vulnerability_disclosure() {
        let report = sample_report();
        let html = render_cra(&report).unwrap();

        assert!(html.contains("CVE-2021-3711"));
        assert!(html.contains("severity-high"));
        assert!(html.contains("9.8"));
        assert!(html.contains("SM2 Decryption Buffer Overflow"));
        assert!(html.contains("Upgrade to 1.1.1l"));
    }

    #[test]
    fn test_render_cra_contains_conformity_checklist() {
        let report = sample_report();
        let html = render_cra(&report).unwrap();

        // Checklist items
        assert!(html.contains("Delivered without known exploitable vulnerabilities"));
        assert!(html.contains("Secure by default configuration"));
        assert!(html.contains("Security updates available"));
        assert!(html.contains("Vulnerability handling process in place"));
        assert!(html.contains("SBOM documented"));
        assert!(html.contains("Third-party component due diligence"));

        // CRA references
        assert!(html.contains("Annex I, Part I, Sec. 1"));
        assert!(html.contains("Annex I, Part II, Sec. 1; Annex VII, Sec. 2"));
    }

    #[test]
    fn test_render_cra_checklist_fail_on_high_vulns() {
        let report = sample_report();
        let html = render_cra(&report).unwrap();

        // Should have FAIL for "delivered without known exploitable vulns" because we have HIGH
        assert!(html.contains("FAIL"));
        assert!(html.contains("1 high severity vulnerabilities"));
    }

    #[test]
    fn test_render_cra_checklist_pass_on_clean_report() {
        let report = clean_report();
        let html = render_cra(&report).unwrap();

        // "Delivered without known exploitable vulnerabilities" should pass
        assert!(html.contains("PASS"));
        assert!(html.contains("No known vulnerabilities detected"));
    }

    #[test]
    fn test_render_cra_license_breakdown() {
        let report = sample_report();
        let html = render_cra(&report).unwrap();

        assert!(html.contains("Apache-2.0"));
        assert!(html.contains("No license specified"));
    }

    #[test]
    fn test_render_cra_components_table() {
        let report = sample_report();
        let html = render_cra(&report).unwrap();

        assert!(html.contains("openssl"));
        assert!(html.contains("1.1.1k"));
        assert!(html.contains("OpenSSL Project"));
        assert!(html.contains("zlib"));
    }

    #[test]
    fn test_render_cra_security_update_info() {
        let report = sample_report();
        let html = render_cra(&report).unwrap();

        assert!(html.contains("CRA minimum: 5 years"));
        assert!(html.contains("Annex I, Part II, Sec. 8"));
    }

    #[test]
    fn test_render_cra_tech_doc_reference() {
        let report = sample_report();
        let html = render_cra(&report).unwrap();

        assert!(html.contains("Technical Documentation Reference"));
        assert!(html.contains("ShieldBOM v"));
        assert!(html.contains("Annex VII"));
    }

    #[test]
    fn test_render_cra_footer() {
        let report = sample_report();
        let html = render_cra(&report).unwrap();

        assert!(html.contains("Generated by ShieldBOM"));
        assert!(html.contains("does not constitute a complete security assessment, legal advice"));
    }

    #[test]
    fn test_render_cra_empty_report() {
        let report = AnalysisReport::new(
            PathBuf::from("empty.spdx.json"),
            SourceFormat::Spdx23Json,
            vec![],
            vec![],
            vec![],
        );
        let html = render_cra(&report).unwrap();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("No components found."));
        assert!(html.contains("No known vulnerabilities found"));
        // SBOM documented should fail
        assert!(html.contains("FAIL"));
        assert!(html.contains("No components found in SBOM"));
    }

    #[test]
    fn test_render_cra_no_fix_available() {
        let components = vec![Component {
            name: "test-lib".to_string(),
            version: "1.0.0".to_string(),
            supplier: None,
            cpe: None,
            purl: None,
            licenses: vec!["MIT".to_string()],
            hashes: vec![],
            source_format: SourceFormat::Spdx23Json,
        }];

        let vulns = vec![VulnMatch {
            component_name: "test-lib".to_string(),
            component_version: "1.0.0".to_string(),
            cve_id: "CVE-2024-0001".to_string(),
            severity: Severity::Medium,
            cvss_score: Some(5.0),
            source: VulnSource::Osv,
            affected_versions: "*".to_string(),
            fixed_version: None,
            description: "Test vulnerability".to_string(),
        }];

        let report = AnalysisReport::new(
            PathBuf::from("test.json"),
            SourceFormat::Spdx23Json,
            components,
            vulns,
            vec![],
        );
        let html = render_cra(&report).unwrap();

        assert!(html.contains("No fix available"));
    }

    #[test]
    fn test_license_breakdown_counts() {
        let components = vec![
            Component {
                name: "a".to_string(),
                version: "1.0".to_string(),
                supplier: None,
                cpe: None,
                purl: None,
                licenses: vec!["MIT".to_string()],
                hashes: vec![],
                source_format: SourceFormat::Spdx23Json,
            },
            Component {
                name: "b".to_string(),
                version: "1.0".to_string(),
                supplier: None,
                cpe: None,
                purl: None,
                licenses: vec!["MIT".to_string()],
                hashes: vec![],
                source_format: SourceFormat::Spdx23Json,
            },
            Component {
                name: "c".to_string(),
                version: "1.0".to_string(),
                supplier: None,
                cpe: None,
                purl: None,
                licenses: vec!["Apache-2.0".to_string()],
                hashes: vec![],
                source_format: SourceFormat::Spdx23Json,
            },
        ];

        let report = AnalysisReport::new(
            PathBuf::from("test.json"),
            SourceFormat::Spdx23Json,
            components,
            vec![],
            vec![],
        );

        let breakdown = compute_license_breakdown(&report);
        assert_eq!(breakdown.len(), 2);
        // BTreeMap is sorted, so Apache-2.0 comes first
        assert_eq!(breakdown[0].name, "Apache-2.0");
        assert_eq!(breakdown[0].count, 1);
        assert_eq!(breakdown[1].name, "MIT");
        assert_eq!(breakdown[1].count, 2);
    }

    #[test]
    fn test_checklist_all_pass_clean_report() {
        let report = clean_report();
        let checklist = build_checklist(&report);

        // Item 0: no exploitable vulns -> Pass
        assert_eq!(checklist[0].status, "Pass");
        // Item 1: secure by default -> N/A
        assert_eq!(checklist[1].status, "N/A");
        // Item 2: security updates -> N/A
        assert_eq!(checklist[2].status, "N/A");
        // Item 3: vuln handling -> Pass
        assert_eq!(checklist[3].status, "Pass");
        // Item 4: SBOM documented -> Pass
        assert_eq!(checklist[4].status, "Pass");
        // Item 5: due diligence -> Pass (all licensed, no critical)
        assert_eq!(checklist[5].status, "Pass");
    }

    #[test]
    fn test_checklist_fails_with_critical_vulns() {
        let components = vec![Component {
            name: "bad-lib".to_string(),
            version: "0.1.0".to_string(),
            supplier: None,
            cpe: None,
            purl: None,
            licenses: vec!["MIT".to_string()],
            hashes: vec![],
            source_format: SourceFormat::Spdx23Json,
        }];

        let vulns = vec![VulnMatch {
            component_name: "bad-lib".to_string(),
            component_version: "0.1.0".to_string(),
            cve_id: "CVE-2024-9999".to_string(),
            severity: Severity::Critical,
            cvss_score: Some(10.0),
            source: VulnSource::Osv,
            affected_versions: "*".to_string(),
            fixed_version: None,
            description: "Critical issue".to_string(),
        }];

        let report = AnalysisReport::new(
            PathBuf::from("test.json"),
            SourceFormat::Spdx23Json,
            components,
            vulns,
            vec![],
        );

        let checklist = build_checklist(&report);
        assert_eq!(checklist[0].status, "Fail"); // no exploitable vulns
        assert_eq!(checklist[5].status, "Fail"); // due diligence (critical vuln)
    }
}
