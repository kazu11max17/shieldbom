use anyhow::{Context, Result};
use serde::Serialize;
use tera::Tera;

use super::truncate_str;
use crate::models::{AnalysisReport, Severity};

const TEMPLATE: &str = include_str!("template.html");

/// Render an analysis report as an HTML string.
pub fn render_html(report: &AnalysisReport) -> Result<String> {
    let mut tera = Tera::default();
    tera.add_raw_template("report.html", TEMPLATE)
        .context("Failed to parse HTML template")?;

    let context = build_context(report)?;
    let html = tera
        .render("report.html", &context)
        .context("Failed to render HTML report")?;

    Ok(html)
}

fn build_context(report: &AnalysisReport) -> Result<tera::Context> {
    let mut ctx = tera::Context::new();

    ctx.insert("sbom_file", &report.sbom_file.display().to_string());
    ctx.insert("format_detected", &report.format_detected.to_string());
    ctx.insert(
        "timestamp",
        &report.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    );
    ctx.insert("version", env!("CARGO_PKG_VERSION"));
    ctx.insert("stats", &report.stats);

    // Components
    let components: Vec<TemplateComponent> = report
        .components
        .iter()
        .map(|c| TemplateComponent {
            name: c.name.clone(),
            version: c.version.clone(),
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
            let description_truncated = truncate_str(&v.description, 200);
            TemplateVuln {
                cve_id: v.cve_id.clone(),
                severity: v.severity.to_string(),
                severity_class: severity_class.to_string(),
                cvss_score: v.cvss_score.map(|s| format!("{:.1}", s)),
                component_name: v.component_name.clone(),
                component_version: v.component_version.clone(),
                description_truncated,
            }
        })
        .collect();
    ctx.insert("vulnerabilities", &vulns);

    // License issues
    let license_issues: Vec<TemplateLicenseIssue> = report
        .license_issues
        .iter()
        .map(|i| TemplateLicenseIssue {
            issue_type: i.issue_type.to_string(),
            component_name: i.component_name.clone(),
            component_version: i.component_version.clone(),
            description: i.description.clone(),
        })
        .collect();
    ctx.insert("license_issues", &license_issues);

    Ok(ctx)
}

#[derive(Serialize)]
struct TemplateComponent {
    name: String,
    version: String,
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
}

#[derive(Serialize)]
struct TemplateLicenseIssue {
    issue_type: String,
    component_name: String,
    component_version: String,
    description: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AffectedVersions, AnalysisReport, Component, Hash, LicenseIssue, LicenseIssueType,
        Severity, SourceFormat, VulnMatch, VulnSource,
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
            affected_versions: AffectedVersions {
                display: "<1.1.1l".to_string(),
                ranges: vec![],
            },
            fixed_version: Some("1.1.1l".to_string()),
            description: "SM2 Decryption Buffer Overflow".to_string(),
            in_kev: false,
            kev_due_date: None,
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

    #[test]
    fn test_render_html_produces_valid_output() {
        let report = sample_report();
        let html = render_html(&report).unwrap();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("ShieldBOM Scan Report"));
        assert!(html.contains("test-sbom.spdx.json"));
        assert!(html.contains("SPDX 2.3 (JSON)"));
    }

    #[test]
    fn test_render_html_contains_components() {
        let report = sample_report();
        let html = render_html(&report).unwrap();

        assert!(html.contains("openssl"));
        assert!(html.contains("1.1.1k"));
        assert!(html.contains("Apache-2.0"));
        assert!(html.contains("zlib"));
        assert!(html.contains("1.2.11"));
    }

    #[test]
    fn test_render_html_contains_vulnerabilities() {
        let report = sample_report();
        let html = render_html(&report).unwrap();

        assert!(html.contains("CVE-2021-3711"));
        assert!(html.contains("severity-high"));
        assert!(html.contains("9.8"));
        assert!(html.contains("SM2 Decryption Buffer Overflow"));
    }

    #[test]
    fn test_render_html_contains_license_issues() {
        let report = sample_report();
        let html = render_html(&report).unwrap();

        assert!(html.contains("Missing License"));
        assert!(html.contains("No license specified for this component"));
    }

    #[test]
    fn test_render_html_contains_stats() {
        let report = sample_report();
        let html = render_html(&report).unwrap();

        // 2 components total
        assert!(html.contains(">2<"));
        // 1 high vuln
        assert!(html.contains("severity-badge severity-high"));
    }

    #[test]
    fn test_render_html_empty_report() {
        let report = AnalysisReport::new(
            PathBuf::from("empty.spdx.json"),
            SourceFormat::Spdx23Json,
            vec![],
            vec![],
            vec![],
        );
        let html = render_html(&report).unwrap();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("No components found."));
        assert!(html.contains("No vulnerabilities found."));
        assert!(html.contains("No license issues found."));
    }

    #[test]
    fn test_render_html_long_description_truncated() {
        let long_desc = "A".repeat(300);
        let vulns = vec![VulnMatch {
            component_name: "test".to_string(),
            component_version: "1.0".to_string(),
            cve_id: "CVE-2024-0001".to_string(),
            severity: Severity::Critical,
            cvss_score: Some(10.0),
            source: VulnSource::Osv,
            affected_versions: AffectedVersions {
                display: "*".to_string(),
                ranges: vec![],
            },
            fixed_version: None,
            description: long_desc.clone(),
            in_kev: false,
            kev_due_date: None,
        }];

        let report = AnalysisReport::new(
            PathBuf::from("test.json"),
            SourceFormat::CycloneDx14Json,
            vec![],
            vulns,
            vec![],
        );
        let html = render_html(&report).unwrap();

        // Should contain truncated version (200 chars + "...")
        let expected_truncated = format!("{}...", long_desc.chars().take(200).collect::<String>());
        assert!(html.contains(&expected_truncated));
        // Should NOT contain the full 300-char string
        assert!(!html.contains(&long_desc));
    }

    #[test]
    fn test_severity_class_mapping() {
        let severities = vec![
            (Severity::Critical, "severity-critical"),
            (Severity::High, "severity-high"),
            (Severity::Medium, "severity-medium"),
            (Severity::Low, "severity-low"),
        ];

        for (severity, expected_class) in severities {
            let vulns = vec![VulnMatch {
                component_name: "pkg".to_string(),
                component_version: "1.0".to_string(),
                cve_id: "CVE-2024-0001".to_string(),
                severity,
                cvss_score: Some(5.0),
                source: VulnSource::Osv,
                affected_versions: AffectedVersions {
                    display: "*".to_string(),
                    ranges: vec![],
                },
                fixed_version: None,
                description: "test".to_string(),
                in_kev: false,
                kev_due_date: None,
            }];

            let report = AnalysisReport::new(
                PathBuf::from("test.json"),
                SourceFormat::Spdx23Json,
                vec![],
                vulns,
                vec![],
            );
            let html = render_html(&report).unwrap();
            assert!(
                html.contains(expected_class),
                "Expected class '{}' for severity {:?}",
                expected_class,
                severity
            );
        }
    }
}
