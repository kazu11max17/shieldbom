use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::Serialize;
use tera::Tera;

use super::{truncate_str, ProductMetadata};
use crate::models::{AnalysisReport, Severity};

const CRA_TEMPLATE: &str = include_str!("cra_template.html");

/// Placeholders used when the manufacturer supplies no product identification.
///
/// These are deliberately obvious: an unfilled report must read as unfilled, so
/// that it is never mistaken for a completed conformity record.
// Kept mutually non-substring so that asserting on one cannot match another.
const DEFAULT_PRODUCT_NAME: &str = "UNSPECIFIED PRODUCT";
const DEFAULT_PRODUCT_VERSION: &str = "UNSPECIFIED VERSION";
const DEFAULT_MANUFACTURER: &str = "UNSPECIFIED MANUFACTURER";
const DEFAULT_SUPPORT_PERIOD: &str =
    "To be determined by manufacturer (CRA Art. 13(8): at least 5 years, or the expected product lifetime if shorter)";
const DEFAULT_UPDATE_MECHANISM: &str =
    "To be determined by manufacturer (CRA Annex I, Part II, point (7))";

/// Upper bound on manufacturer-supplied identification fields.
///
/// These arrive from the command line and are embedded in the HTML report.
/// Tera escapes them, so this is a size guard rather than an injection guard.
const MAX_METADATA_CHARS: usize = 200;

/// Render a CRA compliance report as an HTML string.
pub fn render_cra(report: &AnalysisReport, product: &ProductMetadata) -> Result<String> {
    let mut tera = Tera::default();
    tera.add_raw_template("cra.html", CRA_TEMPLATE)
        .context("Failed to parse CRA HTML template")?;

    let context = build_context(report, product)?;
    let html = tera
        .render("cra.html", &context)
        .context("Failed to render CRA report")?;

    Ok(html)
}

/// Resolve one manufacturer-supplied field, falling back to its placeholder.
///
/// Blank and whitespace-only values are treated as absent so that `--manufacturer ""`
/// cannot silently blank out the identification section.
fn field_or_default(value: &Option<String>, default: &str) -> String {
    match value {
        Some(v) if !v.trim().is_empty() => truncate_str(v.trim(), MAX_METADATA_CHARS),
        _ => default.to_string(),
    }
}

fn build_context(report: &AnalysisReport, product: &ProductMetadata) -> Result<tera::Context> {
    let mut ctx = tera::Context::new();

    // Product identification
    ctx.insert(
        "product_name",
        &field_or_default(&product.product_name, DEFAULT_PRODUCT_NAME),
    );
    ctx.insert(
        "product_version",
        &field_or_default(&product.product_version, DEFAULT_PRODUCT_VERSION),
    );
    ctx.insert(
        "manufacturer",
        &field_or_default(&product.manufacturer, DEFAULT_MANUFACTURER),
    );
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
    ctx.insert(
        "support_period",
        &field_or_default(&product.support_period, DEFAULT_SUPPORT_PERIOD),
    );
    ctx.insert(
        "update_mechanism",
        &field_or_default(&product.update_mechanism, DEFAULT_UPDATE_MECHANISM),
    );

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

    // Essential requirements checklist
    let checklist = build_checklist(report, product);
    ctx.insert("checklist", &checklist);

    // Single source of truth for the disclaimer: the template must not carry its
    // own copy, or a legal revision would leave the distributed HTML stale.
    ctx.insert("disclaimer", super::DISCLAIMER);

    // Drives the "not for compliance use" banner.
    ctx.insert("missing_identification", &product.missing_identification());

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

/// Checklist status values. `Review` marks items that this tool can inform but
/// cannot decide — the manufacturer must reach the conclusion.
const STATUS_PASS: &str = "Pass";
const STATUS_FAIL: &str = "Fail";
const STATUS_REVIEW: &str = "Review";
const STATUS_NA: &str = "N/A";

fn build_checklist(report: &AnalysisReport, product: &ProductMetadata) -> Vec<ChecklistItem> {
    let has_any_vuln = report.stats.total_vulns > 0;
    let sbom_documented = !report.components.is_empty();

    // CISA KEV is the only evidence of actual exploitation available here.
    // Annex I, Part I, point (2)(a) is about *exploitable* vulnerabilities, and
    // CVSS severity is not a measure of exploitation.
    let kev_ids: Vec<&str> = report
        .vulnerabilities
        .iter()
        .filter(|v| v.in_kev)
        .map(|v| v.cve_id.as_str())
        .collect();

    let missing_licenses = report
        .components
        .iter()
        .filter(|c| c.licenses.is_empty())
        .count();

    vec![
        ChecklistItem {
            requirement: "Delivered without known exploitable vulnerabilities".to_string(),
            cra_reference: "Annex I, Part I, point (2)(a)".to_string(),
            status: if !kev_ids.is_empty() {
                STATUS_FAIL.to_string()
            } else if has_any_vuln {
                // Severity is not exploitability, so no Pass can be claimed while
                // any known vulnerability remains.
                STATUS_REVIEW.to_string()
            } else {
                STATUS_PASS.to_string()
            },
            evidence: if !kev_ids.is_empty() {
                format!(
                    "{} vulnerabilit(y/ies) are listed in the CISA Known Exploited Vulnerabilities catalogue and are therefore known to be exploited: {}. Remediation required before market placement.",
                    kev_ids.len(),
                    truncate_str(&kev_ids.join(", "), 300)
                )
            } else if has_any_vuln {
                format!(
                    "{} known vulnerabilit(y/ies) remain ({} critical, {} high, {} medium, {} low). None are listed in the CISA KEV catalogue, but exploitability must be assessed by the manufacturer.",
                    report.stats.total_vulns,
                    report.stats.critical,
                    report.stats.high,
                    report.stats.medium,
                    report.stats.low
                )
            } else {
                "No known vulnerabilities detected in the SBOM components against the consulted databases.".to_string()
            },
        },
        ChecklistItem {
            requirement: "Secure by default configuration".to_string(),
            cra_reference: "Annex I, Part I, point (2)(b)".to_string(),
            status: STATUS_NA.to_string(),
            evidence: "Requires manual verification by the manufacturer. Outside the scope of SBOM analysis."
                .to_string(),
        },
        ChecklistItem {
            requirement: "Security updates available".to_string(),
            cra_reference: "Annex I, Part I, point (2)(c); Part II, points (7)-(8)".to_string(),
            status: STATUS_NA.to_string(),
            // Reflect what the manufacturer declared, so this row cannot contradict
            // the Security Update Information section rendered above it.
            evidence: match (&product.support_period, &product.update_mechanism) {
                (Some(period), Some(mechanism))
                    if !period.trim().is_empty() && !mechanism.trim().is_empty() =>
                {
                    format!(
                        "Manufacturer declares support period \"{}\" and update mechanism \"{}\". Self-declared; not independently verified by this tool.",
                        truncate_str(period.trim(), MAX_METADATA_CHARS),
                        truncate_str(mechanism.trim(), MAX_METADATA_CHARS)
                    )
                }
                _ => "Requires the manufacturer to document the update mechanism and support period."
                    .to_string(),
            },
        },
        ChecklistItem {
            requirement: "Vulnerability handling process in place".to_string(),
            cra_reference: "Annex I, Part II, points (1)-(3)".to_string(),
            // A single scan does not demonstrate an ongoing process. Points (2) and (3)
            // require remediation "without delay" and "effective and regular" testing,
            // neither of which this tool can observe.
            status: STATUS_NA.to_string(),
            evidence: format!(
                "Component analysis performed with ShieldBOM v{} over {} components. The existence of an ongoing vulnerability handling process — including remediation without delay, regular testing, a coordinated disclosure policy and a contact address — requires manufacturer attestation.",
                env!("CARGO_PKG_VERSION"),
                report.stats.total_components
            ),
        },
        ChecklistItem {
            requirement: "SBOM documented".to_string(),
            cra_reference: "Annex I, Part II, point (1); Annex VII, point 2(b)".to_string(),
            status: if sbom_documented {
                STATUS_PASS.to_string()
            } else {
                STATUS_FAIL.to_string()
            },
            evidence: if sbom_documented {
                format!(
                    "SBOM contains {} components in {} format.",
                    report.stats.total_components, report.format_detected
                )
            } else {
                "No components found in SBOM. Ensure the SBOM is complete.".to_string()
            },
        },
        ChecklistItem {
            requirement: "Third-party component due diligence".to_string(),
            cra_reference: "Article 13(5)".to_string(),
            // Article 13(5) is about components not compromising the product's
            // cybersecurity. License completeness is not a proxy for that, so this
            // row reports what was observed instead of judging compliance.
            status: STATUS_REVIEW.to_string(),
            evidence: format!(
                "{} components analysed; {} known vulnerabilit(y/ies) attributable to them ({} in the CISA KEV catalogue). {} component(s) lack license information, which limits provenance review. Due diligence under Article 13(5) covers more than this tool observes.",
                report.stats.total_components,
                report.stats.total_vulns,
                kev_ids.len(),
                missing_licenses
            ),
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
        let html = render_cra(&report, &ProductMetadata::default()).unwrap();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("EU Cyber Resilience Act (CRA) Compliance Report"));
        assert!(html.contains("test-sbom.spdx.json"));
        assert!(html.contains("SPDX 2.3 (JSON)"));
    }

    #[test]
    fn test_render_cra_contains_product_identification() {
        let report = sample_report();
        let html = render_cra(&report, &ProductMetadata::default()).unwrap();

        // With no metadata supplied the report must read as explicitly unfilled.
        assert!(html.contains(DEFAULT_PRODUCT_NAME));
        assert!(html.contains(DEFAULT_MANUFACTURER));
        assert!(html.contains("shieldbom-scan-"));
    }

    fn filled_metadata() -> ProductMetadata {
        ProductMetadata {
            product_name: Some("Acme Gateway".to_string()),
            product_version: Some("2.4.1".to_string()),
            manufacturer: Some("Acme Industrial GmbH".to_string()),
            support_period: Some("5 years from 2026-01-01".to_string()),
            update_mechanism: Some("Signed OTA updates over HTTPS".to_string()),
        }
    }

    #[test]
    fn test_render_cra_uses_supplied_product_metadata() {
        let report = sample_report();
        let html = render_cra(&report, &filled_metadata()).unwrap();

        assert!(html.contains("Acme Gateway"));
        assert!(html.contains("2.4.1"));
        assert!(html.contains("Acme Industrial GmbH"));
        assert!(html.contains("5 years from 2026-01-01"));
        assert!(html.contains("Signed OTA updates over HTTPS"));

        // Placeholders must be gone once real values are supplied.
        assert!(!html.contains(DEFAULT_PRODUCT_NAME));
        assert!(!html.contains(DEFAULT_MANUFACTURER));
    }

    #[test]
    fn test_render_cra_blank_metadata_falls_back_to_placeholder() {
        let report = sample_report();
        let product = ProductMetadata {
            product_name: Some("   ".to_string()),
            manufacturer: Some(String::new()),
            ..Default::default()
        };
        let html = render_cra(&report, &product).unwrap();

        // Whitespace-only input must not blank out the identification section.
        assert!(html.contains(DEFAULT_PRODUCT_NAME));
        assert!(html.contains(DEFAULT_MANUFACTURER));
    }

    #[test]
    fn test_render_cra_handles_japanese_metadata() {
        let report = sample_report();
        let product = ProductMetadata {
            product_name: Some("スマートゲートウェイ".to_string()),
            manufacturer: Some("株式会社アクメ工業".to_string()),
            // U+3000 IDEOGRAPHIC SPACE is whitespace for str::trim, so this must fall back.
            product_version: Some("\u{3000}".to_string()),
            ..Default::default()
        };

        let html = render_cra(&report, &product).unwrap();

        assert!(html.contains("スマートゲートウェイ"));
        assert!(html.contains("株式会社アクメ工業"));
        assert!(html.contains(DEFAULT_PRODUCT_VERSION));
    }

    #[test]
    fn test_render_cra_metadata_at_exact_length_limit_is_not_truncated() {
        let report = sample_report();
        let exact = "M".repeat(MAX_METADATA_CHARS);
        let product = ProductMetadata {
            manufacturer: Some(exact.clone()),
            ..Default::default()
        };

        let html = render_cra(&report, &product).unwrap();

        assert!(html.contains(&exact));
        assert!(!html.contains(&format!("{exact}...")));
    }

    #[test]
    fn test_render_cra_escapes_html_in_every_metadata_field() {
        let report = sample_report();
        let payload = "<img src=x onerror=alert(1)>";
        let product = ProductMetadata {
            product_name: Some(payload.to_string()),
            product_version: Some(payload.to_string()),
            manufacturer: Some(payload.to_string()),
            support_period: Some(payload.to_string()),
            update_mechanism: Some(payload.to_string()),
            ..Default::default()
        };

        let html = render_cra(&report, &product).unwrap();

        assert!(!html.contains(payload));
        assert!(html.contains("&lt;img"));
    }

    #[test]
    fn test_render_ignores_product_metadata_for_non_cra_formats() {
        // Product identification must not leak into machine-readable outputs.
        let report = sample_report();
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("Acme Industrial GmbH"));
    }

    #[test]
    fn test_render_cra_trims_and_truncates_metadata() {
        let report = sample_report();
        let product = ProductMetadata {
            product_name: Some("  Padded Name  ".to_string()),
            manufacturer: Some("M".repeat(MAX_METADATA_CHARS + 50)),
            ..Default::default()
        };
        let html = render_cra(&report, &product).unwrap();

        assert!(html.contains("Padded Name"));
        assert!(!html.contains("  Padded Name  "));
        assert!(html.contains(&format!("{}...", "M".repeat(MAX_METADATA_CHARS))));
        assert!(!html.contains(&"M".repeat(MAX_METADATA_CHARS + 1)));
    }

    #[test]
    fn test_render_cra_escapes_html_in_metadata() {
        let report = sample_report();
        let product = ProductMetadata {
            product_name: Some("<script>alert(1)</script>".to_string()),
            ..Default::default()
        };
        let html = render_cra(&report, &product).unwrap();

        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn test_missing_identification_reports_every_unset_field() {
        assert_eq!(
            ProductMetadata::default().missing_identification(),
            vec!["--product-name", "--product-version", "--manufacturer"]
        );
        assert!(filled_metadata().missing_identification().is_empty());
    }

    #[test]
    fn test_missing_identification_treats_blank_as_unset() {
        // The renderer falls back to a placeholder for whitespace-only input, so the
        // warning must agree with it — otherwise the guard rail silently passes.
        let product = ProductMetadata {
            product_name: Some("   ".to_string()),
            product_version: Some(String::new()),
            manufacturer: Some("\u{3000}".to_string()), // ideographic space
            ..Default::default()
        };

        assert_eq!(
            product.missing_identification(),
            vec!["--product-name", "--product-version", "--manufacturer"]
        );
    }

    #[test]
    fn test_missing_identification_flags_partial_fill() {
        // A partially filled report looks complete at a glance, so it must still warn.
        let product = ProductMetadata {
            product_name: Some("Acme Gateway".to_string()),
            ..Default::default()
        };

        assert_eq!(
            product.missing_identification(),
            vec!["--product-version", "--manufacturer"]
        );
    }

    #[test]
    fn test_missing_identification_ignores_non_identifying_fields() {
        // Support period alone does not identify a product.
        let product = ProductMetadata {
            support_period: Some("5 years".to_string()),
            ..Default::default()
        };

        assert_eq!(product.missing_identification().len(), 3);
    }

    #[test]
    fn test_render_cra_draft_banner_when_identification_incomplete() {
        let report = sample_report();

        let html = render_cra(&report, &ProductMetadata::default()).unwrap();
        assert!(html.contains("DRAFT &mdash; NOT FOR COMPLIANCE USE"));
        assert!(html.contains("--manufacturer"));

        let html = render_cra(&report, &filled_metadata()).unwrap();
        assert!(!html.contains("NOT FOR COMPLIANCE USE"));
    }

    #[test]
    fn test_render_cra_partial_fill_still_shows_draft_banner() {
        let report = sample_report();
        let product = ProductMetadata {
            product_name: Some("Acme Gateway".to_string()),
            ..Default::default()
        };

        let html = render_cra(&report, &product).unwrap();
        assert!(html.contains("DRAFT &mdash; NOT FOR COMPLIANCE USE"));
        assert!(html.contains(DEFAULT_MANUFACTURER));
    }

    #[test]
    fn test_render_cra_states_it_is_not_a_conformity_assessment() {
        let report = sample_report();
        let html = render_cra(&report, &filled_metadata()).unwrap();

        // The disclaimer must travel with the document; readers never see the README.
        assert!(html.contains("<strong>not</strong> a conformity"));
        assert!(html.contains("Regulation (EU) 2024/2847"));
        // "Conformity Assessment" is a legal term under Art. 32 / Annex VIII and must
        // not appear as a section heading claiming to be one.
        assert!(!html.contains("Conformity Assessment &mdash;"));
    }

    #[test]
    fn test_render_cra_disclaimer_comes_from_the_shared_constant() {
        let report = sample_report();
        let html = render_cra(&report, &filled_metadata()).unwrap();

        // Guards against the template drifting from a revised DISCLAIMER.
        assert!(html.contains(&tera::escape_html(super::super::DISCLAIMER)));
    }

    #[test]
    fn test_render_cra_contains_vulnerability_disclosure() {
        let report = sample_report();
        let html = render_cra(&report, &ProductMetadata::default()).unwrap();

        assert!(html.contains("CVE-2021-3711"));
        assert!(html.contains("severity-high"));
        assert!(html.contains("9.8"));
        assert!(html.contains("SM2 Decryption Buffer Overflow"));
        assert!(html.contains("Upgrade to 1.1.1l"));
    }

    #[test]
    fn test_render_cra_contains_conformity_checklist() {
        let report = sample_report();
        let html = render_cra(&report, &ProductMetadata::default()).unwrap();

        // Checklist items
        assert!(html.contains("Delivered without known exploitable vulnerabilities"));
        assert!(html.contains("Secure by default configuration"));
        assert!(html.contains("Security updates available"));
        assert!(html.contains("Vulnerability handling process in place"));
        assert!(html.contains("SBOM documented"));
        assert!(html.contains("Third-party component due diligence"));

        // CRA references
        assert!(html.contains("Annex I, Part I, point (2)(a)"));
        assert!(html.contains("Annex I, Part II, point (1); Annex VII, point 2(b)"));
    }

    #[test]
    fn test_render_cra_checklist_review_on_non_kev_high_vulns() {
        let report = sample_report();
        let checklist = build_checklist(&report, &ProductMetadata::default());
        let html = render_cra(&report, &ProductMetadata::default()).unwrap();

        // A HIGH severity finding that is not in the KEV catalogue is not proven
        // exploitable. Asserting on the checklist entry rather than on the rendered
        // badge keeps this test tied to the decision, not to any row that happens
        // to carry the same status.
        assert_eq!(checklist[0].status, "Review");
        assert!(html.contains("REVIEW"));
        assert!(checklist[0].evidence.contains("1 high"));
        assert!(checklist[0].evidence.contains("CISA KEV"));
    }

    #[test]
    fn test_render_cra_checklist_pass_on_clean_report() {
        let report = clean_report();
        let html = render_cra(&report, &ProductMetadata::default()).unwrap();

        // Assert on the decision, not on any PASS badge in the table — six rows
        // render badges, so `contains("PASS")` would survive a broken checklist.
        let checklist = build_checklist(&report, &ProductMetadata::default());
        assert_eq!(checklist[0].status, "Pass");
        assert!(html.contains("PASS"));
        assert!(html.contains("No known vulnerabilities detected"));
    }

    #[test]
    fn test_render_cra_license_breakdown() {
        let report = sample_report();
        let html = render_cra(&report, &ProductMetadata::default()).unwrap();

        assert!(html.contains("Apache-2.0"));
        assert!(html.contains("No license specified"));
    }

    #[test]
    fn test_render_cra_components_table() {
        let report = sample_report();
        let html = render_cra(&report, &ProductMetadata::default()).unwrap();

        assert!(html.contains("openssl"));
        assert!(html.contains("1.1.1k"));
        assert!(html.contains("OpenSSL Project"));
        assert!(html.contains("zlib"));
    }

    #[test]
    fn test_render_cra_security_update_info() {
        let report = sample_report();
        let html = render_cra(&report, &ProductMetadata::default()).unwrap();

        // Reference the constants so a change to the placeholder text cannot leave
        // this test asserting on a string that no longer exists (Ren P2-6).
        assert!(html.contains(&tera::escape_html(DEFAULT_SUPPORT_PERIOD)));
        assert!(html.contains(&tera::escape_html(DEFAULT_UPDATE_MECHANISM)));
        assert!(html.contains("Annex I, Part II, points (7)-(8)"));
    }

    #[test]
    fn test_render_cra_tech_doc_reference() {
        let report = sample_report();
        let html = render_cra(&report, &ProductMetadata::default()).unwrap();

        assert!(html.contains("Technical Documentation Reference"));
        assert!(html.contains("ShieldBOM v"));
        assert!(html.contains("Annex VII"));
    }

    #[test]
    fn test_render_cra_footer() {
        let report = sample_report();
        let html = render_cra(&report, &ProductMetadata::default()).unwrap();

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
        let html = render_cra(&report, &ProductMetadata::default()).unwrap();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("No components found."));
        assert!(html.contains("No known vulnerabilities found"));
        // "SBOM documented" is the row that must fail; pin it to the entry rather
        // than to the presence of a FAIL badge anywhere in the table.
        let checklist = build_checklist(&report, &ProductMetadata::default());
        assert_eq!(checklist[4].status, "Fail");
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
            affected_versions: AffectedVersions {
                display: "*".to_string(),
                ranges: vec![],
            },
            fixed_version: None,
            description: "Test vulnerability".to_string(),
            in_kev: false,
            kev_due_date: None,
        }];

        let report = AnalysisReport::new(
            PathBuf::from("test.json"),
            SourceFormat::Spdx23Json,
            components,
            vulns,
            vec![],
        );
        let html = render_cra(&report, &ProductMetadata::default()).unwrap();

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
        let checklist = build_checklist(&report, &ProductMetadata::default());

        // Item 0: no known vulnerabilities at all -> Pass
        assert_eq!(checklist[0].status, "Pass");
        // Item 1: secure by default -> N/A (not observable from an SBOM)
        assert_eq!(checklist[1].status, "N/A");
        // Item 2: security updates -> N/A (manufacturer declaration)
        assert_eq!(checklist[2].status, "N/A");
        // Item 3: vuln handling -> N/A. One scan is not an ongoing process.
        assert_eq!(checklist[3].status, "N/A");
        // Item 4: SBOM documented -> Pass
        assert_eq!(checklist[4].status, "Pass");
        // Item 5: due diligence -> Review. Art. 13(5) is broader than what we observe.
        assert_eq!(checklist[5].status, "Review");
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
            affected_versions: AffectedVersions {
                display: "*".to_string(),
                ranges: vec![],
            },
            fixed_version: None,
            description: "Critical issue".to_string(),
            in_kev: false,
            kev_due_date: None,
        }];

        let report = AnalysisReport::new(
            PathBuf::from("test.json"),
            SourceFormat::Spdx23Json,
            components,
            vulns,
            vec![],
        );

        let checklist = build_checklist(&report, &ProductMetadata::default());

        // A CRITICAL vulnerability that is not in the KEV catalogue is not proven
        // exploitable, so this must not be an outright Fail — but it cannot Pass either.
        assert_eq!(checklist[0].status, "Review");
        assert!(checklist[0].evidence.contains("1 critical"));
        assert_eq!(checklist[5].status, "Review");
    }

    /// Builds a report whose single vulnerability is listed in the CISA KEV catalogue.
    fn kev_report() -> AnalysisReport {
        let components = vec![Component {
            name: "exploited-lib".to_string(),
            version: "1.0.0".to_string(),
            supplier: None,
            cpe: None,
            purl: None,
            licenses: vec!["MIT".to_string()],
            hashes: vec![],
            source_format: SourceFormat::Spdx23Json,
        }];
        let vuln = VulnMatch {
            cve_id: "CVE-2024-99999".to_string(),
            component_name: "exploited-lib".to_string(),
            component_version: "1.0.0".to_string(),
            severity: Severity::Medium,
            cvss_score: Some(5.5),
            description: "Actively exploited in the wild".to_string(),
            fixed_version: Some("1.0.1".to_string()),
            affected_versions: AffectedVersions::default(),
            source: VulnSource::Osv,
            in_kev: true,
            kev_due_date: None,
        };

        AnalysisReport::new(
            PathBuf::from("kev.spdx.json"),
            SourceFormat::Spdx23Json,
            components,
            vec![vuln],
            vec![],
        )
    }

    #[test]
    fn test_checklist_fails_when_vulnerability_is_in_kev() {
        let checklist = build_checklist(&kev_report(), &ProductMetadata::default());

        // KEV membership is actual evidence of exploitation, which is what
        // Annex I, Part I, point (2)(a) is about — severity alone is not.
        assert_eq!(checklist[0].status, "Fail");
        assert!(checklist[0].evidence.contains("CVE-2024-99999"));
        assert!(checklist[0].evidence.contains("CISA Known Exploited"));
    }

    #[test]
    fn test_checklist_cites_correct_cra_references() {
        let checklist = build_checklist(&clean_report(), &ProductMetadata::default());

        assert_eq!(checklist[0].cra_reference, "Annex I, Part I, point (2)(a)");
        assert_eq!(checklist[1].cra_reference, "Annex I, Part I, point (2)(b)");
        assert_eq!(
            checklist[2].cra_reference,
            "Annex I, Part I, point (2)(c); Part II, points (7)-(8)"
        );
        assert_eq!(
            checklist[3].cra_reference,
            "Annex I, Part II, points (1)-(3)"
        );
        assert_eq!(checklist[5].cra_reference, "Article 13(5)");

        // Annex I Part II has eight points; there is no point 9.
        assert!(!checklist.iter().any(|i| i.cra_reference.contains("Sec.")));
    }

    #[test]
    fn test_checklist_security_updates_reflects_declared_metadata() {
        // Riku M1: this row must not claim the manufacturer still has to document
        // what the report already prints above it.
        let product = ProductMetadata {
            support_period: Some("5 years from 2026-01-01".to_string()),
            update_mechanism: Some("Signed OTA over HTTPS".to_string()),
            ..Default::default()
        };

        let checklist = build_checklist(&clean_report(), &product);

        assert_eq!(checklist[2].status, "N/A");
        assert!(checklist[2].evidence.contains("5 years from 2026-01-01"));
        assert!(checklist[2].evidence.contains("Signed OTA over HTTPS"));
        assert!(checklist[2].evidence.contains("Self-declared"));
        assert!(!checklist[2].evidence.contains("Requires the manufacturer"));
    }

    #[test]
    fn test_checklist_vulnerability_handling_is_never_self_certified() {
        // Scanning once must never assert that an ongoing process exists.
        for report in [clean_report(), kev_report()] {
            let checklist = build_checklist(&report, &filled_metadata());
            assert_eq!(checklist[3].status, "N/A");
            assert!(checklist[3]
                .evidence
                .contains("requires manufacturer attestation"));
        }
    }
}
