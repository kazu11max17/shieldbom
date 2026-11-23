pub mod badge;
mod cra;
mod html;
mod sarif;

pub use badge::write_badge;

use anyhow::Result;
use colored::Colorize;

use crate::models::{AnalysisReport, ScanGap, Severity};

/// Disclaimer text included in all output formats.
pub const DISCLAIMER: &str = "DISCLAIMER: This report is provided \"AS IS\" without warranty of any kind. Vulnerability results are based on publicly available data sources (e.g., OSV.dev, NVD) which may be incomplete or delayed. The absence of reported vulnerabilities does not guarantee that the software is free of security issues. This tool assists with security analysis but does not constitute a complete security assessment, legal advice, or certification of regulatory compliance (including EU CRA conformity). Users are solely responsible for their own compliance determinations. Always perform additional security assessments as appropriate.";

/// Strip ANSI escape sequences from a string.
///
/// Removes sequences like `\x1b[31m`, `\x1b[0m`, etc. that could be injected
/// via malicious component names to manipulate terminal output.
fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut in_escape = false;
    for ch in s.chars() {
        if in_escape {
            if ch.is_ascii_alphabetic() {
                in_escape = false;
            }
            continue;
        }
        if ch == '\x1b' {
            in_escape = true;
            continue;
        }
        result.push(ch);
    }
    result
}

/// Truncate a string at a safe UTF-8 char boundary.
fn truncate_str(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

#[derive(Clone, Default)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
pub enum OutputFormat {
    /// Human-readable terminal table
    #[default]
    Table,
    /// Machine-readable JSON
    Json,
    /// SARIF 2.1.0 format
    Sarif,
    /// HTML report
    Html,
    /// EU CRA compliance report (HTML)
    Cra,
}

/// Product identification supplied by the manufacturer for the CRA report.
///
/// The CRA requires the technical documentation to identify the product and its
/// manufacturer (Annex VII). Fields left as `None` fall back to explicit
/// placeholders so that an unfilled report is obviously unfilled rather than
/// silently claiming to describe a real product.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ProductMetadata {
    pub product_name: Option<String>,
    pub product_version: Option<String>,
    pub manufacturer: Option<String>,
    pub support_period: Option<String>,
    pub update_mechanism: Option<String>,
}

impl ProductMetadata {
    /// Names of the identification flags that were left unset.
    ///
    /// A partially filled report is more dangerous than an empty one — it looks
    /// complete at a glance — so a single missing field is worth reporting.
    /// Blank and whitespace-only values count as unset, matching how the CRA
    /// renderer resolves them.
    pub fn missing_identification(&self) -> Vec<&'static str> {
        [
            ("--product-name", &self.product_name),
            ("--product-version", &self.product_version),
            ("--manufacturer", &self.manufacturer),
        ]
        .into_iter()
        .filter(|(_, value)| value.as_deref().is_none_or(|v| v.trim().is_empty()))
        .map(|(flag, _)| flag)
        .collect()
    }
}

/// Strips ANSI sequences and replaces every remaining control character
/// (newline, carriage return, backspace, C1 controls) with a space, so an SBOM
/// string cannot forge or overwrite lines of the output.
fn single_line(s: &str) -> String {
    strip_ansi(s)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// One-line, terminal-safe description of a failed lookup.
pub fn format_scan_gap(gap: &ScanGap) -> String {
    let name = single_line(&gap.component_name);
    let reason = single_line(&gap.reason);
    if gap.component_version.is_empty() {
        format!("{name} [{}]: {reason}", gap.source)
    } else {
        format!(
            "{name} @ {} [{}]: {reason}",
            single_line(&gap.component_version),
            gap.source
        )
    }
}

/// Failed lookups listed individually in reports; the rest are counted.
pub(crate) const MAX_LISTED_GAPS: usize = 50;

/// Gap descriptions for embedding in reports, capped so a mass failure does
/// not bury the rest of the document. The last entry states how many were cut.
pub(crate) fn scan_gap_lines(report: &AnalysisReport) -> Vec<String> {
    let mut lines: Vec<String> = report
        .scan_gaps
        .iter()
        .take(MAX_LISTED_GAPS)
        .map(format_scan_gap)
        .collect();
    if report.scan_gaps.len() > MAX_LISTED_GAPS {
        lines.push(format!(
            "... and {} more",
            report.scan_gaps.len() - MAX_LISTED_GAPS
        ));
    }
    lines
}

/// Lines of the "scan incomplete" block of the table output; empty when the
/// scan is complete.
pub(crate) fn incomplete_banner_lines(report: &AnalysisReport) -> Vec<String> {
    if report.is_complete() {
        return Vec::new();
    }
    let mut lines = vec![
        format!(
            "SCAN INCOMPLETE: {} vulnerability lookup(s) failed or were not possible.",
            report.scan_gaps.len()
        ),
        "The counts above are a lower bound, not a clean result.".to_string(),
    ];
    lines.extend(
        scan_gap_lines(report)
            .into_iter()
            .map(|l| format!("  - {l}")),
    );
    lines
}

/// Shown next to a finding whose applicability could not be confirmed.
pub(crate) const UNCONFIRMED_LABEL: &str =
    "Unconfirmed: it could not be confirmed from NVD's data whether this version is affected (the CVE has not been analysed, or its version range could not be compared). Check whether it applies.";

/// One-line note under the severity counts.
pub(crate) fn unconfirmed_summary(count: usize, total: usize) -> String {
    format!(
        "{count} of the {total} findings are unconfirmed (it could not be confirmed from NVD's data whether this version is affected); check whether they apply."
    )
}

/// Comma-separated, terminal-safe list of names, capped at ten.
pub fn summarize_names(names: &[String]) -> String {
    const SHOWN: usize = 10;
    let mut out: Vec<String> = names.iter().take(SHOWN).map(|n| single_line(n)).collect();
    if names.len() > SHOWN {
        out.push(format!("and {} more", names.len() - SHOWN));
    }
    out.join(", ")
}

/// Whether the table output may say "No issues found."
pub(crate) fn can_claim_no_issues(report: &AnalysisReport) -> bool {
    report.vulnerabilities.is_empty()
        && report.license_issues.is_empty()
        && report.is_complete()
        && !report.offline
        && report.unverified.is_empty()
}

pub fn render(report: &AnalysisReport, format: OutputFormat) -> Result<()> {
    render_with_product(report, format, &ProductMetadata::default())
}

/// Same as [`render`], but lets the caller supply product identification for the
/// CRA report. Other formats ignore `product`.
pub fn render_with_product(
    report: &AnalysisReport,
    format: OutputFormat,
    product: &ProductMetadata,
) -> Result<()> {
    match format {
        OutputFormat::Table => render_table(report),
        OutputFormat::Json => render_json(report),
        OutputFormat::Sarif => sarif::render_sarif(report),
        OutputFormat::Html => {
            let output = html::render_html(report)?;
            println!("{output}");
            Ok(())
        }
        OutputFormat::Cra => {
            let output = cra::render_cra(report, product)?;
            println!("{output}");
            Ok(())
        }
    }?;

    // Print disclaimer to stderr for all formats.
    // For structured outputs (JSON, SARIF) this avoids corrupting stdout.
    // For table output, render_table already prints it, so we skip.
    // For HTML/CRA, the disclaimer is embedded in the template footer AND printed to stderr.
    match format {
        OutputFormat::Table => {} // already printed inside render_table
        _ => eprintln!("\n{}", report.disclaimer),
    }

    Ok(())
}

fn render_table(report: &AnalysisReport) -> Result<()> {
    println!();
    println!("{}", "ShieldBOM Scan Results".bold().underline());
    println!("File: {}", report.sbom_file.display());
    println!("Format: {}", report.format_detected);
    println!("Components: {}", report.stats.total_components);
    println!();

    // Summary bar
    println!(
        "  {} Critical  {} High  {} Medium  {} Low",
        format_severity_count(report.stats.critical, Severity::Critical),
        format_severity_count(report.stats.high, Severity::High),
        format_severity_count(report.stats.medium, Severity::Medium),
        format_severity_count(report.stats.low, Severity::Low),
    );
    if report.stats.unconfirmed > 0 {
        println!(
            "  {}",
            unconfirmed_summary(report.stats.unconfirmed, report.stats.total_vulns)
        );
    }
    println!();

    let banner = incomplete_banner_lines(report);
    if let Some((headline, rest)) = banner.split_first() {
        println!("{}", headline.red().bold());
        for line in rest {
            println!("{line}");
        }
        println!();
    }
    if report.offline {
        println!("Offline scan: only the local database snapshot was consulted.");
        println!();
    }
    if !report.unverified.is_empty() {
        println!(
            "Unverified: {} Debian/Ubuntu component(s) without source package information had no findings; vulnerabilities may have been missed: {}",
            report.unverified.len(),
            summarize_names(&report.unverified)
        );
        println!();
    }

    // Vulnerabilities
    if !report.vulnerabilities.is_empty() {
        println!("{}", "Vulnerabilities".bold());
        println!("{:-<80}", "");
        for vuln in &report.vulnerabilities {
            let severity_str = match vuln.severity {
                Severity::Critical => vuln.severity.to_string().red().bold(),
                Severity::High => vuln.severity.to_string().red(),
                Severity::Medium => vuln.severity.to_string().yellow(),
                Severity::Low => vuln.severity.to_string().blue(),
                _ => vuln.severity.to_string().normal(),
            };

            let safe_name = strip_ansi(&vuln.component_name);
            let safe_version = strip_ansi(&vuln.component_version);
            println!(
                "  [{severity_str}] {} {} @ {}",
                vuln.cve_id, safe_name, safe_version
            );
            if !vuln.description.is_empty() {
                // Truncate long descriptions, strip ANSI from untrusted input
                let desc = truncate_str(&strip_ansi(&vuln.description), 100);
                println!("    {}", desc.dimmed());
            }
            if vuln.unconfirmed {
                println!("    {}", UNCONFIRMED_LABEL.yellow());
            }
            if vuln.in_kev {
                let kev_label = if let Some(due) = vuln.kev_due_date {
                    format!("    ⚠ CISA KEV — actively exploited, remediation due {due}")
                } else {
                    "    ⚠ CISA KEV — actively exploited in the wild".to_string()
                };
                println!("{}", kev_label.red().bold());
            }
            if let Some(fixed) = &vuln.fixed_version {
                println!("    Fix: upgrade to {}", fixed.green());
            }
        }
        println!();
    }

    // License issues
    if !report.license_issues.is_empty() {
        println!("{}", "License Issues".bold());
        println!("{:-<80}", "");
        for issue in &report.license_issues {
            println!(
                "  [{}] {} @ {} - {}",
                issue.issue_type.to_string().yellow(),
                strip_ansi(&issue.component_name),
                strip_ansi(&issue.component_version),
                strip_ansi(&issue.description)
            );
        }
        println!();
    }

    if can_claim_no_issues(report) {
        println!("{}", "No issues found.".green().bold());
    }

    eprintln!("\n{DISCLAIMER}");

    Ok(())
}

fn format_severity_count(count: usize, severity: Severity) -> String {
    let s = format!("{count}");
    match severity {
        Severity::Critical => format!("{}", s.red().bold()),
        Severity::High => format!("{}", s.red()),
        Severity::Medium => format!("{}", s.yellow()),
        Severity::Low => format!("{}", s.blue()),
        _ => s,
    }
}

fn render_json(report: &AnalysisReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    println!("{json}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_ansi_removes_escape_sequences() {
        assert_eq!(strip_ansi("\x1b[31mred text\x1b[0m"), "red text");
        assert_eq!(strip_ansi("\x1b[1;32mbold green\x1b[0m"), "bold green");
        assert_eq!(strip_ansi("no escapes here"), "no escapes here");
        assert_eq!(strip_ansi(""), "");
    }

    #[test]
    fn test_strip_ansi_nested() {
        assert_eq!(
            strip_ansi("before\x1b[31m\x1b[1minner\x1b[0mafter"),
            "beforeinnerafter"
        );
    }

    #[test]
    fn test_truncate_str_safe() {
        assert_eq!(truncate_str("hello", 10), "hello");
        assert_eq!(truncate_str("hello world", 5), "hello...");
        assert_eq!(truncate_str("日本語テスト", 3), "日本語...");
    }

    fn report_with_gaps(n: usize) -> AnalysisReport {
        let gaps = (0..n)
            .map(|i| ScanGap {
                component_name: format!("c{i}"),
                component_version: "1.0".to_string(),
                source: "NVD".to_string(),
                reason: "could not connect".to_string(),
            })
            .collect();
        AnalysisReport::new(
            std::path::PathBuf::from("x.json"),
            crate::models::SourceFormat::Unknown,
            vec![],
            vec![],
            vec![],
        )
        .with_scan_gaps(gaps)
    }

    #[test]
    fn test_format_scan_gap_omits_empty_version() {
        let gap = ScanGap {
            component_name: ScanGap::ALL_COMPONENTS.to_string(),
            component_version: String::new(),
            source: "CISA KEV".to_string(),
            reason: "catalogue unavailable".to_string(),
        };
        let line = format_scan_gap(&gap);
        assert_eq!(line, "(all components) [CISA KEV]: catalogue unavailable");
    }

    // SBOM strings must not be able to recolour, overwrite or forge lines.
    #[test]
    fn test_format_scan_gap_neutralises_terminal_control() {
        let gap = ScanGap {
            component_name: "\x1b[31mevil\x1b[0m\nNo issues found.".to_string(),
            component_version: "1.0\r\u{9b}2J".to_string(),
            source: "OSV".to_string(),
            reason: "HTTP 400".to_string(),
        };
        let line = format_scan_gap(&gap);
        assert!(!line.chars().any(char::is_control));
        assert!(line.starts_with("evil"));
        assert!(line.ends_with("[OSV]: HTTP 400"));
    }

    #[test]
    fn test_scan_gap_lines_cap() {
        assert!(scan_gap_lines(&report_with_gaps(0)).is_empty());
        assert_eq!(scan_gap_lines(&report_with_gaps(50)).len(), 50);
        let capped = scan_gap_lines(&report_with_gaps(51));
        assert_eq!(capped.len(), 51);
        assert_eq!(capped.last().unwrap(), "... and 1 more");
    }

    #[test]
    fn test_incomplete_banner_lines() {
        assert!(incomplete_banner_lines(&report_with_gaps(0)).is_empty());
        let lines = incomplete_banner_lines(&report_with_gaps(2));
        assert!(lines[0].starts_with("SCAN INCOMPLETE: 2 "));
        assert_eq!(lines.len(), 4);
        assert!(lines[2].contains("c0 @ 1.0 [NVD]"));
    }

    // Regression: a scan with every lookup failed printed "No issues found."
    #[test]
    fn test_no_issues_claim_requires_complete_online_scan() {
        assert!(can_claim_no_issues(&report_with_gaps(0)));
        assert!(!can_claim_no_issues(&report_with_gaps(1)));
        assert!(!can_claim_no_issues(
            &report_with_gaps(0).with_offline(true)
        ));
        assert!(!can_claim_no_issues(
            &report_with_gaps(0).with_unverified(vec!["zlib1g@1".to_string()])
        ));
    }
}
