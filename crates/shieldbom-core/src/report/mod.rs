mod cra;
mod html;
mod sarif;

use anyhow::Result;
use colored::Colorize;

use crate::models::{AnalysisReport, Severity};

/// Disclaimer text included in all output formats.
pub const DISCLAIMER: &str = "DISCLAIMER: This report is provided \"AS IS\" without warranty of any kind. Vulnerability results are based on publicly available data sources (e.g., OSV.dev, NVD) which may be incomplete or delayed. The absence of reported vulnerabilities does not guarantee that the software is free of security issues. This tool assists with security analysis but does not constitute a complete security assessment, legal advice, or certification of regulatory compliance (including EU CRA conformity). Users are solely responsible for their own compliance determinations. Always perform additional security assessments as appropriate.";

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

pub fn render(report: &AnalysisReport, format: OutputFormat) -> Result<()> {
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
            let output = cra::render_cra(report)?;
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
    println!();

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

            println!(
                "  [{severity_str}] {} {} @ {}",
                vuln.cve_id, vuln.component_name, vuln.component_version
            );
            if !vuln.description.is_empty() {
                // Truncate long descriptions
                let desc = truncate_str(&vuln.description, 100);
                println!("    {}", desc.dimmed());
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
                issue.component_name,
                issue.component_version,
                issue.description
            );
        }
        println!();
    }

    if report.vulnerabilities.is_empty() && report.license_issues.is_empty() {
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
