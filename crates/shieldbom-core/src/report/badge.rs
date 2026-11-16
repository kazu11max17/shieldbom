use crate::models::AnalysisReport;
use anyhow::Result;
use std::path::Path;

/// Write an SVG badge representing the scan result to the given path.
pub fn write_badge(report: &AnalysisReport, path: &Path) -> Result<()> {
    let svg = generate_badge_svg(report);
    std::fs::write(path, svg)?;
    Ok(())
}

/// Generate a shields.io flat-square style SVG badge for the scan result.
pub fn generate_badge_svg(report: &AnalysisReport) -> String {
    let stats = &report.stats;

    // An incomplete scan must never render as a green "0 vulns" badge.
    let (color, message) = if !report.is_complete() {
        ("#9f9f9f", "scan incomplete".to_string())
    } else if stats.critical > 0 {
        ("#e05d44", format!("{} critical", stats.critical))
    } else if stats.high > 0 {
        ("#e0a020", format!("{} high", stats.high))
    } else if !report.vulnerabilities.is_empty() {
        // Medium, low and unscored findings are still findings: never "0 vulns".
        ("#dfb317", format!("{} vulns", report.vulnerabilities.len()))
    } else if report.offline {
        // The local snapshot is not a full check, so no green badge from it.
        ("#9f9f9f", "offline scan".to_string())
    } else if !report.unverified.is_empty() {
        ("#9f9f9f", "0 vulns (unverified)".to_string())
    } else {
        ("#44cc11", "0 vulns".to_string())
    };

    // Counts every finding, including ones with no severity score.
    let total_vulns = report.vulnerabilities.len();
    let timestamp = current_utc_timestamp();
    let version = env!("CARGO_PKG_VERSION");
    let desc = format!(
        "ShieldBOM scan: {total_vulns} vulnerabilities. Scanned: {timestamp}. Tool: shieldbom {version}"
    );

    render_badge_svg("ShieldBOM", &message, color, &desc)
}

/// Return the current UTC time formatted as `%Y-%m-%dT%H:%M:%SZ`.
pub fn current_utc_timestamp() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// NOTE: All inputs to this function must be trusted/sanitized values.
// If untrusted data (component names, CVE descriptions, etc.) is ever embedded
// in the SVG, apply HTML escaping (&amp; &lt; &gt; &quot;) before passing here.
fn render_badge_svg(label: &str, message: &str, color: &str, desc: &str) -> String {
    let msg_width = message.len() * 6 + 10;
    let total_width = 80 + msg_width;
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20">
  <desc>{desc}</desc>
  <rect width="80" height="20" fill="#555"/>
  <rect x="80" width="{msg_width}" height="20" fill="{color}"/>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="40" y="14">{label}</text>
    <text x="{msg_center}" y="14">{message}</text>
  </g>
</svg>"##,
        msg_center = 80 + msg_width / 2,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AnalysisReport, AnalysisStats};
    use std::path::PathBuf;

    fn make_report(critical: usize, high: usize, medium: usize, low: usize) -> AnalysisReport {
        use crate::models::SourceFormat;
        AnalysisReport {
            sbom_file: PathBuf::from("test.spdx"),
            format_detected: SourceFormat::Spdx23Json,
            components: vec![],
            vulnerabilities: vec![],
            license_issues: vec![],
            disclaimer: String::new(),
            scan_gaps: Vec::new(),
            offline: false,
            unverified: Vec::new(),
            timestamp: chrono::Utc::now(),
            stats: AnalysisStats {
                total_components: 0,
                components_with_vulns: 0,
                total_vulns: critical + high + medium + low,
                critical,
                high,
                medium,
                low,
                unconfirmed: 0,
                license_issues: 0,
            },
        }
    }

    #[test]
    fn test_badge_zero_vulns() {
        let report = make_report(0, 0, 0, 0);
        let svg = generate_badge_svg(&report);
        assert!(svg.contains("#44cc11"), "should be green");
        assert!(svg.contains("0 vulns"), "should show '0 vulns'");
    }

    // Regression (existing since the badge was added): medium/low-only
    // findings rendered as a green "0 vulns" badge.
    #[test]
    fn test_badge_medium_low_only_is_not_zero() {
        use crate::models::{AffectedVersions, Severity, VulnMatch, VulnSource};
        let mut report = make_report(0, 0, 1, 1);
        report.vulnerabilities = [Severity::Medium, Severity::Low]
            .into_iter()
            .map(|severity| VulnMatch {
                component_name: "zlib".to_string(),
                component_version: "1.2.13".to_string(),
                cve_id: "CVE-2024-0001".to_string(),
                severity,
                cvss_score: None,
                source: VulnSource::Nvd,
                affected_versions: AffectedVersions::default(),
                fixed_version: None,
                description: String::new(),
                in_kev: false,
                kev_due_date: None,
                unconfirmed: false,
            })
            .collect();
        let svg = generate_badge_svg(&report);
        assert!(svg.contains("2 vulns"));
        assert!(!svg.contains("0 vulns"));
        assert!(!svg.contains("#44cc11"));
    }

    #[test]
    fn test_badge_unverified_is_not_green() {
        let mut report = make_report(0, 0, 0, 0);
        report.unverified = vec!["zlib1g".to_string()];
        let svg = generate_badge_svg(&report);
        assert!(svg.contains("0 vulns (unverified)"));
        assert!(!svg.contains("#44cc11"));
    }

    #[test]
    fn test_badge_offline_scan_is_not_green() {
        let mut report = make_report(0, 0, 0, 0);
        report.offline = true;
        let svg = generate_badge_svg(&report);
        assert!(svg.contains("offline scan"));
        assert!(!svg.contains("#44cc11"));
        // Findings from the snapshot are still shown.
        let mut report = make_report(2, 0, 0, 0);
        report.offline = true;
        assert!(generate_badge_svg(&report).contains("2 critical"));
    }

    // Regression guard: an incomplete scan must not look green or definite.
    #[test]
    fn test_badge_incomplete_scan() {
        for mut report in [make_report(0, 0, 0, 0), make_report(3, 0, 0, 0)] {
            report.scan_gaps = vec![crate::models::ScanGap {
                component_name: "openssl".to_string(),
                component_version: "3.0.8".to_string(),
                source: "NVD".to_string(),
                reason: "could not connect".to_string(),
            }];
            let svg = generate_badge_svg(&report);
            assert!(svg.contains("scan incomplete"));
            assert!(!svg.contains("#44cc11"), "must not be green");
            assert!(!svg.contains("0 vulns"));
            assert!(!svg.contains("3 critical"));
        }
    }

    #[test]
    fn test_badge_critical() {
        let report = make_report(3, 0, 0, 0);
        let svg = generate_badge_svg(&report);
        assert!(svg.contains("#e05d44"), "should be red");
        assert!(svg.contains("3 critical"), "should show count");
    }

    #[test]
    fn test_badge_high_only() {
        let report = make_report(0, 2, 1, 0);
        let svg = generate_badge_svg(&report);
        assert!(svg.contains("#e0a020"), "should be orange");
        assert!(svg.contains("2 high"), "should show high count");
    }

    #[test]
    fn test_badge_contains_desc() {
        let report = make_report(1, 0, 0, 0);
        let svg = generate_badge_svg(&report);
        assert!(svg.contains("<desc>"), "should have desc tag");
        assert!(
            svg.contains("ShieldBOM scan:"),
            "desc should mention ShieldBOM scan"
        );
        assert!(
            svg.contains("Tool: shieldbom"),
            "desc should include tool name"
        );
        // Timestamp format check: contains 'T' and 'Z'
        assert!(
            svg.contains('T') && svg.contains('Z'),
            "desc should contain UTC timestamp"
        );
    }
}
