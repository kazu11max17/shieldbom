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

    let (color, message) = if stats.critical > 0 {
        ("#e05d44", format!("{} critical", stats.critical))
    } else if stats.high > 0 {
        ("#e0a020", format!("{} high", stats.high))
    } else {
        ("#44cc11", "0 vulns".to_string())
    };

    let total_vulns = stats.critical + stats.high + stats.medium + stats.low;
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
            timestamp: chrono::Utc::now(),
            stats: AnalysisStats {
                total_components: 0,
                components_with_vulns: 0,
                total_vulns: critical + high + medium + low,
                critical,
                high,
                medium,
                low,
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
