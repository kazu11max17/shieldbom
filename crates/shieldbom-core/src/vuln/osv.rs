use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::models::{
    AffectedVersions, Component, Severity, VersionRangeInfo, VulnMatch, VulnSource,
};

const OSV_API_URL: &str = "https://api.osv.dev/v1/query";

#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Serialize)]
struct OsvPackage {
    purl: String,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    aliases: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: Option<String>,
    score: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[allow(dead_code)]
    #[serde(rename = "type")]
    range_type: Option<String>,
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    #[allow(dead_code)]
    introduced: Option<String>,
    fixed: Option<String>,
}

/// Query OSV for vulnerabilities for each component that has a PURL
pub async fn query_batch(components: &[&Component]) -> Result<Vec<VulnMatch>> {
    let client = reqwest::Client::new();
    let mut results = Vec::new();

    for component in components {
        let Some(purl) = &component.purl else {
            continue;
        };

        if component.version.is_empty() {
            continue;
        }

        let query = OsvQuery {
            package: OsvPackage { purl: purl.clone() },
            version: component.version.clone(),
        };

        match client.post(OSV_API_URL).json(&query).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(osv_resp) = resp.json::<OsvResponse>().await {
                    for vuln in osv_resp.vulns {
                        results.push(convert_osv_vuln(&vuln, component));
                    }
                }
            }
            Ok(resp) => {
                tracing::warn!(
                    "OSV API returned {} for {}@{}",
                    resp.status(),
                    component.name,
                    component.version
                );
            }
            Err(e) => {
                tracing::warn!(
                    "OSV API error for {}@{}: {e}",
                    component.name,
                    component.version
                );
            }
        }
    }

    Ok(results)
}

fn convert_osv_vuln(vuln: &OsvVuln, component: &Component) -> VulnMatch {
    let (severity, cvss_score) = extract_severity(vuln);
    let fixed_version = extract_fixed_version(vuln);
    let affected_versions = extract_affected_versions(vuln);

    // Use CVE alias as the ID if available, otherwise use the OSV ID.
    // This enables proper deduplication with NVD results.
    let cve_id = vuln
        .aliases
        .iter()
        .find(|a| a.starts_with("CVE-"))
        .cloned()
        .unwrap_or_else(|| vuln.id.clone());

    VulnMatch {
        component_name: component.name.clone(),
        component_version: component.version.clone(),
        cve_id,
        severity,
        cvss_score,
        source: VulnSource::Osv,
        affected_versions,
        fixed_version,
        description: vuln.summary.clone(),
        in_kev: false,
        kev_due_date: None,
    }
}

/// Extract structured affected version information from OSV affected ranges.
fn extract_affected_versions(vuln: &OsvVuln) -> AffectedVersions {
    let mut ranges = Vec::new();
    let mut display_parts = Vec::new();

    for affected in &vuln.affected {
        for range in &affected.ranges {
            let mut introduced: Option<String> = None;
            let mut fixed: Option<String> = None;

            for event in &range.events {
                if let Some(ref i) = event.introduced {
                    introduced = Some(i.clone());
                }
                if let Some(ref f) = event.fixed {
                    fixed = Some(f.clone());
                }
            }

            // Only add if we have at least one piece of range info
            if introduced.is_some() || fixed.is_some() {
                // Build display string for this range
                let display = match (&introduced, &fixed) {
                    (Some(i), Some(f)) => format!(">={}, <{}", i, f),
                    (Some(i), None) => format!(">={}", i),
                    (None, Some(f)) => format!("<{}", f),
                    (None, None) => unreachable!(),
                };
                display_parts.push(display);

                ranges.push(VersionRangeInfo { introduced, fixed });
            }
        }
    }

    AffectedVersions {
        display: display_parts.join("; "),
        ranges,
    }
}

fn extract_severity(vuln: &OsvVuln) -> (Severity, Option<f64>) {
    for sev in &vuln.severity {
        if sev.severity_type.as_deref() == Some("CVSS_V3") {
            if let Some(score_str) = &sev.score {
                // Try plain number first (some sources provide numeric scores)
                if let Ok(score) = score_str.parse::<f64>() {
                    return (Severity::from_cvss(score), Some(score));
                }
                // Try parsing CVSS v3.x vector string (e.g. "CVSS:3.1/AV:N/AC:L/...")
                if let Some(score) = cvss_v3_base_score(score_str) {
                    return (Severity::from_cvss(score), Some(score));
                }
            }
        }
    }
    (Severity::Unknown, None)
}

// ---------------------------------------------------------------------------
// CVSS v3.0/v3.1 base score calculation from vector string
// Reference: https://www.first.org/cvss/v3.1/specification-document
// ---------------------------------------------------------------------------

/// Parse a CVSS v3.x vector string and compute the base score.
///
/// Accepts strings like `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`.
/// Returns `None` if the string is not a valid CVSS v3 vector.
pub(crate) fn cvss_v3_base_score(vector: &str) -> Option<f64> {
    // Must start with "CVSS:3.0/" or "CVSS:3.1/"
    let metrics_part = vector
        .strip_prefix("CVSS:3.1/")
        .or_else(|| vector.strip_prefix("CVSS:3.0/"))?;

    let mut av: Option<f64> = None;
    let mut ac: Option<f64> = None;
    let mut pr: Option<f64> = None;
    let mut ui: Option<f64> = None;
    let mut scope_changed: Option<bool> = None;
    let mut c: Option<f64> = None;
    let mut i: Option<f64> = None;
    let mut a: Option<f64> = None;

    for metric in metrics_part.split('/') {
        let (key, val) = metric.split_once(':')?;
        match key {
            "AV" => {
                av = Some(match val {
                    "N" => 0.85,
                    "A" => 0.62,
                    "L" => 0.55,
                    "P" => 0.20,
                    _ => return None,
                });
            }
            "AC" => {
                ac = Some(match val {
                    "L" => 0.77,
                    "H" => 0.44,
                    _ => return None,
                });
            }
            "PR" => {
                // PR values depend on Scope; we resolve after parsing all metrics
                pr = Some(match val {
                    "N" => 0.0, // placeholder: N = no privilege
                    "L" => 1.0, // placeholder: L = low
                    "H" => 2.0, // placeholder: H = high
                    _ => return None,
                });
            }
            "UI" => {
                ui = Some(match val {
                    "N" => 0.85,
                    "R" => 0.62,
                    _ => return None,
                });
            }
            "S" => {
                scope_changed = Some(match val {
                    "U" => false,
                    "C" => true,
                    _ => return None,
                });
            }
            "C" => {
                c = Some(match val {
                    "H" => 0.56,
                    "L" => 0.22,
                    "N" => 0.0,
                    _ => return None,
                });
            }
            "I" => {
                i = Some(match val {
                    "H" => 0.56,
                    "L" => 0.22,
                    "N" => 0.0,
                    _ => return None,
                });
            }
            "A" => {
                a = Some(match val {
                    "H" => 0.56,
                    "L" => 0.22,
                    "N" => 0.0,
                    _ => return None,
                });
            }
            // Ignore temporal/environmental metrics (E, RL, RC, etc.)
            _ => {}
        }
    }

    let av = av?;
    let ac = ac?;
    let pr_raw = pr?;
    let ui = ui?;
    let scope_changed = scope_changed?;
    let c = c?;
    let i = i?;
    let a = a?;

    // Resolve PR based on Scope
    let pr_val = if scope_changed {
        match pr_raw as u8 {
            0 => 0.85, // N
            1 => 0.68, // L (Changed)
            2 => 0.50, // H (Changed)
            _ => return None,
        }
    } else {
        match pr_raw as u8 {
            0 => 0.85, // N
            1 => 0.62, // L (Unchanged)
            2 => 0.27, // H (Unchanged)
            _ => return None,
        }
    };

    // ISS = 1 - [(1 - C) * (1 - I) * (1 - A)]
    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);

    // Impact
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
    } else {
        6.42 * iss
    };

    if impact <= 0.0 {
        return Some(0.0);
    }

    // Exploitability = 8.22 * AV * AC * PR * UI
    let exploitability = 8.22 * av * ac * pr_val * ui;

    let score = if scope_changed {
        roundup((1.08 * (impact + exploitability)).min(10.0))
    } else {
        roundup((impact + exploitability).min(10.0))
    };

    Some(score)
}

/// CVSS v3 "roundup" function: round up to nearest 0.1
fn roundup(val: f64) -> f64 {
    let rounded = (val * 10.0).ceil() / 10.0;
    rounded.clamp(0.0, 10.0)
}

fn extract_fixed_version(vuln: &OsvVuln) -> Option<String> {
    for affected in &vuln.affected {
        for range in &affected.ranges {
            for event in &range.events {
                if let Some(fixed) = &event.fixed {
                    return Some(fixed.clone());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- CVSS vector string parsing tests --

    #[test]
    fn test_cvss_v31_critical_all_high() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
        let score = cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert_eq!(score, Some(9.8));
    }

    #[test]
    fn test_cvss_v31_high_scope_changed() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1
        let score = cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
        assert_eq!(score, Some(6.1));
    }

    #[test]
    fn test_cvss_v31_medium() {
        // CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N = 4.8
        let score = cvss_v3_base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
        assert_eq!(score, Some(4.8));
    }

    #[test]
    fn test_cvss_v31_low() {
        // CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N = 1.8
        let score = cvss_v3_base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N");
        assert_eq!(score, Some(1.8));
    }

    #[test]
    fn test_cvss_v31_zero_impact() {
        // All impact metrics are None => ISS=0 => impact<=0 => score=0
        let score = cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
        assert_eq!(score, Some(0.0));
    }

    #[test]
    fn test_cvss_v30_accepted() {
        // Should also accept CVSS:3.0 prefix
        let score = cvss_v3_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert_eq!(score, Some(9.8));
    }

    #[test]
    fn test_cvss_invalid_prefix() {
        assert_eq!(cvss_v3_base_score("CVSS:2.0/AV:N/AC:L"), None);
        assert_eq!(cvss_v3_base_score("not a vector"), None);
        assert_eq!(cvss_v3_base_score(""), None);
    }

    #[test]
    fn test_cvss_missing_metric() {
        // Missing A metric
        assert_eq!(
            cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"),
            None
        );
    }

    #[test]
    fn test_cvss_invalid_metric_value() {
        assert_eq!(
            cvss_v3_base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            None
        );
    }

    #[test]
    fn test_cvss_v31_scope_changed_pr_low() {
        // CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.9
        let score = cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
        assert_eq!(score, Some(9.9));
    }

    #[test]
    fn test_cvss_v31_physical_access() {
        // CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 6.8
        let score = cvss_v3_base_score("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert_eq!(score, Some(6.8));
    }

    // -- extract_severity integration tests --

    #[test]
    fn test_extract_severity_with_vector_string() {
        let vuln = OsvVuln {
            id: "GHSA-test".to_string(),
            summary: String::new(),
            severity: vec![OsvSeverity {
                severity_type: Some("CVSS_V3".to_string()),
                score: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
            }],
            affected: vec![],
            aliases: vec![],
        };
        let (sev, score) = extract_severity(&vuln);
        assert_eq!(score, Some(9.8));
        assert_eq!(sev, Severity::Critical);
    }

    #[test]
    fn test_extract_severity_plain_number() {
        let vuln = OsvVuln {
            id: "GHSA-test".to_string(),
            summary: String::new(),
            severity: vec![OsvSeverity {
                severity_type: Some("CVSS_V3".to_string()),
                score: Some("7.5".to_string()),
            }],
            affected: vec![],
            aliases: vec![],
        };
        let (sev, score) = extract_severity(&vuln);
        assert_eq!(score, Some(7.5));
        assert_eq!(sev, Severity::High);
    }

    #[test]
    fn test_extract_severity_no_cvss() {
        let vuln = OsvVuln {
            id: "GHSA-test".to_string(),
            summary: String::new(),
            severity: vec![],
            affected: vec![],
            aliases: vec![],
        };
        let (sev, score) = extract_severity(&vuln);
        assert_eq!(score, None);
        assert_eq!(sev, Severity::Unknown);
    }
}
