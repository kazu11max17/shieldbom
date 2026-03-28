mod nvd;
mod osv;

use std::collections::HashMap;

use anyhow::Result;

use crate::models::{Component, VulnMatch, VulnSource};

/// Match vulnerabilities using online APIs.
///
/// Strategy (PURL-first):
/// 1. For components with a PURL: query OSV.dev (native PURL support, free, accurate).
/// 2. For components without a PURL (or when NVD is explicitly enabled): query NVD via CPE.
/// 3. Deduplicate: when both sources return the same CVE, merge them
///    (prefer OSV for fix_version, NVD for CVSS scores).
pub async fn match_vulnerabilities(
    components: &[Component],
    use_nvd: bool,
) -> Result<Vec<VulnMatch>> {
    // Partition components by whether they have a PURL
    let (purl_components, no_purl_components): (Vec<&Component>, Vec<&Component>) =
        components.iter().partition(|c| c.purl.is_some());

    let mut all_vulns: Vec<VulnMatch> = Vec::new();

    // Step 1: Query OSV for all components that have a PURL (primary source)
    if !purl_components.is_empty() {
        tracing::info!(
            "Querying OSV.dev for {} components with PURLs...",
            purl_components.len()
        );
        let osv_vulns = osv::query_batch(&purl_components).await?;
        all_vulns.extend(osv_vulns);
    }

    // Step 2: Query NVD for components without a PURL,
    // OR for all components if --nvd is explicitly enabled
    if use_nvd {
        let nvd_targets: Vec<&Component> = if purl_components.is_empty() {
            // No PURLs at all - query NVD for everything
            components.iter().collect()
        } else {
            // Have PURLs - only query NVD for components without PURL,
            // plus all components if user explicitly asked for NVD
            components.iter().collect()
        };

        if !nvd_targets.is_empty() {
            tracing::info!(
                "Querying NVD API for {} components (this may be slow due to rate limiting)...",
                nvd_targets.len()
            );
            let nvd_vulns = nvd::query_batch(&nvd_targets).await?;
            all_vulns.extend(nvd_vulns);
        }
    } else if !no_purl_components.is_empty() {
        // Components without PURL and NVD not explicitly enabled:
        // still try NVD for these as a fallback since OSV can't handle them
        tracing::info!(
            "Querying NVD API for {} components without PURLs...",
            no_purl_components.len()
        );
        let nvd_vulns = nvd::query_batch(&no_purl_components).await?;
        all_vulns.extend(nvd_vulns);
    }

    // Step 3: Smart deduplication - merge results from multiple sources
    let merged = deduplicate_vulns(all_vulns);

    Ok(merged)
}

/// Match vulnerabilities using only the local database (offline mode)
pub async fn match_offline(components: &[Component]) -> Result<Vec<VulnMatch>> {
    crate::db::lookup_offline(components)
}

/// Deduplicate vulnerability matches across sources.
///
/// When the same CVE is reported by both OSV and NVD for the same component:
/// - Keep the entry with the best data quality
/// - Prefer OSV for: fixed_version (more accurate, package-level)
/// - Prefer NVD for: cvss_score, severity (authoritative CVSS source)
/// - Merge description from whichever has more detail
fn deduplicate_vulns(vulns: Vec<VulnMatch>) -> Vec<VulnMatch> {
    // Key: (component_name, cve_id)
    let mut merged: HashMap<(String, String), VulnMatch> = HashMap::new();

    for vuln in vulns {
        let key = (vuln.component_name.clone(), vuln.cve_id.clone());

        match merged.get_mut(&key) {
            Some(existing) => {
                merge_vuln_match(existing, &vuln);
            }
            None => {
                merged.insert(key, vuln);
            }
        }
    }

    let mut result: Vec<VulnMatch> = merged.into_values().collect();
    result.sort_by(|a, b| (&a.component_name, &a.cve_id).cmp(&(&b.component_name, &b.cve_id)));
    result
}

/// Merge a new VulnMatch into an existing one, picking the best fields from each.
fn merge_vuln_match(existing: &mut VulnMatch, incoming: &VulnMatch) {
    // Prefer NVD for CVSS scores (authoritative source); fall back to any available score
    if incoming.cvss_score.is_some()
        && (incoming.source == VulnSource::Nvd || existing.cvss_score.is_none())
    {
        existing.cvss_score = incoming.cvss_score;
        existing.severity = incoming.severity;
    }

    // Prefer OSV for fixed_version (package-level, more accurate); fall back to any available
    if incoming.fixed_version.is_some()
        && (incoming.source == VulnSource::Osv || existing.fixed_version.is_none())
    {
        existing.fixed_version = incoming.fixed_version.clone();
    }

    // Use longer description (more informative)
    if incoming.description.len() > existing.description.len() {
        existing.description = incoming.description.clone();
    }

    // Use non-empty affected_versions
    if existing.affected_versions.is_empty() && !incoming.affected_versions.is_empty() {
        existing.affected_versions = incoming.affected_versions.clone();
    }

    // Mark source as merged (prefer showing original primary source)
    // Keep whichever source was first (usually OSV since we query it first)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;

    fn make_vuln(
        component: &str,
        cve: &str,
        source: VulnSource,
        cvss: Option<f64>,
        fixed: Option<&str>,
        desc: &str,
    ) -> VulnMatch {
        VulnMatch {
            component_name: component.to_string(),
            component_version: "1.0.0".to_string(),
            cve_id: cve.to_string(),
            severity: cvss.map(Severity::from_cvss).unwrap_or(Severity::Unknown),
            cvss_score: cvss,
            source,
            affected_versions: String::new(),
            fixed_version: fixed.map(|s| s.to_string()),
            description: desc.to_string(),
        }
    }

    #[test]
    fn test_dedup_no_duplicates() {
        let vulns = vec![
            make_vuln(
                "openssl",
                "CVE-2024-0001",
                VulnSource::Osv,
                Some(7.5),
                Some("1.1.1w"),
                "OSV desc",
            ),
            make_vuln(
                "curl",
                "CVE-2024-0002",
                VulnSource::Nvd,
                Some(9.8),
                None,
                "NVD desc",
            ),
        ];
        let result = deduplicate_vulns(vulns);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_dedup_merge_osv_nvd() {
        let vulns = vec![
            // OSV result: has fix version, no CVSS
            make_vuln(
                "openssl",
                "CVE-2024-0001",
                VulnSource::Osv,
                None,
                Some("1.1.1w"),
                "Short",
            ),
            // NVD result: has CVSS, no fix version, longer description
            make_vuln(
                "openssl",
                "CVE-2024-0001",
                VulnSource::Nvd,
                Some(7.5),
                None,
                "Detailed NVD description of the vulnerability",
            ),
        ];

        let result = deduplicate_vulns(vulns);
        assert_eq!(result.len(), 1);

        let merged = &result[0];
        // Should have NVD's CVSS score
        assert_eq!(merged.cvss_score, Some(7.5));
        assert_eq!(merged.severity, Severity::High);
        // Should have OSV's fix version
        assert_eq!(merged.fixed_version, Some("1.1.1w".to_string()));
        // Should have the longer description (from NVD)
        assert!(merged.description.contains("Detailed NVD description"));
    }

    #[test]
    fn test_dedup_prefer_nvd_cvss_over_osv() {
        let vulns = vec![
            make_vuln(
                "lib",
                "CVE-2024-0001",
                VulnSource::Osv,
                Some(6.0),
                Some("2.0.0"),
                "OSV",
            ),
            make_vuln(
                "lib",
                "CVE-2024-0001",
                VulnSource::Nvd,
                Some(7.5),
                None,
                "NVD",
            ),
        ];

        let result = deduplicate_vulns(vulns);
        assert_eq!(result.len(), 1);
        // NVD CVSS should win
        assert_eq!(result[0].cvss_score, Some(7.5));
        // OSV fix version should be preserved
        assert_eq!(result[0].fixed_version, Some("2.0.0".to_string()));
    }

    #[test]
    fn test_dedup_different_components_same_cve() {
        // Same CVE affecting different components should NOT be merged
        let vulns = vec![
            make_vuln(
                "lib-a",
                "CVE-2024-0001",
                VulnSource::Osv,
                Some(7.0),
                None,
                "A",
            ),
            make_vuln(
                "lib-b",
                "CVE-2024-0001",
                VulnSource::Nvd,
                Some(7.0),
                None,
                "B",
            ),
        ];
        let result = deduplicate_vulns(vulns);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_dedup_preserves_osv_fix_when_nvd_has_none() {
        let vulns = vec![
            make_vuln(
                "pkg",
                "CVE-2024-0001",
                VulnSource::Nvd,
                Some(8.0),
                None,
                "NVD",
            ),
            make_vuln(
                "pkg",
                "CVE-2024-0001",
                VulnSource::Osv,
                None,
                Some("3.1.0"),
                "OSV",
            ),
        ];
        let result = deduplicate_vulns(vulns);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].fixed_version, Some("3.1.0".to_string()));
        assert_eq!(result[0].cvss_score, Some(8.0));
    }
}
