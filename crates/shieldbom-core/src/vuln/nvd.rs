use std::env;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;

use crate::models::{
    AffectedVersions, Component, Severity, VersionRangeInfo, VulnMatch, VulnSource,
};
use crate::version::{fuzzy_vendor_match, parse_cpe_parts, SemVer, VersionRange};

const NVD_API_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// Rate limit: 5 req/30s without key, 50 req/30s with key.
/// We use a conservative per-request delay to stay within limits.
const DELAY_WITHOUT_KEY: Duration = Duration::from_millis(6500); // ~4.6 req/30s
const DELAY_WITH_KEY: Duration = Duration::from_millis(650); // ~46 req/30s

// -- NVD API 2.0 response structures --

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[allow(dead_code)]
    #[serde(default, rename = "resultsPerPage")]
    results_per_page: u32,
    #[allow(dead_code)]
    #[serde(default, rename = "totalResults")]
    total_results: u32,
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnWrapper>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnWrapper {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    id: String,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    #[serde(default)]
    metrics: NvdMetrics,
    #[serde(default)]
    configurations: Vec<NvdConfiguration>,
}

#[derive(Debug, Default, Deserialize)]
struct NvdMetrics {
    #[serde(default, rename = "cvssMetricV31")]
    cvss_v31: Vec<NvdCvssV31>,
    #[serde(default, rename = "cvssMetricV30")]
    cvss_v30: Vec<NvdCvssV30>,
}

#[derive(Debug, Deserialize)]
struct NvdCvssV31 {
    #[serde(rename = "cvssData")]
    cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
struct NvdCvssV30 {
    #[serde(rename = "cvssData")]
    cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
struct CvssData {
    #[serde(rename = "baseScore")]
    base_score: f64,
    #[allow(dead_code)]
    #[serde(rename = "baseSeverity")]
    base_severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

/// NVD configuration node - contains CPE match criteria with version ranges.
#[derive(Debug, Deserialize)]
struct NvdConfiguration {
    #[serde(default)]
    nodes: Vec<NvdNode>,
}

#[derive(Debug, Deserialize)]
struct NvdNode {
    #[serde(default, rename = "cpeMatch")]
    cpe_match: Vec<NvdCpeMatch>,
}

/// A single CPE match criterion from NVD, including version range boundaries.
#[derive(Debug, Deserialize)]
struct NvdCpeMatch {
    vulnerable: bool,
    criteria: String,
    #[serde(default, rename = "versionStartIncluding")]
    version_start_including: Option<String>,
    #[serde(default, rename = "versionStartExcluding")]
    version_start_excluding: Option<String>,
    #[serde(default, rename = "versionEndIncluding")]
    version_end_including: Option<String>,
    #[serde(default, rename = "versionEndExcluding")]
    version_end_excluding: Option<String>,
}

/// Query NVD API 2.0 for vulnerabilities matching the given components.
///
/// Uses CPE match when a component has a `cpe` field, otherwise falls back
/// to keyword search by package name.
pub async fn query_batch(components: &[&Component]) -> Result<Vec<VulnMatch>> {
    let api_key = env::var("SHIELDBOM_NVD_API_KEY").ok();
    let delay = if api_key.is_some() {
        DELAY_WITH_KEY
    } else {
        DELAY_WITHOUT_KEY
    };

    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(ref key) = api_key {
        if let Ok(val) = reqwest::header::HeaderValue::from_str(key) {
            headers.insert("apiKey", val);
        }
    }

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .build()?;

    let mut results = Vec::new();

    for (i, component) in components.iter().enumerate() {
        if component.version.is_empty() {
            continue;
        }

        // Rate-limit: wait between requests (skip delay before the first)
        if i > 0 {
            tokio::time::sleep(delay).await;
        }

        let vulns = if let Some(cpe) = &component.cpe {
            query_by_cpe(&client, cpe, component).await
        } else {
            query_by_keyword(&client, &component.name, component).await
        };

        match vulns {
            Ok(v) => results.extend(v),
            Err(e) => {
                tracing::warn!(
                    "NVD API error for {}@{}: {e}",
                    component.name,
                    component.version
                );
            }
        }
    }

    Ok(results)
}

async fn query_by_cpe(
    client: &reqwest::Client,
    cpe: &str,
    component: &Component,
) -> Result<Vec<VulnMatch>> {
    let url = format!("{}?cpeName={}", NVD_API_URL, cpe);
    fetch_and_convert(client, &url, component).await
}

async fn query_by_keyword(
    client: &reqwest::Client,
    keyword: &str,
    component: &Component,
) -> Result<Vec<VulnMatch>> {
    let url = format!("{}?keywordSearch={}", NVD_API_URL, keyword);
    fetch_and_convert(client, &url, component).await
}

async fn fetch_and_convert(
    client: &reqwest::Client,
    url: &str,
    component: &Component,
) -> Result<Vec<VulnMatch>> {
    let resp = client.get(url).send().await?;

    if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        tracing::warn!(
            "NVD rate limit hit for {}@{}, skipping",
            component.name,
            component.version
        );
        return Ok(Vec::new());
    }

    if resp.status() == reqwest::StatusCode::FORBIDDEN {
        tracing::warn!("NVD API returned 403 - check your API key");
        return Ok(Vec::new());
    }

    if !resp.status().is_success() {
        tracing::warn!(
            "NVD API returned {} for {}@{}",
            resp.status(),
            component.name,
            component.version
        );
        return Ok(Vec::new());
    }

    let nvd_resp: NvdResponse = resp.json().await?;
    let mut results = Vec::new();

    for wrapper in &nvd_resp.vulnerabilities {
        // Apply version range filtering if configuration data is available
        if is_component_affected(&wrapper.cve, component) {
            results.push(convert_nvd_cve(&wrapper.cve, component));
        }
    }

    Ok(results)
}

/// Check whether a component is actually affected by this CVE
/// using NVD's CPE match configurations and version ranges.
fn is_component_affected(cve: &NvdCve, component: &Component) -> bool {
    // If there are no configurations, we can't filter - assume affected
    if cve.configurations.is_empty() {
        return true;
    }

    let component_version = match SemVer::parse(&component.version) {
        Some(v) => v,
        None => {
            // Cannot parse component version - fall back to accepting the match
            return true;
        }
    };

    for config in &cve.configurations {
        for node in &config.nodes {
            for cpe_match in &node.cpe_match {
                if !cpe_match.vulnerable {
                    continue;
                }

                // Check if this CPE match criterion applies to our component
                if !cpe_matches_component(&cpe_match.criteria, component) {
                    continue;
                }

                // Check version range
                let range = VersionRange::from_nvd(
                    cpe_match.version_start_including.as_deref(),
                    cpe_match.version_start_excluding.as_deref(),
                    cpe_match.version_end_including.as_deref(),
                    cpe_match.version_end_excluding.as_deref(),
                );

                if range.is_unbounded() {
                    // No version range specified in the match criteria.
                    // Check if the CPE itself has a specific version.
                    if let Some(cpe_parts) = parse_cpe_parts(&cpe_match.criteria) {
                        if let Some(cpe_ver_str) = &cpe_parts.version {
                            // CPE has a specific version - only match if component version matches
                            if let Some(cpe_ver) = SemVer::parse(cpe_ver_str) {
                                if component_version == cpe_ver {
                                    return true;
                                }
                            }
                            // If we can't parse the CPE version, fall through
                        } else {
                            // CPE version is wildcard (*) - matches all versions
                            return true;
                        }
                    }
                } else if range.contains(&component_version) {
                    return true;
                }
            }
        }
    }

    false
}

/// Check if a CPE match criteria string applies to a given component,
/// using fuzzy vendor/product matching.
fn cpe_matches_component(cpe_criteria: &str, component: &Component) -> bool {
    let cpe_parts = match parse_cpe_parts(cpe_criteria) {
        Some(p) => p,
        None => return false,
    };

    // If the component has its own CPE, compare directly
    if let Some(component_cpe) = &component.cpe {
        if let Some(comp_parts) = parse_cpe_parts(component_cpe) {
            // Compare vendor (fuzzy) and product (fuzzy)
            let vendor_match = fuzzy_vendor_match(&cpe_parts.vendor, &comp_parts.vendor);
            let product_match =
                cpe_parts.product.to_lowercase() == comp_parts.product.to_lowercase();
            return vendor_match && product_match;
        }
    }

    // Fallback: match CPE product against component name using fuzzy matching
    let product_match = cpe_parts.product.to_lowercase() == component.name.to_lowercase()
        || fuzzy_vendor_match(&cpe_parts.product, &component.name);

    // Also check vendor against component name (some components match by vendor)
    let vendor_match = fuzzy_vendor_match(&cpe_parts.vendor, &component.name);

    product_match || vendor_match
}

fn convert_nvd_cve(cve: &NvdCve, component: &Component) -> VulnMatch {
    let (severity, cvss_score) = extract_severity(cve);
    let description = extract_description(cve);
    let (affected_versions, fixed_version) = extract_version_info(cve, component);

    VulnMatch {
        component_name: component.name.clone(),
        component_version: component.version.clone(),
        cve_id: cve.id.clone(),
        severity,
        cvss_score,
        source: VulnSource::Nvd,
        affected_versions: AffectedVersions {
            display: affected_versions.display,
            ranges: affected_versions.ranges,
        },
        fixed_version,
        description,
    }
}

fn extract_severity(cve: &NvdCve) -> (Severity, Option<f64>) {
    // Prefer CVSS v3.1, fall back to v3.0
    if let Some(metric) = cve.metrics.cvss_v31.first() {
        let score = metric.cvss_data.base_score;
        return (Severity::from_cvss(score), Some(score));
    }
    if let Some(metric) = cve.metrics.cvss_v30.first() {
        let score = metric.cvss_data.base_score;
        return (Severity::from_cvss(score), Some(score));
    }
    (Severity::Unknown, None)
}

fn extract_description(cve: &NvdCve) -> String {
    // Prefer English description
    cve.descriptions
        .iter()
        .find(|d| d.lang == "en")
        .or_else(|| cve.descriptions.first())
        .map(|d| d.value.clone())
        .unwrap_or_default()
}

/// Extract affected version range and fixed version from NVD configuration data.
fn extract_version_info(cve: &NvdCve, component: &Component) -> (AffectedVersions, Option<String>) {
    let mut display_parts = Vec::new();
    let mut ranges = Vec::new();
    let mut fixed_version: Option<String> = None;

    for config in &cve.configurations {
        for node in &config.nodes {
            for cpe_match in &node.cpe_match {
                if !cpe_match.vulnerable {
                    continue;
                }

                if !cpe_matches_component(&cpe_match.criteria, component) {
                    continue;
                }

                // Build a human-readable affected range
                let range_str = build_range_string(cpe_match);
                if !range_str.is_empty() {
                    display_parts.push(range_str);
                }

                // Build structured range info
                ranges.push(VersionRangeInfo {
                    introduced: cpe_match
                        .version_start_including
                        .clone()
                        .or_else(|| cpe_match.version_start_excluding.clone()),
                    fixed: cpe_match.version_end_excluding.clone(),
                });

                // The versionEndExcluding is often the fix version
                if fixed_version.is_none() {
                    if let Some(ref end_excl) = cpe_match.version_end_excluding {
                        fixed_version = Some(end_excl.clone());
                    }
                }
            }
        }
    }

    let affected = AffectedVersions {
        display: display_parts.join("; "),
        ranges,
    };
    (affected, fixed_version)
}

/// Build a human-readable version range string from a CPE match criterion.
fn build_range_string(cpe_match: &NvdCpeMatch) -> String {
    let mut parts = Vec::new();

    if let Some(ref v) = cpe_match.version_start_including {
        parts.push(format!(">={}", v));
    }
    if let Some(ref v) = cpe_match.version_start_excluding {
        parts.push(format!(">{}", v));
    }
    if let Some(ref v) = cpe_match.version_end_including {
        parts.push(format!("<={}", v));
    }
    if let Some(ref v) = cpe_match.version_end_excluding {
        parts.push(format!("<{}", v));
    }

    parts.join(", ")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SourceFormat;

    fn make_component(name: &str, version: &str, cpe: Option<&str>) -> Component {
        Component {
            name: name.to_string(),
            version: version.to_string(),
            supplier: None,
            cpe: cpe.map(|s| s.to_string()),
            purl: None,
            licenses: vec![],
            hashes: vec![],
            source_format: SourceFormat::Unknown,
        }
    }

    #[test]
    fn test_cpe_matches_component_exact() {
        let comp = make_component(
            "openssl",
            "1.1.1",
            Some("cpe:2.3:a:openssl_project:openssl:1.1.1:*:*:*:*:*:*:*"),
        );
        assert!(cpe_matches_component(
            "cpe:2.3:a:openssl_project:openssl:1.1.1:*:*:*:*:*:*:*",
            &comp
        ));
    }

    #[test]
    fn test_cpe_matches_component_fuzzy_vendor() {
        // Component CPE has "openssl" as vendor, NVD has "openssl_project"
        let comp = make_component(
            "openssl",
            "1.1.1",
            Some("cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"),
        );
        assert!(cpe_matches_component(
            "cpe:2.3:a:openssl_project:openssl:*:*:*:*:*:*:*:*",
            &comp
        ));
    }

    #[test]
    fn test_cpe_matches_component_by_name() {
        // No CPE on component, match by name
        let comp = make_component("openssl", "1.1.1", None);
        assert!(cpe_matches_component(
            "cpe:2.3:a:openssl_project:openssl:*:*:*:*:*:*:*:*",
            &comp
        ));
    }

    #[test]
    fn test_cpe_no_match_different_product() {
        let comp = make_component("curl", "7.0.0", None);
        assert!(!cpe_matches_component(
            "cpe:2.3:a:openssl_project:openssl:*:*:*:*:*:*:*:*",
            &comp
        ));
    }

    #[test]
    fn test_is_component_affected_version_range() {
        let comp = make_component(
            "openssl",
            "1.1.1k",
            Some("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"),
        );

        // Note: "1.1.1k" won't parse as semver cleanly (the 'k' part),
        // so the function should fall back to accepting the match.
        let cve = NvdCve {
            id: "CVE-2024-TEST".to_string(),
            descriptions: vec![],
            metrics: NvdMetrics::default(),
            configurations: vec![NvdConfiguration {
                nodes: vec![NvdNode {
                    cpe_match: vec![NvdCpeMatch {
                        vulnerable: true,
                        criteria: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*".to_string(),
                        version_start_including: Some("1.1.1".to_string()),
                        version_start_excluding: None,
                        version_end_excluding: Some("1.1.1t".to_string()),
                        version_end_including: None,
                    }],
                }],
            }],
        };

        // Can't parse "1.1.1k" as semver, so it falls back to true
        assert!(is_component_affected(&cve, &comp));
    }

    #[test]
    fn test_is_component_affected_semver_range() {
        let comp = make_component("mylib", "1.3.0", None);

        let cve = NvdCve {
            id: "CVE-2024-TEST".to_string(),
            descriptions: vec![],
            metrics: NvdMetrics::default(),
            configurations: vec![NvdConfiguration {
                nodes: vec![NvdNode {
                    cpe_match: vec![NvdCpeMatch {
                        vulnerable: true,
                        criteria: "cpe:2.3:a:mylib:mylib:*:*:*:*:*:*:*:*".to_string(),
                        version_start_including: Some("1.0.0".to_string()),
                        version_start_excluding: None,
                        version_end_excluding: Some("1.5.0".to_string()),
                        version_end_including: None,
                    }],
                }],
            }],
        };

        assert!(is_component_affected(&cve, &comp));
    }

    #[test]
    fn test_is_component_not_affected_outside_range() {
        let comp = make_component("mylib", "2.0.0", None);

        let cve = NvdCve {
            id: "CVE-2024-TEST".to_string(),
            descriptions: vec![],
            metrics: NvdMetrics::default(),
            configurations: vec![NvdConfiguration {
                nodes: vec![NvdNode {
                    cpe_match: vec![NvdCpeMatch {
                        vulnerable: true,
                        criteria: "cpe:2.3:a:mylib:mylib:*:*:*:*:*:*:*:*".to_string(),
                        version_start_including: Some("1.0.0".to_string()),
                        version_start_excluding: None,
                        version_end_excluding: Some("1.5.0".to_string()),
                        version_end_including: None,
                    }],
                }],
            }],
        };

        assert!(!is_component_affected(&cve, &comp));
    }

    #[test]
    fn test_is_component_affected_no_configurations() {
        let comp = make_component("mylib", "1.0.0", None);

        let cve = NvdCve {
            id: "CVE-2024-TEST".to_string(),
            descriptions: vec![],
            metrics: NvdMetrics::default(),
            configurations: vec![],
        };

        // No configurations = assume affected (conservative)
        assert!(is_component_affected(&cve, &comp));
    }

    #[test]
    fn test_build_range_string() {
        let cpe_match = NvdCpeMatch {
            vulnerable: true,
            criteria: String::new(),
            version_start_including: Some("1.0.0".to_string()),
            version_start_excluding: None,
            version_end_excluding: Some("2.0.0".to_string()),
            version_end_including: None,
        };
        assert_eq!(build_range_string(&cpe_match), ">=1.0.0, <2.0.0");
    }

    #[test]
    fn test_build_range_string_end_only() {
        let cpe_match = NvdCpeMatch {
            vulnerable: true,
            criteria: String::new(),
            version_start_including: None,
            version_start_excluding: None,
            version_end_excluding: Some("3.0.0".to_string()),
            version_end_including: None,
        };
        assert_eq!(build_range_string(&cpe_match), "<3.0.0");
    }
}
