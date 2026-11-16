use std::env;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;

use crate::models::{
    AffectedVersions, Component, ScanGap, Severity, VersionRangeInfo, VulnMatch, VulnSource,
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
    /// Required on purpose: a 200 response without it is not an NVD result
    /// page and must not be read as "0 vulnerabilities".
    #[serde(rename = "totalResults")]
    total_results: u32,
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnWrapper>,
}

/// Upper bound on result pages fetched per component (2000 CVEs each).
/// Beyond this the lookup is reported as truncated rather than complete.
const MAX_PAGES: usize = 5;

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

/// Query NVD for each component.
///
/// Every lookup that fails (network error, rate limit, auth, bad response) or
/// cannot be attempted is returned as a [`ScanGap`] instead of being dropped.
pub async fn query_batch(components: &[&Component]) -> Result<(Vec<VulnMatch>, Vec<ScanGap>)> {
    // A key that cannot be sent as a header is treated as no key, loudly:
    // sending nothing at the with-key rate would only produce HTTP 429s.
    let mut headers = reqwest::header::HeaderMap::new();
    let mut has_key = false;
    if let Ok(key) = env::var("SHIELDBOM_NVD_API_KEY") {
        match reqwest::header::HeaderValue::from_str(key.trim()) {
            Ok(mut val) if !key.trim().is_empty() => {
                val.set_sensitive(true);
                headers.insert("apiKey", val);
                has_key = true;
            }
            _ => eprintln!(
                "Warning: SHIELDBOM_NVD_API_KEY is empty or contains invalid characters; \
                 querying NVD without an API key."
            ),
        }
    }
    let delay = if has_key {
        DELAY_WITH_KEY
    } else {
        DELAY_WITHOUT_KEY
    };

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .build()?;

    let mut results = Vec::new();
    let mut gaps = Vec::new();
    let mut requests_sent = 0usize;
    let mut streak = super::UnreachableStreak::default();

    for component in components {
        if component.version.is_empty() {
            gaps.push(ScanGap::new(
                component,
                "NVD",
                "no version in SBOM; not queried",
            ));
            continue;
        }

        if streak.exhausted() {
            gaps.push(ScanGap::new(
                component,
                "NVD",
                "not queried: NVD unreachable or not responding",
            ));
            continue;
        }

        // Rate-limit: wait between requests (skip delay before the first)
        if requests_sent > 0 {
            tokio::time::sleep(delay).await;
        }
        requests_sent += 1;

        // Passed as a query parameter so reqwest percent-encodes it; SBOM
        // strings such as "libstdc++" or "a&b" must not reshape the request.
        let param = match &component.cpe {
            Some(cpe) => ("cpeName", cpe.as_str()),
            None => ("keywordSearch", component.name.as_str()),
        };
        let (vulns, failure) = fetch_and_convert(&client, param, component, delay).await;
        results.extend(vulns);
        streak.record(failure.as_ref().map(|e| {
            e.downcast_ref::<reqwest::Error>()
                .is_some_and(super::is_unreachable)
        }));
        if let Some(e) = failure {
            gaps.push(ScanGap::new(component, "NVD", describe_error(&e)));
        }
    }

    Ok((results, gaps))
}

/// Error text for a gap. Request URLs are left out: they add noise and would
/// echo SBOM-controlled strings back into reports.
fn describe_error(e: &anyhow::Error) -> String {
    match e.downcast_ref::<reqwest::Error>() {
        Some(r) => super::describe_request_error(r).to_string(),
        None => e.to_string(),
    }
}

/// A non-success HTTP status from NVD.
#[derive(Debug, PartialEq, Eq)]
struct StatusError(u16);

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            429 => write!(
                f,
                "rate limited (HTTP 429); set SHIELDBOM_NVD_API_KEY or retry later"
            ),
            403 => write!(f, "HTTP 403; check SHIELDBOM_NVD_API_KEY or retry later"),
            code => write!(f, "HTTP {code}"),
        }
    }
}

impl std::error::Error for StatusError {}

/// Maps an NVD HTTP status to an error. A failed lookup is an error, never an
/// empty result: "no answer" must not be reported as "no vulnerabilities".
fn check_status(status: reqwest::StatusCode) -> Result<()> {
    if status.is_success() {
        Ok(())
    } else {
        Err(StatusError(status.as_u16()).into())
    }
}

/// Attempts per result page. NVD is frequently slow or briefly unavailable;
/// without a retry, ordinary scans would often end up marked incomplete.
const MAX_ATTEMPTS: usize = 3;

/// True for failures worth retrying: transport errors, rate limiting and
/// server-side errors. Client errors (bad key, bad request) are not.
fn is_retryable(e: &anyhow::Error) -> bool {
    match e.downcast_ref::<StatusError>() {
        Some(StatusError(code)) => *code == 429 || *code >= 500,
        None => e
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|r| r.is_timeout() || !r.is_decode()),
    }
}

/// Fetches one result page, without retrying.
async fn fetch_page(
    client: &reqwest::Client,
    param: (&str, &str),
    start_index: usize,
) -> Result<NvdResponse> {
    let start = start_index.to_string();
    let resp = client
        .get(NVD_API_URL)
        .query(&[param, ("startIndex", start.as_str())])
        .send()
        .await?;
    check_status(resp.status())?;
    Ok(resp.json().await?)
}

/// What to do after receiving a result page.
#[derive(Debug, PartialEq, Eq)]
enum NextStep {
    Done,
    /// Fetch the next page starting at this index.
    Fetch(usize),
}

/// Decides whether more pages are needed. Errors when the result set cannot be
/// read to the end, so a partial list is never treated as complete.
fn next_step(total: usize, fetched: usize, page_len: usize, pages_done: usize) -> Result<NextStep> {
    if fetched >= total {
        return Ok(NextStep::Done);
    }
    if page_len == 0 || pages_done >= MAX_PAGES {
        anyhow::bail!(
            "results truncated ({fetched} of {total} CVEs read); \
             add a CPE to this SBOM entry to narrow the lookup"
        );
    }
    Ok(NextStep::Fetch(fetched))
}

/// Reads every result page for one component. Findings read before a failure
/// are still returned alongside the error: dropping them could hide a
/// known-exploited CVE behind a mere "incomplete".
async fn fetch_and_convert(
    client: &reqwest::Client,
    param: (&str, &str),
    component: &Component,
    delay: Duration,
) -> (Vec<VulnMatch>, Option<anyhow::Error>) {
    let mut results = Vec::new();
    let mut start_index = 0usize;
    let mut fetched = 0usize;
    let mut pages_done = 0usize;

    loop {
        let mut attempt = 1;
        let nvd_resp = loop {
            match fetch_page(client, param, start_index).await {
                Ok(page) => break page,
                Err(e) if attempt < MAX_ATTEMPTS && is_retryable(&e) => {
                    attempt += 1;
                    tokio::time::sleep(delay).await;
                }
                // Still failing after the retries: the caller records a gap.
                Err(e) => return (results, Some(e)),
            }
        };
        pages_done += 1;
        fetched += nvd_resp.vulnerabilities.len();

        for wrapper in &nvd_resp.vulnerabilities {
            // Apply version range filtering if configuration data is available
            if is_component_affected(&wrapper.cve, component) {
                results.push(convert_nvd_cve(&wrapper.cve, component));
            }
        }

        match next_step(
            nvd_resp.total_results as usize,
            fetched,
            nvd_resp.vulnerabilities.len(),
            pages_done,
        ) {
            Ok(NextStep::Done) => return (results, None),
            Ok(NextStep::Fetch(next)) => {
                start_index = next;
                tokio::time::sleep(delay).await;
            }
            Err(e) => return (results, Some(e)),
        }
    }
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
        in_kev: false,
        kev_due_date: None,
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

    // Regression (v0.3.0): 429/403/5xx were turned into empty results.
    #[test]
    fn test_check_status_errors_are_not_empty_results() {
        use reqwest::StatusCode;
        assert!(check_status(StatusCode::OK).is_ok());
        for code in [429u16, 403, 404, 500, 503] {
            let status = StatusCode::from_u16(code).unwrap();
            assert!(
                check_status(status).is_err(),
                "HTTP {code} must be an error"
            );
        }
    }

    #[test]
    fn test_is_retryable() {
        for code in [429u16, 500, 502, 503] {
            assert!(is_retryable(&StatusError(code).into()), "HTTP {code}");
        }
        for code in [400u16, 403, 404] {
            assert!(!is_retryable(&StatusError(code).into()), "HTTP {code}");
        }
        assert!(!is_retryable(&anyhow::anyhow!("results truncated")));
    }

    #[test]
    fn test_status_error_messages_name_the_api_key() {
        assert!(StatusError(429)
            .to_string()
            .contains("SHIELDBOM_NVD_API_KEY"));
        assert!(StatusError(403).to_string().contains("HTTP 403"));
        assert_eq!(StatusError(503).to_string(), "HTTP 503");
    }

    #[test]
    fn test_next_step_paging() {
        assert_eq!(next_step(0, 0, 0, 1).unwrap(), NextStep::Done);
        assert_eq!(next_step(150, 150, 150, 1).unwrap(), NextStep::Done);
        assert_eq!(
            next_step(2500, 2000, 2000, 1).unwrap(),
            NextStep::Fetch(2000)
        );
        // Page cap reached with results left: must not be treated as complete.
        assert!(next_step(26535, 10000, 2000, MAX_PAGES).is_err());
        // Server claims more results but sends none: must not loop or pass.
        assert!(next_step(10, 0, 0, 1).is_err());
    }

    // A 200 response that is not an NVD result page must fail to parse.
    #[test]
    fn test_response_without_total_results_is_rejected() {
        assert!(serde_json::from_str::<NvdResponse>("{}").is_err());
        assert!(serde_json::from_str::<NvdResponse>(r#"{"message":"x"}"#).is_err());
        let ok: NvdResponse =
            serde_json::from_str(r#"{"totalResults":0,"vulnerabilities":[]}"#).unwrap();
        assert_eq!(ok.total_results, 0);
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
