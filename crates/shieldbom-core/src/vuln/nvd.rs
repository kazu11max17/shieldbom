use std::env;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;

use crate::models::{
    AffectedVersions, Component, ScanGap, Severity, VersionRangeInfo, VulnMatch, VulnSource,
};
use crate::version::{
    fuzzy_vendor_match, parse_cpe_parts, SemVer, VersionRange, NVD_NAME_SUFFIXES,
};

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
    /// "Analyzed", "Awaiting Analysis", "Rejected", ... A rejected record is
    /// not a vulnerability (withdrawn, duplicate or "DO NOT USE").
    #[serde(default, rename = "vulnStatus")]
    vuln_status: Option<String>,
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

        results.extend(convert_page(&nvd_resp, component));

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

/// Findings for one component from one result page. Rejected records are
/// skipped; the rest are filtered by NVD's product and version data.
fn convert_page(page: &NvdResponse, component: &Component) -> Vec<VulnMatch> {
    page.vulnerabilities
        .iter()
        .filter(|w| !is_rejected(&w.cve))
        .filter_map(|w| match affects_component(&w.cve, component) {
            Applicability::Confirmed => Some(convert_nvd_cve(&w.cve, component, false)),
            Applicability::Unconfirmed => Some(convert_nvd_cve(&w.cve, component, true)),
            Applicability::NotAffected => None,
        })
        .collect()
}

/// True for records NVD has rejected. They carry no affected products and
/// would otherwise be reported as unconfirmed findings.
fn is_rejected(cve: &NvdCve) -> bool {
    cve.vuln_status
        .as_deref()
        .is_some_and(|s| s.eq_ignore_ascii_case("rejected"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Applicability {
    /// NVD's CPE configuration names this product and a range containing the
    /// component's version (or, as in 0.3.1, the component version cannot be
    /// compared and the match is accepted).
    Confirmed,
    /// Could not be checked: NVD has no configuration for the CVE (common for
    /// "Awaiting Analysis" / "Deferred" records, which a keyword search returns
    /// whenever the name appears in the description), or a matching CPE entry
    /// has a version boundary that cannot be parsed. Reported, but flagged.
    Unconfirmed,
    NotAffected,
}

/// Check whether a component is actually affected by this CVE
/// using NVD's CPE match configurations and version ranges.
fn affects_component(cve: &NvdCve, component: &Component) -> Applicability {
    // No configurations: nothing to check the match against. Keep it rather
    // than drop it (no silent misses), but do not present it as confirmed.
    if cve.configurations.is_empty() {
        return Applicability::Unconfirmed;
    }

    let component_version = match SemVer::parse(&component.version) {
        Some(v) => v,
        None => {
            // Cannot parse component version - fall back to accepting the match
            // (unchanged from 0.3.1; see the v0.3.2 notes before narrowing it),
            // unless the only matching CPEs are other products' (loose).
            return if best_product_match(cve, component) == CpeMatch::Loose {
                Applicability::Unconfirmed
            } else {
                Applicability::Confirmed
            };
        }
    };

    // A matching CPE entry whose version could not be compared, or whose
    // product only loosely matches the component name. If nothing else
    // confirms the match, report it as unconfirmed instead of dropping it.
    let mut not_comparable = false;

    for config in &cve.configurations {
        for node in &config.nodes {
            for cpe_match in &node.cpe_match {
                if !cpe_match.vulnerable {
                    continue;
                }

                // Check if this CPE match criterion applies to our component
                let product = cpe_matches_component(&cpe_match.criteria, component);
                if product == CpeMatch::None {
                    continue;
                }
                // A loose name match (e.g. `openssl.js` for `openssl`) may be
                // another product: never confirm on it.
                let confirmed = if product == CpeMatch::Exact {
                    Applicability::Confirmed
                } else {
                    Applicability::Unconfirmed
                };

                // Check version range
                let range = VersionRange::from_nvd(
                    cpe_match.version_start_including.as_deref(),
                    cpe_match.version_start_excluding.as_deref(),
                    cpe_match.version_end_including.as_deref(),
                    cpe_match.version_end_excluding.as_deref(),
                );

                if range.unparsed {
                    // Do not drop the boundary: that widens the range (v0.3.2
                    // put Heartbleed, `<1.0.1g`, on OpenSSL 3.0.8).
                    not_comparable = true;
                } else if range.is_unbounded() {
                    // No version range specified in the match criteria.
                    // Check if the CPE itself has a specific version.
                    if let Some(cpe_parts) = parse_cpe_parts(&cpe_match.criteria) {
                        if let Some(cpe_ver_str) = &cpe_parts.version {
                            // CPE has a specific version - only match if component version matches
                            if let Some(cpe_ver) = SemVer::parse(cpe_ver_str) {
                                if component_version == cpe_ver {
                                    if confirmed == Applicability::Confirmed {
                                        return confirmed;
                                    }
                                    not_comparable = true;
                                }
                            } else if cpe_ver_str != "-" {
                                // "-" is "not applicable" in CPE, not a version.
                                not_comparable = true;
                            }
                        } else {
                            // CPE version is wildcard (*) - matches all versions
                            if confirmed == Applicability::Confirmed {
                                return confirmed;
                            }
                            not_comparable = true;
                        }
                    }
                } else if range.contains(&component_version) {
                    if confirmed == Applicability::Confirmed {
                        return confirmed;
                    }
                    not_comparable = true;
                }
            }
        }
    }

    if not_comparable {
        Applicability::Unconfirmed
    } else {
        Applicability::NotAffected
    }
}

/// How a CPE match criterion relates to a component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpeMatch {
    None,
    /// Same product, or a name NVD extends with `_` (`linux` and
    /// `linux_kernel`, `confluence` and `confluence_server`), as before 0.3.4.
    Exact,
    /// A name match that points at another product: the CPE is for a
    /// language package (`openssl.js` for node.js, `openssl_encrypt` for
    /// python), or the name continues with `.` or `-` (`openssl-feedstock`).
    /// It can only yield an unconfirmed finding.
    Loose,
}

/// Target software values (CPE 2.3 field 10) of language package ecosystems.
/// A CPE for such a package is a different product from a C library of the
/// same name.
const LANGUAGE_TARGETS: [&str; 12] = [
    "node.js", "nodejs", "npm", "python", "pypi", "ruby", "rubygems", "php", "perl", "go", "rust",
    "java",
];

/// Check if a CPE match criteria string applies to a given component.
fn cpe_matches_component(cpe_criteria: &str, component: &Component) -> CpeMatch {
    let cpe_parts = match parse_cpe_parts(cpe_criteria) {
        Some(p) => p,
        None => return CpeMatch::None,
    };

    // If the component has its own CPE, compare directly
    if let Some(component_cpe) = &component.cpe {
        if let Some(comp_parts) = parse_cpe_parts(component_cpe) {
            // Compare vendor (fuzzy) and product (exact)
            let vendor_match = fuzzy_vendor_match(&cpe_parts.vendor, &comp_parts.vendor);
            let product_match =
                cpe_parts.product.to_lowercase() == comp_parts.product.to_lowercase();
            return if vendor_match && product_match {
                CpeMatch::Exact
            } else {
                CpeMatch::None
            };
        }
    }

    // Fallback: match CPE product against component name
    if same_product_name(&cpe_parts.product, &component.name) {
        return CpeMatch::Exact;
    }
    if !(fuzzy_vendor_match(&cpe_parts.product, &component.name)
        || fuzzy_vendor_match(&cpe_parts.vendor, &component.name))
    {
        return CpeMatch::None;
    }
    if is_language_package(cpe_criteria)
        || extends_with_separator(&cpe_parts.product, &component.name)
    {
        CpeMatch::Loose
    } else {
        CpeMatch::Exact
    }
}

/// True when the CPE's target software is a language package ecosystem.
fn is_language_package(cpe_criteria: &str) -> bool {
    // cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:...
    cpe_criteria
        .split(':')
        .nth(10)
        .is_some_and(|t| LANGUAGE_TARGETS.contains(&t.to_lowercase().as_str()))
}

/// True when the CPE product is the component name followed by `.` or `-`
/// (`openssl.js`, `openssl-feedstock`). NVD joins words of one product with
/// `_`, so those are left alone.
fn extends_with_separator(cpe_product: &str, component_name: &str) -> bool {
    let product = cpe_product.to_lowercase();
    let name = component_name.to_lowercase();
    product
        .strip_prefix(name.as_str())
        .is_some_and(|rest| rest.starts_with(['.', '-']))
}

/// The strongest relation between the component and any vulnerable CPE entry.
fn best_product_match(cve: &NvdCve, component: &Component) -> CpeMatch {
    let mut best = CpeMatch::None;
    for m in cve
        .configurations
        .iter()
        .flat_map(|c| &c.nodes)
        .flat_map(|n| &n.cpe_match)
        .filter(|m| m.vulnerable)
    {
        match cpe_matches_component(&m.criteria, component) {
            CpeMatch::Exact => return CpeMatch::Exact,
            CpeMatch::Loose => best = CpeMatch::Loose,
            CpeMatch::None => {}
        }
    }
    best
}

/// Product names that differ only in case, `-`/`_`/space, or a suffix NVD
/// adds such as `_project`. Unlike `fuzzy_vendor_match`, no prefix matching.
fn same_product_name(cpe_product: &str, component_name: &str) -> bool {
    let norm = |s: &str| s.to_lowercase().replace(['-', ' '], "_");
    let (a, b) = (norm(cpe_product), norm(component_name));
    a == b
        || NVD_NAME_SUFFIXES.iter().any(|suf| {
            a.strip_suffix(suf) == Some(b.as_str()) || b.strip_suffix(suf) == Some(a.as_str())
        })
}

fn convert_nvd_cve(cve: &NvdCve, component: &Component, unconfirmed: bool) -> VulnMatch {
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
        unconfirmed,
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
    let component_version = SemVer::parse(&component.version);
    // Another product's fix is never named when this product is listed.
    let exact_listed = best_product_match(cve, component) == CpeMatch::Exact;
    // Fix of the range that contains the component's version. NVD lists one
    // range per release line; the first one is not necessarily ours (3.0.8 was
    // told to upgrade to 1.0.2zq).
    let mut fixed_version: Option<String> = None;
    // Fixes of ranges that cannot be compared with the component's version.
    let mut maybe_ours: Vec<String> = Vec::new();

    for config in &cve.configurations {
        for node in &config.nodes {
            for cpe_match in &node.cpe_match {
                if !cpe_match.vulnerable {
                    continue;
                }

                let product = cpe_matches_component(&cpe_match.criteria, component);
                if product == CpeMatch::None {
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
                let Some(ref end_excl) = cpe_match.version_end_excluding else {
                    continue;
                };
                if exact_listed && product != CpeMatch::Exact {
                    continue;
                }
                let range = VersionRange::from_nvd(
                    cpe_match.version_start_including.as_deref(),
                    cpe_match.version_start_excluding.as_deref(),
                    cpe_match.version_end_including.as_deref(),
                    Some(end_excl),
                );
                match component_version {
                    Some(ref ver) if !range.unparsed => {
                        if range.contains(ver) && fixed_version.is_none() {
                            fixed_version = Some(end_excl.clone());
                        }
                    }
                    _ => {
                        if !maybe_ours.contains(end_excl) {
                            maybe_ours.push(end_excl.clone());
                        }
                    }
                }
            }
        }
    }

    // No comparable range contains the version: name a fix only when a single
    // range might be ours, never guess between release lines. A range we know
    // the version is outside of is never a candidate.
    if fixed_version.is_none() && maybe_ours.len() == 1 {
        fixed_version = maybe_ours.pop();
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
        assert_eq!(
            cpe_matches_component(
                "cpe:2.3:a:openssl_project:openssl:1.1.1:*:*:*:*:*:*:*",
                &comp
            ),
            CpeMatch::Exact
        );
    }

    #[test]
    fn test_cpe_matches_component_fuzzy_vendor() {
        // Component CPE has "openssl" as vendor, NVD has "openssl_project"
        let comp = make_component(
            "openssl",
            "1.1.1",
            Some("cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"),
        );
        assert_eq!(
            cpe_matches_component("cpe:2.3:a:openssl_project:openssl:*:*:*:*:*:*:*:*", &comp),
            CpeMatch::Exact
        );
    }

    #[test]
    fn test_cpe_matches_component_by_name() {
        // No CPE on component, match by name
        let comp = make_component("openssl", "1.1.1", None);
        assert_eq!(
            cpe_matches_component("cpe:2.3:a:openssl_project:openssl:*:*:*:*:*:*:*:*", &comp),
            CpeMatch::Exact
        );
    }

    #[test]
    fn test_cpe_no_match_different_product() {
        let comp = make_component("curl", "7.0.0", None);
        assert_eq!(
            cpe_matches_component("cpe:2.3:a:openssl_project:openssl:*:*:*:*:*:*:*:*", &comp),
            CpeMatch::None
        );
    }

    #[test]
    fn test_affects_component_version_range() {
        let comp = make_component(
            "openssl",
            "1.1.1k",
            Some("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"),
        );

        // "1.1.1k" and "1.1.1t" are OpenSSL letter releases; both parse
        // since v0.3.3, and 1.1.1 <= 1.1.1k < 1.1.1t.
        let cve = NvdCve {
            id: "CVE-2024-TEST".to_string(),
            vuln_status: None,
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

        assert_eq!(affects_component(&cve, &comp), Applicability::Confirmed);
    }

    fn openssl_cve(cpe: &str, start_incl: Option<&str>, end_excl: Option<&str>) -> NvdCve {
        NvdCve {
            id: "CVE-2014-0160".to_string(),
            vuln_status: None,
            descriptions: vec![],
            metrics: NvdMetrics::default(),
            configurations: vec![NvdConfiguration {
                nodes: vec![NvdNode {
                    cpe_match: vec![NvdCpeMatch {
                        vulnerable: true,
                        criteria: cpe.to_string(),
                        version_start_including: start_incl.map(str::to_string),
                        version_start_excluding: None,
                        version_end_excluding: end_excl.map(str::to_string),
                        version_end_including: None,
                    }],
                }],
            }],
        }
    }

    // Regression (v0.3.2): "1.0.1g" did not parse, the bound was dropped and
    // Heartbleed (KEV) was confirmed on OpenSSL 3.0.8, failing the CRA check.
    #[test]
    fn test_affects_component_letter_release_bound() {
        let cve = openssl_cve(
            "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            Some("1.0.1"),
            Some("1.0.1g"),
        );
        let new = make_component("openssl", "3.0.8", None);
        assert_eq!(affects_component(&cve, &new), Applicability::NotAffected);
        // A KEV entry on an affected version must still be confirmed (Fail).
        let old = make_component("openssl", "1.0.1f", None);
        assert_eq!(affects_component(&cve, &old), Applicability::Confirmed);
    }

    #[test]
    fn test_affects_component_unparseable_bound_is_unconfirmed() {
        let cve = openssl_cve(
            "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            Some("1.0.1"),
            Some("2.4.x"),
        );
        let comp = make_component("openssl", "3.0.8", None);
        assert_eq!(affects_component(&cve, &comp), Applicability::Unconfirmed);
    }

    fn two_entries(first: NvdCpeMatch, second: NvdCpeMatch) -> NvdCve {
        NvdCve {
            id: "CVE-2024-TEST".to_string(),
            vuln_status: None,
            descriptions: vec![],
            metrics: NvdMetrics::default(),
            configurations: vec![NvdConfiguration {
                nodes: vec![NvdNode {
                    cpe_match: vec![first, second],
                }],
            }],
        }
    }

    fn entry(start_incl: &str, end_excl: &str) -> NvdCpeMatch {
        NvdCpeMatch {
            vulnerable: true,
            criteria: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*".to_string(),
            version_start_including: Some(start_incl.to_string()),
            version_start_excluding: None,
            version_end_excluding: Some(end_excl.to_string()),
            version_end_including: None,
        }
    }

    #[test]
    fn test_affects_component_unparseable_entry_mixed() {
        let comp = make_component("openssl", "3.0.8", None);
        // Another entry confirms the version: the unparseable one does not
        // downgrade it, in either order.
        let a = two_entries(entry("1.0.1", "2.4.x"), entry("3.0.0", "3.0.9"));
        let b = two_entries(entry("3.0.0", "3.0.9"), entry("1.0.1", "2.4.x"));
        assert_eq!(affects_component(&a, &comp), Applicability::Confirmed);
        assert_eq!(affects_component(&b, &comp), Applicability::Confirmed);
        // The other entry is out of range: still unconfirmed, not dropped.
        let c = two_entries(entry("1.0.1", "2.4.x"), entry("1.1.1", "1.1.1u"));
        assert_eq!(affects_component(&c, &comp), Applicability::Unconfirmed);
    }

    #[test]
    fn test_affects_component_exact_cpe_versions() {
        let comp = make_component("openssl", "1.0.1g", None);
        let same = openssl_cve("cpe:2.3:a:openssl:openssl:1.0.1g:*:*:*:*:*:*:*", None, None);
        assert_eq!(affects_component(&same, &comp), Applicability::Confirmed);
        let other = openssl_cve("cpe:2.3:a:openssl:openssl:1.0.1h:*:*:*:*:*:*:*", None, None);
        assert_eq!(affects_component(&other, &comp), Applicability::NotAffected);
        // "-" (not applicable) is not a version to compare against.
        let na = openssl_cve("cpe:2.3:a:openssl:openssl:-:*:*:*:*:*:*:*", None, None);
        assert_eq!(affects_component(&na, &comp), Applicability::NotAffected);
        let odd = openssl_cve("cpe:2.3:a:openssl:openssl:2.4.x:*:*:*:*:*:*:*", None, None);
        assert_eq!(affects_component(&odd, &comp), Applicability::Unconfirmed);
    }

    #[test]
    fn test_affects_component_semver_range() {
        let comp = make_component("mylib", "1.3.0", None);

        let cve = NvdCve {
            id: "CVE-2024-TEST".to_string(),
            vuln_status: None,
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

        assert_eq!(affects_component(&cve, &comp), Applicability::Confirmed);
    }

    #[test]
    fn test_affects_component_outside_range() {
        let comp = make_component("mylib", "2.0.0", None);

        let cve = NvdCve {
            id: "CVE-2024-TEST".to_string(),
            vuln_status: None,
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

        assert_eq!(affects_component(&cve, &comp), Applicability::NotAffected);
    }

    #[test]
    fn test_affects_component_no_configurations() {
        let comp = make_component("mylib", "1.0.0", None);

        let cve = NvdCve {
            id: "CVE-2024-TEST".to_string(),
            vuln_status: None,
            descriptions: vec![],
            metrics: NvdMetrics::default(),
            configurations: vec![],
        };

        // No configurations (NVD has not analysed it): kept, but flagged.
        // Regression (v0.3.1): these were reported as plain findings, e.g.
        // rethinkdb's bundled cJSON or U-Boot's lwIP wget against cjson/lwip.
        assert_eq!(affects_component(&cve, &comp), Applicability::Unconfirmed);
        assert!(convert_nvd_cve(&cve, &comp, true).unconfirmed);
        assert!(!convert_nvd_cve(&cve, &comp, false).unconfirmed);
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

    // Regression (v0.3.3): `openssl.js` (an npm package) matched `openssl` by
    // prefix and, with a wildcard version, was reported as confirmed.
    #[test]
    fn test_loose_product_match_is_unconfirmed() {
        let comp = make_component("openssl", "3.0.8", None);
        let crit = "cpe:2.3:a:openssl.js_project:openssl.js:*:*:*:*:*:node.js:*:*";
        assert_eq!(cpe_matches_component(crit, &comp), CpeMatch::Loose);
        let cve = openssl_cve(crit, None, None);
        assert_eq!(affects_component(&cve, &comp), Applicability::Unconfirmed);
        // Also inside a version range: still only unconfirmed.
        let ranged = openssl_cve(
            "cpe:2.3:a:conda-forge:openssl-feedstock:*:*:*:*:*:*:*:*",
            Some("3.0.0"),
            Some("3.0.9"),
        );
        assert_eq!(
            affects_component(&ranged, &comp),
            Applicability::Unconfirmed
        );
        // Outside the range it is not reported at all.
        let outside = openssl_cve(crit, Some("4.0.0"), Some("4.0.1"));
        assert_eq!(
            affects_component(&outside, &comp),
            Applicability::NotAffected
        );
    }

    #[test]
    fn test_same_product_name() {
        assert!(same_product_name("openssl", "OpenSSL"));
        assert!(same_product_name("busybox_project", "busybox"));
        assert!(same_product_name("libxml-2", "libxml_2"));
        assert!(!same_product_name("openssl.js", "openssl"));
        assert!(!same_product_name("openssl-feedstock", "openssl"));
    }

    // An exact product match next to a loose one still confirms.
    #[test]
    fn test_exact_match_wins_over_loose() {
        let comp = make_component("openssl", "3.0.8", None);
        let mut loose = entry("3.0.0", "3.0.9");
        loose.criteria = "cpe:2.3:a:openssl.js_project:openssl.js:*:*:*:*:*:*:*:*".to_string();
        let cve = two_entries(loose, entry("3.0.0", "3.0.9"));
        assert_eq!(affects_component(&cve, &comp), Applicability::Confirmed);
    }

    // Regression (v0.3.3): the fix of the first range was reported, so 3.0.8
    // was told to upgrade to 1.0.2zq.
    #[test]
    fn test_fixed_version_is_from_the_containing_range() {
        let comp = make_component("openssl", "3.0.8", None);
        let cve = two_entries(entry("1.0.2", "1.0.2zq"), entry("3.0.0", "3.0.21"));
        let (affected, fixed) = extract_version_info(&cve, &comp);
        assert_eq!(fixed.as_deref(), Some("3.0.21"));
        assert_eq!(affected.ranges.len(), 2, "all ranges are still listed");

        let old = make_component("openssl", "1.0.2k", None);
        assert_eq!(
            extract_version_info(&cve, &old).1.as_deref(),
            Some("1.0.2zq")
        );
    }

    #[test]
    fn test_fixed_version_not_guessed_between_release_lines() {
        let cve = two_entries(entry("1.0.2", "1.0.2zq"), entry("3.0.0", "3.0.21"));
        // Version that cannot be compared: two candidates, name neither.
        let odd = make_component("openssl", "vendor-build-7", None);
        assert_eq!(extract_version_info(&cve, &odd).1, None);
        // A single range still names its fix.
        let one = openssl_cve(
            "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            Some("3.0.0"),
            Some("3.0.21"),
        );
        assert_eq!(
            extract_version_info(&one, &odd).1.as_deref(),
            Some("3.0.21")
        );
    }

    #[test]
    fn test_rejected_records_are_detected() {
        let page: NvdResponse = serde_json::from_str(
            r#"{"totalResults":2,"vulnerabilities":[
                {"cve":{"id":"CVE-2006-7248","vulnStatus":"Rejected"}},
                {"cve":{"id":"CVE-2023-2650","vulnStatus":"Analyzed"}}]}"#,
        )
        .unwrap();
        let rejected: Vec<bool> = page
            .vulnerabilities
            .iter()
            .map(|w| is_rejected(&w.cve))
            .collect();
        assert_eq!(rejected, vec![true, false]);
        // Older responses without the field are kept.
        let none: NvdResponse = serde_json::from_str(
            r#"{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-1"}}]}"#,
        )
        .unwrap();
        assert!(!is_rejected(&none.vulnerabilities[0].cve));
    }

    fn cpe_entry(
        criteria: &str,
        start_incl: Option<&str>,
        end_incl: Option<&str>,
        end_excl: Option<&str>,
    ) -> NvdCpeMatch {
        NvdCpeMatch {
            vulnerable: true,
            criteria: criteria.to_string(),
            version_start_including: start_incl.map(str::to_string),
            version_start_excluding: None,
            version_end_excluding: end_excl.map(str::to_string),
            version_end_including: end_incl.map(str::to_string),
        }
    }

    // Review of 0.3.4: names NVD extends with `_` are the same product and
    // must stay confirmed (a KEV CVE on them makes the CRA report FAIL).
    #[test]
    fn test_underscore_extended_names_stay_exact() {
        for (name, crit) in [
            (
                "confluence",
                "cpe:2.3:a:atlassian:confluence_server:*:*:*:*:*:*:*:*",
            ),
            ("linux", "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"),
            (
                "dropbear",
                "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:*:*:*:*:*:*:*:*",
            ),
            ("nginx", "cpe:2.3:a:f5:nginx_open_source:*:*:*:*:*:*:*:*"),
        ] {
            let comp = make_component(name, "7.13.0", None);
            assert_eq!(
                cpe_matches_component(crit, &comp),
                CpeMatch::Exact,
                "{crit}"
            );
            let cve = openssl_cve(crit, Some("7.0.0"), Some("7.14.0"));
            assert_eq!(
                affects_component(&cve, &comp),
                Applicability::Confirmed,
                "{crit}"
            );
        }
    }

    #[test]
    fn test_language_package_cpe_is_loose() {
        let comp = make_component("openssl", "1.0.1f", None);
        let crit = "cpe:2.3:a:jahlives:openssl_encrypt:*:*:*:*:*:python:*:*";
        assert_eq!(cpe_matches_component(crit, &comp), CpeMatch::Loose);
        let cve = openssl_cve(crit, None, Some("1.4.9"));
        assert_eq!(affects_component(&cve, &comp), Applicability::Unconfirmed);
        // The same name as a language package is still an exact match.
        let js = make_component("openssl.js", "1.0.0", None);
        assert_eq!(
            cpe_matches_component(
                "cpe:2.3:a:openssl.js_project:openssl.js:*:*:*:*:*:node.js:*:*",
                &js
            ),
            CpeMatch::Exact
        );
    }

    // Review of 0.3.4: a range the version is known to be outside of must not
    // supply the fix (3.0.8 confirmed by `<=3.0.8`, other line `<1.0.2zq`).
    #[test]
    fn test_fixed_version_never_from_a_range_outside_the_version() {
        let comp = make_component("openssl", "3.0.8", None);
        let crit = "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*";
        let cve = two_entries(
            entry("1.0.2", "1.0.2zq"),
            cpe_entry(crit, Some("3.0.0"), Some("3.0.8"), None),
        );
        assert_eq!(affects_component(&cve, &comp), Applicability::Confirmed);
        assert_eq!(extract_version_info(&cve, &comp).1, None);
        // Confirmed by an exact CPE version, other line only.
        let pinned = two_entries(
            entry("1.0.2", "1.0.2zq"),
            cpe_entry(
                "cpe:2.3:a:openssl:openssl:3.0.8:*:*:*:*:*:*:*",
                None,
                None,
                None,
            ),
        );
        assert_eq!(affects_component(&pinned, &comp), Applicability::Confirmed);
        assert_eq!(extract_version_info(&pinned, &comp).1, None);
    }

    // Review of 0.3.4: another product's fix is not named for this product.
    #[test]
    fn test_fixed_version_not_taken_from_a_loose_match() {
        let comp = make_component("openssl", "3.0.8", None);
        let cve = two_entries(
            cpe_entry(
                "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                Some("3.0.0"),
                Some("3.0.9"),
                None,
            ),
            cpe_entry(
                "cpe:2.3:a:openssl.js_project:openssl.js:*:*:*:*:*:node.js:*:*",
                None,
                None,
                Some("4.0.0"),
            ),
        );
        assert_eq!(affects_component(&cve, &comp), Applicability::Confirmed);
        assert_eq!(extract_version_info(&cve, &comp).1, None);
    }

    // Review of 0.3.4: an unparseable component version no longer confirms
    // a CVE whose only matching CPE is another product's.
    #[test]
    fn test_unparseable_version_with_only_loose_match_is_unconfirmed() {
        let comp = make_component("openssl", "vendor-build-7", None);
        let loose = openssl_cve(
            "cpe:2.3:a:openssl.js_project:openssl.js:*:*:*:*:*:node.js:*:*",
            None,
            None,
        );
        assert_eq!(affects_component(&loose, &comp), Applicability::Unconfirmed);
        let exact = openssl_cve("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", None, None);
        assert_eq!(affects_component(&exact, &comp), Applicability::Confirmed);
    }

    #[test]
    fn test_convert_page_skips_rejected_records() {
        let page: NvdResponse = serde_json::from_str(
            r#"{"totalResults":2,"vulnerabilities":[
                {"cve":{"id":"CVE-2006-7248","vulnStatus":"Rejected"}},
                {"cve":{"id":"CVE-2099-0001","vulnStatus":"Awaiting Analysis"}}]}"#,
        )
        .unwrap();
        let comp = make_component("openssl", "3.0.8", None);
        let ids: Vec<String> = convert_page(&page, &comp)
            .into_iter()
            .map(|v| v.cve_id)
            .collect();
        assert_eq!(ids, vec!["CVE-2099-0001".to_string()]);
    }
}
