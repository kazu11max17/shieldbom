use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::models::{
    AffectedVersions, Component, ScanGap, Severity, VersionRangeInfo, VulnMatch, VulnSource,
};

const OSV_API_URL: &str = "https://api.osv.dev/v1/query";

#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
    /// OSV rejects the request (HTTP 400) when a version is given both here and
    /// inside the PURL, so this is only set for version-less PURLs.
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<String>,
}

/// Upper bound on result pages fetched per component. Beyond this the lookup
/// is reported as truncated rather than complete.
const MAX_PAGES: usize = 10;

#[derive(Serialize)]
struct OsvPackage {
    purl: String,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
    /// Present when more results exist than fit in this page.
    #[serde(default)]
    next_page_token: Option<String>,
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

/// True when the PURL carries its own version (`pkg:type/ns/name@version`).
pub(crate) fn purl_has_version(purl: &str) -> bool {
    let end = purl.find(['?', '#']).unwrap_or(purl.len());
    let path = &purl[..end];
    let name = path.rsplit('/').next().unwrap_or(path);
    // A leading '@' is an unencoded npm scope, not a version separator.
    matches!(name.rfind('@'), Some(i) if i > 0 && i + 1 < name.len())
}

/// Returns the PURL without the given qualifier, keeping everything else.
fn without_qualifier(purl: &str, key: &str) -> String {
    let (main, subpath) = match purl.split_once('#') {
        Some((m, sub)) => (m, Some(sub)),
        None => (purl, None),
    };
    let Some((base, qualifiers)) = main.split_once('?') else {
        return purl.to_string();
    };
    let kept: Vec<&str> = qualifiers
        .split('&')
        .filter(|q| {
            let name = q.split('=').next().unwrap_or("");
            !q.is_empty() && !name.eq_ignore_ascii_case(key)
        })
        .collect();
    let mut out = base.to_string();
    if !kept.is_empty() {
        out.push('?');
        out.push_str(&kept.join("&"));
    }
    if let Some(sub) = subpath {
        out.push('#');
        out.push_str(sub);
    }
    out
}

/// Decodes `%XX` escapes; invalid escapes are kept as written.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        // Work on bytes, never on `&str` slices: a multi-byte character after
        // '%' would put a slice boundary inside it and panic on SBOM input.
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hex = |b: u8| (b as char).to_digit(16).unwrap_or(0) as u8;
            out.push((hex(bytes[i + 1]) << 4) | hex(bytes[i + 2]));
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The decoded value of the `upstream` qualifier (the Debian source package,
/// optionally `name@version`), if present and non-empty.
pub(crate) fn upstream_qualifier(purl: &str) -> Option<String> {
    let main = purl.split('#').next().unwrap_or(purl);
    let (_, qualifiers) = main.split_once('?')?;
    qualifiers
        .split('&')
        .filter_map(|q| q.split_once('='))
        .find(|(k, _)| k.eq_ignore_ascii_case("upstream"))
        .map(|(_, v)| percent_decode(v))
        .filter(|v| !v.trim().is_empty())
}

/// Rewrites a Debian/Ubuntu binary-package PURL to its source package, which
/// is how OSV.dev indexes those distributions. Uses the `upstream` qualifier
/// (`upstream=openssl` or `upstream=openssl@3.0.11-1`); returns the PURL
/// unchanged when there is none or it is not a `deb` PURL.
pub(crate) fn to_source_package(purl: &str) -> String {
    let is_deb = purl
        .strip_prefix("pkg:")
        .and_then(|rest| rest.split('/').next())
        .is_some_and(|t| t.eq_ignore_ascii_case("deb"));
    let Some(upstream) = upstream_qualifier(purl).filter(|_| is_deb) else {
        return purl.to_string();
    };
    let (src_name, src_version) = match upstream.split_once('@') {
        Some((n, v)) if !v.is_empty() => (n.trim(), Some(v.trim())),
        Some((n, _)) => (n.trim(), None),
        None => (upstream.trim(), None),
    };
    // Debian package names only use [a-z0-9.+-]; anything else is not a
    // source package name and must not be spliced into the PURL.
    let valid_name = |n: &str| {
        !n.is_empty()
            && n.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+-.".contains(&b))
    };
    if !valid_name(src_name) {
        return purl.to_string();
    }

    let without = without_qualifier(purl, "upstream");
    // Split off qualifiers/subpath, then replace the last path segment's name.
    let cut = without.find(['?', '#']).unwrap_or(without.len());
    let (path, rest) = without.split_at(cut);
    let Some(slash) = path.rfind('/') else {
        return purl.to_string();
    };
    let (prefix, last) = path.split_at(slash + 1);
    let binary_version = last.split_once('@').map(|(_, v)| v);
    // A version taken from `upstream` must not smuggle in qualifiers or path.
    if src_version
        .is_some_and(|v| v.contains(['/', '?', '#', '&', '=']) || v.chars().any(char::is_control))
    {
        return purl.to_string();
    }
    let version = src_version.or(binary_version);
    match version {
        Some(v) => format!("{prefix}{src_name}@{v}{rest}"),
        None => format!("{prefix}{src_name}{rest}"),
    }
}

/// Builds the OSV request body, or `None` when no version is known at all.
///
/// The `distro` qualifier is dropped: OSV.dev reads its value as a release
/// name and answers "no vulnerabilities" for spellings it does not know
/// (`distro=debian-12` returns nothing where `distro=bookworm` or no
/// qualifier returns results). Without it OSV.dev answers for all releases,
/// which errs towards reporting too much rather than nothing.
///
/// Debian/Ubuntu binary package names are replaced by their source package
/// (see [`to_source_package`]).
fn build_query(purl: &str, component_version: &str) -> Option<OsvQuery> {
    let purl = to_source_package(&without_qualifier(purl, "distro"));
    let version = if purl_has_version(&purl) {
        None
    } else if component_version.is_empty() {
        return None;
    } else {
        Some(component_version.to_string())
    };
    Some(OsvQuery {
        package: OsvPackage { purl },
        version,
        page_token: None,
    })
}

/// Reason text for a non-success OSV status, or `None` when the response is usable.
fn status_failure(status: reqwest::StatusCode) -> Option<String> {
    (!status.is_success()).then(|| format!("HTTP {}", status.as_u16()))
}

/// Why a component's lookup did not complete.
struct Failure {
    reason: String,
    /// The host could not be reached (as opposed to answering with an error).
    unreachable: bool,
}

impl Failure {
    fn transport(e: &reqwest::Error) -> Self {
        Self {
            reason: super::describe_request_error(e).to_string(),
            unreachable: super::is_unreachable(e),
        }
    }

    fn answered(reason: String) -> Self {
        Self {
            reason,
            unreachable: false,
        }
    }
}

/// Runs one component's query to the last page. Findings read before a
/// failure are still returned: dropping them could hide a known-exploited CVE.
async fn query_component(
    client: &reqwest::Client,
    mut query: OsvQuery,
    component: &Component,
) -> (Vec<VulnMatch>, Option<Failure>) {
    let mut results = Vec::new();

    for _ in 0..MAX_PAGES {
        let resp = match client.post(OSV_API_URL).json(&query).send().await {
            Ok(resp) => resp,
            Err(e) => return (results, Some(Failure::transport(&e))),
        };
        if let Some(reason) = status_failure(resp.status()) {
            return (results, Some(Failure::answered(reason)));
        }
        let page: OsvResponse = match resp.json().await {
            Ok(page) => page,
            Err(e) => return (results, Some(Failure::transport(&e))),
        };

        for vuln in &page.vulns {
            results.push(convert_osv_vuln(vuln, component));
        }
        match page.next_page_token {
            Some(token) if !token.is_empty() => query.page_token = Some(token),
            _ => return (results, None),
        }
    }

    let reason = format!("results truncated (more than {MAX_PAGES} result pages)");
    (results, Some(Failure::answered(reason)))
}

/// Query OSV for vulnerabilities for each component that has a PURL.
///
/// Every lookup that does not yield a complete, parsed answer is returned as a
/// [`ScanGap`]; an empty vulnerability list alone never means "clean".
pub async fn query_batch(components: &[&Component]) -> Result<(Vec<VulnMatch>, Vec<ScanGap>)> {
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let mut results = Vec::new();
    let mut gaps = Vec::new();
    let mut streak = super::UnreachableStreak::default();

    for component in components {
        let Some(purl) = &component.purl else {
            gaps.push(ScanGap::new(component, "OSV", "no PURL; not queried"));
            continue;
        };

        let Some(query) = build_query(purl, &component.version) else {
            gaps.push(ScanGap::new(
                component,
                "OSV",
                "no version in SBOM; not queried",
            ));
            continue;
        };

        if streak.exhausted() {
            gaps.push(ScanGap::new(
                component,
                "OSV",
                "not queried: OSV.dev unreachable or not responding",
            ));
            continue;
        }

        let (vulns, failure) = query_component(&client, query, component).await;
        results.extend(vulns);
        streak.record(failure.as_ref().map(|f| f.unreachable));
        if let Some(f) = failure {
            gaps.push(ScanGap::new(component, "OSV", f.reason));
        }
    }

    Ok((results, gaps))
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
    fn test_purl_has_version() {
        assert!(purl_has_version("pkg:npm/lodash@4.17.15"));
        assert!(purl_has_version("pkg:generic/openssl@3.0.8"));
        assert!(purl_has_version("pkg:npm/%40angular/core@16.0.0"));
        assert!(purl_has_version("pkg:npm/@angular/core@16.0.0"));
        assert!(purl_has_version("pkg:deb/debian/curl@7.88.1-10?arch=amd64"));
        assert!(!purl_has_version("pkg:npm/lodash"));
        assert!(!purl_has_version("pkg:npm/@angular/core"));
        assert!(!purl_has_version(
            "pkg:cargo/time?download_url=https://x/a@b"
        ));
        assert!(!purl_has_version("pkg:cargo/time@"));
    }

    // Regression: OSV answers HTTP 400 ("version specified in params and PURL
    // query") when both are sent, which used to turn every lookup into 0 results.
    #[test]
    fn test_query_omits_version_when_purl_has_one() {
        let q = build_query("pkg:npm/lodash@4.17.15", "4.17.15").unwrap();
        let json = serde_json::to_value(&q).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"package": {"purl": "pkg:npm/lodash@4.17.15"}})
        );
    }

    #[test]
    fn test_query_sends_version_for_versionless_purl() {
        let q = build_query("pkg:npm/lodash", "4.17.15").unwrap();
        let json = serde_json::to_value(&q).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"package": {"purl": "pkg:npm/lodash"}, "version": "4.17.15"})
        );
    }

    // Regression (v0.3.0): non-2xx answers were logged and dropped.
    #[test]
    fn test_status_failure() {
        use reqwest::StatusCode;
        assert_eq!(status_failure(StatusCode::OK), None);
        assert_eq!(
            status_failure(StatusCode::BAD_REQUEST).as_deref(),
            Some("HTTP 400")
        );
        assert!(status_failure(StatusCode::TOO_MANY_REQUESTS).is_some());
        assert!(status_failure(StatusCode::INTERNAL_SERVER_ERROR).is_some());
    }

    #[test]
    fn test_response_exposes_next_page_token() {
        let page: OsvResponse =
            serde_json::from_str(r#"{"vulns":[],"next_page_token":"abc"}"#).unwrap();
        assert_eq!(page.next_page_token.as_deref(), Some("abc"));
        let last: OsvResponse = serde_json::from_str("{}").unwrap();
        assert!(last.next_page_token.is_none());
    }

    #[test]
    fn test_page_token_is_sent_when_set() {
        let mut q = build_query("pkg:npm/lodash@4.17.15", "").unwrap();
        q.page_token = Some("abc".to_string());
        let json = serde_json::to_value(&q).unwrap();
        assert_eq!(json["page_token"], "abc");
    }

    #[test]
    fn test_without_qualifier() {
        assert_eq!(
            without_qualifier(
                "pkg:deb/debian/curl@7.88.1-10?arch=amd64&distro=debian-12",
                "distro"
            ),
            "pkg:deb/debian/curl@7.88.1-10?arch=amd64"
        );
        assert_eq!(
            without_qualifier("pkg:deb/debian/curl@7.88.1-10?distro=debian-12", "distro"),
            "pkg:deb/debian/curl@7.88.1-10"
        );
        assert_eq!(
            without_qualifier(
                "pkg:deb/debian/curl@1?DISTRO=x&arch=arm64#sub/path",
                "distro"
            ),
            "pkg:deb/debian/curl@1?arch=arm64#sub/path"
        );
        assert_eq!(
            without_qualifier("pkg:npm/lodash@4.17.15", "distro"),
            "pkg:npm/lodash@4.17.15"
        );
    }

    // Regression: OSV.dev answers 200 with no results for
    // `pkg:deb/debian/...?distro=debian-12`, the spelling SBOM tools emit.
    #[test]
    fn test_query_never_sends_distro_qualifier() {
        let q = build_query(
            "pkg:deb/debian/curl@7.88.1-10?arch=amd64&distro=debian-12",
            "7.88.1-10",
        )
        .unwrap();
        let json = serde_json::to_value(&q).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"package": {"purl": "pkg:deb/debian/curl@7.88.1-10?arch=amd64"}})
        );
    }

    #[test]
    fn test_without_qualifier_matches_whole_key_only() {
        assert_eq!(
            without_qualifier("pkg:deb/debian/curl@1?distroname=x&distro=y", "distro"),
            "pkg:deb/debian/curl@1?distroname=x"
        );
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("openssl%403.0.11-1"), "openssl@3.0.11-1");
        assert_eq!(percent_decode("a%2"), "a%2");
        assert_eq!(percent_decode("a%zz"), "a%zz");
        // Regression: these panicked (slice boundary inside a multi-byte
        // character) or decoded a sign as a digit.
        assert_eq!(percent_decode("%aé"), "%aé");
        assert_eq!(percent_decode("%é"), "%é");
        assert_eq!(percent_decode("%+1"), "%+1");
        assert_eq!(percent_decode("%"), "%");
    }

    // Regression: OSV.dev returns nothing for Debian binary names
    // (libssl3 -> 0, openssl -> 87 for the same version).
    #[test]
    fn test_debian_binary_name_is_queried_as_source_package() {
        let q = build_query(
            "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&upstream=openssl&distro=debian-12",
            "3.0.11-1~deb12u2",
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&q).unwrap(),
            serde_json::json!({"package": {"purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64"}})
        );
    }

    #[test]
    fn test_upstream_with_version_uses_source_version() {
        assert_eq!(
            to_source_package(
                "pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1?upstream=zlib%401:1.2.13.dfsg-1"
            ),
            "pkg:deb/debian/zlib@1:1.2.13.dfsg-1"
        );
        assert_eq!(
            to_source_package("pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.10?upstream=openssl#sub"),
            "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10#sub"
        );
    }

    #[test]
    fn test_to_source_package_leaves_others_alone() {
        for purl in [
            "pkg:deb/debian/curl@7.88.1-10",
            "pkg:npm/lodash@4.17.15?upstream=x",
            "pkg:deb/debian/libssl3@1?upstream=",
            "pkg:deb/debian/libssl3@1?upstream=a%2Fb",
            "pkg:deb/debian/libssl3@1?upstream=a%26b%3Dc",
            "pkg:deb/debian/libssl3@1?upstream=Open%20SSL",
            "pkg:deb/debian/libssl3@1?upstream=%aé",
            "pkg:deb/debian/libssl3@1?upstream=openssl%40x%3Fdistro%3Ddebian-12",
        ] {
            assert_eq!(to_source_package(purl), purl);
        }
    }

    #[test]
    fn test_query_none_without_any_version() {
        assert!(build_query("pkg:npm/lodash", "").is_none());
    }

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
