mod kev;
mod nvd;
mod osv;

use std::collections::HashMap;

use anyhow::Result;

use crate::models::{Component, ScanGap, VulnMatch, VulnSource};

/// Result of an online scan: what was found, and what could not be checked.
#[derive(Debug, Default)]
pub struct MatchOutcome {
    pub vulns: Vec<VulnMatch>,
    /// Lookups that failed or were impossible. Non-empty means `vulns` is
    /// incomplete; callers must not present the result as clean.
    pub gaps: Vec<ScanGap>,
    /// Components whose empty result cannot be trusted; see
    /// [`crate::models::AnalysisReport::unverified`].
    pub unverified: Vec<String>,
}

/// PURL types confirmed to get answers from OSV.dev. Anything else goes to NVD.
///
/// Each entry was checked against the live API with a known-vulnerable package.
/// Deliberately absent, because OSV.dev answered "no vulnerabilities" for
/// known-vulnerable packages: `generic`, `github` (OSV's GitHub ecosystem is
/// GitHub Actions, not C/C++ source repositories), `conan` and `apk`. A type
/// that is wrongly listed here produces false "clean" results; a type wrongly
/// missing only costs a slower NVD lookup. When unsure, leave it out.
const OSV_PURL_TYPES: &[&str] = &[
    "bitnami", "cargo", "composer", "cran", "gem", "golang", "hackage", "hex", "maven", "npm",
    "nuget", "pub", "pypi", "swift",
];

/// Distribution PURLs are only answered for specific namespaces: OSV.dev
/// returns nothing for e.g. `pkg:rpm/centos`, `pkg:deb/raspbian` or
/// `pkg:apk/openwrt`. Only (type, namespace) pairs confirmed against the live
/// API are listed; every other distribution goes to NVD.
const OSV_DISTRO_NAMESPACES: &[(&str, &str)] = &[
    ("deb", "debian"),
    ("deb", "ubuntu"),
    ("rpm", "redhat"),
    ("rpm", "rocky-linux"),
    ("rpm", "suse"),
];

/// True when OSV can meaningfully answer for this PURL.
fn osv_covers(purl: &str) -> bool {
    let Some(rest) = purl.strip_prefix("pkg:") else {
        return false;
    };
    let mut segments = rest.split('/');
    let purl_type = segments.next().unwrap_or("").to_ascii_lowercase();
    if OSV_PURL_TYPES.contains(&purl_type.as_str()) {
        // A bare "pkg:npm" names no package at all.
        return segments.next().is_some_and(|s| !s.is_empty());
    }
    let namespace = segments.next().unwrap_or("").to_ascii_lowercase();
    segments.next().is_some()
        && OSV_DISTRO_NAMESPACES.contains(&(purl_type.as_str(), namespace.as_str()))
}

/// True when OSV is queried but may answer "nothing" because the PURL names a
/// Debian/Ubuntu *binary* package (e.g. `libssl3`, `zlib1g`): OSV.dev indexes
/// these distributions by *source* package (`openssl`, `zlib`). With an
/// `upstream` qualifier the source name is known and OSV is asked for that;
/// without one there is no way to tell, so NVD is asked as well.
fn osv_answer_uncertain(purl: &str) -> bool {
    let is_deb = purl
        .strip_prefix("pkg:")
        .and_then(|rest| rest.split('/').next())
        .is_some_and(|t| t.eq_ignore_ascii_case("deb"));
    // Uncertain unless the PURL is actually rewritten to a source package;
    // an `upstream` value that cannot be used counts as no information.
    is_deb && osv::to_source_package(purl) == purl
}

/// Components looked up without error whose empty result cannot be trusted:
/// Debian/Ubuntu binary packages that OSV was asked about under a name it may
/// not index. Components with findings, or already recorded as a gap, are
/// left out; distributions OSV does not cover were never asked and are not
/// affected.
fn unverified_components(
    components: &[Component],
    vulns: &[VulnMatch],
    gaps: &[ScanGap],
) -> Vec<String> {
    let same = |name: &str, version: &str, c: &Component| name == c.name && version == c.version;
    components
        .iter()
        .filter(|c| {
            c.purl
                .as_deref()
                .is_some_and(|p| osv_covers(p) && osv_answer_uncertain(p))
        })
        .filter(|c| {
            !vulns
                .iter()
                .any(|v| same(&v.component_name, &v.component_version, c))
        })
        .filter(|c| {
            !gaps
                .iter()
                .any(|g| same(&g.component_name, &g.component_version, c))
        })
        .map(|c| {
            if c.version.is_empty() {
                c.name.clone()
            } else {
                format!("{}@{}", c.name, c.version)
            }
        })
        .collect()
}

/// Splits components into (OSV targets, NVD targets).
///
/// - PURL of a type OSV covers -> OSV.
/// - No PURL, or a PURL type OSV has no data for -> NVD.
/// - Debian/Ubuntu PURL without an `upstream` qualifier -> OSV and NVD.
/// - `use_nvd` -> NVD for everything, in addition to OSV.
fn route(components: &[Component], use_nvd: bool) -> (Vec<&Component>, Vec<&Component>) {
    let mut osv_targets = Vec::new();
    let mut nvd_targets = Vec::new();
    for c in components {
        let purl = c.purl.as_deref();
        let covered = purl.is_some_and(osv_covers);
        if covered {
            osv_targets.push(c);
        }
        if use_nvd || !covered || purl.is_some_and(osv_answer_uncertain) {
            // (For a deb PURL OSV does not cover, `!covered` already applies.)
            nvd_targets.push(c);
        }
    }
    (osv_targets, nvd_targets)
}

/// After this many consecutive unreachable-host failures, a source is given up
/// on and its remaining components are recorded as gaps without being queried.
/// Otherwise a network that silently drops packets costs a full timeout (and
/// retries) per component, which can stall a CI job for hours.
const UNREACHABLE_LIMIT: usize = 3;

/// Tracks consecutive unreachable-host failures for one data source.
#[derive(Debug, Default)]
struct UnreachableStreak(usize);

impl UnreachableStreak {
    /// Records one lookup: `None` = success, `Some(true)` = host unreachable
    /// or not responding, `Some(false)` = the host answered with an error.
    /// Anything but an unreachable host resets the streak.
    fn record(&mut self, failure: Option<bool>) {
        self.0 = match failure {
            Some(true) => self.0 + 1,
            _ => 0,
        };
    }

    /// True once the source should be given up on.
    fn exhausted(&self) -> bool {
        self.0 >= UNREACHABLE_LIMIT
    }
}

/// True when the failure says the host could not be reached at all.
fn is_unreachable(e: &reqwest::Error) -> bool {
    e.is_connect() || e.is_timeout()
}

/// Short, URL-free description of a transport failure.
fn describe_request_error(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "request timed out"
    } else if e.is_decode() {
        "unreadable response"
    } else if e.is_connect() {
        "could not connect"
    } else {
        "request failed"
    }
}

/// Match vulnerabilities using online APIs.
///
/// Strategy:
/// 1. Components whose PURL type OSV.dev covers: query OSV.
/// 2. Components without a PURL, or with a PURL OSV has no data for
///    (e.g. `pkg:generic`): query NVD via CPE, falling back to keyword search.
///    With `use_nvd`, NVD is queried for every component.
/// 3. Deduplicate: when both sources return the same CVE, merge them
///    (prefer OSV for fix_version, NVD for CVSS scores).
///
/// Failed lookups are never dropped: they come back in [`MatchOutcome::gaps`].
pub async fn match_vulnerabilities(
    components: &[Component],
    use_nvd: bool,
) -> Result<MatchOutcome> {
    let (osv_targets, nvd_targets) = route(components, use_nvd);

    let mut all_vulns: Vec<VulnMatch> = Vec::new();
    let mut gaps: Vec<ScanGap> = Vec::new();

    if !osv_targets.is_empty() {
        tracing::info!("Querying OSV.dev for {} components...", osv_targets.len());
        let (vulns, osv_gaps) = osv::query_batch(&osv_targets).await?;
        all_vulns.extend(vulns);
        gaps.extend(osv_gaps);
    }

    if !nvd_targets.is_empty() {
        tracing::info!(
            "Querying NVD API for {} components (this may be slow due to rate limiting)...",
            nvd_targets.len()
        );
        let (vulns, nvd_gaps) = nvd::query_batch(&nvd_targets).await?;
        all_vulns.extend(vulns);
        gaps.extend(nvd_gaps);
    }

    let mut merged = deduplicate_vulns(all_vulns);

    // Enrich with the CISA KEV catalogue. Without it nothing can be said about
    // known exploitation, so a failure is a gap whenever there are findings.
    match kev::fetch_kev_lookup().await {
        Ok(kev_map) => {
            for vuln in &mut merged {
                if let Some(due_date) = kev_map.get(&vuln.cve_id) {
                    vuln.in_kev = true;
                    vuln.kev_due_date = *due_date;
                }
            }
            tracing::debug!("KEV catalog loaded ({} entries)", kev_map.len());
        }
        Err(e) => {
            tracing::warn!("Could not fetch CISA KEV catalog: {e}");
            gaps.extend(kev_gap(!merged.is_empty()));
        }
    }

    let unverified = unverified_components(components, &merged, &gaps);
    Ok(MatchOutcome {
        vulns: merged,
        gaps,
        unverified,
    })
}

/// Gap to record when the KEV catalogue could not be loaded. With no findings
/// there is nothing to look up in it, so the scan is still complete.
fn kev_gap(has_findings: bool) -> Option<ScanGap> {
    has_findings.then(|| ScanGap {
        component_name: ScanGap::ALL_COMPONENTS.to_string(),
        component_version: String::new(),
        source: "CISA KEV".to_string(),
        reason: "catalogue unavailable; known-exploited status not checked".to_string(),
    })
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
    } else if !incoming.affected_versions.ranges.is_empty()
        && existing.affected_versions.ranges.is_empty()
    {
        // Prefer structured ranges even if display is non-empty
        existing.affected_versions.ranges = incoming.affected_versions.ranges.clone();
    }

    // Confirmed by either source is confirmed.
    existing.unconfirmed = existing.unconfirmed && incoming.unconfirmed;

    // Mark source as merged (prefer showing original primary source)
    // Keep whichever source was first (usually OSV since we query it first)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AffectedVersions, Severity};

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
            affected_versions: AffectedVersions::default(),
            fixed_version: fixed.map(|s| s.to_string()),
            description: desc.to_string(),
            in_kev: false,
            kev_due_date: None,
            unconfirmed: false,
        }
    }

    fn comp(name: &str, purl: Option<&str>) -> Component {
        Component {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            supplier: None,
            cpe: None,
            purl: purl.map(str::to_string),
            licenses: vec![],
            hashes: vec![],
            source_format: crate::models::SourceFormat::Unknown,
        }
    }

    fn names(v: &[&Component]) -> Vec<String> {
        v.iter().map(|c| c.name.clone()).collect()
    }

    #[test]
    fn test_osv_covers() {
        assert!(osv_covers("pkg:cargo/time@0.1.43"));
        assert!(osv_covers("pkg:NPM/lodash@4.17.15"));
        assert!(!osv_covers("pkg:generic/openssl@3.0.8"));
        // OSV.dev answers 200 with no results for these; they must reach NVD.
        assert!(!osv_covers("pkg:github/madler/zlib@v1.2.11"));
        assert!(!osv_covers("pkg:conan/openssl@1.1.1k"));
        assert!(!osv_covers("pkg:apk/alpine/busybox@1.31.1-r9"));
        assert!(osv_covers("pkg:deb/debian/openssl@1.1.1k-1"));
        assert!(osv_covers("pkg:rpm/redhat/openssl@1.0.2k-19.el7"));
        // Distributions OSV.dev has no data for must reach NVD.
        assert!(!osv_covers("pkg:deb/raspbian/openssl@1.1.1k-1"));
        assert!(!osv_covers("pkg:rpm/centos/openssl@1.0.2k"));
        assert!(!osv_covers("pkg:rpm/fedora/openssl@3.0.8"));
        assert!(!osv_covers("pkg:apk/openwrt/busybox@1.36.0"));
        assert!(!osv_covers("pkg:deb/openssl@1.1.1k-1"));
        assert!(!osv_covers("pkg:npm"));
        assert!(!osv_covers("pkg:/x"));
        assert!(!osv_covers("pkg:unknowntype/x@1"));
        assert!(!osv_covers("not-a-purl"));
    }

    // Regression: pkg:generic components used to be sent to OSV only, which
    // has no data for them, so the bundled firmware example reported 0 vulns.
    #[test]
    fn test_route_generic_purl_goes_to_nvd_by_default() {
        let comps = vec![
            comp("openssl", Some("pkg:generic/openssl@3.0.8")),
            comp("lodash", Some("pkg:npm/lodash@4.17.15")),
            comp("nopurl", None),
        ];
        let (osv, nvd) = route(&comps, false);
        assert_eq!(names(&osv), ["lodash"]);
        assert_eq!(names(&nvd), ["openssl", "nopurl"]);
    }

    #[test]
    fn test_unreachable_streak() {
        let mut s = UnreachableStreak::default();
        s.record(Some(true));
        s.record(Some(true));
        assert!(!s.exhausted());
        // A success resets the count.
        s.record(None);
        s.record(Some(true));
        s.record(Some(true));
        assert!(!s.exhausted());
        // An answered error (HTTP 500) also resets: the host is reachable.
        s.record(Some(false));
        s.record(Some(true));
        s.record(Some(true));
        assert!(!s.exhausted());
        s.record(Some(true));
        assert!(s.exhausted());
    }

    // Regression: OSV.dev answers 200 with no results for Debian binary
    // package names, so such components must also reach NVD.
    #[test]
    fn test_route_deb_binary_name_also_goes_to_nvd() {
        let comps = vec![
            comp(
                "libssl3",
                Some("pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64"),
            ),
            comp(
                "libssl3",
                Some("pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&upstream=openssl"),
            ),
            comp("openssl", Some("pkg:rpm/redhat/openssl-libs@1.0.2k-19.el7")),
        ];
        let (osv, nvd) = route(&comps, false);
        assert_eq!(osv.len(), 3);
        assert_eq!(nvd.len(), 1);
        assert!(nvd[0].purl.as_deref().unwrap().ends_with("arch=amd64"));
    }

    #[test]
    fn test_unverified_components() {
        let comps = vec![
            comp("zlib1g", Some("pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1")),
            comp("curl", Some("pkg:deb/debian/curl@7.88.1-10")),
            comp(
                "libssl3",
                Some("pkg:deb/debian/libssl3@3.0.11-1?upstream=openssl"),
            ),
            comp("lodash", Some("pkg:npm/lodash@4.17.15")),
            // Unusable upstream value: still unverified.
            comp("libx", Some("pkg:deb/debian/libx@1?upstream=a%2Fb")),
            // Never sent to OSV, so OSV's indexing does not apply.
            comp("busybox", Some("pkg:deb/raspbian/busybox@1.35.0")),
            // Same name, other version than the finding: still unverified.
            Component {
                version: "2.0.0".to_string(),
                ..comp("curl", Some("pkg:deb/debian/curl@2.0.0"))
            },
            // Failed lookup: already a gap, not listed twice.
            comp("libgap", Some("pkg:deb/debian/libgap@1")),
            Component {
                version: String::new(),
                ..comp("libnover", Some("pkg:deb/debian/libnover@3"))
            },
        ];
        let gaps = vec![ScanGap::new(&comps[7], "OSV", "HTTP 503")];
        let found = VulnMatch {
            component_name: "curl".to_string(),
            component_version: "1.0.0".to_string(),
            cve_id: "CVE-2024-0001".to_string(),
            severity: crate::models::Severity::High,
            cvss_score: None,
            source: VulnSource::Osv,
            affected_versions: crate::models::AffectedVersions::default(),
            fixed_version: None,
            description: String::new(),
            in_kev: false,
            kev_due_date: None,
            unconfirmed: false,
        };
        assert_eq!(
            unverified_components(&comps, &[found], &gaps),
            ["zlib1g@1.0.0", "libx@1.0.0", "curl@2.0.0", "libnover"]
        );
    }

    #[test]
    fn test_kev_gap_only_when_there_are_findings() {
        let gap = kev_gap(true).unwrap();
        assert_eq!(gap.component_name, ScanGap::ALL_COMPONENTS);
        assert!(gap.component_version.is_empty());
        assert_eq!(gap.source, "CISA KEV");
        assert!(kev_gap(false).is_none());
    }

    #[test]
    fn test_route_nvd_flag_queries_everything() {
        let comps = vec![
            comp("openssl", Some("pkg:generic/openssl@3.0.8")),
            comp("lodash", Some("pkg:npm/lodash@4.17.15")),
        ];
        let (osv, nvd) = route(&comps, true);
        assert_eq!(names(&osv), ["lodash"]);
        assert_eq!(names(&nvd), ["openssl", "lodash"]);
    }

    #[test]
    fn test_route_every_component_has_a_source() {
        let comps = vec![
            comp("a", Some("pkg:generic/a@1")),
            comp("b", Some("pkg:cargo/b@1")),
            comp("c", None),
            comp("d", Some("garbage")),
            comp("e", Some("pkg:npm")),
            comp("f", Some("pkg:/x")),
            comp("g", Some("pkg:github/madler/zlib@v1.2.11")),
        ];
        let (osv, nvd) = route(&comps, false);
        for c in &comps {
            assert!(
                osv.iter().chain(nvd.iter()).any(|t| t.name == c.name),
                "{} was routed nowhere",
                c.name
            );
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

    #[test]
    fn test_dedup_confirmed_source_wins_over_unconfirmed() {
        let mut nvd = make_vuln("lwip", "CVE-2026-0001", VulnSource::Nvd, None, None, "");
        nvd.unconfirmed = true;
        let osv = make_vuln("lwip", "CVE-2026-0001", VulnSource::Osv, None, None, "");
        let result = deduplicate_vulns(vec![nvd.clone(), osv]);
        assert_eq!(result.len(), 1);
        assert!(!result[0].unconfirmed);

        let nvd2 = nvd.clone();
        let result = deduplicate_vulns(vec![nvd, nvd2]);
        assert!(result[0].unconfirmed);
    }
}
