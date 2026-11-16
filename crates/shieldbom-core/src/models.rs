use std::fmt;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Unified component model - format-agnostic internal representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub supplier: Option<String>,
    pub cpe: Option<String>,
    pub purl: Option<String>,
    pub licenses: Vec<String>,
    pub hashes: Vec<Hash>,
    pub source_format: SourceFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hash {
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceFormat {
    Spdx23Json,
    Spdx23TagValue,
    CycloneDx14Json,
    CycloneDx14Xml,
    CycloneDx15Json,
    CycloneDx15Xml,
    Unknown,
}

impl fmt::Display for SourceFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spdx23Json => write!(f, "SPDX 2.3 (JSON)"),
            Self::Spdx23TagValue => write!(f, "SPDX 2.3 (Tag-Value)"),
            Self::CycloneDx14Json => write!(f, "CycloneDX 1.4 (JSON)"),
            Self::CycloneDx14Xml => write!(f, "CycloneDX 1.4 (XML)"),
            Self::CycloneDx15Json => write!(f, "CycloneDX 1.5 (JSON)"),
            Self::CycloneDx15Xml => write!(f, "CycloneDX 1.5 (XML)"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Parsed SBOM result
#[derive(Debug)]
pub struct ParsedSbom {
    pub format_detected: SourceFormat,
    pub components: Vec<Component>,
}

/// Structured version range information for programmatic use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VersionRangeInfo {
    /// Version where the vulnerability was introduced (e.g. "1.0.0").
    pub introduced: Option<String>,
    /// Version where the vulnerability was fixed (e.g. "2.0.0").
    pub fixed: Option<String>,
}

/// Affected version information combining human-readable display and structured ranges.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AffectedVersions {
    /// Human-readable representation (e.g. ">=1.0.0, <2.0.0").
    pub display: String,
    /// Structured version ranges for programmatic use.
    pub ranges: Vec<VersionRangeInfo>,
}

impl AffectedVersions {
    /// Returns true if no range information is available.
    pub fn is_empty(&self) -> bool {
        self.display.is_empty() && self.ranges.is_empty()
    }
}

/// Vulnerability matched against a component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnMatch {
    pub component_name: String,
    pub component_version: String,
    pub cve_id: String,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub source: VulnSource,
    pub affected_versions: AffectedVersions,
    pub fixed_version: Option<String>,
    pub description: String,
    /// Whether this CVE is in the CISA Known Exploited Vulnerabilities catalog.
    pub in_kev: bool,
    /// CISA KEV remediation due date (if applicable).
    pub kev_due_date: Option<chrono::NaiveDate>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
            Self::None => write!(f, "NONE"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl Severity {
    pub fn from_cvss(score: f64) -> Self {
        match score {
            s if s >= 9.0 => Self::Critical,
            s if s >= 7.0 => Self::High,
            s if s >= 4.0 => Self::Medium,
            s if s > 0.0 => Self::Low,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VulnSource {
    Nvd,
    Osv,
    LocalDb,
}

impl fmt::Display for VulnSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nvd => write!(f, "NVD"),
            Self::Osv => write!(f, "OSV"),
            Self::LocalDb => write!(f, "Local DB"),
        }
    }
}

/// License issue found in the SBOM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseIssue {
    pub component_name: String,
    pub component_version: String,
    pub issue_type: LicenseIssueType,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LicenseIssueType {
    /// Copyleft license found (may conflict with proprietary)
    CopyleftDetected,
    /// License is unknown or not in SPDX list
    UnknownLicense,
    /// No license specified
    MissingLicense,
}

impl fmt::Display for LicenseIssueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CopyleftDetected => write!(f, "Copyleft"),
            Self::UnknownLicense => write!(f, "Unknown License"),
            Self::MissingLicense => write!(f, "Missing License"),
        }
    }
}

/// Top-level analysis result
#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub sbom_file: PathBuf,
    pub format_detected: SourceFormat,
    pub components: Vec<Component>,
    pub vulnerabilities: Vec<VulnMatch>,
    pub license_issues: Vec<LicenseIssue>,
    pub stats: AnalysisStats,
    pub timestamp: DateTime<Utc>,
    pub disclaimer: String,
    /// Lookups that failed or could not be attempted. Non-empty means the
    /// vulnerability list is incomplete and "0 vulnerabilities" proves nothing.
    #[serde(default)]
    pub scan_gaps: Vec<ScanGap>,
    /// True for `--offline` scans: only the local database snapshot was
    /// consulted, the CISA KEV catalogue was not, and components the snapshot
    /// has no data for are not identified. Such a result cannot support a Pass.
    #[serde(default)]
    pub offline: bool,
    /// Components looked up without error but with a result that cannot be
    /// trusted as "none": Debian/Ubuntu binary packages with no source package
    /// information and no findings. Not a gap (the exit code is unaffected),
    /// but such a result cannot support a Pass.
    #[serde(default)]
    pub unverified: Vec<String>,
}

/// A vulnerability lookup that did not produce a trustworthy answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanGap {
    /// Component the lookup was for, or [`ScanGap::ALL_COMPONENTS`].
    pub component_name: String,
    pub component_version: String,
    /// Data source involved ("OSV", "NVD", "CISA KEV"), or "none" when no
    /// source could be queried for the component.
    pub source: String,
    pub reason: String,
}

impl ScanGap {
    /// Placeholder name for gaps that affect every component.
    pub const ALL_COMPONENTS: &'static str = "(all components)";

    pub fn new(component: &Component, source: &str, reason: impl Into<String>) -> Self {
        Self {
            component_name: component.name.clone(),
            component_version: component.version.clone(),
            source: source.to_string(),
            reason: reason.into(),
        }
    }
}

impl AnalysisReport {
    pub fn new(
        sbom_file: PathBuf,
        format_detected: SourceFormat,
        components: Vec<Component>,
        vulnerabilities: Vec<VulnMatch>,
        license_issues: Vec<LicenseIssue>,
    ) -> Self {
        let stats = AnalysisStats::from_results(&components, &vulnerabilities, &license_issues);
        Self {
            sbom_file,
            format_detected,
            components,
            vulnerabilities,
            license_issues,
            stats,
            timestamp: Utc::now(),
            disclaimer: crate::report::DISCLAIMER.to_string(),
            scan_gaps: Vec::new(),
            offline: false,
            unverified: Vec::new(),
        }
    }

    /// Records components whose "no findings" result cannot be trusted.
    pub fn with_unverified(mut self, unverified: Vec<String>) -> Self {
        self.unverified = unverified;
        self
    }

    /// Marks the report as produced from the local database snapshot only.
    pub fn with_offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    /// Records lookups that failed or could not be attempted.
    pub fn with_scan_gaps(mut self, scan_gaps: Vec<ScanGap>) -> Self {
        self.scan_gaps = scan_gaps;
        self
    }

    /// False when at least one vulnerability lookup failed or was not possible.
    pub fn is_complete(&self) -> bool {
        self.scan_gaps.is_empty()
    }

    /// Returns exit code: 0 = clean, 1 = issues above threshold,
    /// 2 = scan incomplete (takes precedence: the result cannot be trusted).
    pub fn exit_code(&self, threshold: &Severity) -> i32 {
        if !self.is_complete() {
            return 2;
        }
        let has_vuln_above_threshold = self
            .vulnerabilities
            .iter()
            .any(|v| v.severity >= *threshold);
        let has_license_issues = !self.license_issues.is_empty();

        if has_vuln_above_threshold || has_license_issues {
            1
        } else {
            0
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisStats {
    pub total_components: usize,
    pub components_with_vulns: usize,
    pub total_vulns: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub license_issues: usize,
}

impl AnalysisStats {
    fn from_results(
        components: &[Component],
        vulns: &[VulnMatch],
        license_issues: &[LicenseIssue],
    ) -> Self {
        use std::collections::HashSet;
        let components_with_vulns: HashSet<_> = vulns.iter().map(|v| &v.component_name).collect();
        Self {
            total_components: components.len(),
            components_with_vulns: components_with_vulns.len(),
            total_vulns: vulns.len(),
            critical: vulns
                .iter()
                .filter(|v| v.severity == Severity::Critical)
                .count(),
            high: vulns
                .iter()
                .filter(|v| v.severity == Severity::High)
                .count(),
            medium: vulns
                .iter()
                .filter(|v| v.severity == Severity::Medium)
                .count(),
            low: vulns.iter().filter(|v| v.severity == Severity::Low).count(),
            license_issues: license_issues.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_report() -> AnalysisReport {
        AnalysisReport::new(
            PathBuf::from("x.json"),
            SourceFormat::Unknown,
            vec![],
            vec![],
            vec![],
        )
    }

    #[test]
    fn test_exit_code_clean_scan_is_zero() {
        assert_eq!(empty_report().exit_code(&Severity::Low), 0);
    }

    // A scan with failed lookups must fail CI even when nothing was found.
    #[test]
    fn test_exit_code_incomplete_scan_is_two() {
        let report = empty_report().with_scan_gaps(vec![ScanGap {
            component_name: "openssl".to_string(),
            component_version: "3.0.8".to_string(),
            source: "NVD".to_string(),
            reason: "could not connect".to_string(),
        }]);
        assert!(!report.is_complete());
        assert_eq!(report.exit_code(&Severity::Low), 2);
    }

    fn finding(severity: Severity) -> VulnMatch {
        VulnMatch {
            component_name: "openssl".to_string(),
            component_version: "3.0.8".to_string(),
            cve_id: "CVE-2024-0001".to_string(),
            severity,
            cvss_score: None,
            source: VulnSource::Nvd,
            affected_versions: AffectedVersions::default(),
            fixed_version: None,
            description: String::new(),
            in_kev: false,
            kev_due_date: None,
        }
    }

    fn report_with_finding() -> AnalysisReport {
        AnalysisReport::new(
            PathBuf::from("x.json"),
            SourceFormat::Unknown,
            vec![],
            vec![finding(Severity::Critical)],
            vec![],
        )
    }

    #[test]
    fn test_exit_code_findings_without_gaps_is_one() {
        assert_eq!(report_with_finding().exit_code(&Severity::Low), 1);
    }

    // "Incomplete" outranks "issues found": the list cannot be trusted either way.
    #[test]
    fn test_exit_code_incomplete_takes_precedence_over_findings() {
        let report = report_with_finding().with_scan_gaps(vec![ScanGap {
            component_name: "zlib".to_string(),
            component_version: "1.2.13".to_string(),
            source: "NVD".to_string(),
            reason: "HTTP 503".to_string(),
        }]);
        assert_eq!(report.exit_code(&Severity::Low), 2);
    }

    #[test]
    fn test_scan_gaps_round_trip_through_json() {
        let gap = ScanGap {
            component_name: "zlib".to_string(),
            component_version: "1.2.13".to_string(),
            source: "NVD".to_string(),
            reason: "HTTP 503".to_string(),
        };
        let report = empty_report()
            .with_scan_gaps(vec![gap.clone()])
            .with_offline(true);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["scan_gaps"][0]["component_name"], "zlib");
        assert_eq!(json["scan_gaps"][0]["component_version"], "1.2.13");
        assert_eq!(json["scan_gaps"][0]["source"], "NVD");
        assert_eq!(json["scan_gaps"][0]["reason"], "HTTP 503");
        assert_eq!(json["offline"], true);
        let back: AnalysisReport = serde_json::from_value(json).unwrap();
        assert_eq!(back.scan_gaps, vec![gap]);
        assert!(back.offline);
    }

    // Reports stored by older versions have no `scan_gaps` field.
    #[test]
    fn test_report_without_scan_gaps_field_deserializes() {
        let mut json = serde_json::to_value(empty_report()).unwrap();
        json.as_object_mut().unwrap().remove("scan_gaps");
        json.as_object_mut().unwrap().remove("offline");
        let report: AnalysisReport = serde_json::from_value(json).unwrap();
        assert!(report.is_complete());
        assert!(!report.offline);
    }
}
