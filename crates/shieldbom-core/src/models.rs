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

/// Vulnerability matched against a component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnMatch {
    pub component_name: String,
    pub component_version: String,
    pub cve_id: String,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub source: VulnSource,
    pub affected_versions: String,
    pub fixed_version: Option<String>,
    pub description: String,
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
        }
    }

    /// Returns exit code: 0 = clean, 1 = issues above threshold
    pub fn exit_code(&self, threshold: &Severity) -> i32 {
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
