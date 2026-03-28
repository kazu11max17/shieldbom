//! Version comparison utilities for vulnerability matching.
//!
//! Handles semantic versioning, pre-release versions, and NVD-style version ranges.

use std::cmp::Ordering;
use std::fmt;

/// A parsed semantic version with optional pre-release tag.
///
/// Supports formats like:
/// - `1.2.3`
/// - `1.2.3-alpha.1`
/// - `1.2.3-rc1`
/// - `1.2` (treated as `1.2.0`)
/// - `1` (treated as `1.0.0`)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Option<String>,
}

impl SemVer {
    /// Parse a version string into a SemVer.
    /// Returns None if the string cannot be parsed at all.
    pub fn parse(input: &str) -> Option<Self> {
        let input = input.trim().trim_start_matches('v').trim_start_matches('V');

        if input.is_empty() {
            return None;
        }

        // Split off pre-release: "1.2.3-alpha" -> ("1.2.3", Some("alpha"))
        let (version_part, pre) = if let Some(idx) = input.find('-') {
            let pre_str = &input[idx + 1..];
            (
                &input[..idx],
                if pre_str.is_empty() {
                    None
                } else {
                    Some(pre_str.to_string())
                },
            )
        } else {
            (input, None)
        };

        let parts: Vec<&str> = version_part.split('.').collect();
        if parts.is_empty() || parts.len() > 4 {
            return None;
        }

        let major = parts[0].parse::<u64>().ok()?;
        let minor = if let Some(s) = parts.get(1) {
            s.parse::<u64>().ok()?
        } else {
            0
        };
        let patch = if let Some(s) = parts.get(2) {
            s.parse::<u64>().ok()?
        } else {
            0
        };

        Some(SemVer {
            major,
            minor,
            patch,
            pre,
        })
    }

    /// Returns true if this is a pre-release version.
    pub fn is_prerelease(&self) -> bool {
        self.pre.is_some()
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = &self.pre {
            write!(f, "-{}", pre)?;
        }
        Ok(())
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.minor.cmp(&other.minor) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.patch.cmp(&other.patch) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Pre-release versions have lower precedence than release versions.
        // 1.0.0-alpha < 1.0.0
        match (&self.pre, &other.pre) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(a), Some(b)) => compare_pre_release(a, b),
        }
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Compare pre-release identifiers.
/// Split by '.' and compare each segment numerically if possible, otherwise lexicographically.
fn compare_pre_release(a: &str, b: &str) -> Ordering {
    let a_parts: Vec<&str> = a.split('.').collect();
    let b_parts: Vec<&str> = b.split('.').collect();

    for (ap, bp) in a_parts.iter().zip(b_parts.iter()) {
        let ord = match (ap.parse::<u64>(), bp.parse::<u64>()) {
            (Ok(an), Ok(bn)) => an.cmp(&bn),
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            (Err(_), Err(_)) => ap.cmp(bp),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }

    a_parts.len().cmp(&b_parts.len())
}

/// NVD-style version range for CPE matching.
///
/// Represents conditions like:
/// - versionStartIncluding: "1.0.0", versionEndExcluding: "1.5.3"
///   meaning: affected if 1.0.0 <= version < 1.5.3
#[derive(Debug, Clone)]
pub struct VersionRange {
    pub start_including: Option<SemVer>,
    pub start_excluding: Option<SemVer>,
    pub end_including: Option<SemVer>,
    pub end_excluding: Option<SemVer>,
}

impl VersionRange {
    /// Create a range from NVD-style version boundary strings.
    pub fn from_nvd(
        start_including: Option<&str>,
        start_excluding: Option<&str>,
        end_including: Option<&str>,
        end_excluding: Option<&str>,
    ) -> Self {
        Self {
            start_including: start_including.and_then(SemVer::parse),
            start_excluding: start_excluding.and_then(SemVer::parse),
            end_including: end_including.and_then(SemVer::parse),
            end_excluding: end_excluding.and_then(SemVer::parse),
        }
    }

    /// Check whether a version falls within this range.
    pub fn contains(&self, version: &SemVer) -> bool {
        // Check lower bound
        if let Some(ref start) = self.start_including {
            if version < start {
                return false;
            }
        }
        if let Some(ref start) = self.start_excluding {
            if version <= start {
                return false;
            }
        }

        // Check upper bound
        if let Some(ref end) = self.end_including {
            if version > end {
                return false;
            }
        }
        if let Some(ref end) = self.end_excluding {
            if version >= end {
                return false;
            }
        }

        true
    }

    /// Returns true if this range has no bounds at all (matches everything).
    pub fn is_unbounded(&self) -> bool {
        self.start_including.is_none()
            && self.start_excluding.is_none()
            && self.end_including.is_none()
            && self.end_excluding.is_none()
    }
}

/// Fuzzy vendor matching for CPE strings.
///
/// Handles common discrepancies between CPE vendor names and actual package names:
/// - "openssl" vs "openssl_project"
/// - "apache" vs "apache_software_foundation"
/// - "busybox" vs "busybox_project"
pub fn fuzzy_vendor_match(cpe_vendor: &str, component_name: &str) -> bool {
    let cpe_v = normalize_vendor(cpe_vendor);
    let comp_n = normalize_vendor(component_name);

    // Exact match after normalization
    if cpe_v == comp_n {
        return true;
    }

    // Check if one is a prefix/suffix of the other (handles "_project", "_software_foundation")
    if cpe_v.starts_with(&comp_n) || comp_n.starts_with(&cpe_v) {
        return true;
    }

    // Check common suffixes that NVD adds
    let common_suffixes = [
        "_project",
        "_software_foundation",
        "_developers",
        "_team",
        "_org",
    ];
    for suffix in common_suffixes {
        let stripped = cpe_v.trim_end_matches(suffix);
        if stripped == comp_n {
            return true;
        }
        let stripped = comp_n.trim_end_matches(suffix);
        if stripped == cpe_v {
            return true;
        }
    }

    false
}

/// Normalize a vendor/product name for comparison.
fn normalize_vendor(name: &str) -> String {
    name.to_lowercase().replace(['-', ' '], "_")
}

/// Extract vendor and product from a CPE 2.3 URI string.
///
/// CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:...
/// Example: cpe:2.3:a:openssl_project:openssl:1.1.1:*:*:*:*:*:*:*
pub fn parse_cpe_parts(cpe: &str) -> Option<CpeParts> {
    let parts: Vec<&str> = cpe.split(':').collect();
    if parts.len() < 6 {
        return None;
    }

    // CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
    // CPE 2.2 format: cpe:/part:vendor:product:version:...
    let (vendor, product, version) = if parts[1] == "2.3" {
        (
            parts.get(3).copied().unwrap_or("*"),
            parts.get(4).copied().unwrap_or("*"),
            parts.get(5).copied().unwrap_or("*"),
        )
    } else if parts[0] == "cpe" && parts[1].starts_with('/') {
        // CPE 2.2: cpe:/a:vendor:product:version
        let part1 = parts[1].trim_start_matches('/');
        (
            part1.get(2..).unwrap_or("*"),
            parts.get(2).copied().unwrap_or("*"),
            parts.get(3).copied().unwrap_or("*"),
        )
    } else {
        return None;
    };

    Some(CpeParts {
        vendor: vendor.to_string(),
        product: product.to_string(),
        version: if version == "*" {
            None
        } else {
            Some(version.to_string())
        },
    })
}

/// Parsed components from a CPE string.
#[derive(Debug, Clone)]
pub struct CpeParts {
    pub vendor: String,
    pub product: String,
    pub version: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- SemVer parsing tests --

    #[test]
    fn test_parse_basic() {
        let v = SemVer::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
        assert_eq!(v.pre, None);
    }

    #[test]
    fn test_parse_with_v_prefix() {
        let v = SemVer::parse("v2.0.1").unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 1);
    }

    #[test]
    fn test_parse_two_parts() {
        let v = SemVer::parse("1.2").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_parse_single_part() {
        let v = SemVer::parse("5").unwrap();
        assert_eq!(v.major, 5);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_parse_prerelease() {
        let v = SemVer::parse("1.0.0-alpha.1").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 0);
        assert_eq!(v.pre, Some("alpha.1".to_string()));
        assert!(v.is_prerelease());
    }

    #[test]
    fn test_parse_rc() {
        let v = SemVer::parse("3.2.1-rc2").unwrap();
        assert_eq!(v.pre, Some("rc2".to_string()));
    }

    #[test]
    fn test_parse_empty() {
        assert!(SemVer::parse("").is_none());
    }

    #[test]
    fn test_parse_garbage() {
        assert!(SemVer::parse("not-a-version").is_none());
    }

    // -- SemVer ordering tests --

    #[test]
    fn test_ordering_basic() {
        let v1 = SemVer::parse("1.0.0").unwrap();
        let v2 = SemVer::parse("2.0.0").unwrap();
        assert!(v1 < v2);
    }

    #[test]
    fn test_ordering_minor() {
        let v1 = SemVer::parse("1.2.0").unwrap();
        let v2 = SemVer::parse("1.3.0").unwrap();
        assert!(v1 < v2);
    }

    #[test]
    fn test_ordering_patch() {
        let v1 = SemVer::parse("1.0.1").unwrap();
        let v2 = SemVer::parse("1.0.2").unwrap();
        assert!(v1 < v2);
    }

    #[test]
    fn test_ordering_prerelease_vs_release() {
        // Pre-release < release for same version
        let pre = SemVer::parse("1.0.0-alpha").unwrap();
        let rel = SemVer::parse("1.0.0").unwrap();
        assert!(pre < rel);
    }

    #[test]
    fn test_ordering_prerelease_alpha_vs_beta() {
        let alpha = SemVer::parse("1.0.0-alpha").unwrap();
        let beta = SemVer::parse("1.0.0-beta").unwrap();
        assert!(alpha < beta);
    }

    #[test]
    fn test_ordering_prerelease_numeric() {
        let rc1 = SemVer::parse("1.0.0-rc.1").unwrap();
        let rc2 = SemVer::parse("1.0.0-rc.2").unwrap();
        assert!(rc1 < rc2);
    }

    #[test]
    fn test_ordering_equal() {
        let v1 = SemVer::parse("1.2.3").unwrap();
        let v2 = SemVer::parse("1.2.3").unwrap();
        assert_eq!(v1, v2);
    }

    // -- VersionRange tests --

    #[test]
    fn test_range_start_including_end_excluding() {
        // Affected: 1.0.0 <= v < 1.5.0
        let range = VersionRange::from_nvd(Some("1.0.0"), None, None, Some("1.5.0"));

        assert!(range.contains(&SemVer::parse("1.0.0").unwrap()));
        assert!(range.contains(&SemVer::parse("1.2.3").unwrap()));
        assert!(range.contains(&SemVer::parse("1.4.9").unwrap()));
        assert!(!range.contains(&SemVer::parse("1.5.0").unwrap()));
        assert!(!range.contains(&SemVer::parse("0.9.9").unwrap()));
        assert!(!range.contains(&SemVer::parse("2.0.0").unwrap()));
    }

    #[test]
    fn test_range_start_excluding_end_including() {
        // Affected: 1.0.0 < v <= 2.0.0
        let range = VersionRange::from_nvd(None, Some("1.0.0"), Some("2.0.0"), None);

        assert!(!range.contains(&SemVer::parse("1.0.0").unwrap()));
        assert!(range.contains(&SemVer::parse("1.0.1").unwrap()));
        assert!(range.contains(&SemVer::parse("2.0.0").unwrap()));
        assert!(!range.contains(&SemVer::parse("2.0.1").unwrap()));
    }

    #[test]
    fn test_range_only_end_excluding() {
        // Affected: v < 3.0.0 (all versions before 3.0.0)
        let range = VersionRange::from_nvd(None, None, None, Some("3.0.0"));

        assert!(range.contains(&SemVer::parse("0.1.0").unwrap()));
        assert!(range.contains(&SemVer::parse("2.9.9").unwrap()));
        assert!(!range.contains(&SemVer::parse("3.0.0").unwrap()));
    }

    #[test]
    fn test_range_unbounded() {
        let range = VersionRange::from_nvd(None, None, None, None);
        assert!(range.is_unbounded());
        assert!(range.contains(&SemVer::parse("99.99.99").unwrap()));
    }

    #[test]
    fn test_range_with_prerelease() {
        let range = VersionRange::from_nvd(Some("1.0.0"), None, None, Some("1.5.0"));

        // 1.0.0-alpha < 1.0.0, so it should NOT be in range
        assert!(!range.contains(&SemVer::parse("1.0.0-alpha").unwrap()));
        // 1.5.0-rc1 < 1.5.0, so it IS in range
        assert!(range.contains(&SemVer::parse("1.5.0-rc1").unwrap()));
    }

    // -- Fuzzy vendor matching tests --

    #[test]
    fn test_fuzzy_vendor_exact() {
        assert!(fuzzy_vendor_match("openssl", "openssl"));
    }

    #[test]
    fn test_fuzzy_vendor_project_suffix() {
        assert!(fuzzy_vendor_match("openssl_project", "openssl"));
        assert!(fuzzy_vendor_match("openssl", "openssl_project"));
    }

    #[test]
    fn test_fuzzy_vendor_foundation_suffix() {
        assert!(fuzzy_vendor_match("apache_software_foundation", "apache"));
    }

    #[test]
    fn test_fuzzy_vendor_case_insensitive() {
        assert!(fuzzy_vendor_match("OpenSSL", "openssl"));
    }

    #[test]
    fn test_fuzzy_vendor_hyphen_vs_underscore() {
        assert!(fuzzy_vendor_match("my-project", "my_project"));
    }

    #[test]
    fn test_fuzzy_vendor_no_match() {
        assert!(!fuzzy_vendor_match("curl", "openssl"));
    }

    #[test]
    fn test_fuzzy_vendor_busybox() {
        assert!(fuzzy_vendor_match("busybox_project", "busybox"));
    }

    // -- CPE parsing tests --

    #[test]
    fn test_parse_cpe_23() {
        let cpe = parse_cpe_parts("cpe:2.3:a:openssl_project:openssl:1.1.1:*:*:*:*:*:*:*").unwrap();
        assert_eq!(cpe.vendor, "openssl_project");
        assert_eq!(cpe.product, "openssl");
        assert_eq!(cpe.version, Some("1.1.1".to_string()));
    }

    #[test]
    fn test_parse_cpe_23_wildcard_version() {
        let cpe = parse_cpe_parts("cpe:2.3:a:busybox_project:busybox:*:*:*:*:*:*:*:*").unwrap();
        assert_eq!(cpe.vendor, "busybox_project");
        assert_eq!(cpe.product, "busybox");
        assert_eq!(cpe.version, None);
    }

    #[test]
    fn test_parse_cpe_invalid() {
        assert!(parse_cpe_parts("not-a-cpe").is_none());
    }

    #[test]
    fn test_display_semver() {
        assert_eq!(SemVer::parse("1.2.3").unwrap().to_string(), "1.2.3");
        assert_eq!(
            SemVer::parse("1.0.0-beta.1").unwrap().to_string(),
            "1.0.0-beta.1"
        );
    }
}
