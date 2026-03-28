use crate::models::{Component, LicenseIssue, LicenseIssueType};

/// Known copyleft licenses that may conflict with proprietary use
const COPYLEFT_LICENSES: &[&str] = &[
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-2.0",
    "EUPL-1.2",
    "CPAL-1.0",
    "OSL-3.0",
    // Common shorthand variants
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
    "LGPL-2.1",
    "LGPL-3.0",
];

/// Check components for license issues
pub fn check(components: &[Component]) -> Vec<LicenseIssue> {
    let mut issues = Vec::new();

    for component in components {
        if component.licenses.is_empty() {
            issues.push(LicenseIssue {
                component_name: component.name.clone(),
                component_version: component.version.clone(),
                issue_type: LicenseIssueType::MissingLicense,
                description: "No license information found".to_string(),
            });
            continue;
        }

        for license in &component.licenses {
            // SPDX LicenseRef-* identifiers are valid custom licenses
            if license.starts_with("LicenseRef-") {
                continue;
            }
            if is_copyleft(license) {
                issues.push(LicenseIssue {
                    component_name: component.name.clone(),
                    component_version: component.version.clone(),
                    issue_type: LicenseIssueType::CopyleftDetected,
                    description: format!(
                        "Copyleft license '{}' detected - may conflict with proprietary distribution",
                        license
                    ),
                });
            } else if !is_known_license(license) && license != "NOASSERTION" && license != "NONE" {
                issues.push(LicenseIssue {
                    component_name: component.name.clone(),
                    component_version: component.version.clone(),
                    issue_type: LicenseIssueType::UnknownLicense,
                    description: format!("Unrecognized license identifier: '{}'", license),
                });
            }
        }
    }

    issues
}

fn is_copyleft(license: &str) -> bool {
    // Check if license string contains any copyleft identifier
    // Handle SPDX expressions like "GPL-3.0-only AND MIT"
    for copyleft in COPYLEFT_LICENSES {
        if license.contains(copyleft) {
            return true;
        }
    }
    false
}

fn is_known_license(license: &str) -> bool {
    const KNOWN_PERMISSIVE: &[&str] = &[
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "Unlicense",
        "CC0-1.0",
        "Zlib",
        "BSL-1.0",
        "0BSD",
        "BlueOak-1.0.0",
        "EPL-1.0",
        "EPL-2.0",
        "WTFPL",
        "CC-BY-4.0",
        "CC-BY-SA-4.0",
        "PostgreSQL",
        "Artistic-2.0",
    ];

    // Check permissive
    for known in KNOWN_PERMISSIVE {
        if license.contains(known) {
            return true;
        }
    }

    // Copyleft is also "known"
    is_copyleft(license)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SourceFormat;

    fn make_component(name: &str, licenses: Vec<&str>) -> Component {
        Component {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            supplier: None,
            cpe: None,
            purl: None,
            licenses: licenses.into_iter().map(String::from).collect(),
            hashes: Vec::new(),
            source_format: SourceFormat::Spdx23Json,
        }
    }

    #[test]
    fn test_copyleft_detected() {
        let components = vec![make_component("libfoo", vec!["GPL-3.0-only"])];
        let issues = check(&components);
        assert_eq!(issues.len(), 1);
        assert!(matches!(
            issues[0].issue_type,
            LicenseIssueType::CopyleftDetected
        ));
    }

    #[test]
    fn test_missing_license() {
        let components = vec![make_component("libbar", vec![])];
        let issues = check(&components);
        assert_eq!(issues.len(), 1);
        assert!(matches!(
            issues[0].issue_type,
            LicenseIssueType::MissingLicense
        ));
    }

    #[test]
    fn test_permissive_no_issues() {
        let components = vec![make_component("libclean", vec!["MIT", "Apache-2.0"])];
        let issues = check(&components);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_unknown_license() {
        let components = vec![make_component("libweird", vec!["CustomLicense-1.0"])];
        let issues = check(&components);
        assert_eq!(issues.len(), 1);
        assert!(matches!(
            issues[0].issue_type,
            LicenseIssueType::UnknownLicense
        ));
    }
}
