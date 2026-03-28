use anyhow::Result;
use serde::Deserialize;

use crate::models::{Component, Hash, ParsedSbom, SourceFormat};

/// SPDX 2.3 JSON document structure (subset we care about)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxDocument {
    #[allow(dead_code)]
    spdx_version: Option<String>,
    #[serde(default)]
    packages: Vec<SpdxPackage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPackage {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version_info: Option<String>,
    #[serde(default)]
    supplier: Option<String>,
    #[serde(default)]
    license_concluded: Option<String>,
    #[serde(default)]
    license_declared: Option<String>,
    #[serde(default)]
    external_refs: Vec<SpdxExternalRef>,
    #[serde(default)]
    checksums: Vec<SpdxChecksum>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxExternalRef {
    #[allow(dead_code)]
    reference_category: Option<String>,
    reference_type: Option<String>,
    reference_locator: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxChecksum {
    algorithm: Option<String>,
    checksum_value: Option<String>,
}

pub fn parse_json(content: &str) -> Result<ParsedSbom> {
    let doc: SpdxDocument = serde_json::from_str(content)
        .map_err(|e| crate::errors::ShieldBomError::ParseError(format!("SPDX JSON: {e}")))?;

    let components = doc
        .packages
        .into_iter()
        .map(|pkg| {
            let cpe = pkg
                .external_refs
                .iter()
                .find(|r| r.reference_type.as_deref() == Some("cpe23Type"))
                .and_then(|r| r.reference_locator.clone());

            let purl = pkg
                .external_refs
                .iter()
                .find(|r| r.reference_type.as_deref() == Some("purl"))
                .and_then(|r| r.reference_locator.clone());

            let licenses = extract_licenses(&pkg);
            let hashes = pkg
                .checksums
                .into_iter()
                .filter_map(|c| {
                    Some(Hash {
                        algorithm: c.algorithm?,
                        value: c.checksum_value?,
                    })
                })
                .collect();

            Component {
                name: pkg.name,
                version: pkg.version_info.unwrap_or_default(),
                supplier: pkg.supplier,
                cpe,
                purl,
                licenses,
                hashes,
                source_format: SourceFormat::Spdx23Json,
            }
        })
        .collect();

    Ok(ParsedSbom {
        format_detected: SourceFormat::Spdx23Json,
        components,
    })
}

pub fn parse_tag_value(content: &str) -> Result<ParsedSbom> {
    let mut components = Vec::new();
    let mut current: Option<TagValueBuilder> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Split on first ": " to handle values that contain colons (e.g., CPE strings)
        let (key, value) = if let Some((k, v)) = line.split_once(": ") {
            (k.trim(), v.trim())
        } else if let Some((k, v)) = line.split_once(':') {
            // Fallback for tags with no space after colon (edge case)
            (k.trim(), v.trim())
        } else {
            continue;
        };

        match key {
            "PackageName" => {
                if let Some(builder) = current.take() {
                    components.push(builder.build());
                }
                current = Some(TagValueBuilder::new(value.to_string()));
            }
            "PackageVersion" => {
                if let Some(ref mut b) = current {
                    b.version = Some(value.to_string());
                }
            }
            "PackageSupplier" => {
                if let Some(ref mut b) = current {
                    b.supplier = Some(value.to_string());
                }
            }
            "PackageLicenseConcluded" | "PackageLicenseDeclared" => {
                if let Some(ref mut b) = current {
                    let v = value.to_string();
                    if value != "NOASSERTION" && value != "NONE" && !b.licenses.contains(&v) {
                        b.licenses.push(v);
                    }
                }
            }
            "PackageChecksum" => {
                if let Some(ref mut b) = current {
                    // Format: "SHA256: abc123..." or "SHA1: def456..."
                    if let Some((alg, hash_val)) = value.split_once(": ") {
                        b.hashes.push(Hash {
                            algorithm: alg.trim().to_string(),
                            value: hash_val.trim().to_string(),
                        });
                    } else if let Some((alg, hash_val)) = value.split_once(':') {
                        b.hashes.push(Hash {
                            algorithm: alg.trim().to_string(),
                            value: hash_val.trim().to_string(),
                        });
                    }
                }
            }
            "ExternalRef" => {
                if let Some(ref mut b) = current {
                    // Format: "SECURITY cpe23Type cpe:2.3:..." or "PACKAGE-MANAGER purl pkg:..."
                    let parts: Vec<&str> = value.splitn(3, ' ').collect();
                    if parts.len() == 3 {
                        match parts[1] {
                            "cpe23Type" => b.cpe = Some(parts[2].to_string()),
                            "purl" => b.purl = Some(parts[2].to_string()),
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if let Some(builder) = current {
        components.push(builder.build());
    }

    Ok(ParsedSbom {
        format_detected: SourceFormat::Spdx23TagValue,
        components,
    })
}

struct TagValueBuilder {
    name: String,
    version: Option<String>,
    supplier: Option<String>,
    cpe: Option<String>,
    purl: Option<String>,
    licenses: Vec<String>,
    hashes: Vec<Hash>,
}

impl TagValueBuilder {
    fn new(name: String) -> Self {
        Self {
            name,
            version: None,
            supplier: None,
            cpe: None,
            purl: None,
            licenses: Vec::new(),
            hashes: Vec::new(),
        }
    }

    fn build(self) -> Component {
        Component {
            name: self.name,
            version: self.version.unwrap_or_default(),
            supplier: self.supplier,
            cpe: self.cpe,
            purl: self.purl,
            licenses: self.licenses,
            hashes: self.hashes,
            source_format: SourceFormat::Spdx23TagValue,
        }
    }
}

fn extract_licenses(pkg: &SpdxPackage) -> Vec<String> {
    let mut licenses = Vec::new();
    for lic in [&pkg.license_concluded, &pkg.license_declared]
        .iter()
        .copied()
        .flatten()
    {
        if lic != "NOASSERTION" && lic != "NONE" && !licenses.contains(lic) {
            licenses.push(lic.clone());
        }
    }
    licenses
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full SPDX tag-value document with multiple packages
    const SAMPLE_TAG_VALUE: &str = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: embedded-firmware
DocumentNamespace: https://example.org/firmware-v1.0
Creator: Tool: shieldbom-1.0

PackageName: openssl
SPDXID: SPDXRef-Package-openssl
PackageVersion: 3.0.1
PackageSupplier: Organization: OpenSSL Software Foundation
PackageDownloadLocation: https://www.openssl.org
FilesAnalyzed: false
PackageLicenseConcluded: Apache-2.0
PackageLicenseDeclared: Apache-2.0
PackageCopyrightText: NOASSERTION
PackageChecksum: SHA256: abc123def456789
ExternalRef: SECURITY cpe23Type cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*
ExternalRef: PACKAGE-MANAGER purl pkg:generic/openssl@3.0.1

PackageName: zlib
SPDXID: SPDXRef-Package-zlib
PackageVersion: 1.2.13
PackageSupplier: Organization: zlib
PackageDownloadLocation: https://zlib.net
FilesAnalyzed: false
PackageLicenseConcluded: Zlib
PackageLicenseDeclared: Zlib
PackageCopyrightText: Copyright (C) 1995-2022 Jean-loup Gailly and Mark Adler
ExternalRef: SECURITY cpe23Type cpe:2.3:a:zlib:zlib:1.2.13:*:*:*:*:*:*:*
ExternalRef: PACKAGE-MANAGER purl pkg:generic/zlib@1.2.13
";

    #[test]
    fn test_parse_tag_value_basic() {
        let result = parse_tag_value(SAMPLE_TAG_VALUE).unwrap();
        assert_eq!(result.format_detected, SourceFormat::Spdx23TagValue);
        assert_eq!(result.components.len(), 2);
    }

    #[test]
    fn test_parse_tag_value_package_fields() {
        let result = parse_tag_value(SAMPLE_TAG_VALUE).unwrap();
        let openssl = &result.components[0];

        assert_eq!(openssl.name, "openssl");
        assert_eq!(openssl.version, "3.0.1");
        assert_eq!(
            openssl.supplier.as_deref(),
            Some("Organization: OpenSSL Software Foundation")
        );
        assert_eq!(openssl.source_format, SourceFormat::Spdx23TagValue);
    }

    #[test]
    fn test_parse_tag_value_cpe_extraction() {
        let result = parse_tag_value(SAMPLE_TAG_VALUE).unwrap();
        let openssl = &result.components[0];

        assert_eq!(
            openssl.cpe.as_deref(),
            Some("cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*")
        );
    }

    #[test]
    fn test_parse_tag_value_purl_extraction() {
        let result = parse_tag_value(SAMPLE_TAG_VALUE).unwrap();
        let openssl = &result.components[0];

        assert_eq!(openssl.purl.as_deref(), Some("pkg:generic/openssl@3.0.1"));
    }

    #[test]
    fn test_parse_tag_value_license_dedup() {
        // When concluded and declared are the same, should appear only once
        let result = parse_tag_value(SAMPLE_TAG_VALUE).unwrap();
        let openssl = &result.components[0];

        assert_eq!(openssl.licenses, vec!["Apache-2.0"]);
    }

    #[test]
    fn test_parse_tag_value_different_licenses() {
        let content = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: https://example.org/test

PackageName: testpkg
PackageVersion: 1.0.0
PackageLicenseConcluded: MIT
PackageLicenseDeclared: Apache-2.0
";
        let result = parse_tag_value(content).unwrap();
        let pkg = &result.components[0];

        assert_eq!(pkg.licenses.len(), 2);
        assert!(pkg.licenses.contains(&"MIT".to_string()));
        assert!(pkg.licenses.contains(&"Apache-2.0".to_string()));
    }

    #[test]
    fn test_parse_tag_value_noassertion_licenses_skipped() {
        let content = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: https://example.org/test

PackageName: testpkg
PackageVersion: 1.0.0
PackageLicenseConcluded: NOASSERTION
PackageLicenseDeclared: NONE
";
        let result = parse_tag_value(content).unwrap();
        let pkg = &result.components[0];

        assert!(pkg.licenses.is_empty());
    }

    #[test]
    fn test_parse_tag_value_checksum() {
        let result = parse_tag_value(SAMPLE_TAG_VALUE).unwrap();
        let openssl = &result.components[0];

        assert_eq!(openssl.hashes.len(), 1);
        assert_eq!(openssl.hashes[0].algorithm, "SHA256");
        assert_eq!(openssl.hashes[0].value, "abc123def456789");
    }

    #[test]
    fn test_parse_tag_value_multiple_packages() {
        let result = parse_tag_value(SAMPLE_TAG_VALUE).unwrap();

        assert_eq!(result.components[0].name, "openssl");
        assert_eq!(result.components[0].version, "3.0.1");

        assert_eq!(result.components[1].name, "zlib");
        assert_eq!(result.components[1].version, "1.2.13");
        assert_eq!(
            result.components[1].cpe.as_deref(),
            Some("cpe:2.3:a:zlib:zlib:1.2.13:*:*:*:*:*:*:*")
        );
    }

    #[test]
    fn test_parse_tag_value_empty_content() {
        let result = parse_tag_value("").unwrap();
        assert!(result.components.is_empty());
    }

    #[test]
    fn test_parse_tag_value_header_only() {
        let content = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: https://example.org/test
Creator: Tool: test-tool
";
        let result = parse_tag_value(content).unwrap();
        assert!(result.components.is_empty());
    }

    #[test]
    fn test_parse_tag_value_missing_version() {
        let content = "\
PackageName: libfoo
PackageLicenseConcluded: MIT
";
        let result = parse_tag_value(content).unwrap();
        assert_eq!(result.components.len(), 1);
        assert_eq!(result.components[0].name, "libfoo");
        assert_eq!(result.components[0].version, ""); // defaults to empty
    }

    #[test]
    fn test_parse_tag_value_comments_and_blank_lines() {
        let content = "\
# This is a comment
SPDXVersion: SPDX-2.3

# Another comment
PackageName: libbar
PackageVersion: 2.0.0

# Package-level comment
PackageLicenseConcluded: BSD-3-Clause
";
        let result = parse_tag_value(content).unwrap();
        assert_eq!(result.components.len(), 1);
        assert_eq!(result.components[0].name, "libbar");
        assert_eq!(result.components[0].version, "2.0.0");
        assert_eq!(result.components[0].licenses, vec!["BSD-3-Clause"]);
    }

    #[test]
    fn test_parse_tag_value_single_package_no_trailing_newline() {
        let content = "PackageName: solo\nPackageVersion: 0.1.0";
        let result = parse_tag_value(content).unwrap();
        assert_eq!(result.components.len(), 1);
        assert_eq!(result.components[0].name, "solo");
        assert_eq!(result.components[0].version, "0.1.0");
    }

    #[test]
    fn test_parse_tag_value_supplier_with_colons() {
        // Supplier value contains colons -- must not be truncated
        let content = "\
PackageName: testpkg
PackageVersion: 1.0
PackageSupplier: Organization: Foo: Bar Corp
";
        let result = parse_tag_value(content).unwrap();
        // split_once(": ") splits at first ": ", so key=PackageSupplier, value="Organization: Foo: Bar Corp"
        assert_eq!(
            result.components[0].supplier.as_deref(),
            Some("Organization: Foo: Bar Corp")
        );
    }

    #[test]
    fn test_parse_tag_value_multiple_checksums() {
        let content = "\
PackageName: multi-hash
PackageVersion: 1.0
PackageChecksum: SHA1: aabbccdd
PackageChecksum: SHA256: 11223344556677889900
PackageChecksum: MD5: deadbeef
";
        let result = parse_tag_value(content).unwrap();
        let pkg = &result.components[0];
        assert_eq!(pkg.hashes.len(), 3);
        assert_eq!(pkg.hashes[0].algorithm, "SHA1");
        assert_eq!(pkg.hashes[0].value, "aabbccdd");
        assert_eq!(pkg.hashes[1].algorithm, "SHA256");
        assert_eq!(pkg.hashes[2].algorithm, "MD5");
        assert_eq!(pkg.hashes[2].value, "deadbeef");
    }

    #[test]
    fn test_parse_tag_value_realistic_embedded_sbom() {
        // Simulates an SBOM from an embedded toolchain (e.g., Yocto/Buildroot output)
        let content = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: firmware-image
DocumentNamespace: https://example.com/firmware-v2.1
Creator: Tool: yocto-spdx-2.0

PackageName: busybox
SPDXID: SPDXRef-Package-busybox
PackageVersion: 1.36.1
PackageSupplier: Organization: BusyBox
PackageDownloadLocation: https://busybox.net
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only
PackageCopyrightText: NOASSERTION
ExternalRef: SECURITY cpe23Type cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*
ExternalRef: PACKAGE-MANAGER purl pkg:generic/busybox@1.36.1

PackageName: linux-kernel
SPDXID: SPDXRef-Package-linux
PackageVersion: 6.1.38
PackageSupplier: Organization: Linux Foundation
PackageDownloadLocation: https://kernel.org
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only
PackageCopyrightText: NOASSERTION
PackageChecksum: SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
ExternalRef: SECURITY cpe23Type cpe:2.3:o:linux:linux_kernel:6.1.38:*:*:*:*:*:*:*

PackageName: u-boot
SPDXID: SPDXRef-Package-uboot
PackageVersion: 2023.07
PackageSupplier: NOASSERTION
PackageDownloadLocation: https://source.denx.de/u-boot
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-or-later
PackageLicenseDeclared: GPL-2.0-or-later
PackageCopyrightText: NOASSERTION
ExternalRef: SECURITY cpe23Type cpe:2.3:a:denx:u-boot:2023.07:*:*:*:*:*:*:*
ExternalRef: PACKAGE-MANAGER purl pkg:generic/u-boot@2023.07
";
        let result = parse_tag_value(content).unwrap();
        assert_eq!(result.components.len(), 3);

        // busybox
        assert_eq!(result.components[0].name, "busybox");
        assert_eq!(result.components[0].version, "1.36.1");
        assert_eq!(result.components[0].licenses, vec!["GPL-2.0-only"]);
        assert!(result.components[0].cpe.is_some());
        assert!(result.components[0].purl.is_some());

        // linux-kernel with checksum but no purl
        assert_eq!(result.components[1].name, "linux-kernel");
        assert_eq!(result.components[1].version, "6.1.38");
        assert_eq!(result.components[1].hashes.len(), 1);
        assert!(result.components[1].purl.is_none());

        // u-boot with NOASSERTION supplier
        assert_eq!(result.components[2].name, "u-boot");
        assert_eq!(
            result.components[2].supplier.as_deref(),
            Some("NOASSERTION")
        );
    }
}
