# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Known-answer regression tests against the live OSV.dev, NVD and CISA KEV data (ignored by default).

### Fixed
- **The suggested fix version now comes from the affected range that contains the
  component's version.** When NVD lists one range per release line, earlier versions
  reported the fix of the first range, so OpenSSL 3.0.8 was told to "upgrade to 1.0.2zq"
  instead of 3.0.21. When no range is known to contain the version (for example, the
  range ends with "up to and including"), no fix version from another range is suggested.
  Findings themselves are unchanged.
- **A CVE that NVD lists only for a similarly named product is no longer confirmed.**
  Without a CPE in the SBOM, the product is matched by name. A CPE for a language package
  (`openssl.js` for node.js, `openssl_encrypt` for Python) or a name continued with `.` or
  `-` (`openssl-feedstock`) matched a component named `openssl` and was reported as
  confirmed. Such findings are now kept as unconfirmed. Names NVD extends with `_` (`linux`
  and `linux_kernel`, `confluence` and `confluence_server`) are still matched as before.
  The same applies when the component's version cannot be compared.
- **CVE records that NVD has rejected are no longer reported.** Withdrawn or duplicate
  records ("DO NOT USE THIS CANDIDATE NUMBER") showed up as unconfirmed findings.

## [0.3.3] - 2026-11-24

If you scanned components with OpenSSL-style versions, or whose NVD data uses them (such
as OpenSSL 1.0.x or 1.1.x), with 0.3.2 or earlier, re-run the scan and regenerate any CRA report.
Those versions could report findings outside the affected range, including a `FAIL` for
"Delivered without known exploitable vulnerabilities". This concerns the NVD lookup only.

### Fixed
- **OpenSSL-style versions with a letter (`1.0.1g`, `1.0.2zh`) are now compared
  correctly.** Earlier versions could not parse them and silently dropped such a boundary
  from NVD's version range, which widened the range. In November 2026, scanning OpenSSL
  3.0.8 reported 259 findings, among them CVEs fixed in 0.9.x and 1.0.x and Heartbleed
  (CVE-2014-0160, affecting 1.0.1 through 1.0.1f and 1.0.2-beta1), so the CRA report
  issued `FAIL` for "Delivered without known exploitable vulnerabilities". The same scan
  now reports 152 findings. Heartbleed is still reported on 1.0.1f.
- **Components whose own version has a letter (such as `1.0.1f`) are now checked against
  NVD's product and version data.** Earlier versions could not parse the version and
  reported every NVD match as confirmed, including CVEs for other products and other
  versions. In November 2026, a keyword scan of OpenSSL 1.0.1f went from 705 to 240
  findings.
- A version boundary that still cannot be parsed is no longer dropped: the finding is
  kept and marked unconfirmed instead of being reported as confirmed or not reported.
  If such a finding is listed in the CISA KEV catalogue, the CRA report issues `REVIEW`
  and names the CVE instead of `FAIL`. The unconfirmed label in every output format now
  covers both reasons (NVD has not analysed the CVE, or its version range could not be
  compared).

### Known limitations
- A letter after the last number is read as a later release, as OpenSSL uses it. For a
  project that writes a pre-release as a bare letter (`2.0b` for a beta of 2.0), a CVE
  fixed in 2.0 can be missed on `2.0b`.

## [0.3.2] - 2026-11-17

### Changed
- **NVD findings that could not be checked against product and version data are now
  marked unconfirmed.** A keyword search (components without a CPE) returns any CVE whose
  description mentions the name. When NVD has not analysed a CVE (awaiting analysis or
  deferred), it has no product or version data, and such CVEs were reported as plain
  findings. In the bundled sample in November 2026, 12 of 21 such findings concerned other
  products (for example software that bundles its own copy of cJSON or lwIP) or other
  versions. They are still reported and still count toward the exit code, but are now
  labelled in the table, HTML and CRA reports, SARIF (`"may affect"`,
  `properties.unconfirmed`) and JSON (`unconfirmed`, `stats.unconfirmed`).
- The CRA report no longer issues `FAIL` for "Delivered without known exploitable
  vulnerabilities" on the basis of an unconfirmed finding listed in the CISA KEV
  catalogue. It issues `REVIEW` and names the CVE. Other findings listed in the CISA KEV
  catalogue still produce `FAIL`.

## [0.3.1] - 2026-11-16

Everyone on 0.3.0 or earlier should upgrade. Those versions can report
"0 vulnerabilities" for components that have known vulnerabilities, and the CRA report
could issue `PASS` for "Delivered without known exploitable vulnerabilities" on that
basis. Re-run any scan and regenerate any CRA report produced with those versions.

### Fixed
- **OSV.dev lookups always failed for PURLs that carry a version.** The request sent
  the version both inside the PURL and as a separate field, which OSV.dev rejects with
  HTTP 400. The error was swallowed, so such components always showed 0 vulnerabilities.
  The version is now sent once.
- **Failed lookups are no longer reported as "no vulnerabilities" in online scans.**
  Network errors, rate limits (HTTP 429), HTTP 403 and other API errors from OSV.dev
  and NVD were only logged at a level hidden by default. With the network down, a scan
  printed "Found 0 vulnerabilities" and the CRA report issued `PASS` for "Delivered
  without known exploitable vulnerabilities". Failed and impossible lookups are now
  recorded: the scan is marked `SCAN INCOMPLETE` on stderr and in the table, JSON
  (`scan_gaps`), SARIF (`invocations[].executionSuccessful`, plus `scanComplete` and
  `scanGaps` properties), HTML and CRA outputs; the CRA item becomes `REVIEW`; the
  badge shows "scan incomplete"; and the exit code is 2.
- **Components OSV.dev has no data for were never matched by default.** `pkg:generic`
  components were sent only to OSV.dev, so the bundled firmware example showed
  0 vulnerabilities unless `--nvd` was passed. PURLs are now sent to OSV.dev only for
  ecosystems and distributions confirmed to be answered; everything else goes to NVD by
  default, including `pkg:generic`, `pkg:github`, `pkg:conan`, `pkg:apk` and
  distributions such as OpenWrt, Raspbian, CentOS and Fedora. The `distro` qualifier is
  no longer sent to OSV.dev, which returned nothing for spellings such as
  `distro=debian-12`. Results now cover all releases of the distribution, so some
  findings may already be fixed in the release you ship.
- **Debian and Ubuntu binary packages were never matched.** OSV.dev indexes these
  distributions by source package, so `libssl3`, `zlib1g`, `libc6` and similar returned
  0 vulnerabilities. A `pkg:deb` PURL with an `upstream` qualifier is now looked up by
  that source package; one without is also looked up in NVD, and if it still has no
  findings it is reported as unverified and the CRA report does not issue `PASS`.
- **Large result sets were silently cut off.** OSV.dev and NVD results are now read
  page by page. A result set too large to read completely marks the scan incomplete.
- **CISA KEV data was never applied.** The catalogue field `cveID` was read as `cveId`,
  so the catalogue failed to parse and no finding was ever flagged as known-exploited
  (and the CRA report never issued `FAIL` on that basis). The client now also sends a
  `User-Agent`, and keeps entries whose due date cannot be read. A KEV fetch failure
  with findings present marks the scan incomplete.
- **Offline scans could issue a CRA `PASS` and state that no finding is in the CISA KEV
  catalogue**, although `--offline` never consults it. The item is now always `REVIEW`
  for offline scans and the evidence says what was and was not checked. Offline HTML
  and CRA reports and the badge no longer show a clean result.
- HTML and CRA reports no longer show "No vulnerabilities found" for an incomplete scan.
- The badge showed a green "0 vulns" when all findings were medium, low or unscored.
  It now shows the number of findings in yellow.
- An unusable `SHIELDBOM_NVD_API_KEY` is reported instead of silently ignored.
- The CRA report footer printed "DISCLAIMER: DISCLAIMER:".

### Security
- **NVD query values were not URL-encoded.** Characters such as `+`, `#` and `&` in a
  component name or CPE changed the request (for example `libstdc++`), and a crafted
  SBOM could narrow the query to hide findings.
- Control characters in SBOM strings can no longer forge or overwrite lines in the
  list of failed lookups.

### Changed
- Exit code 2 now also means "scan incomplete" and takes precedence over 1.
- Scans of SBOMs with PURLs that OSV.dev does not cover are slower by default because
  they now query NVD (about 6.5 s per component without `SHIELDBOM_NVD_API_KEY`).
- Transient NVD failures (timeouts, HTTP 429, server errors) are retried up to twice,
  so a scan without network access takes longer to fail than before. After three
  consecutive failures to connect or to get a response in time, a data source is given
  up on and its remaining components are reported as not queried. A data source that is
  only very slow can therefore be given up on as well.
- `shieldbom-core`: `vuln::match_vulnerabilities` now returns `MatchOutcome`, and
  `AnalysisReport` has new public fields `scan_gaps` and `offline`.
- README example output replaced with real output.

### Known limitations
- `--offline` scans do not track lookup completeness and do not consult the CISA KEV
  catalogue. A clean offline result means nothing was found in the local snapshot.
  The snapshot generally has no data for `pkg:generic` components.
- NVD keyword search (used for components without a CPE) can return false positives
  and can miss vulnerabilities.
- `pkg:deb` PURLs without an `upstream` qualifier name a binary package, which OSV.dev
  does not index; NVD is queried as well, but vulnerabilities can still be missed.

## [0.3.0] - 2026-08-03

### Fixed
- **Corrected six wrong CRA references in the compliance report.** Annex I, Part I
  points (2)(a) and (2)(b) were swapped, so the "known exploitable vulnerabilities"
  and "secure by default" rows cited each other's requirement. Annex I, Part II has
  eight points, but the report referenced a "point 9" that does not exist. Annex VII
  points 3 and 4 were mismapped. Third-party component due diligence is Article 13(5),
  not 13(4).
- **"Vulnerability handling process in place" no longer reports Pass.** It was
  hardcoded, so a single scan certified an ongoing process that the tool cannot
  observe — Annex I, Part II requires remediation without delay and regular testing.
  It is now `N/A` with evidence stating that manufacturer attestation is required.
- **Severity is no longer used as a proxy for exploitability.** Annex I, Part I,
  point (2)(a) concerns *known exploitable* vulnerabilities, but the check passed
  whenever no critical or high findings existed, so medium and low findings passed
  silently. CISA KEV membership — already collected elsewhere in the codebase — now
  drives this verdict.
- **Third-party due diligence no longer uses license completeness as a proxy.**
  Article 13(5) is about components not compromising cybersecurity; a component with
  a missing license field is not evidence of that either way.
- **The report no longer calls itself a "Conformity Assessment".** That is a legal
  term under Article 32 and Annex VIII, performed by the manufacturer or a notified
  body. The section is now "CRA Essential Requirements — SBOM-derived Indicators".

### Added
- CRA report product identification: `--product-name`, `--product-version`,
  `--manufacturer`, `--support-period`, `--update-mechanism`. Previously these were
  hardcoded placeholders, which meant the report could not identify the product it
  described and so could not serve as technical documentation.
- A `REVIEW` status for findings the tool can report but must not adjudicate.
- A `DRAFT — NOT FOR COMPLIANCE USE` banner, shown whenever product identification
  is incomplete. It survives printing, because reports get circulated as PDFs.
- A scope note on the report itself stating that it is not a conformity assessment.
  The README is not distributed with the HTML, so the disclaimer has to travel with
  the document.
- `ProductMetadata` and `report::render_with_product()` in `shieldbom-core`.
  `render()` is unchanged.
- CISA KEV integration: `in_kev` on vulnerability matches, surfaced in table output.
- Local database staleness warning, with `--allow-stale` to override.
- `init` command for generating CI configuration.
- SARIF output metadata and an SVG badge (`--badge`).
- `aarch64-apple-darwin` release target.

### Changed
- The report footer disclaimer is now rendered from the shared `DISCLAIMER` constant
  instead of a copy in the template, so a revision cannot leave distributed HTML stale.
- `Product ID` in the report header is now `Report ID`; it was always a scan
  identifier, not a product identifier in the sense of Annex VII.
- Structured `AffectedVersions` in place of free-form strings.

### Security
- Input validation and ANSI escape sanitisation for values taken from SBOM files.

## [0.2.0] - 2026-04-04

### Changed
- Swapped crate names for crates.io: the CLI is now `shieldbom` and the library is
  `shieldbom-core`. `shieldbom-cli` 0.1.2 was yanked.
- `shieldbom-server` is marked `publish = false`.

## [0.1.2] - 2026-04-03

### Added
- Publish metadata for crates.io.
- A disclaimer on all report output.

### Security
- XXE protection in the CycloneDX XML parser.

## [0.1.1] - 2026-03-20

### Changed
- Removed the competitor comparison table from the README and revised the roadmap.
- Corrected `SECURITY.md` and `CONTRIBUTING.md`.

## [0.1.0] - 2026-03-19

### Added
- SBOM parsing: SPDX 2.3 (JSON, Tag-Value) and CycloneDX 1.4/1.5 (JSON, XML)
- Vulnerability matching via OSV.dev and NVD API 2.0
- CPE-based vulnerability lookup with CVSS severity scoring
- License conflict detection (copyleft detection, missing license warnings)
- SQLite-based offline vulnerability database (`db update` / `db info`)
- Multiple output formats: table (default), JSON, SARIF 2.1.0
- CLI commands: `scan`, `validate`, `db update`, `db info`
- Configurable severity threshold (`--severity`)
- Offline mode (`--offline`)
- Non-zero exit codes for CI/CD integration
- Example SBOM files for an IoT gateway firmware project
