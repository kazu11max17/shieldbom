# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
