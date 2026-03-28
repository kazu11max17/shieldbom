# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
