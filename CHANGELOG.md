# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-05-09

### Changed

- README updated for multi-repo structure, links to main [ossguard](https://github.com/kirankotari/ossguard) docs repo
- Added "Other Implementations" section to README

### Fixed

- All commands now accept positional path argument (`ossguard scan /path`) in addition to `--path` flag

## [0.1.0] - 2026-05-08

### Added

- Native Go implementation of all 26 ossguard commands
- Single static binary, zero runtime dependencies
- Project detection for Python, JavaScript/TypeScript, Go, Rust, Java, C/C++
- OSV and deps.dev API integrations
- SPDX and CycloneDX SBOM generation
- OSPS Baseline compliance checking (Levels 1–3)
- SLSA provenance level assessment (Levels 1–4)
- S2C2F maturity framework assessment
- Secret scanning with 17 regex-based detection rules
- Dockerfile security linting
- GitHub Actions pinning to commit SHAs
- SECURITY-INSIGHTS.yml generation and validation
- Cross-project security posture comparison
- HTML and JSON compliance report export
- JSON output mode for all commands (`--json`)
- Cobra-based CLI with shell completion
- OpenSSF repository standards: LICENSE, CONTRIBUTING, CODE_OF_CONDUCT, CHANGELOG, SECURITY
