// Package ossguard provides a CLI tool to guard any OSS project with
// OpenSSF security best practices.
//
// OSSGuard scans any project and tells you exactly what OpenSSF security
// components are missing — then fixes them. It works with Python, JavaScript,
// Go, Rust, Java, C/C++, and more.
//
// # Installation
//
// Install via Go:
//
//	go install github.com/kirankotari/ossguard-go/cmd/ossguard@latest
//
// Or via Homebrew:
//
//	brew install kirankotari/tap/ossguard
//
// Or download a binary from the releases page:
//
//	https://github.com/kirankotari/ossguard-go/releases
//
// # Quick Start
//
//	ossguard scan .          # Quick security posture check
//	ossguard audit .         # Full security audit with grade
//	ossguard init .          # Bootstrap all OpenSSF security configs
//	ossguard baseline .      # OSPS Baseline compliance check
//
// # Commands
//
// OSSGuard provides 27 commands organized into four categories:
//
// Core: init, scan, audit, version
//
// Security Analysis: secrets, baseline, slsa, badge, maturity, container, fuzz
//
// Dependency Management: deps, drift, watch, reach, update, license, supply-chain, tpn
//
// Compliance & Generation: policy, ci, report, insights, pin, fix, sbom-gen, compare
//
// All commands support --json for machine-readable output and --path to specify
// the project directory (or accept a positional argument).
//
// # Architecture
//
// The CLI is built with cobra and organized into:
//
//   - cmd/ossguard: CLI entry point and command definitions
//   - internal/detector: Project type and language detection
//   - internal/analyzers: Security analysis functions
//   - internal/generators: Security configuration file generators
//   - internal/parsers: Dependency file parsers
//   - internal/apis: External API clients (deps.dev, OSV)
//
// # Other Implementations
//
// OSSGuard is also available as:
//
//   - Python: https://github.com/kirankotari/ossguard-python
//   - Node.js: https://github.com/kirankotari/ossguard-npm
//
// For full documentation see: https://github.com/kirankotari/ossguard
package ossguard
