# OSSGuard — Go Implementation

**The native Go implementation of [OSSGuard](https://github.com/kirankotari/ossguard).**

[![Go](https://img.shields.io/github/v/release/kirankotari/ossguard-go)](https://github.com/kirankotari/ossguard-go/releases)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Single static binary, zero runtime dependencies. Optimized for CI pipelines and automation.

> For full documentation, all install methods, and command examples, see the main [ossguard](https://github.com/kirankotari/ossguard) repo.

## Install

### Homebrew

```bash
brew install kirankotari/tap/ossguard
```

### Go

```bash
go install github.com/kirankotari/ossguard-go/cmd/ossguard@latest
```

### Binary

Download from [GitHub Releases](https://github.com/kirankotari/ossguard-go/releases).

## Quick Start

```bash
# Initialize security configs
ossguard init

# Run a full security audit
ossguard audit

# Scan for leaked secrets
ossguard secrets

# Check OSPS Baseline compliance
ossguard baseline

# Pin GitHub Actions to commit SHAs
ossguard pin --apply
```

## Commands

| Command | Description |
|---------|-------------|
| `init` | Bootstrap security configs for a project |
| `scan` | Quick scan for security configuration |
| `version` | Show version |
| **Dependencies** | |
| `deps` | Analyze dependency health and vulnerabilities |
| `drift` | Detect dependency drift from lock files |
| `watch` | Monitor dependencies for new vulnerabilities |
| `tpn` | Generate third-party notices |
| `reach` | Reachability-filtered vulnerability analysis |
| **Audit & Fix** | |
| `audit` | Comprehensive security audit |
| `fix` | Auto-remediate common security issues |
| `badge` | OpenSSF Best Practices Badge readiness |
| `ci` | Generate unified security CI pipeline |
| `report` | Export HTML/JSON compliance reports |
| `policy` | Organization-wide security policy enforcement |
| `license` | License compliance checking |
| **Advanced** | |
| `baseline` | OSPS Baseline compliance (Levels 1–3) |
| `insights` | Generate/validate SECURITY-INSIGHTS.yml |
| `pin` | Pin GitHub Actions to commit SHAs |
| `secrets` | Scan for leaked credentials |
| `slsa` | SLSA provenance level assessment |
| `sbom-gen` | Generate SPDX or CycloneDX SBOMs |
| `supply-chain` | Malicious package and typosquatting detection |
| `container` | Dockerfile security linting |
| `compare` | Compare security posture of two projects |
| `update` | Security-prioritized dependency updates |
| `maturity` | S2C2F maturity assessment |
| `fuzz` | Fuzzing readiness check |

All commands support `--json` for machine-readable output.

## Other Implementations

| Implementation | Install | Best for |
|---------------|---------|----------|
| **[ossguard-python](https://github.com/kirankotari/ossguard-python)** | `pip install ossguard` | Rich UI, developer workstation |
| **[ossguard-npm](https://github.com/kirankotari/ossguard-npm)** | `npx ossguard` | Node.js projects |

## Development

```bash
git clone https://github.com/kirankotari/ossguard-go.git
cd ossguard-go
go build -o ossguard ./cmd/ossguard
go test ./...
go vet ./...
```

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
