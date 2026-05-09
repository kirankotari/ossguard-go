// Package generators produces security configuration files.
package generators

import (
	"fmt"
	"strings"
)

// GenerateSecurityMd creates a SECURITY.md file.
func GenerateSecurityMd(repoName string) string {
	return fmt.Sprintf(`# Security Policy

## Reporting a Vulnerability

**Please DO NOT file a public issue for security vulnerabilities.**

- **GitHub Security Advisories**: Use [private vulnerability reporting](https://github.com/OWNER/%s/security/advisories/new)
- **Email**: security@example.com

### Response Timeline

- **Acknowledgment**: within 48 hours
- **Assessment**: within 1 week
- **Fix**: within 90 days

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |
`, repoName)
}

// GenerateDependabot creates a dependabot.yml config.
func GenerateDependabot(packageManagers []string) string {
	var b strings.Builder
	b.WriteString("version: 2\nupdates:\n")
	b.WriteString("  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n")
	ecoMap := map[string]string{"npm": "npm", "pip": "pip", "gomod": "gomod", "cargo": "cargo", "maven": "maven", "bundler": "bundler", "composer": "composer", "gradle": "gradle"}
	for _, pm := range packageManagers {
		if eco, ok := ecoMap[pm]; ok {
			b.WriteString(fmt.Sprintf("  - package-ecosystem: %s\n    directory: /\n    schedule:\n      interval: weekly\n", eco))
		}
	}
	return b.String()
}

// GenerateCodeQL creates a CodeQL analysis workflow.
func GenerateCodeQL(language string) string {
	lang := strings.ToLower(language)
	cqlLang := "javascript"
	switch lang {
	case "python":
		cqlLang = "python"
	case "go":
		cqlLang = "go"
	case "java", "kotlin":
		cqlLang = "java"
	case "c", "c++":
		cqlLang = "cpp"
	case "ruby":
		cqlLang = "ruby"
	}
	return fmt.Sprintf(`name: CodeQL

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'

permissions: read-all

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    strategy:
      matrix:
        language: ['%s']
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
`, cqlLang)
}

// GenerateScorecard creates an OpenSSF Scorecard workflow.
func GenerateScorecard() string {
	return `name: Scorecard

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'

permissions: read-all

jobs:
  analysis:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: ossf/scorecard-action@v2.4.0
        with:
          results_file: results.sarif
          results_format: sarif
          publish_results: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
`
}

// GenerateSBOMWorkflow creates an SBOM generation workflow.
func GenerateSBOMWorkflow() string {
	return `name: SBOM

on:
  push:
    tags: ['v*']

permissions: read-all

jobs:
  sbom:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - uses: anchore/sbom-action@v0
        with:
          artifact-name: sbom.spdx.json
`
}

// GenerateSigstore creates a Sigstore signing workflow.
func GenerateSigstore() string {
	return `name: Sign Release

on:
  release:
    types: [published]

permissions: read-all

jobs:
  sign:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: sigstore/cosign-installer@v3
      - run: cosign sign-blob --yes --output-signature release.sig --output-certificate release.pem dist/*
`
}
