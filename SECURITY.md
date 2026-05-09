# Security Policy

## Reporting a Vulnerability

The ossguard team takes security vulnerabilities seriously. We appreciate
your efforts to responsibly disclose your findings.

**Please DO NOT file a public issue for security vulnerabilities.**

### How to Report

- **GitHub Security Advisories**: Use [GitHub's private vulnerability reporting](https://github.com/kirankotari/ossguard-go/security/advisories/new) to report a vulnerability directly.

### What to Include

- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Impact** assessment (what an attacker could achieve)
- **Affected versions**
- **Suggested fix** (if you have one)

### Response Timeline

- **Acknowledgment**: We will acknowledge receipt of your report within **48 hours**.
- **Assessment**: We will provide an initial assessment within **1 week**.
- **Fix & Disclosure**: We aim to release a fix within **90 days** of the report, following [coordinated vulnerability disclosure](https://github.com/ossf/oss-vulnerability-guide) practices.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Security Updates

Security updates will be released as patch versions and announced via:
- [GitHub Security Advisories](https://github.com/kirankotari/ossguard-go/security/advisories)
- Release notes

## Security Best Practices

This project follows [OpenSSF Best Practices](https://www.bestpractices.dev/) and uses:
- [OpenSSF Scorecard](https://scorecard.dev/) for automated security assessment
- Dependency scanning via Dependabot
- Code scanning via CodeQL
- Signed releases via Sigstore
