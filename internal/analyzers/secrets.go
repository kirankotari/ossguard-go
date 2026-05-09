package analyzers

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SecretFinding represents a detected secret leak.
type SecretFinding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Match    string `json:"match"`
}

// SecretsReport is the result of a secrets scan.
type SecretsReport struct {
	Findings     []SecretFinding `json:"findings"`
	FilesScanned int             `json:"files_scanned"`
	TotalSecrets int             `json:"total_secrets"`
}

type secretRule struct {
	id       string
	severity string
	re       *regexp.Regexp
}

var secretRules = []secretRule{
	{"aws-access-key", "critical", regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)},
	{"aws-secret-key", "critical", regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`)},
	{"github-token", "critical", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)},
	{"github-oauth", "critical", regexp.MustCompile(`gho_[A-Za-z0-9]{36}`)},
	{"github-pat", "critical", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`)},
	{"slack-token", "high", regexp.MustCompile(`xox[bpors]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`)},
	{"slack-webhook", "high", regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`)},
	{"generic-api-key", "medium", regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9]{20,}['\"]?`)},
	{"generic-secret", "medium", regexp.MustCompile(`(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?`)},
	{"private-key", "critical", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	{"google-api-key", "high", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"stripe-key", "critical", regexp.MustCompile(`(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}`)},
	{"npm-token", "critical", regexp.MustCompile(`npm_[A-Za-z0-9]{36}`)},
	{"pypi-token", "critical", regexp.MustCompile(`pypi-AgEIcH[A-Za-z0-9\-_]{50,}`)},
	{"jwt", "medium", regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)},
	{"sendgrid", "high", regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`)},
	{"twilio", "high", regexp.MustCompile(`SK[0-9a-fA-F]{32}`)},
}

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true, "__pycache__": true, "dist": true, "build": true, "target": true}
var binaryExts = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".zip": true, ".tar": true, ".gz": true, ".pdf": true, ".exe": true, ".dll": true, ".so": true, ".dylib": true}

// ScanSecrets walks a project directory and scans for leaked secrets.
func ScanSecrets(projectPath string) *SecretsReport {
	abs, _ := filepath.Abs(projectPath)
	report := &SecretsReport{}
	ignores := loadIgnorePatterns(abs)

	filepath.Walk(abs, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if fi.IsDir() {
			if skipDirs[fi.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if fi.Size() > 1<<20 || binaryExts[filepath.Ext(path)] {
			return nil
		}
		rel, _ := filepath.Rel(abs, path)
		if isIgnored(rel, ignores) {
			return nil
		}
		report.FilesScanned++
		scanFile(path, rel, report)
		return nil
	})
	report.TotalSecrets = len(report.Findings)
	return report
}

func scanFile(path, rel string, report *SecretsReport) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		for _, rule := range secretRules {
			if rule.re.MatchString(line) {
				report.Findings = append(report.Findings, SecretFinding{
					File: rel, Line: lineNum, RuleID: rule.id, Severity: rule.severity,
					Match: redact(line),
				})
			}
		}
	}
}

func redact(line string) string {
	if len(line) > 80 {
		line = line[:80] + "..."
	}
	re := regexp.MustCompile(`[A-Za-z0-9+/=_\-]{16,}`)
	return re.ReplaceAllStringFunc(line, func(m string) string {
		if len(m) > 8 {
			return m[:4] + strings.Repeat("*", len(m)-8) + m[len(m)-4:]
		}
		return m
	})
}

func loadIgnorePatterns(p string) []string {
	f, err := os.Open(filepath.Join(p, ".ossguard-secrets-ignore"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var patterns []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}
	return patterns
}

func isIgnored(rel string, patterns []string) bool {
	for _, p := range patterns {
		if matched, _ := filepath.Match(p, rel); matched {
			return true
		}
		if matched, _ := filepath.Match(p, filepath.Base(rel)); matched {
			return true
		}
	}
	return false
}
