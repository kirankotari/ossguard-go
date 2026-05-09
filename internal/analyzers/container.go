package analyzers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ContainerFinding represents a Dockerfile lint finding.
type ContainerFinding struct {
	File           string `json:"file"`
	LineNumber     int    `json:"line_number"`
	RuleID         string `json:"rule_id"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

// ContainerReport is the result of Dockerfile linting.
type ContainerReport struct {
	Findings      []ContainerFinding `json:"findings"`
	FilesScanned  int                `json:"files_scanned"`
	CriticalCount int                `json:"critical_count"`
	HighCount     int                `json:"high_count"`
	MediumCount   int                `json:"medium_count"`
	LowCount      int                `json:"low_count"`
	Clean         bool               `json:"clean"`
}

type containerRule struct {
	id, severity, desc, rec string
	re                      *regexp.Regexp
}

var containerRules = []containerRule{
	{"DL-001", "high", "Using ':latest' tag — image not pinned", "Pin base image to a specific version or SHA digest", regexp.MustCompile(`(?i)^FROM\s+\S+:latest\b`)},
	{"DL-010", "high", "Container runs as root user", "Use a non-root user: USER nonroot", regexp.MustCompile(`(?i)^\s*USER\s+root\s*$`)},
	{"DL-020", "critical", "Secret value hardcoded in build arg/env", "Use Docker secrets or mount secrets at runtime", regexp.MustCompile(`(?i)(?:ARG|ENV)\s+\w*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)\w*\s*=`)},
	{"DL-021", "high", "Cloud credentials in Dockerfile", "Pass credentials at runtime", regexp.MustCompile(`(?i)(?:ARG|ENV)\s+\w*(?:AWS_ACCESS|AWS_SECRET|DATABASE_URL)\w*\s*=`)},
	{"DL-032", "high", "Piping curl to shell — insecure RCE", "Download, verify, then execute", regexp.MustCompile(`(?i)RUN\s+.*curl\s+.*\|\s*(?:sh|bash)`)},
	{"DL-033", "high", "Piping wget to shell — insecure RCE", "Download, verify, then execute", regexp.MustCompile(`(?i)RUN\s+.*wget\s+.*\|\s*(?:sh|bash)`)},
	{"DL-034", "medium", "Setting world-writable permissions (777)", "Use least-privilege permissions", regexp.MustCompile(`(?i)RUN\s+.*chmod\s+777\b`)},
	{"DL-040", "medium", "Using ADD for local files", "Use COPY instead of ADD", regexp.MustCompile(`(?i)^\s*ADD\s+[^h]`)},
}

// ScanContainers scans Dockerfiles for security issues.
func ScanContainers(projectPath string) *ContainerReport {
	abs, _ := filepath.Abs(projectPath)
	report := &ContainerReport{}
	dockerfiles := findDockerfiles(abs)

	for _, df := range dockerfiles {
		report.FilesScanned++
		rel, _ := filepath.Rel(abs, df)
		data, err := os.ReadFile(df)
		if err != nil {
			continue
		}
		content := string(data)
		lines := strings.Split(content, "\n")

		for _, rule := range containerRules {
			for i, line := range lines {
				if rule.re.MatchString(line) {
					report.Findings = append(report.Findings, ContainerFinding{File: rel, LineNumber: i + 1, RuleID: rule.id, Severity: rule.severity, Description: rule.desc, Recommendation: rule.rec})
				}
			}
		}
		if !regexp.MustCompile(`(?mi)^\s*HEALTHCHECK\b`).MatchString(content) {
			report.Findings = append(report.Findings, ContainerFinding{File: rel, RuleID: "DL-050", Severity: "low", Description: "No HEALTHCHECK instruction found", Recommendation: "Add HEALTHCHECK"})
		}
		if !regexp.MustCompile(`(?mi)^\s*USER\b`).MatchString(content) {
			report.Findings = append(report.Findings, ContainerFinding{File: rel, RuleID: "DL-010", Severity: "high", Description: "No USER instruction — runs as root", Recommendation: "Add USER nonroot"})
		}
	}

	if report.FilesScanned > 0 {
		if _, err := os.Stat(filepath.Join(abs, ".dockerignore")); err != nil {
			report.Findings = append(report.Findings, ContainerFinding{File: ".dockerignore", RuleID: "DL-060", Severity: "medium", Description: "No .dockerignore file", Recommendation: "Create .dockerignore"})
		}
	}

	for _, f := range report.Findings {
		switch f.Severity {
		case "critical":
			report.CriticalCount++
		case "high":
			report.HighCount++
		case "medium":
			report.MediumCount++
		case "low":
			report.LowCount++
		}
	}
	report.Clean = len(report.Findings) == 0
	return report
}

func findDockerfiles(p string) []string {
	candidates := []string{"Dockerfile", "Dockerfile.dev", "Dockerfile.prod", "Dockerfile.build", "Containerfile", "docker/Dockerfile"}
	var found []string
	for _, name := range candidates {
		full := filepath.Join(p, name)
		if _, err := os.Stat(full); err == nil {
			found = append(found, full)
		}
	}
	entries, _ := os.ReadDir(p)
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "Dockerfile") {
			full := filepath.Join(p, e.Name())
			exists := false
			for _, f := range found {
				if f == full {
					exists = true
					break
				}
			}
			if !exists {
				found = append(found, full)
			}
		}
	}
	return found
}
