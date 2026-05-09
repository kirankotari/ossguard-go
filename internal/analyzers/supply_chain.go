package analyzers

import (
	"strings"

	"github.com/kirankotari/ossguard-go/internal/apis"
	"github.com/kirankotari/ossguard-go/internal/parsers"
)

// SupplyChainFinding represents a supply chain risk.
type SupplyChainFinding struct {
	Package     string `json:"package"`
	Version     string `json:"version"`
	Ecosystem   string `json:"ecosystem"`
	FindingType string `json:"finding_type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// SupplyChainReport is the result of supply chain analysis.
type SupplyChainReport struct {
	Findings       []SupplyChainFinding `json:"findings"`
	TotalDeps      int                  `json:"total_deps"`
	MaliciousCount int                  `json:"malicious_count"`
	TyposquatCount int                  `json:"typosquat_count"`
	Clean          bool                 `json:"clean"`
}

var popularPackages = map[string][]string{
	"npm":  {"lodash", "express", "react", "vue", "axios", "moment", "webpack", "eslint", "prettier", "typescript", "jquery", "commander", "chalk", "debug", "uuid", "dotenv", "cors", "helmet", "next", "svelte"},
	"pypi": {"requests", "flask", "django", "numpy", "pandas", "scipy", "tensorflow", "torch", "scikit-learn", "boto3", "pillow", "sqlalchemy", "fastapi", "pytest", "black", "ruff", "httpx", "cryptography"},
}

// CheckSupplyChain analyzes deps for malicious packages and typosquatting.
func CheckSupplyChain(projectPath string) *SupplyChainReport {
	deps := parsers.ParseDependencies(projectPath)
	report := &SupplyChainReport{TotalDeps: len(deps)}

	for _, dep := range deps {
		// Check OSV for known malicious
		vulns, err := apis.QueryOSV(dep.Name, dep.Version, dep.Ecosystem)
		if err == nil {
			for _, v := range vulns {
				if strings.HasPrefix(v.ID, "MAL-") {
					report.Findings = append(report.Findings, SupplyChainFinding{
						Package: dep.Name, Version: dep.Version, Ecosystem: dep.Ecosystem,
						FindingType: "malicious", Severity: "critical", Description: "Known malicious: " + v.Summary,
					})
					report.MaliciousCount++
				}
			}
		}

		// Typosquat check
		if popular, ok := popularPackages[dep.Ecosystem]; ok {
			for _, pop := range popular {
				if dep.Name == pop {
					continue
				}
				d := levenshtein(strings.ToLower(dep.Name), strings.ToLower(pop))
				if d > 0 && d <= 1 && len(dep.Name) > 4 {
					report.Findings = append(report.Findings, SupplyChainFinding{
						Package: dep.Name, Version: dep.Version, Ecosystem: dep.Ecosystem,
						FindingType: "typosquat", Severity: "high",
						Description: "Name similar to popular package '" + pop + "'",
					})
					report.TyposquatCount++
					break
				}
			}
		}
	}
	report.Clean = len(report.Findings) == 0
	return report
}

func levenshtein(s1, s2 string) int {
	if len(s1) < len(s2) {
		return levenshtein(s2, s1)
	}
	if len(s2) == 0 {
		return len(s1)
	}
	prev := make([]int, len(s2)+1)
	for i := range prev {
		prev[i] = i
	}
	for i := 0; i < len(s1); i++ {
		curr := make([]int, len(s2)+1)
		curr[0] = i + 1
		for j := 0; j < len(s2); j++ {
			cost := 0
			if s1[i] != s2[j] {
				cost = 1
			}
			curr[j+1] = min(prev[j+1]+1, min(curr[j]+1, prev[j]+cost))
		}
		prev = curr
	}
	return prev[len(s2)]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
