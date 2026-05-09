// Package analyzers contains all security analysis functions.
package analyzers

import (
	"time"

	"github.com/kirankotari/ossguard-go/internal/detector"
	"github.com/kirankotari/ossguard-go/internal/parsers"
)

// AuditReport is the result of a comprehensive security audit.
type AuditReport struct {
	ProjectInfo     *detector.ProjectInfo `json:"project_info"`
	ConfigScore     int                   `json:"config_score"`
	ConfigTotal     int                   `json:"config_total"`
	ConfigPct       int                   `json:"config_pct"`
	OverallGrade    string                `json:"overall_grade"`
	TotalVulns      int                   `json:"total_vulns"`
	CriticalVulns   int                   `json:"critical_vulns"`
	HighVulns       int                   `json:"high_vulns"`
	DepsCount       int                   `json:"deps_count"`
	Findings        []string              `json:"findings"`
	Recommendations []string              `json:"recommendations"`
	AuditTime       string                `json:"audit_time"`
}

// RunAudit performs a comprehensive security audit.
func RunAudit(projectPath string) *AuditReport {
	info := detector.DetectProject(projectPath)
	findings := []string{}
	recs := []string{}

	checks := []bool{info.HasSecurityMd, info.HasScorecard, info.HasDependabot, info.HasCodeql, info.HasSbomWorkflow, info.HasSigstore}
	labels := []struct{ name, rec string }{
		{"SECURITY.md", "Run `ossguard init` to add SECURITY.md"},
		{"Scorecard workflow", "Run `ossguard init` to add Scorecard CI"},
		{"Dependabot", "Run `ossguard init` to add Dependabot config"},
		{"CodeQL", "Run `ossguard init` to add CodeQL workflow"},
		{"SBOM workflow", "Run `ossguard init` to add SBOM workflow"},
		{"Sigstore", "Run `ossguard init` to add Sigstore signing"},
	}
	score := 0
	for i, ok := range checks {
		if ok {
			score++
		} else {
			findings = append(findings, "Missing "+labels[i].name)
			recs = append(recs, labels[i].rec)
		}
	}

	deps := parsers.ParseDependencies(projectPath)
	depsCount := len(deps)
	if depsCount == 0 {
		findings = append(findings, "No dependencies detected — skipping dependency analysis")
	}

	total := len(checks)
	pct := 0
	if total > 0 {
		pct = (score * 100) / total
	}

	report := &AuditReport{
		ProjectInfo:     &info,
		ConfigScore:     score,
		ConfigTotal:     total,
		ConfigPct:       pct,
		DepsCount:       depsCount,
		Findings:        findings,
		Recommendations: recs,
		AuditTime:       time.Now().UTC().Format(time.RFC3339),
	}
	report.OverallGrade = calculateGrade(report)
	return report
}

func calculateGrade(r *AuditReport) string {
	score := 100.0
	if r.ConfigTotal > 0 {
		pct := float64(r.ConfigScore) / float64(r.ConfigTotal) * 100
		score -= (100 - pct) * 0.3
	}
	if r.CriticalVulns > 0 {
		score -= 30
	}
	if r.HighVulns > 0 {
		score -= 15
	}
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}
