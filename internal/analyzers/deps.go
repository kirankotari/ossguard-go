package analyzers

import (
	"github.com/kirankotari/ossguard-go/internal/apis"
	"github.com/kirankotari/ossguard-go/internal/parsers"
)

// DepResult holds analysis for a single dependency.
type DepResult struct {
	Dep        parsers.Dependency     `json:"dep"`
	Vulns      []apis.Vulnerability   `json:"vulns"`
	VulnCount  int                    `json:"vuln_count"`
	HealthScore float64               `json:"health_score"`
}

// DepHealthReport is the result of dependency health analysis.
type DepHealthReport struct {
	Results        []DepResult `json:"results"`
	TotalDeps      int         `json:"total_deps"`
	TotalVulns     int         `json:"total_vulns"`
	CriticalVulns  int         `json:"critical_vulns"`
	HighVulns      int         `json:"high_vulns"`
	AggregateScore float64     `json:"aggregate_score"`
}

// AnalyzeDeps analyzes dependency health and vulnerabilities.
func AnalyzeDeps(projectPath string) *DepHealthReport {
	deps := parsers.ParseDependencies(projectPath)
	report := &DepHealthReport{TotalDeps: len(deps)}

	for _, dep := range deps {
		result := DepResult{Dep: dep, HealthScore: 10.0}
		vulns, err := apis.QueryOSV(dep.Name, dep.Version, dep.Ecosystem)
		if err == nil {
			result.Vulns = vulns
			result.VulnCount = len(vulns)
			report.TotalVulns += len(vulns)
			for _, v := range vulns {
				switch v.Severity {
				case "CRITICAL":
					report.CriticalVulns++
					result.HealthScore -= 3.0
				case "HIGH":
					report.HighVulns++
					result.HealthScore -= 2.0
				default:
					result.HealthScore -= 1.0
				}
			}
		}
		if result.HealthScore < 0 {
			result.HealthScore = 0
		}
		report.Results = append(report.Results, result)
	}

	if len(report.Results) > 0 {
		total := 0.0
		for _, r := range report.Results {
			total += r.HealthScore
		}
		report.AggregateScore = total / float64(len(report.Results))
	}
	return report
}
