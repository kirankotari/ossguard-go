package analyzers

import (
	"github.com/kirankotari/ossguard-go/internal/apis"
	"github.com/kirankotari/ossguard-go/internal/parsers"
)

// UpdateCandidate represents a dependency that can be updated.
type UpdateCandidate struct {
	Name           string `json:"name"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	Ecosystem      string `json:"ecosystem"`
	VulnCount      int    `json:"vuln_count"`
	HasSecurityFix bool   `json:"has_security_fix"`
	Priority       string `json:"priority"`
	Reason         string `json:"reason"`
}

// UpdateReport is the result of checking for updates.
type UpdateReport struct {
	Candidates      []UpdateCandidate `json:"candidates"`
	SecurityUpdates int               `json:"security_updates"`
	TotalUpdates    int               `json:"total_updates"`
	UpToDate        int               `json:"up_to_date"`
}

// CheckUpdates finds dependencies with available updates.
func CheckUpdates(projectPath string, securityOnly bool) *UpdateReport {
	deps := parsers.ParseDependencies(projectPath)
	report := &UpdateReport{}

	for _, dep := range deps {
		if dep.IsDev {
			continue
		}
		info, err := apis.GetPackageInfo(dep.Name, dep.Ecosystem)
		if err != nil || info == nil || info.LatestVersion == "" {
			continue
		}
		if dep.Version == info.LatestVersion {
			report.UpToDate++
			continue
		}

		vulns, _ := apis.QueryOSV(dep.Name, dep.Version, dep.Ecosystem)
		vulnCount := len(vulns)
		hasFix := false
		critical, high := 0, 0
		for _, v := range vulns {
			if v.FixedVersion != "" {
				hasFix = true
			}
			switch v.Severity {
			case "CRITICAL":
				critical++
			case "HIGH":
				high++
			}
		}

		priority, reason := "low", "Newer version available"
		if critical > 0 {
			priority, reason = "critical", "Critical vulnerability — update immediately"
		} else if high > 0 {
			priority, reason = "high", "High vulnerability"
		} else if vulnCount > 0 {
			priority, reason = "medium", "Known vulnerabilities"
		}

		if securityOnly && vulnCount == 0 && !hasFix {
			continue
		}
		if vulnCount > 0 || hasFix {
			report.SecurityUpdates++
		}

		report.Candidates = append(report.Candidates, UpdateCandidate{
			Name: dep.Name, CurrentVersion: dep.Version, LatestVersion: info.LatestVersion,
			Ecosystem: dep.Ecosystem, VulnCount: vulnCount, HasSecurityFix: hasFix, Priority: priority, Reason: reason,
		})
	}
	report.TotalUpdates = len(report.Candidates)
	return report
}
