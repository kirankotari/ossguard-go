package analyzers

import (
	"os"
	"path/filepath"

	"github.com/kirankotari/ossguard-go/internal/detector"
)

// BadgeCriterion represents a single Best Practices Badge check.
type BadgeCriterion struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Evidence    string `json:"evidence"`
}

// BadgeReport is the result of an OpenSSF Best Practices Badge assessment.
type BadgeReport struct {
	Criteria     []BadgeCriterion `json:"criteria"`
	PassingPct   float64          `json:"passing_pct"`
	MetCount     int              `json:"met_count"`
	TotalCount   int              `json:"total_count"`
	Level        string           `json:"level"`
}

// AssessBadgeReadiness evaluates OpenSSF Best Practices Badge criteria.
func AssessBadgeReadiness(projectPath string) *BadgeReport {
	abs, _ := filepath.Abs(projectPath)
	info := detector.DetectProject(abs)

	fe := func(names ...string) bool {
		for _, n := range names {
			if _, err := os.Stat(filepath.Join(abs, n)); err == nil {
				return true
			}
		}
		return false
	}

	criteria := []BadgeCriterion{
		check("badge-license", "Basics", "Project has a license", fe("LICENSE", "LICENSE.md", "LICENSE.txt"), "LICENSE found"),
		check("badge-readme", "Basics", "Project has documentation", fe("README.md", "README.rst"), "README found"),
		check("badge-contributing", "Basics", "Contributing guide exists", fe("CONTRIBUTING.md", ".github/CONTRIBUTING.md"), "CONTRIBUTING.md found"),
		check("badge-security", "Security", "Security policy published", info.HasSecurityMd, "SECURITY.md found"),
		check("badge-ci", "Quality", "CI/CD pipeline exists", info.HasGithubActions, "GitHub Actions found"),
		check("badge-tests", "Quality", "Automated test suite exists", fe("tests", "test", "__tests__", "spec"), "Test directory found"),
		check("badge-codeql", "Security", "Static analysis configured", info.HasCodeql, "CodeQL workflow found"),
		check("badge-deps", "Security", "Dependency monitoring enabled", info.HasDependabot, "Dependabot configured"),
		check("badge-changelog", "Reporting", "CHANGELOG maintained", fe("CHANGELOG.md", "CHANGES.md"), "CHANGELOG found"),
		check("badge-coc", "Basics", "Code of Conduct published", fe("CODE_OF_CONDUCT.md"), "CODE_OF_CONDUCT.md found"),
	}

	met := 0
	for _, c := range criteria {
		if c.Status == "met" {
			met++
		}
	}
	pct := 0.0
	if len(criteria) > 0 {
		pct = float64(met) / float64(len(criteria)) * 100
	}
	level := "in progress"
	if pct >= 100 {
		level = "passing"
	} else if pct >= 80 {
		level = "silver"
	}

	return &BadgeReport{Criteria: criteria, PassingPct: pct, MetCount: met, TotalCount: len(criteria), Level: level}
}

func check(id, cat, desc string, ok bool, evidence string) BadgeCriterion {
	s := "unmet"
	e := ""
	if ok {
		s = "met"
		e = evidence
	}
	return BadgeCriterion{ID: id, Category: cat, Description: desc, Status: s, Evidence: e}
}
