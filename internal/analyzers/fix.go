package analyzers

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kirankotari/ossguard-go/internal/detector"
	"github.com/kirankotari/ossguard-go/internal/generators"
)

// FixAction represents a single remediation action.
type FixAction struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Applied     bool   `json:"applied"`
	FilePath    string `json:"file_path"`
}

// FixReport is the result of auto-remediation.
type FixReport struct {
	Actions      []FixAction `json:"actions"`
	AppliedCount int         `json:"applied_count"`
	SkippedCount int         `json:"skipped_count"`
}

// AutoFix applies automatic security remediations.
func AutoFix(projectPath string, dryRun bool) *FixReport {
	abs, _ := filepath.Abs(projectPath)
	info := detector.DetectProject(abs)
	report := &FixReport{}

	if !info.HasSecurityMd {
		act := FixAction{ID: "fix-security-md", Description: "Add SECURITY.md"}
		if !dryRun {
			content := generators.GenerateSecurityMd(info.RepoName)
			os.WriteFile(filepath.Join(abs, "SECURITY.md"), []byte(content), 0644)
			act.Applied = true
			act.FilePath = "SECURITY.md"
		}
		report.Actions = append(report.Actions, act)
	}

	if !info.HasDependabot {
		act := FixAction{ID: "fix-dependabot", Description: "Add Dependabot config"}
		if !dryRun {
			content := generators.GenerateDependabot(info.PackageManagers)
			dir := filepath.Join(abs, ".github")
			os.MkdirAll(dir, 0755)
			os.WriteFile(filepath.Join(dir, "dependabot.yml"), []byte(content), 0644)
			act.Applied = true
			act.FilePath = ".github/dependabot.yml"
		}
		report.Actions = append(report.Actions, act)
	}

	if !info.HasCodeql {
		act := FixAction{ID: "fix-codeql", Description: "Add CodeQL workflow"}
		if !dryRun {
			content := generators.GenerateCodeQL(info.PrimaryLanguage)
			dir := filepath.Join(abs, ".github", "workflows")
			os.MkdirAll(dir, 0755)
			os.WriteFile(filepath.Join(dir, "codeql.yml"), []byte(content), 0644)
			act.Applied = true
			act.FilePath = ".github/workflows/codeql.yml"
		}
		report.Actions = append(report.Actions, act)
	}

	if !info.HasScorecard {
		act := FixAction{ID: "fix-scorecard", Description: "Add Scorecard workflow"}
		if !dryRun {
			content := generators.GenerateScorecard()
			dir := filepath.Join(abs, ".github", "workflows")
			os.MkdirAll(dir, 0755)
			os.WriteFile(filepath.Join(dir, "scorecard.yml"), []byte(content), 0644)
			act.Applied = true
			act.FilePath = ".github/workflows/scorecard.yml"
		}
		report.Actions = append(report.Actions, act)
	}

	for i := range report.Actions {
		if report.Actions[i].Applied {
			report.AppliedCount++
		} else {
			report.SkippedCount++
			if dryRun {
				report.Actions[i].Description = fmt.Sprintf("[DRY RUN] %s", report.Actions[i].Description)
			}
		}
	}
	return report
}
