package analyzers

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/kirankotari/ossguard-go/internal/detector"
)

// BaselineControl represents a single OSPS Baseline compliance check.
type BaselineControl struct {
	ID             string `json:"id"`
	Level          int    `json:"level"`
	Category       string `json:"category"`
	Description    string `json:"description"`
	Status         string `json:"status"`
	Evidence       string `json:"evidence"`
	Recommendation string `json:"recommendation"`
}

// BaselineReport is the result of an OSPS Baseline compliance check.
type BaselineReport struct {
	Controls      []BaselineControl `json:"controls"`
	AchievedLevel int               `json:"achieved_level"`
	Level1Pct     float64           `json:"level1_pct"`
	Level2Pct     float64           `json:"level2_pct"`
	Level3Pct     float64           `json:"level3_pct"`
}

type controlDef struct {
	id, cat, desc string
	level         int
}

var baselineControls = []controlDef{
	{"OSPS-01", "Documentation", "Project has a LICENSE file", 1},
	{"OSPS-02", "Documentation", "Project has a README", 1},
	{"OSPS-03", "Documentation", "Project has a SECURITY.md policy", 1},
	{"OSPS-04", "Documentation", "Project has CONTRIBUTING guidelines", 1},
	{"OSPS-05", "Documentation", "Project has a CODE_OF_CONDUCT", 1},
	{"OSPS-06", "Documentation", "Project has a CHANGELOG", 1},
	{"OSPS-10", "Access Control", "Project uses branch protection", 2},
	{"OSPS-11", "Access Control", "Project requires code review", 2},
	{"OSPS-12", "Access Control", "Project has CODEOWNERS", 2},
	{"OSPS-20", "Build & Release", "CI/CD pipeline exists", 1},
	{"OSPS-21", "Build & Release", "Automated testing in CI", 1},
	{"OSPS-22", "Build & Release", "Dependency update automation", 2},
	{"OSPS-23", "Build & Release", "SBOM generation", 2},
	{"OSPS-24", "Build & Release", "Signed releases", 3},
	{"OSPS-30", "Vulnerability Mgmt", "Vulnerability scanning enabled", 2},
	{"OSPS-31", "Vulnerability Mgmt", "Security advisory process", 2},
	{"OSPS-32", "Vulnerability Mgmt", "Static analysis enabled", 2},
	{"OSPS-40", "Quality", "Linting configured", 1},
	{"OSPS-41", "Quality", "Reproducible builds", 3},
}

// CheckBaseline evaluates OSPS Baseline compliance for a project.
func CheckBaseline(projectPath string) *BaselineReport {
	abs, _ := filepath.Abs(projectPath)
	info := detector.DetectProject(abs)

	controls := make([]BaselineControl, 0, len(baselineControls))
	for _, cd := range baselineControls {
		status, evidence, rec := checkBaselineControl(cd.id, abs, &info)
		controls = append(controls, BaselineControl{ID: cd.id, Level: cd.level, Category: cd.cat, Description: cd.desc, Status: status, Evidence: evidence, Recommendation: rec})
	}

	report := &BaselineReport{Controls: controls}
	for lvl := 1; lvl <= 3; lvl++ {
		cs := filterLevel(controls, lvl)
		met := countMet(cs)
		pct := 0.0
		if len(cs) > 0 {
			pct = float64(met) / float64(len(cs)) * 100
		}
		switch lvl {
		case 1:
			report.Level1Pct = pct
		case 2:
			report.Level2Pct = pct
		case 3:
			report.Level3Pct = pct
		}
	}
	for lvl := 1; lvl <= 3; lvl++ {
		cs := filterLevel(controls, lvl)
		if countMet(cs) == len(cs) {
			report.AchievedLevel = lvl
		} else {
			break
		}
	}
	return report
}

func checkBaselineControl(id, p string, info *detector.ProjectInfo) (string, string, string) {
	fe := func(names ...string) bool {
		for _, n := range names {
			if _, err := os.Stat(filepath.Join(p, n)); err == nil {
				return true
			}
		}
		return false
	}
	wfs := readWorkflows(p)
	wfContains := func(kw string) bool {
		for _, c := range wfs {
			if strings.Contains(c, kw) {
				return true
			}
		}
		return false
	}

	switch id {
	case "OSPS-01":
		if fe("LICENSE", "LICENSE.md", "LICENSE.txt") {
			return "met", "LICENSE file found", ""
		}
		return "unmet", "", "Add a LICENSE file"
	case "OSPS-02":
		if fe("README.md", "README.rst", "README.txt", "README") {
			return "met", "README found", ""
		}
		return "unmet", "", "Add a README"
	case "OSPS-03":
		if info.HasSecurityMd {
			return "met", "SECURITY.md found", ""
		}
		return "unmet", "", "Add SECURITY.md — run `ossguard init`"
	case "OSPS-04":
		if fe("CONTRIBUTING.md", ".github/CONTRIBUTING.md") {
			return "met", "CONTRIBUTING.md found", ""
		}
		return "unmet", "", "Add CONTRIBUTING.md"
	case "OSPS-05":
		if fe("CODE_OF_CONDUCT.md", ".github/CODE_OF_CONDUCT.md") {
			return "met", "CODE_OF_CONDUCT found", ""
		}
		return "unmet", "", "Add CODE_OF_CONDUCT.md"
	case "OSPS-06":
		if fe("CHANGELOG.md", "CHANGES.md", "HISTORY.md") {
			return "met", "CHANGELOG found", ""
		}
		return "unmet", "", "Add CHANGELOG.md"
	case "OSPS-10":
		if fe(".github/BRANCH_PROTECTION.md") {
			return "met", "Branch protection documented", ""
		}
		return "unknown", "", "Enable branch protection on main"
	case "OSPS-11":
		return "unknown", "", "Require code review on pull requests"
	case "OSPS-12":
		if fe(".github/CODEOWNERS", "CODEOWNERS") {
			return "met", "CODEOWNERS found", ""
		}
		return "unmet", "", "Add CODEOWNERS file"
	case "OSPS-20":
		if info.HasGithubActions {
			return "met", "GitHub Actions CI found", ""
		}
		return "unmet", "", "Set up CI — run `ossguard ci`"
	case "OSPS-21":
		if wfContains("test") || wfContains("pytest") || wfContains("vitest") {
			return "met", "Testing found in CI", ""
		}
		return "unmet", "", "Add automated testing to CI"
	case "OSPS-22":
		if info.HasDependabot {
			return "met", "Dependabot configured", ""
		}
		return "unmet", "", "Enable Dependabot — run `ossguard init`"
	case "OSPS-23":
		if info.HasSbomWorkflow {
			return "met", "SBOM generation found", ""
		}
		return "unmet", "", "Add SBOM generation — run `ossguard sbom-gen`"
	case "OSPS-24":
		if info.HasSigstore {
			return "met", "Sigstore signing configured", ""
		}
		return "unmet", "", "Enable release signing — run `ossguard init`"
	case "OSPS-30":
		if info.HasDependabot || wfContains("audit") {
			return "met", "Vulnerability scanning configured", ""
		}
		return "unmet", "", "Enable vulnerability scanning"
	case "OSPS-31":
		if fe(".github/SECURITY.md", "SECURITY.md") {
			return "met", "Security advisory process documented", ""
		}
		return "unmet", "", "Add security advisory process"
	case "OSPS-32":
		if info.HasCodeql || wfContains("codeql") || wfContains("semgrep") || wfContains("sonar") {
			return "met", "Static analysis configured", ""
		}
		return "unmet", "", "Enable CodeQL or similar static analysis"
	case "OSPS-40":
		if wfContains("lint") || wfContains("eslint") || wfContains("ruff") || wfContains("golangci") {
			return "met", "Linting configured in CI", ""
		}
		return "unmet", "", "Add linting to CI"
	case "OSPS-41":
		return "unknown", "", "Verify builds are reproducible"
	}
	return "unknown", "", ""
}

func readWorkflows(p string) []string {
	wfDir := filepath.Join(p, ".github", "workflows")
	entries, err := os.ReadDir(wfDir)
	if err != nil {
		return nil
	}
	var contents []string
	for _, e := range entries {
		if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml")) {
			data, err := os.ReadFile(filepath.Join(wfDir, e.Name()))
			if err == nil {
				contents = append(contents, strings.ToLower(string(data)))
			}
		}
	}
	return contents
}

func filterLevel(cs []BaselineControl, lvl int) []BaselineControl {
	var result []BaselineControl
	for _, c := range cs {
		if c.Level == lvl {
			result = append(result, c)
		}
	}
	return result
}

func countMet(cs []BaselineControl) int {
	n := 0
	for _, c := range cs {
		if c.Status == "met" {
			n++
		}
	}
	return n
}
