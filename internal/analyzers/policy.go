package analyzers

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// PolicyRule defines a security policy rule.
type PolicyRule struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Evidence    string `json:"evidence"`
}

// PolicyReport is the result of policy enforcement.
type PolicyReport struct {
	Rules       []PolicyRule `json:"rules"`
	PassCount   int          `json:"pass_count"`
	FailCount   int          `json:"fail_count"`
	TotalCount  int          `json:"total_count"`
	Compliant   bool         `json:"compliant"`
}

var defaultPolicyRules = []struct {
	id, cat, desc, sev string
	check              func(string) (bool, string)
}{
	{"POL-001", "Documentation", "SECURITY.md must exist", "high", func(p string) (bool, string) { return fileExistsCheck(p, "SECURITY.md", ".github/SECURITY.md") }},
	{"POL-002", "Documentation", "LICENSE must exist", "high", func(p string) (bool, string) { return fileExistsCheck(p, "LICENSE", "LICENSE.md") }},
	{"POL-003", "CI/CD", "CI pipeline must exist", "high", func(p string) (bool, string) {
		if _, err := os.Stat(filepath.Join(p, ".github", "workflows")); err == nil { return true, "GitHub Actions found" }
		return false, ""
	}},
	{"POL-004", "Dependencies", "Dependabot or Renovate must be configured", "medium", func(p string) (bool, string) { return fileExistsCheck(p, ".github/dependabot.yml", "renovate.json", ".renovaterc") }},
	{"POL-005", "Security", "Code scanning must be enabled", "high", func(p string) (bool, string) {
		wfs := readWorkflows(p)
		for _, c := range wfs {
			if containsStr(c, "codeql") || containsStr(c, "semgrep") { return true, "Code scanning found" }
		}
		return false, ""
	}},
	{"POL-006", "Security", "Branch protection should be documented", "medium", func(p string) (bool, string) { return fileExistsCheck(p, ".github/BRANCH_PROTECTION.md") }},
}

// CheckPolicy evaluates organization security policies.
func CheckPolicy(projectPath string) *PolicyReport {
	abs, _ := filepath.Abs(projectPath)
	report := &PolicyReport{}

	for _, rule := range defaultPolicyRules {
		ok, evidence := rule.check(abs)
		status := "fail"
		if ok { status = "pass"; report.PassCount++ } else { report.FailCount++ }
		report.Rules = append(report.Rules, PolicyRule{ID: rule.id, Category: rule.cat, Description: rule.desc, Severity: rule.sev, Status: status, Evidence: evidence})
		report.TotalCount++
	}
	report.Compliant = report.FailCount == 0
	return report
}

// GeneratePolicyTemplate writes a default policy JSON file.
func GeneratePolicyTemplate(outPath string) error {
	tmpl := []map[string]string{}
	for _, rule := range defaultPolicyRules {
		tmpl = append(tmpl, map[string]string{"id": rule.id, "category": rule.cat, "description": rule.desc, "severity": rule.sev})
	}
	data, _ := json.MarshalIndent(tmpl, "", "  ")
	return os.WriteFile(outPath, data, 0644)
}

func fileExistsCheck(base string, names ...string) (bool, string) {
	for _, n := range names {
		full := filepath.Join(base, n)
		if _, err := os.Stat(full); err == nil { return true, n + " found" }
	}
	return false, ""
}
