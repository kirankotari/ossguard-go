// Package detector identifies project type, language, and security configuration.
package detector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// ProjectInfo holds detected metadata about a project.
type ProjectInfo struct {
	RepoName        string   `json:"repo_name"`
	PrimaryLanguage string   `json:"primary_language"`
	PackageManagers []string `json:"package_managers"`
	HasGithubActions bool    `json:"has_github_actions"`
	HasSecurityMd   bool    `json:"has_security_md"`
	HasScorecard    bool    `json:"has_scorecard"`
	HasDependabot   bool    `json:"has_dependabot"`
	HasCodeql       bool    `json:"has_codeql"`
	HasSbomWorkflow bool    `json:"has_sbom_workflow"`
	HasSigstore     bool    `json:"has_sigstore"`
}

// DetectProject scans a directory and returns project metadata.
func DetectProject(projectPath string) ProjectInfo {
	abs, _ := filepath.Abs(projectPath)
	info := ProjectInfo{
		RepoName: filepath.Base(abs),
	}

	info.PrimaryLanguage = detectLanguage(abs)
	info.PackageManagers = detectPackageManagers(abs)
	info.HasGithubActions = dirExists(abs, ".github", "workflows")
	info.HasSecurityMd = anyFileExists(abs, "SECURITY.md", ".github/SECURITY.md")
	info.HasDependabot = anyFileExists(abs, ".github/dependabot.yml", ".github/dependabot.yaml")

	if info.HasGithubActions {
		wfs := readWorkflowContents(abs)
		info.HasScorecard = workflowContains(wfs, "ossf/scorecard-action")
		info.HasCodeql = workflowContains(wfs, "codeql-action")
		info.HasSbomWorkflow = workflowContains(wfs, "sbom") || workflowContains(wfs, "cyclonedx") || workflowContains(wfs, "spdx")
		info.HasSigstore = workflowContains(wfs, "sigstore") || workflowContains(wfs, "cosign")
	}

	return info
}

func detectLanguage(p string) string {
	langFiles := []struct {
		file string
		lang string
	}{
		{"package.json", "javascript"},
		{"tsconfig.json", "typescript"},
		{"pyproject.toml", "python"},
		{"setup.py", "python"},
		{"requirements.txt", "python"},
		{"go.mod", "go"},
		{"Cargo.toml", "rust"},
		{"pom.xml", "java"},
		{"build.gradle", "java"},
		{"Gemfile", "ruby"},
		{"composer.json", "php"},
	}
	for _, lf := range langFiles {
		if fileExists(filepath.Join(p, lf.file)) {
			if lf.file == "package.json" && fileExists(filepath.Join(p, "tsconfig.json")) {
				return "typescript"
			}
			return lf.lang
		}
	}
	return ""
}

func detectPackageManagers(p string) []string {
	var pms []string
	mapping := []struct {
		file string
		pm   string
	}{
		{"package.json", "npm"},
		{"requirements.txt", "pip"},
		{"pyproject.toml", "pip"},
		{"go.mod", "gomod"},
		{"Cargo.toml", "cargo"},
		{"pom.xml", "maven"},
		{"build.gradle", "gradle"},
		{"Gemfile", "bundler"},
		{"composer.json", "composer"},
	}
	for _, m := range mapping {
		if fileExists(filepath.Join(p, m.file)) {
			pms = append(pms, m.pm)
		}
	}
	if len(pms) == 0 {
		pms = []string{"npm"}
	}
	return pms
}

func readWorkflowContents(p string) []string {
	wfDir := filepath.Join(p, ".github", "workflows")
	entries, err := os.ReadDir(wfDir)
	if err != nil {
		return nil
	}
	var contents []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
			data, err := os.ReadFile(filepath.Join(wfDir, name))
			if err == nil {
				contents = append(contents, strings.ToLower(string(data)))
			}
		}
	}
	return contents
}

func workflowContains(wfs []string, keyword string) bool {
	kw := strings.ToLower(keyword)
	for _, wf := range wfs {
		if strings.Contains(wf, kw) {
			return true
		}
	}
	return false
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func dirExists(parts ...string) bool {
	p := filepath.Join(parts...)
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func anyFileExists(base string, names ...string) bool {
	for _, n := range names {
		if fileExists(filepath.Join(base, n)) {
			return true
		}
	}
	return false
}

// ReadPackageJSON reads and returns parsed package.json data.
func ReadPackageJSON(p string) (map[string]interface{}, error) {
	data, err := os.ReadFile(filepath.Join(p, "package.json"))
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	return result, err
}
