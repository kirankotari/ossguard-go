package analyzers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kirankotari/ossguard-go/internal/detector"
	"gopkg.in/yaml.v3"
)

// InsightsReport is the result of SECURITY-INSIGHTS.yml generation/validation.
type InsightsReport struct {
	Exists  bool     `json:"exists"`
	Valid   bool     `json:"valid"`
	Errors  []string `json:"errors"`
	Content string   `json:"content"`
}

// GenerateInsights creates a SECURITY-INSIGHTS.yml file.
func GenerateInsights(projectPath string) *InsightsReport {
	abs, _ := filepath.Abs(projectPath)
	info := detector.DetectProject(abs)

	doc := map[string]interface{}{
		"header": map[string]interface{}{
			"schema-version":     "1.0.0",
			"expiry-date":        time.Now().AddDate(1, 0, 0).Format("2006-01-02T15:04:05Z"),
			"project-url":        fmt.Sprintf("https://github.com/OWNER/%s", info.RepoName),
			"changelog":          fmt.Sprintf("https://github.com/OWNER/%s/blob/main/CHANGELOG.md", info.RepoName),
			"license":            fmt.Sprintf("https://github.com/OWNER/%s/blob/main/LICENSE", info.RepoName),
		},
		"project-lifecycle": map[string]interface{}{
			"status": "active",
		},
		"contribution-policy": map[string]interface{}{
			"accepts-pull-requests": true,
			"accepts-automated-pull-requests": true,
		},
		"distribution-points": []string{
			fmt.Sprintf("https://github.com/OWNER/%s", info.RepoName),
		},
	}

	if info.HasSecurityMd {
		doc["security-contacts"] = []map[string]string{
			{"type": "email", "value": "security@example.com"},
		}
	}

	vulnReporting := map[string]interface{}{
		"accepts-vulnerability-reports": true,
		"security-policy":              fmt.Sprintf("https://github.com/OWNER/%s/security/policy", info.RepoName),
	}
	doc["vulnerability-reporting"] = vulnReporting

	deps := map[string]interface{}{}
	if info.HasDependabot {
		deps["automated-tools-list"] = []map[string]interface{}{
			{"tool-name": "Dependabot", "tool-url": "https://github.com/dependabot"},
		}
	}
	if info.HasSbomWorkflow {
		deps["sbom"] = []map[string]interface{}{
			{"sbom-creation": "build-time", "sbom-url": fmt.Sprintf("https://github.com/OWNER/%s/releases", info.RepoName)},
		}
	}
	if len(deps) > 0 {
		doc["dependencies"] = deps
	}

	out, _ := yaml.Marshal(doc)
	content := "# SECURITY-INSIGHTS.yml\n# https://github.com/ossf/security-insights-spec\n---\n" + string(out)

	return &InsightsReport{Content: content}
}

// ValidateInsights checks an existing SECURITY-INSIGHTS.yml file.
func ValidateInsights(projectPath string) *InsightsReport {
	abs, _ := filepath.Abs(projectPath)
	siPath := filepath.Join(abs, "SECURITY-INSIGHTS.yml")
	data, err := os.ReadFile(siPath)
	if err != nil {
		return &InsightsReport{Exists: false, Errors: []string{"SECURITY-INSIGHTS.yml not found"}}
	}

	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return &InsightsReport{Exists: true, Valid: false, Errors: []string{"Invalid YAML: " + err.Error()}}
	}

	errs := []string{}
	required := []string{"header", "project-lifecycle", "vulnerability-reporting"}
	for _, key := range required {
		if _, ok := doc[key]; !ok {
			errs = append(errs, "Missing required section: "+key)
		}
	}
	if header, ok := doc["header"].(map[string]interface{}); ok {
		for _, field := range []string{"schema-version", "project-url"} {
			if _, ok := header[field]; !ok {
				errs = append(errs, "Missing header field: "+field)
			}
		}
		if expiry, ok := header["expiry-date"].(string); ok {
			if t, err := time.Parse("2006-01-02T15:04:05Z", expiry); err == nil && t.Before(time.Now()) {
				errs = append(errs, "Security insights file has expired")
			}
		}
	}
	if vr, ok := doc["vulnerability-reporting"].(map[string]interface{}); ok {
		if _, ok := vr["accepts-vulnerability-reports"]; !ok {
			errs = append(errs, "Missing: vulnerability-reporting.accepts-vulnerability-reports")
		}
	}

	_ = strings.Join(errs, "; ")
	return &InsightsReport{Exists: true, Valid: len(errs) == 0, Errors: errs, Content: string(data)}
}
