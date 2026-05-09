package analyzers

import (
	"strings"

	"github.com/kirankotari/ossguard-go/internal/apis"
	"github.com/kirankotari/ossguard-go/internal/parsers"
)

// LicenseInfo describes the license of a single dependency.
type LicenseInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	License   string `json:"license"`
	Category  string `json:"category"`
	Ecosystem string `json:"ecosystem"`
}

// LicenseConflict represents a potential license conflict.
type LicenseConflict struct {
	Package     string `json:"package"`
	License     string `json:"license"`
	Reason      string `json:"reason"`
}

// LicenseReport is the result of a license compliance check.
type LicenseReport struct {
	Licenses     []LicenseInfo   `json:"licenses"`
	Conflicts    []LicenseConflict `json:"conflicts"`
	Categories   map[string]int  `json:"categories"`
	TotalDeps    int             `json:"total_deps"`
	UnknownCount int             `json:"unknown_count"`
}

var permissive = map[string]bool{"MIT": true, "Apache-2.0": true, "BSD-2-Clause": true, "BSD-3-Clause": true, "ISC": true, "0BSD": true, "Unlicense": true, "CC0-1.0": true}
var copyleft = map[string]bool{"GPL-2.0": true, "GPL-3.0": true, "AGPL-3.0": true, "LGPL-2.1": true, "LGPL-3.0": true, "MPL-2.0": true, "EUPL-1.2": true, "SSPL-1.0": true, "OSL-3.0": true}
var restrictive = map[string]bool{"AGPL-3.0": true, "SSPL-1.0": true, "EUPL-1.2": true}

// CheckLicenses analyzes dependency licenses for compliance.
func CheckLicenses(projectPath string) *LicenseReport {
	deps := parsers.ParseDependencies(projectPath)
	report := &LicenseReport{Categories: map[string]int{}, TotalDeps: len(deps)}

	for _, dep := range deps {
		if dep.IsDev {
			continue
		}
		lic := "Unknown"
		info, err := apis.GetPackageInfo(dep.Name, dep.Ecosystem)
		if err == nil && info != nil && info.License != "" {
			lic = info.License
		}

		cat := classifyLicense(lic)
		report.Licenses = append(report.Licenses, LicenseInfo{Name: dep.Name, Version: dep.Version, License: lic, Category: cat, Ecosystem: dep.Ecosystem})
		report.Categories[cat]++

		if lic == "Unknown" {
			report.UnknownCount++
		}
		if restrictive[lic] {
			report.Conflicts = append(report.Conflicts, LicenseConflict{Package: dep.Name, License: lic, Reason: "Restrictive license may be incompatible"})
		}
	}
	return report
}

func classifyLicense(lic string) string {
	normalized := strings.TrimSpace(lic)
	if permissive[normalized] {
		return "permissive"
	}
	if copyleft[normalized] {
		return "copyleft"
	}
	if normalized == "Unknown" || normalized == "" {
		return "unknown"
	}
	return "other"
}
