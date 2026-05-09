package analyzers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// DriftEntry represents a single dependency drift finding.
type DriftEntry struct {
	Name         string `json:"name"`
	ManifestVer  string `json:"manifest_version"`
	LockedVer    string `json:"locked_version"`
	Status       string `json:"status"`
}

// DriftReport is the result of dependency drift detection.
type DriftReport struct {
	Entries    []DriftEntry `json:"entries"`
	DriftCount int          `json:"drift_count"`
	SyncCount  int          `json:"sync_count"`
	HasLock    bool         `json:"has_lock"`
}

// DetectDrift compares manifest vs lock file versions.
func DetectDrift(projectPath string) *DriftReport {
	abs, _ := filepath.Abs(projectPath)
	report := &DriftReport{}

	// Check npm
	pkgPath := filepath.Join(abs, "package.json")
	lockPath := filepath.Join(abs, "package-lock.json")
	if _, err := os.Stat(lockPath); err == nil {
		report.HasLock = true
		manifest := readNpmManifest(pkgPath)
		locked := readNpmLock(lockPath)
		for name, mVer := range manifest {
			lVer, ok := locked[name]
			if !ok {
				report.Entries = append(report.Entries, DriftEntry{Name: name, ManifestVer: mVer, Status: "missing_from_lock"})
				report.DriftCount++
			} else if !versionSatisfies(mVer, lVer) {
				report.Entries = append(report.Entries, DriftEntry{Name: name, ManifestVer: mVer, LockedVer: lVer, Status: "drift"})
				report.DriftCount++
			} else {
				report.SyncCount++
			}
		}
		return report
	}

	// Check for other lock files
	for _, lf := range []string{"yarn.lock", "poetry.lock", "Cargo.lock", "go.sum"} {
		if _, err := os.Stat(filepath.Join(abs, lf)); err == nil {
			report.HasLock = true
			break
		}
	}
	if !report.HasLock {
		report.Entries = append(report.Entries, DriftEntry{Status: "no_lock_file"})
	}
	return report
}

func readNpmManifest(p string) map[string]string {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	json.Unmarshal(data, &pkg)
	result := map[string]string{}
	for k, v := range pkg.Dependencies {
		result[k] = v
	}
	for k, v := range pkg.DevDependencies {
		result[k] = v
	}
	return result
}

func readNpmLock(p string) map[string]string {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	json.Unmarshal(data, &lock)
	result := map[string]string{}
	for key, val := range lock.Packages {
		name := strings.TrimPrefix(key, "node_modules/")
		if name != "" && val.Version != "" {
			result[name] = val.Version
		}
	}
	return result
}

func versionSatisfies(constraint, actual string) bool {
	clean := strings.TrimLeft(constraint, "^~>=<!")
	return strings.HasPrefix(actual, clean) || actual == clean
}
