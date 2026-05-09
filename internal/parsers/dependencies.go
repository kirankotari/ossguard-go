// Package parsers extracts dependencies from project manifest files.
package parsers

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Dependency represents a single project dependency.
type Dependency struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Ecosystem  string `json:"ecosystem"`
	IsDev      bool   `json:"is_dev"`
	SourceFile string `json:"source_file"`
}

// ParseDependencies scans a project path and returns all detected dependencies.
func ParseDependencies(projectPath string) []Dependency {
	abs, _ := filepath.Abs(projectPath)
	var deps []Dependency

	if d := parsePackageJSON(abs); len(d) > 0 {
		deps = append(deps, d...)
	}
	if d := parseRequirementsTxt(abs); len(d) > 0 {
		deps = append(deps, d...)
	}
	if d := parseGoMod(abs); len(d) > 0 {
		deps = append(deps, d...)
	}
	if d := parseCargoToml(abs); len(d) > 0 {
		deps = append(deps, d...)
	}
	return deps
}

func parsePackageJSON(p string) []Dependency {
	data, err := os.ReadFile(filepath.Join(p, "package.json"))
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return nil
	}
	var deps []Dependency
	for name, ver := range pkg.Dependencies {
		deps = append(deps, Dependency{Name: name, Version: cleanVersion(ver), Ecosystem: "npm", IsDev: false, SourceFile: "package.json"})
	}
	for name, ver := range pkg.DevDependencies {
		deps = append(deps, Dependency{Name: name, Version: cleanVersion(ver), Ecosystem: "npm", IsDev: true, SourceFile: "package.json"})
	}
	return deps
}

func parseRequirementsTxt(p string) []Dependency {
	f, err := os.Open(filepath.Join(p, "requirements.txt"))
	if err != nil {
		return nil
	}
	defer f.Close()

	var deps []Dependency
	re := regexp.MustCompile(`^([a-zA-Z0-9_.-]+)\s*([><=!~]+)\s*(.+)`)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		m := re.FindStringSubmatch(line)
		if m != nil {
			deps = append(deps, Dependency{Name: m[1], Version: m[3], Ecosystem: "pypi", SourceFile: "requirements.txt"})
		} else {
			name := strings.Split(line, "[")[0]
			name = strings.TrimSpace(name)
			if name != "" {
				deps = append(deps, Dependency{Name: name, Ecosystem: "pypi", SourceFile: "requirements.txt"})
			}
		}
	}
	return deps
}

func parseGoMod(p string) []Dependency {
	data, err := os.ReadFile(filepath.Join(p, "go.mod"))
	if err != nil {
		return nil
	}
	var deps []Dependency
	inRequire := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "require (") || line == "require (" {
			inRequire = true
			continue
		}
		if line == ")" {
			inRequire = false
			continue
		}
		if inRequire {
			parts := strings.Fields(line)
			if len(parts) >= 2 && !strings.HasPrefix(parts[0], "//") {
				isDev := len(parts) >= 3 && parts[2] == "//indirect" || strings.Contains(line, "// indirect")
				deps = append(deps, Dependency{Name: parts[0], Version: parts[1], Ecosystem: "go", IsDev: isDev, SourceFile: "go.mod"})
			}
		}
	}
	return deps
}

func parseCargoToml(p string) []Dependency {
	data, err := os.ReadFile(filepath.Join(p, "Cargo.toml"))
	if err != nil {
		return nil
	}
	var deps []Dependency
	inDeps := false
	inDevDeps := false
	re := regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"`)
	reTable := regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([^"]+)"`)
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[dependencies]" {
			inDeps = true
			inDevDeps = false
			continue
		}
		if trimmed == "[dev-dependencies]" {
			inDevDeps = true
			inDeps = false
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			inDeps = false
			inDevDeps = false
			continue
		}
		if !inDeps && !inDevDeps {
			continue
		}
		if m := re.FindStringSubmatch(trimmed); m != nil {
			deps = append(deps, Dependency{Name: m[1], Version: cleanVersion(m[2]), Ecosystem: "cargo", IsDev: inDevDeps, SourceFile: "Cargo.toml"})
		} else if m := reTable.FindStringSubmatch(trimmed); m != nil {
			deps = append(deps, Dependency{Name: m[1], Version: cleanVersion(m[2]), Ecosystem: "cargo", IsDev: inDevDeps, SourceFile: "Cargo.toml"})
		}
	}
	return deps
}

func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "^~>=<!")
	return v
}
