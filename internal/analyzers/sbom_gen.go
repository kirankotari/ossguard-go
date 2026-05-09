package analyzers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kirankotari/ossguard-go/internal/detector"
	"github.com/kirankotari/ossguard-go/internal/parsers"
)

// GenerateSBOM creates an SPDX or CycloneDX JSON SBOM.
func GenerateSBOM(projectPath, format string) string {
	abs := projectPath
	info := detector.DetectProject(abs)
	deps := parsers.ParseDependencies(abs)

	if format == "cyclonedx" {
		return generateCycloneDX(info.RepoName, deps)
	}
	return generateSPDX(info.RepoName, deps)
}

func generateSPDX(name string, deps []parsers.Dependency) string {
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	rootID := "SPDXRef-RootPackage"

	packages := []map[string]interface{}{
		{"SPDXID": rootID, "name": name, "versionInfo": "", "downloadLocation": "NOASSERTION", "filesAnalyzed": false},
	}
	rels := []map[string]string{
		{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": rootID, "relationshipType": "DESCRIBES"},
	}

	for i, dep := range deps {
		spdxID := fmt.Sprintf("SPDXRef-Package-%d", i)
		ver := dep.Version
		if ver == "" {
			ver = "NOASSERTION"
		}
		pkg := map[string]interface{}{"SPDXID": spdxID, "name": dep.Name, "versionInfo": ver, "downloadLocation": "NOASSERTION", "filesAnalyzed": false}
		purl := makePURL(dep)
		if purl != "" {
			pkg["externalRefs"] = []map[string]string{{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}}
		}
		packages = append(packages, pkg)
		relType := "DEPENDENCY_OF"
		if dep.IsDev {
			relType = "DEV_DEPENDENCY_OF"
		}
		rels = append(rels, map[string]string{"spdxElementId": spdxID, "relatedSpdxElement": rootID, "relationshipType": relType})
	}

	doc := map[string]interface{}{
		"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
		"name": name + "-sbom", "documentNamespace": fmt.Sprintf("https://spdx.org/spdxdocs/%s-%d", name, time.Now().UnixNano()),
		"creationInfo": map[string]interface{}{"created": now, "creators": []string{"Tool: ossguard"}},
		"packages": packages, "relationships": rels,
	}
	out, _ := json.MarshalIndent(doc, "", "  ")
	return string(out)
}

func generateCycloneDX(name string, deps []parsers.Dependency) string {
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	var components []map[string]interface{}

	for _, dep := range deps {
		comp := map[string]interface{}{"type": "library", "name": dep.Name, "version": dep.Version, "bom-ref": dep.Name + "@" + dep.Version}
		purl := makePURL(dep)
		if purl != "" {
			comp["purl"] = purl
		}
		if dep.IsDev {
			comp["scope"] = "optional"
		} else {
			comp["scope"] = "required"
		}
		components = append(components, comp)
	}

	doc := map[string]interface{}{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"metadata": map[string]interface{}{
			"timestamp": now,
			"tools":     []map[string]string{{"vendor": "ossguard", "name": "ossguard", "version": "0.1.0"}},
			"component": map[string]interface{}{"type": "application", "name": name},
		},
		"components": components,
	}
	out, _ := json.MarshalIndent(doc, "", "  ")
	return string(out)
}

func makePURL(dep parsers.Dependency) string {
	ecoMap := map[string]string{"npm": "npm", "pypi": "pypi", "go": "golang", "cargo": "cargo", "maven": "maven"}
	pt, ok := ecoMap[dep.Ecosystem]
	if !ok {
		return ""
	}
	ver := ""
	if dep.Version != "" {
		ver = "@" + dep.Version
	}
	if dep.Ecosystem == "go" {
		return fmt.Sprintf("pkg:%s/%s%s", pt, dep.Name, ver)
	}
	if dep.Ecosystem == "maven" && strings.Contains(dep.Name, ":") {
		parts := strings.SplitN(dep.Name, ":", 2)
		return fmt.Sprintf("pkg:%s/%s/%s%s", pt, parts[0], parts[1], ver)
	}
	return fmt.Sprintf("pkg:%s/%s%s", pt, dep.Name, ver)
}
