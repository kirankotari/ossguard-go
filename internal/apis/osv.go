// Package apis provides HTTP clients for OSV and deps.dev.
package apis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// Vulnerability represents a single vulnerability from OSV.
type Vulnerability struct {
	ID          string `json:"id"`
	Summary     string `json:"summary"`
	Severity    string `json:"severity"`
	FixedVersion string `json:"fixed_version"`
}

type osvQueryRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version,omitempty"`
}

type osvQueryResponse struct {
	Vulns []struct {
		ID      string `json:"id"`
		Summary string `json:"summary"`
		Affected []struct {
			Ranges []struct {
				Events []struct {
					Fixed string `json:"fixed,omitempty"`
				} `json:"events"`
			} `json:"ranges"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"database_specific,omitempty"`
		} `json:"affected"`
		DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
	} `json:"vulns"`
}

// QueryOSV queries the OSV API for vulnerabilities affecting a package.
func QueryOSV(name, version, ecosystem string) ([]Vulnerability, error) {
	req := osvQueryRequest{}
	req.Package.Name = name
	req.Package.Ecosystem = mapEcosystem(ecosystem)
	if version != "" {
		req.Version = version
	}

	body, _ := json.Marshal(req)
	resp, err := httpClient.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OSV API returned %d", resp.StatusCode)
	}

	var result osvQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var vulns []Vulnerability
	for _, v := range result.Vulns {
		sev := "UNKNOWN"
		fixed := ""
		if len(v.Affected) > 0 {
			for _, r := range v.Affected[0].Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						fixed = e.Fixed
					}
				}
			}
		}
		vulns = append(vulns, Vulnerability{ID: v.ID, Summary: v.Summary, Severity: sev, FixedVersion: fixed})
	}
	return vulns, nil
}

func mapEcosystem(eco string) string {
	m := map[string]string{"npm": "npm", "pypi": "PyPI", "go": "Go", "cargo": "crates.io", "maven": "Maven", "rubygems": "RubyGems", "composer": "Packagist"}
	if mapped, ok := m[eco]; ok {
		return mapped
	}
	return eco
}
