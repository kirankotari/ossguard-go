package apis

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// PackageInfo holds metadata from deps.dev.
type PackageInfo struct {
	Name          string `json:"name"`
	LatestVersion string `json:"latest_version"`
	License       string `json:"license"`
	ScoreCard     float64 `json:"scorecard"`
}

type depsDevResponse struct {
	Versions []struct {
		VersionKey struct {
			Version string `json:"version"`
		} `json:"versionKey"`
		IsDefault bool `json:"isDefault"`
	} `json:"versions"`
}

type depsDevVersionResponse struct {
	Licenses []string `json:"licenses"`
}

// GetPackageInfo fetches package metadata from deps.dev.
func GetPackageInfo(name, ecosystem string) (*PackageInfo, error) {
	sys := mapDepsDevSystem(ecosystem)
	u := fmt.Sprintf("https://api.deps.dev/v3alpha/systems/%s/packages/%s", sys, url.PathEscape(name))

	resp, err := httpClient.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("deps.dev returned %d", resp.StatusCode)
	}

	var result depsDevResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	info := &PackageInfo{Name: name}
	for _, v := range result.Versions {
		if v.IsDefault {
			info.LatestVersion = v.VersionKey.Version
			break
		}
	}
	if info.LatestVersion == "" && len(result.Versions) > 0 {
		info.LatestVersion = result.Versions[len(result.Versions)-1].VersionKey.Version
	}
	return info, nil
}

func mapDepsDevSystem(eco string) string {
	m := map[string]string{"npm": "npm", "pypi": "pypi", "go": "go", "cargo": "cargo", "maven": "maven"}
	if s, ok := m[eco]; ok {
		return s
	}
	return eco
}
