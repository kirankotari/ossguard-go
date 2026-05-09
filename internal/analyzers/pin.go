package analyzers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// PinAction represents a GitHub Actions reference that should be pinned.
type PinAction struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Action     string `json:"action"`
	CurrentRef string `json:"current_ref"`
	PinnedRef  string `json:"pinned_ref"`
	IsPinned   bool   `json:"is_pinned"`
}

// PinReport is the result of scanning for unpinned actions.
type PinReport struct {
	Actions      []PinAction `json:"actions"`
	TotalActions int         `json:"total_actions"`
	PinnedCount  int         `json:"pinned_count"`
	UnpinnedCount int        `json:"unpinned_count"`
}

var usesRe = regexp.MustCompile(`uses:\s*([^@\s]+)@([^\s#]+)`)
var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ScanActions finds all GitHub Actions references and checks if they are pinned.
func ScanActions(projectPath string) *PinReport {
	abs, _ := filepath.Abs(projectPath)
	wfDir := filepath.Join(abs, ".github", "workflows")
	report := &PinReport{}

	entries, err := os.ReadDir(wfDir)
	if err != nil {
		return report
	}
	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yml") && !strings.HasSuffix(e.Name(), ".yaml")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(wfDir, e.Name()))
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			m := usesRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			action, ref := m[1], m[2]
			if strings.HasPrefix(action, ".") || strings.HasPrefix(action, "docker://") {
				continue
			}
			isPinned := shaRe.MatchString(ref)
			report.Actions = append(report.Actions, PinAction{File: e.Name(), Line: i + 1, Action: action, CurrentRef: ref, IsPinned: isPinned})
			report.TotalActions++
			if isPinned {
				report.PinnedCount++
			} else {
				report.UnpinnedCount++
			}
		}
	}
	return report
}

// PinActions resolves unpinned actions to commit SHAs and returns patched content.
func PinActions(projectPath string, apply bool) (*PinReport, error) {
	report := ScanActions(projectPath)
	abs, _ := filepath.Abs(projectPath)

	for i, a := range report.Actions {
		if a.IsPinned {
			continue
		}
		sha, err := resolveActionSHA(a.Action, a.CurrentRef)
		if err != nil {
			continue
		}
		report.Actions[i].PinnedRef = sha

		if apply {
			wfPath := filepath.Join(abs, ".github", "workflows", a.File)
			data, err := os.ReadFile(wfPath)
			if err != nil {
				continue
			}
			old := fmt.Sprintf("%s@%s", a.Action, a.CurrentRef)
			new := fmt.Sprintf("%s@%s # %s", a.Action, sha, a.CurrentRef)
			patched := strings.Replace(string(data), old, new, 1)
			os.WriteFile(wfPath, []byte(patched), 0644)
		}
	}
	return report, nil
}

func resolveActionSHA(action, ref string) (string, error) {
	parts := strings.SplitN(action, "/", 3)
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid action: %s", action)
	}
	owner, repo := parts[0], parts[1]
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/ref/tags/%s", owner, repo, ref)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}
	var result struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.Object.Type == "tag" {
		url2 := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/tags/%s", owner, repo, result.Object.SHA)
		resp2, err := http.Get(url2)
		if err != nil {
			return result.Object.SHA, nil
		}
		defer resp2.Body.Close()
		var tag struct {
			Object struct {
				SHA string `json:"sha"`
			} `json:"object"`
		}
		if json.NewDecoder(resp2.Body).Decode(&tag) == nil && tag.Object.SHA != "" {
			return tag.Object.SHA, nil
		}
	}
	return result.Object.SHA, nil
}
