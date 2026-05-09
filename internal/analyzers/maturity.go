package analyzers

import (
	"os"
	"path/filepath"

	"github.com/kirankotari/ossguard-go/internal/detector"
)

// S2C2FPractice represents a single S2C2F maturity practice.
type S2C2FPractice struct {
	ID             string `json:"id"`
	Level          int    `json:"level"`
	Category       string `json:"category"`
	Description    string `json:"description"`
	Status         string `json:"status"`
	Evidence       string `json:"evidence"`
	Recommendation string `json:"recommendation"`
}

// MaturityReport is the result of an S2C2F maturity assessment.
type MaturityReport struct {
	Practices     []S2C2FPractice `json:"practices"`
	AchievedLevel int             `json:"achieved_level"`
	Level1Pct     float64         `json:"level1_pct"`
	Level2Pct     float64         `json:"level2_pct"`
	Level3Pct     float64         `json:"level3_pct"`
	Level4Pct     float64         `json:"level4_pct"`
}

type practiceDef struct {
	id, cat, desc string
	level         int
}

var s2c2fPractices = []practiceDef{
	{"S2C2F-ING-1", "Ingest", "Use package managers to consume OSS", 1},
	{"S2C2F-ING-2", "Ingest", "Track all OSS dependencies in a manifest", 1},
	{"S2C2F-ING-3", "Ingest", "Use automated dependency update tool", 1},
	{"S2C2F-SCN-1", "Scan", "Scan OSS for known vulnerabilities", 1},
	{"S2C2F-SCN-2", "Scan", "Scan OSS for license compliance", 1},
	{"S2C2F-INV-1", "Inventory", "Maintain an SBOM of consumed OSS", 2},
	{"S2C2F-INV-2", "Inventory", "Track transitive dependencies", 2},
	{"S2C2F-UPD-1", "Update", "Apply security patches within SLAs", 2},
	{"S2C2F-UPD-2", "Update", "Automate dependency updates for security", 2},
	{"S2C2F-ENF-1", "Enforce", "Block known-vulnerable components", 2},
	{"S2C2F-ENF-2", "Enforce", "Enforce license compliance policies", 2},
	{"S2C2F-AUD-1", "Audit", "Security audit critical OSS deps", 3},
	{"S2C2F-AUD-2", "Audit", "Verify provenance of OSS packages", 3},
	{"S2C2F-FIX-1", "Fix", "Ability to privately patch vulnerabilities", 3},
	{"S2C2F-FIX-2", "Fix", "Contribute security fixes upstream", 3},
	{"S2C2F-VER-1", "Verify", "Verify signatures on OSS packages", 3},
	{"S2C2F-VER-2", "Verify", "Validate SBOM accuracy", 3},
	{"S2C2F-REB-1", "Rebuild", "Rebuild OSS from source", 4},
	{"S2C2F-REB-2", "Rebuild", "Verify reproducibility of builds", 4},
	{"S2C2F-SEC-1", "Secure", "Run OSS in sandboxed environments", 4},
	{"S2C2F-SEC-2", "Secure", "Apply runtime protection and monitoring", 4},
}

// AssessMaturity evaluates S2C2F maturity for a project.
func AssessMaturity(projectPath string) *MaturityReport {
	abs, _ := filepath.Abs(projectPath)
	info := detector.DetectProject(abs)
	wfs := readWorkflows(abs)

	practices := make([]S2C2FPractice, 0, len(s2c2fPractices))
	for _, pd := range s2c2fPractices {
		s, e, r := checkS2C2F(pd.id, abs, &info, wfs)
		practices = append(practices, S2C2FPractice{ID: pd.id, Level: pd.level, Category: pd.cat, Description: pd.desc, Status: s, Evidence: e, Recommendation: r})
	}

	report := &MaturityReport{Practices: practices}
	for lvl := 1; lvl <= 4; lvl++ {
		total, met := 0, 0
		for _, p := range practices {
			if p.Level == lvl {
				total++
				if p.Status == "met" { met++ }
			}
		}
		pct := 0.0
		if total > 0 { pct = float64(met) / float64(total) * 100 }
		switch lvl {
		case 1: report.Level1Pct = pct
		case 2: report.Level2Pct = pct
		case 3: report.Level3Pct = pct
		case 4: report.Level4Pct = pct
		}
	}
	for lvl := 1; lvl <= 4; lvl++ {
		all := true
		for _, p := range practices {
			if p.Level == lvl && p.Status != "met" { all = false; break }
		}
		if all { report.AchievedLevel = lvl } else { break }
	}
	return report
}

func checkS2C2F(id, p string, info *detector.ProjectInfo, wfs []string) (string, string, string) {
	manifests := []string{"package.json", "requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml", "pom.xml"}
	lockFiles := []string{"package-lock.json", "yarn.lock", "poetry.lock", "Cargo.lock", "go.sum", "Gemfile.lock"}

	fe := func(names ...string) bool {
		for _, n := range names {
			if _, err := os.Stat(filepath.Join(p, n)); err == nil { return true }
		}
		return false
	}
	wfContains := func(kw string) bool {
		for _, c := range wfs {
			if contains(c, kw) { return true }
		}
		return false
	}

	switch id {
	case "S2C2F-ING-1":
		if fe(manifests...) { return "met", "Package manifest found", "" }
		return "unmet", "", "Use a package manager"
	case "S2C2F-ING-2":
		if fe(manifests...) { return "met", "Dependency manifests found", "" }
		return "unmet", "", "Track dependencies in a manifest"
	case "S2C2F-ING-3":
		if info.HasDependabot { return "met", "Dependabot configured", "" }
		if fe("renovate.json", ".renovaterc") { return "met", "Renovate configured", "" }
		return "unmet", "", "Enable Dependabot or Renovate"
	case "S2C2F-SCN-1":
		if info.HasDependabot || info.HasCodeql { return "met", "Scanning configured", "" }
		return "unmet", "", "Enable vulnerability scanning"
	case "S2C2F-SCN-2":
		if wfContains("license") { return "met", "License scanning in CI", "" }
		return "unknown", "", "Add license compliance scanning"
	case "S2C2F-INV-1":
		if info.HasSbomWorkflow || fe("sbom.json", "bom.json") { return "met", "SBOM found", "" }
		return "unmet", "", "Generate SBOMs — run `ossguard sbom-gen`"
	case "S2C2F-INV-2":
		if fe(lockFiles...) { return "met", "Lock file found", "" }
		return "unmet", "", "Use lock files"
	case "S2C2F-UPD-1", "S2C2F-UPD-2":
		if info.HasDependabot { return "met", "Automated updates configured", "" }
		return "unmet", "", "Enable automated dependency updates"
	case "S2C2F-ENF-1":
		if wfContains("dependency-review") || wfContains("audit") { return "met", "Dependency enforcement in CI", "" }
		return "unmet", "", "Add dependency review to CI"
	case "S2C2F-ENF-2":
		return "unknown", "", "Implement license enforcement"
	case "S2C2F-AUD-1":
		return "unknown", "", "Perform security audits of critical deps"
	case "S2C2F-AUD-2":
		if info.HasSigstore { return "met", "Sigstore verification available", "" }
		return "unmet", "", "Verify provenance of packages"
	case "S2C2F-FIX-1":
		return "unknown", "", "Establish private patching process"
	case "S2C2F-FIX-2":
		if info.HasSecurityMd { return "met", "Security policy encourages upstream contributions", "" }
		return "unknown", "", "Document upstream fix process"
	case "S2C2F-VER-1":
		if wfContains("cosign verify") || wfContains("sigstore") { return "met", "Signature verification configured", "" }
		return "unmet", "", "Add package signature verification"
	case "S2C2F-VER-2":
		return "unknown", "", "Implement SBOM validation"
	default:
		return "unknown", "", "Advanced practice — requires org process"
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
