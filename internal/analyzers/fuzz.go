package analyzers

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/kirankotari/ossguard-go/internal/detector"
)

// FuzzFinding represents a fuzzing readiness finding.
type FuzzFinding struct {
	Category    string `json:"category"`
	Description string `json:"description"`
	File        string `json:"file"`
}

// FuzzReport is the result of a fuzzing readiness check.
type FuzzReport struct {
	HasFuzzing     bool          `json:"has_fuzzing"`
	Framework      string        `json:"framework"`
	Findings       []FuzzFinding `json:"findings"`
	ReadinessScore int           `json:"readiness_score"`
	StarterHarness string        `json:"starter_harness"`
	Language       string        `json:"language"`
}

// CheckFuzzReadiness evaluates fuzzing setup and generates recommendations.
func CheckFuzzReadiness(projectPath string) *FuzzReport {
	abs, _ := filepath.Abs(projectPath)
	info := detector.DetectProject(abs)
	lang := strings.ToLower(info.PrimaryLanguage)

	report := &FuzzReport{Language: info.PrimaryLanguage}
	report.HasFuzzing, report.Framework, report.Findings = detectFuzz(abs, lang)

	score := 0
	if report.HasFuzzing {
		score += 50
	}
	if dirOrFileExists(abs, ".oss-fuzz", "project.yaml") {
		score += 20
		report.Findings = append(report.Findings, FuzzFinding{Category: "existing", Description: "OSS-Fuzz integration found"})
	}
	if dirOrFileExists(abs, ".clusterfuzzlite") {
		score += 15
		report.Findings = append(report.Findings, FuzzFinding{Category: "existing", Description: "ClusterFuzzLite configured"})
	}

	if !report.HasFuzzing {
		for _, rec := range fuzzRecommendations(lang) {
			report.Findings = append(report.Findings, FuzzFinding{Category: "recommendation", Description: rec})
		}
	}
	report.ReadinessScore = score
	if score > 100 {
		report.ReadinessScore = 100
	}
	report.StarterHarness = starterHarness(lang)
	return report
}

func detectFuzz(p, lang string) (bool, string, []FuzzFinding) {
	var findings []FuzzFinding
	found := false
	fw := ""

	switch lang {
	case "python":
		walkFiles(p, ".py", func(f string) {
			data, _ := os.ReadFile(f)
			c := string(data[:minInt(len(data), 2000)])
			if strings.Contains(c, "atheris") {
				found = true; fw = "Atheris"
				findings = append(findings, FuzzFinding{Category: "existing", Description: "Atheris fuzzer found", File: f})
			}
			if strings.Contains(c, "hypothesis") && strings.Contains(c, "@given") {
				found = true; if fw == "" { fw = "Hypothesis" }
				findings = append(findings, FuzzFinding{Category: "existing", Description: "Hypothesis tests found", File: f})
			}
		})
	case "go":
		walkFiles(p, "_test.go", func(f string) {
			data, _ := os.ReadFile(f)
			if strings.Contains(string(data), "func Fuzz") {
				found = true; fw = "Go native fuzzing"
				findings = append(findings, FuzzFinding{Category: "existing", Description: "Go fuzz function found", File: f})
			}
		})
	case "rust":
		if _, err := os.Stat(filepath.Join(p, "fuzz")); err == nil {
			found = true; fw = "cargo-fuzz"
			findings = append(findings, FuzzFinding{Category: "existing", Description: "cargo-fuzz directory found"})
		}
	case "javascript", "typescript":
		data, err := os.ReadFile(filepath.Join(p, "package.json"))
		if err == nil {
			c := string(data)
			if strings.Contains(c, "jsfuzz") || strings.Contains(c, "@jazzer.js/core") {
				found = true; fw = "Jazzer.js"
				findings = append(findings, FuzzFinding{Category: "existing", Description: "JS fuzzer dependency found"})
			}
			if strings.Contains(c, "fast-check") {
				found = true; if fw == "" { fw = "fast-check" }
				findings = append(findings, FuzzFinding{Category: "existing", Description: "fast-check found"})
			}
		}
	case "java", "kotlin":
		walkFiles(p, ".java", func(f string) {
			data, _ := os.ReadFile(f)
			c := string(data[:minInt(len(data), 2000)])
			if strings.Contains(c, "com.code_intelligence.jazzer") || strings.Contains(c, "@FuzzTest") {
				found = true; fw = "Jazzer"
				findings = append(findings, FuzzFinding{Category: "existing", Description: "Jazzer fuzz test found", File: f})
			}
		})
	case "c", "c++":
		walkFiles(p, ".c", func(f string) {
			data, _ := os.ReadFile(f)
			if strings.Contains(string(data[:minInt(len(data), 2000)]), "LLVMFuzzerTestOneInput") {
				found = true; fw = "libFuzzer"
				findings = append(findings, FuzzFinding{Category: "existing", Description: "libFuzzer harness found", File: f})
			}
		})
	}
	return found, fw, findings
}

func fuzzRecommendations(lang string) []string {
	m := map[string][]string{
		"python":     {"Install Atheris: pip install atheris", "Consider Hypothesis for property testing"},
		"go":         {"Use native Go fuzzing (Go 1.18+): func FuzzXxx(f *testing.F)", "Run: go test -fuzz=FuzzXxx"},
		"rust":       {"Install cargo-fuzz: cargo install cargo-fuzz"},
		"javascript": {"Install Jazzer.js: npm install --save-dev @jazzer.js/core"},
		"typescript": {"Install Jazzer.js: npm install --save-dev @jazzer.js/core"},
		"java":       {"Use Jazzer: add com.code_intelligence:jazzer-junit"},
		"c":          {"Use libFuzzer: implement LLVMFuzzerTestOneInput"},
		"c++":        {"Use libFuzzer: implement LLVMFuzzerTestOneInput"},
	}
	recs := m[lang]
	recs = append(recs, "Set up ClusterFuzzLite: https://google.github.io/clusterfuzzlite/")
	return recs
}

func starterHarness(lang string) string {
	m := map[string]string{
		"python":     "import atheris\nimport sys\n\n@atheris.instrument_func\ndef fuzz_target(data: bytes):\n    pass\n\nif __name__ == \"__main__\":\n    atheris.Setup(sys.argv, fuzz_target)\n    atheris.Fuzz()\n",
		"go":         "package mypackage\n\nimport \"testing\"\n\nfunc FuzzParseInput(f *testing.F) {\n\tf.Add([]byte(\"hello\"))\n\tf.Fuzz(func(t *testing.T, data []byte) {\n\t\t// test here\n\t})\n}\n",
		"rust":       "#![no_main]\nuse libfuzzer_sys::fuzz_target;\n\nfuzz_target!(|data: &[u8]| {\n    // test here\n});\n",
		"javascript": "const { fuzz } = require(\"@jazzer.js/core\");\n\nfuzz((data) => {\n  // test here\n});\n",
		"typescript": "const { fuzz } = require(\"@jazzer.js/core\");\n\nfuzz((data) => {\n  // test here\n});\n",
		"java":       "import com.code_intelligence.jazzer.junit.FuzzTest;\n\nclass FuzzTests {\n    @FuzzTest\n    void fuzzInput(byte[] data) {}\n}\n",
		"c":          "#include <stdint.h>\n#include <stddef.h>\n\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n    return 0;\n}\n",
		"c++":        "#include <stdint.h>\n#include <stddef.h>\n\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n    return 0;\n}\n",
	}
	if h, ok := m[lang]; ok {
		return h
	}
	return "# No starter harness for this language.\n"
}

var walkSkip = map[string]bool{".git": true, "node_modules": true, "vendor": true, "venv": true, ".venv": true, "dist": true, "build": true, "target": true}

func walkFiles(root, ext string, fn func(string)) {
	filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil { return nil }
		if fi.IsDir() && walkSkip[fi.Name()] { return filepath.SkipDir }
		if !fi.IsDir() && strings.HasSuffix(path, ext) { fn(path) }
		return nil
	})
}

func dirOrFileExists(base string, names ...string) bool {
	for _, n := range names {
		if _, err := os.Stat(filepath.Join(base, n)); err == nil { return true }
	}
	return false
}

func minInt(a, b int) int {
	if a < b { return a }
	return b
}
