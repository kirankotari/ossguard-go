package analyzers

import "fmt"

// CompareMetric represents a single comparison data point.
type CompareMetric struct {
	Name         string `json:"name"`
	ProjectAVal  string `json:"project_a_value"`
	ProjectBVal  string `json:"project_b_value"`
	Winner       string `json:"winner"`
}

// CompareReport is the result of comparing two projects.
type CompareReport struct {
	ProjectAName  string          `json:"project_a_name"`
	ProjectBName  string          `json:"project_b_name"`
	ProjectAGrade string          `json:"project_a_grade"`
	ProjectBGrade string          `json:"project_b_grade"`
	Metrics       []CompareMetric `json:"metrics"`
	Winner        string          `json:"winner"`
}

// CompareProjects runs audits on two projects and compares them.
func CompareProjects(pathA, pathB string) *CompareReport {
	auditA := RunAudit(pathA)
	auditB := RunAudit(pathB)

	metrics := []CompareMetric{
		compareGrades("Overall Grade", auditA.OverallGrade, auditB.OverallGrade),
		compareNumericHigher("Config Score", auditA.ConfigScore, auditA.ConfigTotal, auditB.ConfigScore, auditB.ConfigTotal),
		{Name: "Dependencies", ProjectAVal: fmt.Sprintf("%d", auditA.DepsCount), ProjectBVal: fmt.Sprintf("%d", auditB.DepsCount), Winner: ""},
		{Name: "Findings", ProjectAVal: fmt.Sprintf("%d", len(auditA.Findings)), ProjectBVal: fmt.Sprintf("%d", len(auditB.Findings)),
			Winner: fewerWins(len(auditA.Findings), len(auditB.Findings))},
	}

	aWins, bWins := 0, 0
	for _, m := range metrics {
		if m.Winner == "a" { aWins++ }
		if m.Winner == "b" { bWins++ }
	}
	winner := "tie"
	if aWins > bWins { winner = "a" }
	if bWins > aWins { winner = "b" }

	return &CompareReport{
		ProjectAName: auditA.ProjectInfo.RepoName, ProjectBName: auditB.ProjectInfo.RepoName,
		ProjectAGrade: auditA.OverallGrade, ProjectBGrade: auditB.OverallGrade,
		Metrics: metrics, Winner: winner,
	}
}

func compareGrades(name, a, b string) CompareMetric {
	vals := map[string]int{"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
	va, vb := vals[a], vals[b]
	w := "tie"
	if va > vb { w = "a" }
	if vb > va { w = "b" }
	return CompareMetric{Name: name, ProjectAVal: a, ProjectBVal: b, Winner: w}
}

func compareNumericHigher(name string, aVal, aTotal, bVal, bTotal int) CompareMetric {
	aP, bP := 0.0, 0.0
	if aTotal > 0 { aP = float64(aVal) / float64(aTotal) * 100 }
	if bTotal > 0 { bP = float64(bVal) / float64(bTotal) * 100 }
	w := "tie"
	if aP > bP { w = "a" }
	if bP > aP { w = "b" }
	return CompareMetric{Name: name, ProjectAVal: fmt.Sprintf("%d/%d (%.0f%%)", aVal, aTotal, aP), ProjectBVal: fmt.Sprintf("%d/%d (%.0f%%)", bVal, bTotal, bP), Winner: w}
}

func fewerWins(a, b int) string {
	if a < b { return "a" }
	if b < a { return "b" }
	return "tie"
}
