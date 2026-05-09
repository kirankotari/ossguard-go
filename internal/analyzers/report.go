package analyzers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// GenerateReport produces an HTML or JSON report from audit data.
func GenerateReport(projectPath, format string) string {
	audit := RunAudit(projectPath)
	if format == "json" {
		data, _ := json.MarshalIndent(audit, "", "  ")
		return string(data)
	}
	return generateHTML(audit)
}

func generateHTML(a *AuditReport) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html><html><head><meta charset='utf-8'><title>OSSGuard Security Report</title>")
	b.WriteString("<style>body{font-family:system-ui;max-width:900px;margin:2rem auto;padding:0 1rem}")
	b.WriteString("table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}")
	b.WriteString("th{background:#f4f4f4}.pass{color:green}.fail{color:red}.grade{font-size:3rem;font-weight:bold}</style></head><body>")
	b.WriteString(fmt.Sprintf("<h1>Security Report: %s</h1>", a.ProjectInfo.RepoName))
	b.WriteString(fmt.Sprintf("<p>Generated: %s</p>", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("<p class='grade'>Grade: %s</p>", a.OverallGrade))
	b.WriteString(fmt.Sprintf("<p>Config Score: %d/%d (%d%%)</p>", a.ConfigScore, a.ConfigTotal, a.ConfigPct))

	if len(a.Findings) > 0 {
		b.WriteString("<h2>Findings</h2><table><tr><th>#</th><th>Finding</th></tr>")
		for i, f := range a.Findings {
			b.WriteString(fmt.Sprintf("<tr><td>%d</td><td class='fail'>%s</td></tr>", i+1, f))
		}
		b.WriteString("</table>")
	}
	if len(a.Recommendations) > 0 {
		b.WriteString("<h2>Recommendations</h2><ul>")
		for _, r := range a.Recommendations {
			b.WriteString(fmt.Sprintf("<li>%s</li>", r))
		}
		b.WriteString("</ul>")
	}
	b.WriteString("</body></html>")
	return b.String()
}
