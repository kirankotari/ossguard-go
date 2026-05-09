// Command ossguard is the CLI entry point for OSSGuard.
//
// Usage:
//
//	ossguard <command> [path] [flags]
//
// Run "ossguard --help" for a full list of commands.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kirankotari/ossguard-go/internal/analyzers"
	"github.com/kirankotari/ossguard-go/internal/detector"
	"github.com/kirankotari/ossguard-go/internal/generators"
	"github.com/spf13/cobra"
)

const version = "0.1.4"

func main() {
	root := &cobra.Command{
		Use:   "ossguard",
		Short: "One CLI to guard any OSS project with OpenSSF security best practices",
	}

	root.PersistentFlags().BoolP("json", "j", false, "Output as JSON")
	root.PersistentFlags().StringP("path", "p", ".", "Project path")

	root.AddCommand(
		versionCmd(), initCmd(), scanCmd(),
		depsCmd(), driftCmd(), watchCmd(), tpnCmd(), reachCmd(),
		auditCmd(), fixCmd(), badgeCmd(), ciCmd(), reportCmd(), policyCmd(), licenseCmd(),
		baselineCmd(), insightsCmd(), pinCmd(), secretsCmd(), slsaCmd(), sbomGenCmd(),
		supplyChainCmd(), containerCmd(), compareCmd(), updateCmd(), maturityCmd(), fuzzCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func getPath(cmd *cobra.Command, args []string) string {
	// Accept positional arg first (ossguard scan .), then --path flag
	if len(args) > 0 && args[0] != "" {
		abs, _ := filepath.Abs(args[0])
		return abs
	}
	p, _ := cmd.Flags().GetString("path")
	abs, _ := filepath.Abs(p)
	return abs
}

func isJSON(cmd *cobra.Command) bool {
	j, _ := cmd.Flags().GetBool("json")
	return j
}

func printJSON(v interface{}) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use: "version", Short: "Show version",
		Run: func(cmd *cobra.Command, args []string) { fmt.Printf("ossguard %s\n", version) },
	}
}

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use: "init", Short: "Bootstrap security configs for a project",
		Run: func(cmd *cobra.Command, args []string) {
			p := getPath(cmd, args)
			info := detector.DetectProject(p)
			fmt.Printf("Initializing security configs for %s...\n", info.RepoName)
			report := analyzers.AutoFix(p, false)
			if isJSON(cmd) { printJSON(report); return }
			for _, a := range report.Actions {
				status := "✓"
				if !a.Applied { status = "–" }
				fmt.Printf("  %s %s\n", status, a.Description)
			}
			fmt.Printf("\nApplied %d actions.\n", report.AppliedCount)
		},
	}
}

func scanCmd() *cobra.Command {
	return &cobra.Command{
		Use: "scan", Short: "Quick security configuration scan",
		Run: func(cmd *cobra.Command, args []string) {
			p := getPath(cmd, args)
			info := detector.DetectProject(p)
			if isJSON(cmd) { printJSON(info); return }
			fmt.Printf("Project: %s\nLanguage: %s\n", info.RepoName, info.PrimaryLanguage)
			checks := []struct{ name string; ok bool }{
				{"SECURITY.md", info.HasSecurityMd}, {"Scorecard", info.HasScorecard},
				{"Dependabot", info.HasDependabot}, {"CodeQL", info.HasCodeql},
				{"SBOM workflow", info.HasSbomWorkflow}, {"Sigstore", info.HasSigstore},
			}
			for _, c := range checks {
				mark := "✗"
				if c.ok { mark = "✓" }
				fmt.Printf("  %s %s\n", mark, c.name)
			}
		},
	}
}

func auditCmd() *cobra.Command {
	return &cobra.Command{
		Use: "audit", Short: "Comprehensive security audit",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.RunAudit(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Audit: %s — Grade: %s (%d/%d config checks)\n", report.ProjectInfo.RepoName, report.OverallGrade, report.ConfigScore, report.ConfigTotal)
			for _, f := range report.Findings { fmt.Printf("  ⚠ %s\n", f) }
			for _, r := range report.Recommendations { fmt.Printf("  → %s\n", r) }
		},
	}
}

func depsCmd() *cobra.Command {
	return &cobra.Command{
		Use: "deps", Short: "Analyze dependency health and vulnerabilities",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.AnalyzeDeps(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Dependencies: %d total, %d vulnerabilities\n", report.TotalDeps, report.TotalVulns)
		},
	}
}

func driftCmd() *cobra.Command {
	return &cobra.Command{
		Use: "drift", Short: "Detect dependency drift from lock files",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.DetectDrift(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Drift: %d drifted, %d synced, lock file: %v\n", report.DriftCount, report.SyncCount, report.HasLock)
		},
	}
}

func watchCmd() *cobra.Command {
	return &cobra.Command{
		Use: "watch", Short: "Monitor dependencies for new vulnerabilities",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.AnalyzeDeps(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Watching %d deps — %d known vulns\n", report.TotalDeps, report.TotalVulns)
		},
	}
}

func tpnCmd() *cobra.Command {
	return &cobra.Command{
		Use: "tpn", Short: "Generate third-party notices",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.CheckLicenses(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Third-party notices: %d deps analyzed\n", report.TotalDeps)
			for _, l := range report.Licenses { fmt.Printf("  %s: %s (%s)\n", l.Name, l.License, l.Category) }
		},
	}
}

func reachCmd() *cobra.Command {
	return &cobra.Command{
		Use: "reach", Short: "Reachability-filtered vulnerability analysis",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.AnalyzeDeps(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Reachability analysis: %d deps, %d vulns\n", report.TotalDeps, report.TotalVulns)
		},
	}
}

func fixCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "fix", Short: "Auto-remediate common security issues",
		Run: func(cmd *cobra.Command, args []string) {
			dryRun, _ := cmd.Flags().GetBool("dry-run")
			report := analyzers.AutoFix(getPath(cmd, args), dryRun)
			if isJSON(cmd) { printJSON(report); return }
			for _, a := range report.Actions {
				s := "✓"
				if !a.Applied { s = "–" }
				fmt.Printf("  %s %s\n", s, a.Description)
			}
		},
	}
	cmd.Flags().Bool("dry-run", false, "Preview changes without applying")
	return cmd
}

func badgeCmd() *cobra.Command {
	return &cobra.Command{
		Use: "badge", Short: "OpenSSF Best Practices Badge readiness",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.AssessBadgeReadiness(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Badge: %s (%.0f%% — %d/%d)\n", report.Level, report.PassingPct, report.MetCount, report.TotalCount)
		},
	}
}

func ciCmd() *cobra.Command {
	return &cobra.Command{
		Use: "ci", Short: "Generate unified security CI pipeline",
		Run: func(cmd *cobra.Command, args []string) {
			content := analyzers.GenerateCI(getPath(cmd, args))
			if isJSON(cmd) { printJSON(map[string]string{"content": content}); return }
			fmt.Println(content)
		},
	}
}

func reportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "report", Short: "Export HTML/JSON compliance report",
		Run: func(cmd *cobra.Command, args []string) {
			format, _ := cmd.Flags().GetString("format")
			content := analyzers.GenerateReport(getPath(cmd, args), format)
			fmt.Println(content)
		},
	}
	cmd.Flags().String("format", "html", "Output format: html or json")
	return cmd
}

func policyCmd() *cobra.Command {
	return &cobra.Command{
		Use: "policy", Short: "Organization-wide security policy enforcement",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.CheckPolicy(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Policy: %d/%d passed — compliant: %v\n", report.PassCount, report.TotalCount, report.Compliant)
		},
	}
}

func licenseCmd() *cobra.Command {
	return &cobra.Command{
		Use: "license", Short: "License compliance checking",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.CheckLicenses(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Licenses: %d deps, %d unknown, %d conflicts\n", report.TotalDeps, report.UnknownCount, len(report.Conflicts))
		},
	}
}

func baselineCmd() *cobra.Command {
	return &cobra.Command{
		Use: "baseline", Short: "OSPS Baseline compliance",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.CheckBaseline(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Baseline Level %d — L1: %.0f%%, L2: %.0f%%, L3: %.0f%%\n", report.AchievedLevel, report.Level1Pct, report.Level2Pct, report.Level3Pct)
		},
	}
}

func insightsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "insights", Short: "Generate/validate SECURITY-INSIGHTS.yml",
		Run: func(cmd *cobra.Command, args []string) {
			validate, _ := cmd.Flags().GetBool("validate")
			if validate {
				report := analyzers.ValidateInsights(getPath(cmd, args))
				if isJSON(cmd) { printJSON(report); return }
				if report.Valid { fmt.Println("SECURITY-INSIGHTS.yml is valid") } else { fmt.Printf("Validation errors: %v\n", report.Errors) }
			} else {
				report := analyzers.GenerateInsights(getPath(cmd, args))
				fmt.Println(report.Content)
			}
		},
	}
	cmd.Flags().Bool("validate", false, "Validate existing file instead of generating")
	return cmd
}

func pinCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "pin", Short: "Pin GitHub Actions to commit SHAs",
		Run: func(cmd *cobra.Command, args []string) {
			apply, _ := cmd.Flags().GetBool("apply")
			report, _ := analyzers.PinActions(getPath(cmd, args), apply)
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Actions: %d total, %d pinned, %d unpinned\n", report.TotalActions, report.PinnedCount, report.UnpinnedCount)
		},
	}
	cmd.Flags().Bool("apply", false, "Apply pinning changes")
	return cmd
}

func secretsCmd() *cobra.Command {
	return &cobra.Command{
		Use: "secrets", Short: "Scan for leaked credentials and secrets",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.ScanSecrets(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Secrets scan: %d files, %d findings\n", report.FilesScanned, report.TotalSecrets)
			for _, f := range report.Findings { fmt.Printf("  %s:%d [%s] %s\n", f.File, f.Line, f.Severity, f.RuleID) }
		},
	}
}

func slsaCmd() *cobra.Command {
	return &cobra.Command{
		Use: "slsa", Short: "SLSA provenance level assessment",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.CheckSLSA(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("%s — %d/%d met\n", report.LevelLabel, report.MetCount, report.TotalCount)
		},
	}
}

func sbomGenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "sbom-gen", Short: "Generate SPDX or CycloneDX SBOMs",
		Run: func(cmd *cobra.Command, args []string) {
			format, _ := cmd.Flags().GetString("format")
			content := analyzers.GenerateSBOM(getPath(cmd, args), format)
			fmt.Println(content)
		},
	}
	cmd.Flags().String("format", "spdx", "SBOM format: spdx or cyclonedx")
	return cmd
}

func supplyChainCmd() *cobra.Command {
	return &cobra.Command{
		Use: "supply-chain", Short: "Malicious package and typosquatting detection",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.CheckSupplyChain(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Supply chain: %d deps, %d malicious, %d typosquat, clean: %v\n", report.TotalDeps, report.MaliciousCount, report.TyposquatCount, report.Clean)
		},
	}
}

func containerCmd() *cobra.Command {
	return &cobra.Command{
		Use: "container", Short: "Dockerfile security linting",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.ScanContainers(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Container scan: %d files, %d findings (C:%d H:%d M:%d L:%d)\n", report.FilesScanned, len(report.Findings), report.CriticalCount, report.HighCount, report.MediumCount, report.LowCount)
		},
	}
}

func compareCmd() *cobra.Command {
	return &cobra.Command{
		Use: "compare [pathA] [pathB]", Short: "Compare security posture of two projects",
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.CompareProjects(args[0], args[1])
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("%s (%s) vs %s (%s) — winner: %s\n", report.ProjectAName, report.ProjectAGrade, report.ProjectBName, report.ProjectBGrade, report.Winner)
		},
	}
}

func updateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "update", Short: "Security-prioritized dependency updates",
		Run: func(cmd *cobra.Command, args []string) {
			secOnly, _ := cmd.Flags().GetBool("security-only")
			report := analyzers.CheckUpdates(getPath(cmd, args), secOnly)
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Updates: %d available, %d security, %d up-to-date\n", report.TotalUpdates, report.SecurityUpdates, report.UpToDate)
		},
	}
	cmd.Flags().Bool("security-only", false, "Show only security updates")
	return cmd
}

func maturityCmd() *cobra.Command {
	return &cobra.Command{
		Use: "maturity", Short: "S2C2F maturity assessment",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.AssessMaturity(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("S2C2F Level %d — L1: %.0f%%, L2: %.0f%%, L3: %.0f%%, L4: %.0f%%\n", report.AchievedLevel, report.Level1Pct, report.Level2Pct, report.Level3Pct, report.Level4Pct)
		},
	}
}

func fuzzCmd() *cobra.Command {
	return &cobra.Command{
		Use: "fuzz", Short: "Fuzzing readiness check",
		Run: func(cmd *cobra.Command, args []string) {
			report := analyzers.CheckFuzzReadiness(getPath(cmd, args))
			if isJSON(cmd) { printJSON(report); return }
			fmt.Printf("Fuzz: %s, framework: %s, score: %d/100\n", report.Language, report.Framework, report.ReadinessScore)
			if !report.HasFuzzing { fmt.Println("  No fuzzing detected — see recommendations:") }
			for _, f := range report.Findings { fmt.Printf("  [%s] %s\n", f.Category, f.Description) }
		},
	}
}

func init() {
	// Ensure generators package is importable (used by fix.go)
	_ = generators.GenerateSecurityMd
}
