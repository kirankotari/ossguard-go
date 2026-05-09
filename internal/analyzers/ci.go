package analyzers

import (
	"fmt"
	"strings"

	"github.com/kirankotari/ossguard-go/internal/detector"
)

// GenerateCI produces a GitHub Actions CI workflow YAML with security checks.
func GenerateCI(projectPath string) string {
	info := detector.DetectProject(projectPath)
	lang := strings.ToLower(info.PrimaryLanguage)

	var b strings.Builder
	b.WriteString("name: CI\n\non:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [main]\n\npermissions: read-all\n\njobs:\n")

	switch lang {
	case "python":
		b.WriteString("  test:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        python-version: ['3.10', '3.11', '3.12']\n    steps:\n")
		b.WriteString("      - uses: actions/checkout@v4\n")
		b.WriteString("      - uses: actions/setup-python@v5\n        with:\n          python-version: ${{ matrix.python-version }}\n")
		b.WriteString("      - run: pip install -e \".[dev]\"\n")
		b.WriteString("      - run: ruff check src/ tests/\n")
		b.WriteString("      - run: pytest --tb=short -q\n")
	case "javascript", "typescript":
		b.WriteString("  test:\n    runs-on: ubuntu-latest\n    steps:\n")
		b.WriteString("      - uses: actions/checkout@v4\n")
		b.WriteString("      - uses: actions/setup-node@v4\n        with:\n          node-version: '20'\n")
		b.WriteString("      - run: npm ci\n")
		b.WriteString("      - run: npm run lint\n")
		b.WriteString("      - run: npm test\n")
	case "go":
		b.WriteString("  test:\n    runs-on: ubuntu-latest\n    steps:\n")
		b.WriteString("      - uses: actions/checkout@v4\n")
		b.WriteString("      - uses: actions/setup-go@v5\n        with:\n          go-version: '1.22'\n")
		b.WriteString("      - run: go vet ./...\n")
		b.WriteString("      - run: go test -race ./...\n")
	case "rust":
		b.WriteString("  test:\n    runs-on: ubuntu-latest\n    steps:\n")
		b.WriteString("      - uses: actions/checkout@v4\n")
		b.WriteString("      - run: cargo fmt --check\n")
		b.WriteString("      - run: cargo clippy -- -D warnings\n")
		b.WriteString("      - run: cargo test\n")
	default:
		b.WriteString(fmt.Sprintf("  # TODO: Add test job for %s\n", info.PrimaryLanguage))
	}

	b.WriteString("\n  security:\n    runs-on: ubuntu-latest\n    permissions:\n      security-events: write\n    steps:\n")
	b.WriteString("      - uses: actions/checkout@v4\n")
	b.WriteString("      - uses: github/codeql-action/init@v3\n      - uses: github/codeql-action/autobuild@v3\n      - uses: github/codeql-action/analyze@v3\n")

	b.WriteString("\n  dependency-review:\n    runs-on: ubuntu-latest\n    if: github.event_name == 'pull_request'\n    steps:\n")
	b.WriteString("      - uses: actions/checkout@v4\n")
	b.WriteString("      - uses: actions/dependency-review-action@v4\n")

	return b.String()
}
