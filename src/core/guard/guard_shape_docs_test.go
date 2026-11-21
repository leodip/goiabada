package guard

// The written brake on the guard suite's growth (#420): a new guard over 250 lines of its own code
// answers three questions in its pull request, and a linter check is looked for before a guard is
// written. Nothing measures guard files; these tests hold the two places the rule is written to
// saying it, and the guide's Guard shape section to keeping the rule rather than a roster of guards,
// which drifted each time a guard was added (#442).

import (
	"path/filepath"
	"testing"
)

const (
	guardsGuide      = "docs/development/guards.md"
	guardShapeHeader = "## Guard shape"
)

func TestGuardsGuide_GuardShapeIsTheRuleWithoutARoster(t *testing.T) {
	AssertSectionSays(t, filepath.Dir(SourceRoot(t)), guardsGuide, guardShapeHeader,
		[]string{
			"`guard.Reporter`",
			"`guard.Run`",
			"250 lines",
			"`credential_read_lint.go`",
			"`golangci-lint`",
			"`core/pkgload`",
			"`git grep -n 'func assert.*\\(r Reporter\\|r guard\\.Reporter\\)' -- '*.go'`",
			"`8883642d`",
		},
		[]string{"the newest", "AssertNoLiteralStackSecrets", "and before it"})
}

// The root instructions carry the threshold because the guide is read only once a guard is
// already being written.
func TestAgentDocs_StateTheGuardThreshold(t *testing.T) {
	AssertSectionSays(t, filepath.Dir(SourceRoot(t)), "AGENTS.md", "", []string{"250 lines"}, nil)
}
