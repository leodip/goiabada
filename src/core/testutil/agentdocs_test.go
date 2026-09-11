package testutil

// Seam 1: the rule table checkAgentDocs enforces, over fixture agent files and a fixture
// auth_context.go written into a temp tree and read through the same function the real caller uses.
//
// The synthetic half exists for the reason errors_lint_test.go's does: the real half cannot fail
// informatively. Once the tree is correct by construction, a guard that had quietly stopped
// matching anything would pass exactly as a working one does, and nothing would be holding the rule
// (#252).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClaudeLines is the fixture CLAUDE.md, one line per element so every case that asserts a line
// number can be read against it. Line numbers below are 1-based, so line N is index N-1.
//
// Three shapes in it are load-bearing and every case leans on at least one: the continuation row at
// line 13 has an empty first cell, the route table at lines 17 and 18 repeats two state values in a
// later column, and the `bogus_state` at line 23 sits below the next `###` heading.
var fakeClaudeLines = []string{
	"# Fake repository notes", // 1
	"",                        // 2
	"## Authentication Flow (Authorization Code)", // 3
	"",                                // 4
	"### Auth States (State Machine)", // 5
	"The values below are the constants in `src/core/oauth/auth_context.go`.", // 6
	"",                               // 7
	"| State | Assigned by | When |", // 8
	"|---|---|---|",                  // 9
	"| `initial` | `HandleAuthorizeGet` | the composite literal |",               // 10
	"| `level2_otp` | `HandleAuthLevel2Get` | level2_mandatory |",                // 11
	"| `ready_to_issue_code` | `handlePromptNone` | every silent check passed |", // 12
	"| | `HandleConsentPost` | approved with at least one scope |",               // 13
	"", // 14
	"| Route | Method | Accepts | On mismatch |",            // 15
	"|---|---|---|---|",                                     // 16
	"| `/auth/otp` | GET | `level2_otp` | 400 |",            // 17
	"| `/auth/issue` | GET | `ready_to_issue_code` | 400 |", // 18
	"",                             // 19
	"### Flow Handlers (in order)", // 20
	"| Handler | File |",           // 21
	"|---|---|",                    // 22
	"| `bogus_state` | `handler_auth_pwd.go` |", // 23
	"", // 24
}

// The fixture auth_context.go. The real file declares the states under `var (`, so that is the
// default; the const variant is here because tightening them to constants must not be a change to
// the guard.
const (
	fakeStatesVar = `package oauth

var (
	AuthStateInitial          = "initial"
	AuthStateLevel2OTP        = "level2_otp"
	AuthStateReadyToIssueCode = "ready_to_issue_code"
)
`
	fakeStatesConst = `package oauth

const (
	AuthStateInitial          = "initial"
	AuthStateLevel2OTP        = "level2_otp"
	AuthStateReadyToIssueCode = "ready_to_issue_code"
)
`
	fakeStatesExtra = `package oauth

var (
	AuthStateInitial          = "initial"
	AuthStateLevel2OTP        = "level2_otp"
	AuthStateReadyToIssueCode = "ready_to_issue_code"
	AuthStateRequiresConsent  = "requires_consent"
)
`
	fakeStatesNone = `package oauth

var (
	sessionCookieName = "session"
)
`
)

// TestAgentDocs_TheRuleTable writes one fixture tree per row of the rule and asserts the exact set
// of findings. Every passing row is a shape that must survive the check untouched; every failing
// row asserts the message, because a finding that fires with unusable text sends the next reader to
// re-derive what the guard already knew.
func TestAgentDocs_TheRuleTable(t *testing.T) {
	const missingHeading = `# Fake repository notes

### Auth States
| State | Assigned by | When |
|---|---|---|
| ` + "`initial`" + ` | x | y |
`

	cases := []struct {
		name   string
		claude []string
		agents []string // nil means AGENTS.md is a copy of claude
		states string
		want   []string
	}{
		{
			name:   "identical files and a full roster pass",
			claude: fakeClaudeLines,
			states: fakeStatesVar,
			want:   nil,
		},
		{
			name:   "the same, with the states declared as constants",
			claude: fakeClaudeLines,
			states: fakeStatesConst,
			want:   nil,
		},
		{
			name:   "a one-line difference in AGENTS.md fails naming the first differing line",
			claude: fakeClaudeLines,
			agents: replaceLine(fakeClaudeLines, 6, "The values below are the constants, probably."),
			states: fakeStatesVar,
			want: []string{
				"CLAUDE.md and AGENTS.md differ at line 6; they are co-maintained copies and must be identical\n" +
					"\tCLAUDE.md: The values below are the constants in `src/core/oauth/auth_context.go`.\n" +
					"\tAGENTS.md: The values below are the constants, probably.",
			},
		},
		{
			name:   "a shorter AGENTS.md fails at the line where it ends",
			claude: fakeClaudeLines,
			agents: fakeClaudeLines[:5],
			states: fakeStatesVar,
			want: []string{
				"CLAUDE.md and AGENTS.md differ at line 6; they are co-maintained copies and must be identical\n" +
					"\tCLAUDE.md: The values below are the constants in `src/core/oauth/auth_context.go`.\n" +
					"\tAGENTS.md: <end of file>",
			},
		},
		{
			name:   "a declared state with no row fails naming the value",
			claude: fakeClaudeLines,
			states: fakeStatesExtra,
			want: []string{
				`state "requires_consent" is declared in src/core/oauth/auth_context.go but has no row in the "### Auth States (State Machine)" section of CLAUDE.md`,
			},
		},
		{
			// The reason the roster reads the first cell rather than the whole section: level2_otp
			// is still on line 17, in the route table's Accepts column, so a rule that accepted any
			// occurrence would see nothing wrong here.
			name:   "a state left only in a later column, its own row deleted, fails naming the value",
			claude: deleteLine(fakeClaudeLines, 11),
			states: fakeStatesVar,
			want: []string{
				`state "level2_otp" is declared in src/core/oauth/auth_context.go but has no row in the "### Auth States (State Machine)" section of CLAUDE.md`,
			},
		},
		{
			name:   "a first-cell token with no declaration fails naming the token",
			claude: insertLine(fakeClaudeLines, 14, "| `level2_otp_completed` | nobody | dead |"),
			states: fakeStatesVar,
			want: []string{
				`the "### Auth States (State Machine)" section of CLAUDE.md has a row for state "level2_otp_completed", which src/core/oauth/auth_context.go does not declare`,
			},
		},
		{
			name:   "a declaration block with no AuthState names fails rather than passing vacuously",
			claude: fakeClaudeLines,
			states: fakeStatesNone,
			want:   []string{"src/core/oauth/auth_context.go declares no AuthState* string constants"},
		},
		{
			name:   "a missing heading fails",
			claude: strings.Split(strings.TrimSuffix(missingHeading, "\n"), "\n"),
			states: fakeStatesVar,
			want:   []string{`CLAUDE.md has no "### Auth States (State Machine)" section`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agents := tc.agents
			if agents == nil {
				agents = tc.claude
			}
			root := writeFakeTree(t, tc.claude, agents, tc.states)

			assert.Equal(t, tc.want, checkAgentDocs(root))
		})
	}
}

// TestAgentDocs_AMissingAgentsFileFails is its own case because the finding carries the operating
// system's own "no such file" text and the path separator it uses, neither of which belongs in a
// table asserting exact strings.
func TestAgentDocs_AMissingAgentsFileFails(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "CLAUDE.md"), strings.Join(fakeClaudeLines, "\n"))
	writeFile(t, filepath.Join(root, "src", "core", "oauth", "auth_context.go"), fakeStatesVar)

	findings := checkAgentDocs(root)

	require.Len(t, findings, 1, "the roster still checks out, so the missing file is the only finding")
	assert.True(t, strings.HasPrefix(findings[0], "reading AGENTS.md: "), findings[0])
}

func writeFakeTree(t *testing.T, claude, agents []string, states string) string {
	t.Helper()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "CLAUDE.md"), strings.Join(claude, "\n"))
	writeFile(t, filepath.Join(root, "AGENTS.md"), strings.Join(agents, "\n"))
	writeFile(t, filepath.Join(root, "src", "core", "oauth", "auth_context.go"), states)
	return root
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// replaceLine, deleteLine and insertLine take 1-based line numbers so a case reads against the
// numbered fixture above. Each copies, because the fixture is shared by every case.
func replaceLine(lines []string, n int, with string) []string {
	out := append([]string(nil), lines...)
	out[n-1] = with
	return out
}

func deleteLine(lines []string, n int) []string {
	out := append([]string(nil), lines[:n-1]...)
	return append(out, lines[n:]...)
}

func insertLine(lines []string, n int, line string) []string {
	out := append([]string(nil), lines[:n-1]...)
	out = append(out, line)
	return append(out, lines[n-1:]...)
}
