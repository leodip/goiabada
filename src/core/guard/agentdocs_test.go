package guard

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

// fakeAuthDocLines is the fixture authentication guide, one line per element so each asserted line
// number can be read against it. Line numbers below are 1-based, so line N is index N-1.
//
// Three shapes in it are load-bearing and every case leans on at least one: the continuation row at
// line 13 has an empty first cell, the route table at lines 17 and 18 repeats two state values in a
// later column, and the `bogus_state` at line 23 sits below the next `###` heading.
var fakeAuthDocLines = []string{
	"# Fake repository notes", // 1
	"",                        // 2
	"## Authentication Flow (Authorization Code)", // 3
	"",                                // 4
	"### Auth States (State Machine)", // 5
	"The values below are the constants in `src/authserver/internal/ceremony/auth_context.go`.", // 6
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

// The fixture auth_context.go. The states are read from constants only, so the default is a const
// block; fakeStatesTyped is the real file's shape, and the two var fixtures are the shapes the guard
// refuses (#436).
const (
	fakeStatesConst = `package oauth

const (
	AuthStateInitial          = "initial"
	AuthStateLevel2OTP        = "level2_otp"
	AuthStateReadyToIssueCode = "ready_to_issue_code"
)
`
	fakeStatesTyped = `package oauth

type AuthState string

const (
	AuthStateInitial          AuthState = "initial"
	AuthStateLevel2OTP        AuthState = "level2_otp"
	AuthStateReadyToIssueCode AuthState = "ready_to_issue_code"
)
`
	fakeStatesVar = `package oauth

var (
	AuthStateInitial          = "initial"
	AuthStateLevel2OTP        = "level2_otp"
	AuthStateReadyToIssueCode = "ready_to_issue_code"
)
`
	fakeStatesStray = `package oauth

type AuthState string

const (
	AuthStateInitial          AuthState = "initial"
	AuthStateLevel2OTP        AuthState = "level2_otp"
	AuthStateReadyToIssueCode AuthState = "ready_to_issue_code"
)

var AuthStateStray = "stray"
`
	fakeStatesExtra = `package oauth

const (
	AuthStateInitial          = "initial"
	AuthStateLevel2OTP        = "level2_otp"
	AuthStateReadyToIssueCode = "ready_to_issue_code"
	AuthStateRequiresConsent  = "requires_consent"
)
`
	fakeStatesNone = `package oauth

const (
	sessionCookieName = "session"
)
`
)

// varFinding is the message for one AuthState* name declared with var.
func varFinding(name string) string {
	return "src/authserver/internal/ceremony/auth_context.go declares " + name +
		" with var; the ceremony's states must be constants, declared in its const block"
}

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
		doc    []string
		claude string // empty means the checked copy of AGENTS.md
		states string
		want   []string
	}{
		{
			name:   "identical entry points and a full roster pass",
			doc:    fakeAuthDocLines,
			states: fakeStatesConst,
			want:   nil,
		},
		{
			// The real file's shape: a defined type and typed constants. The value is still a string
			// literal, so the roster reads it.
			name:   "the same, with a defined AuthState type and typed constants",
			doc:    fakeAuthDocLines,
			states: fakeStatesTyped,
			want:   nil,
		},
		{
			// Every state a var: each is its own finding, and none counts as declared, so the
			// no-constants finding follows and the roster is not compared.
			name:   "states declared with var fail, one finding each, and leave no constants",
			doc:    fakeAuthDocLines,
			states: fakeStatesVar,
			want: []string{
				varFinding("AuthStateInitial"),
				varFinding("AuthStateLevel2OTP"),
				varFinding("AuthStateReadyToIssueCode"),
				"src/authserver/internal/ceremony/auth_context.go declares no AuthState* string constants",
			},
		},
		{
			// One stray var beside a correct const block. Its value is not read into the roster,
			// so the var finding is the only one: no roster row is demanded for "stray".
			name:   "one var beside the const block fails with exactly the var finding",
			doc:    fakeAuthDocLines,
			states: fakeStatesStray,
			want:   []string{varFinding("AuthStateStray")},
		},
		{
			name:   "a prose reference does not replace the checked copy",
			doc:    fakeAuthDocLines,
			claude: "Read AGENTS.md before working.",
			states: fakeStatesConst,
			want:   []string{"CLAUDE.md must match AGENTS.md; run cp AGENTS.md CLAUDE.md from the repository root"},
		},
		{
			name:   "an empty Claude entry fails",
			doc:    fakeAuthDocLines,
			claude: " \n",
			states: fakeStatesConst,
			want:   []string{"CLAUDE.md must match AGENTS.md; run cp AGENTS.md CLAUDE.md from the repository root"},
		},
		{
			name:   "an import wrapper cannot replace the portable checked copy",
			doc:    fakeAuthDocLines,
			claude: "@AGENTS.md\n",
			states: fakeStatesConst,
			want:   []string{"CLAUDE.md must match AGENTS.md; run cp AGENTS.md CLAUDE.md from the repository root"},
		},
		{
			name:   "an import of another file fails",
			doc:    fakeAuthDocLines,
			claude: "@some-other-file.md",
			states: fakeStatesConst,
			want:   []string{"CLAUDE.md must match AGENTS.md; run cp AGENTS.md CLAUDE.md from the repository root"},
		},
		{
			name:   "a declared state with no row fails naming the value",
			doc:    fakeAuthDocLines,
			states: fakeStatesExtra,
			want: []string{
				`state "requires_consent" is declared in src/authserver/internal/ceremony/auth_context.go but has no row in the "### Auth States (State Machine)" section of docs/development/authentication.md`,
			},
		},
		{
			name:   "a top-level heading ends the roster section",
			doc:    replaceAuthDocHeading(fakeAuthDocLines),
			states: fakeStatesConst,
			want:   nil,
		},
		{
			// The reason the roster reads the first cell rather than the whole section: level2_otp
			// is still on line 17, in the route table's Accepts column, so a rule that accepted any
			// occurrence would see nothing wrong here.
			name:   "a state left only in a later column, its own row deleted, fails naming the value",
			doc:    deleteLine(fakeAuthDocLines, 11),
			states: fakeStatesConst,
			want: []string{
				`state "level2_otp" is declared in src/authserver/internal/ceremony/auth_context.go but has no row in the "### Auth States (State Machine)" section of docs/development/authentication.md`,
			},
		},
		{
			name:   "a first-cell token with no declaration fails naming the token",
			doc:    insertLine(fakeAuthDocLines, 14, "| `level2_otp_completed` | nobody | dead |"),
			states: fakeStatesConst,
			want: []string{
				`the "### Auth States (State Machine)" section of docs/development/authentication.md has a row for state "level2_otp_completed", which src/authserver/internal/ceremony/auth_context.go does not declare`,
			},
		},
		{
			name:   "a declaration block with no AuthState names fails rather than passing vacuously",
			doc:    fakeAuthDocLines,
			states: fakeStatesNone,
			want:   []string{"src/authserver/internal/ceremony/auth_context.go declares no AuthState* string constants"},
		},
		{
			name:   "a missing heading fails",
			doc:    strings.Split(strings.TrimSuffix(missingHeading, "\n"), "\n"),
			states: fakeStatesConst,
			want:   []string{`docs/development/authentication.md has no "### Auth States (State Machine)" section`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeFakeTree(t, tc.doc, fakeStatesConst)
			writeFile(t, filepath.Join(root, "src", "authserver", "internal", "ceremony", "auth_context.go"), tc.states)
			if tc.claude != "" {
				writeFile(t, filepath.Join(root, "CLAUDE.md"), tc.claude)
			}

			assert.Equal(t, tc.want, checkAgentDocs(root))
		})
	}
}

// TestAgentDocs_AMissingAgentsFileFails is its own case because the finding carries the operating
// system's own "no such file" text and the path separator it uses, neither of which belongs in a
// table asserting exact strings.
func TestAgentDocs_AMissingAgentsFileFails(t *testing.T) {
	root := writeFakeTree(t, fakeAuthDocLines, fakeStatesConst)
	require.NoError(t, os.Remove(filepath.Join(root, "AGENTS.md")))

	findings := checkAgentDocs(root)

	require.Len(t, findings, 1, "the roster still checks out, so the missing file is the only finding")
	assert.True(t, strings.HasPrefix(findings[0], "reading AGENTS.md: "), findings[0])
}

const fakeAgentEntry = "# Fake instructions\n\n[Authentication](docs/development/authentication.md)\n"

func replaceAuthDocHeading(lines []string) []string {
	out := append([]string(nil), lines...)
	out[19] = "# Another guide section"
	return out
}

func writeFakeTree(t *testing.T, doc []string, states string) string {
	t.Helper()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "CLAUDE.md"), fakeAgentEntry)
	writeFile(t, filepath.Join(root, "AGENTS.md"), fakeAgentEntry)
	writeFile(t, filepath.Join(root, filepath.FromSlash(agentDocsAuthGuide)), strings.Join(doc, "\n"))
	writeFile(t, filepath.Join(root, "src", "authserver", "internal", "ceremony", "auth_context.go"), states)
	return root
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// deleteLine and insertLine use 1-based line numbers from the fixture. Each copies the shared slice.
func deleteLine(lines []string, n int) []string {
	out := append([]string(nil), lines[:n-1]...)
	return append(out, lines[n:]...)
}

func insertLine(lines []string, n int, line string) []string {
	out := append([]string(nil), lines[:n-1]...)
	out = append(out, line)
	return append(out, lines[n-1:]...)
}

// Seam 2: exercise the reporting half as well as the finder. The real repository is clean, so a
// reporting loop that silently stopped emitting findings would otherwise pass the real tiers.
func TestAgentDocs_TheGuardFailsOnADivergedCopy(t *testing.T) {
	root := writeFakeTree(t, fakeAuthDocLines, fakeStatesConst)
	writeFile(t, filepath.Join(root, "CLAUDE.md"), "Read AGENTS.md")

	report := Run(func(r Reporter) { assertAgentDocs(r, root) })

	require.True(t, report.Failed(), "divergent entry points passed")
	assert.False(t, report.Stopped, "a divergent copy is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "CLAUDE.md must match AGENTS.md")
}

// TestAgentDocs_TheGuardFailsOnAStateMissingFromTheRoster is the second rule, and the reason the
// roster is read from the assigned-by table's first column rather than from anywhere the value
// appears: a state deleted from that table is still spelled twice in the route table below it.
func TestAgentDocs_TheGuardFailsOnAStateMissingFromTheRoster(t *testing.T) {
	shortened := deleteLine(fakeAuthDocLines, 11)
	root := writeFakeTree(t, shortened, fakeStatesConst)

	report := Run(func(r Reporter) { assertAgentDocs(r, root) })

	require.True(t, report.Failed(), "a state with no roster row passed the guard")
	assert.Contains(t, report.Text(), "level2_otp")
}

// TestAgentDocs_TheGuardFailsOnAStateDeclaredWithVar drives the var rule through the reporting half:
// a var finding is an Errorf like every other, so the rest of the check still reports.
func TestAgentDocs_TheGuardFailsOnAStateDeclaredWithVar(t *testing.T) {
	root := writeFakeTree(t, fakeAuthDocLines, fakeStatesVar)

	report := Run(func(r Reporter) { assertAgentDocs(r, root) })

	require.True(t, report.Failed(), "states declared with var passed the guard")
	assert.False(t, report.Stopped, "a var finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), varFinding("AuthStateLevel2OTP"))
}

// TestAgentDocs_TheGuardPassesCanonicalInstructions is the other direction, and it is what keeps the
// two cases above from passing for the wrong reason.
func TestAgentDocs_TheGuardPassesCanonicalInstructions(t *testing.T) {
	root := writeFakeTree(t, fakeAuthDocLines, fakeStatesConst)

	report := Run(func(r Reporter) { assertAgentDocs(r, root) })

	assert.False(t, report.Failed(), "valid instructions failed the guard: %s", report.Text())
}

// Named inputs must report their absence instead of silently reducing the check's coverage.
func TestAgentDocs_TheGuardReportsAnUnreadableDocument(t *testing.T) {
	root := writeFakeTree(t, fakeAuthDocLines, fakeStatesConst)
	require.NoError(t, os.Remove(filepath.Join(root, "AGENTS.md")))

	report := Run(func(r Reporter) { assertAgentDocs(r, root) })

	require.True(t, report.Failed(), "a missing AGENTS.md passed the guard")
	assert.Contains(t, report.Text(), "reading AGENTS.md")
}

// These boundaries prevent instructions growing past the part an agent receives. Multibyte text
// matters because the Codex limit is bytes, not characters; exact limits must still pass.
func TestAgentDocs_EntryBudgetsAndReferences(t *testing.T) {
	byteLimit := fakeAgentEntry + strings.Repeat(" ", agentDocsMaxBytes-len(fakeAgentEntry))
	lineLimit := fakeAgentEntry + strings.Repeat("line\n", agentDocsMaxLines-3)
	cases := []struct {
		name, entry, want string
	}{
		{"exact byte budget", byteLimit, ""},
		{"one byte over", byteLimit + "x", "AGENTS.md is 10241 bytes; limit is 10240 bytes"},
		{"multibyte over budget", fakeAgentEntry + strings.Repeat("é", agentDocsMaxBytes/2), "bytes; limit is 10240 bytes"},
		{"exact line budget", lineLimit, ""},
		{"one line over", lineLimit + "line\n", "AGENTS.md is 201 lines; limit is 200 lines"},
		{"empty entry", " \n", "AGENTS.md must not be empty"},
		{"missing reference", fakeAgentEntry + "[Missing](docs/missing.md)\n", `AGENTS.md reference "docs/missing.md"`},
		{"anchor in reference", strings.ReplaceAll(fakeAgentEntry, ".md)", ".md#auth-states-state-machine)"), ""},
		{"external and local anchors", fakeAgentEntry + "[RFC](https://rfc-editor.org/) [Here](#section)\n", ""},
		{"undiscoverable authentication guide", "# Instructions\n", "AGENTS.md must link to " + agentDocsAuthGuide},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeFakeTree(t, fakeAuthDocLines, fakeStatesConst)
			writeFile(t, filepath.Join(root, "AGENTS.md"), tc.entry)
			writeFile(t, filepath.Join(root, "CLAUDE.md"), tc.entry)
			findings := checkAgentDocs(root)
			report := Run(func(r Reporter) { assertAgentDocs(r, root) })
			if tc.want == "" {
				assert.Empty(t, findings)
				assert.False(t, report.Failed(), report.Text())
			} else {
				assert.Contains(t, strings.Join(findings, "\n"), tc.want)
				require.True(t, report.Failed(), "the reporting half missed the defect")
				assert.Contains(t, report.Text(), tc.want)
			}
		})
	}
}

func TestAgentDocs_MissingInputsReportInsteadOfPassingVacuously(t *testing.T) {
	for _, path := range []string{"CLAUDE.md", agentDocsAuthGuide, "src/authserver/internal/ceremony/auth_context.go"} {
		t.Run(path, func(t *testing.T) {
			root := writeFakeTree(t, fakeAuthDocLines, fakeStatesConst)
			require.NoError(t, os.Remove(filepath.Join(root, filepath.FromSlash(path))))
			report := Run(func(r Reporter) { assertAgentDocs(r, root) })
			require.True(t, report.Failed(), "an unreadable input passed")
			assert.Contains(t, report.Text(), "reading "+path)
		})
	}
}
