package testutil

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// AssertAgentDocs holds CLAUDE.md and AGENTS.md to two rules: the two files are
// byte-identical, and the roster of states in CLAUDE.md's "Auth States (State
// Machine)" section is exactly the set of AuthState* string constants declared
// in src/core/oauth/auth_context.go.
//
// Both rules exist because the two files are prose about code, and prose about
// code is the one thing in this repository nothing else checks. The ceremony's
// state list sat in CLAUDE.md describing a machine that had moved underneath it:
// it named ten states in a numbered order the handlers do not follow, omitted
// level1_existing_session entirely, and opened by saying the context lives in a
// session cookie, which stopped being true when #266 moved the store
// server-side. Every one of those was true when written (#252).
//
// The files are co-maintained copies for two different tools, which is the
// second rule's whole reason: an edit that lands in one and not the other leaves
// two agents reading different descriptions of the same handlers, and a plain
// diff is the only thing that ever notices. The drift this guard was written
// against was four lines about test fixtures present in CLAUDE.md and missing
// from AGENTS.md.
//
// The roster rule checks membership, not transitions. Reconstructing the state
// graph from the handlers would be a second implementation of the thing being
// documented, and it would go red on every comment edit; the roster is the part
// that goes stale silently, when a state is added or, as #248 is about to do,
// deleted.
//
// Scope is the source root's parent, because SourceRoot returns the directory
// holding the four go.mod files and the two agent files live one level above it.
// Each module's unit tier calls this, so the guard fires whichever tier is run.
func AssertAgentDocs(t *testing.T) {
	t.Helper()

	findings := checkAgentDocs(filepath.Dir(SourceRoot(t)))
	for _, f := range findings {
		t.Error(f)
	}
}

// agentDocsHeading is the section of CLAUDE.md the roster rule reads. The
// section runs to the next heading at the same level or above.
const agentDocsHeading = "### Auth States (State Machine)"

// agentDocsStateCell matches a first table cell that is exactly one backticked
// state value. It is deliberately narrower than "a backticked token anywhere in
// the row": the accepted-by table repeats most state values in its Accepts
// column, so a rule that accepted any occurrence in the section would still pass
// after a state's assigned-by row was deleted. The first column of the
// assigned-by table carries a state value or nothing, which is what makes it
// readable as a roster; route cells like `/auth/pwd` do not match.
var agentDocsStateCell = regexp.MustCompile("^`([a-z0-9_]+)`$")

// checkAgentDocs returns one finding per rule violation, ordered rule 1 then
// rule 2 and sorted within rule 2 so the message is stable. It returns strings
// rather than errors because every caller is an assertion: a stack captured here
// would point at this file rather than at the prose that is wrong.
func checkAgentDocs(root string) []string {
	var findings []string

	claude, claudeErr := os.ReadFile(filepath.Join(root, "CLAUDE.md"))
	if claudeErr != nil {
		findings = append(findings, fmt.Sprintf("reading CLAUDE.md: %v", claudeErr))
	}
	agents, agentsErr := os.ReadFile(filepath.Join(root, "AGENTS.md"))
	if agentsErr != nil {
		findings = append(findings, fmt.Sprintf("reading AGENTS.md: %v", agentsErr))
	}

	if claudeErr == nil && agentsErr == nil && string(claude) != string(agents) {
		findings = append(findings, firstDifference(string(claude), string(agents)))
	}

	declared, declErr := declaredAuthStates(filepath.Join(root, "src", "core", "oauth", "auth_context.go"))
	switch {
	case declErr != nil:
		findings = append(findings, fmt.Sprintf("reading src/core/oauth/auth_context.go: %v", declErr))
	case len(declared) == 0:
		// A parse that finds nothing would otherwise make every roster check
		// pass vacuously, which is the one direction a guard like this fails in
		// silently.
		findings = append(findings, "src/core/oauth/auth_context.go declares no AuthState* string constants")
	}

	if claudeErr != nil || declErr != nil || len(declared) == 0 {
		return findings
	}

	section, ok := agentDocsSection(string(claude))
	if !ok {
		findings = append(findings, fmt.Sprintf("CLAUDE.md has no %q section", agentDocsHeading))
		return findings
	}

	roster := rosterStates(section)

	var missing, unknown []string
	for state := range declared {
		if !roster[state] {
			missing = append(missing, state)
		}
	}
	for state := range roster {
		if !declared[state] {
			unknown = append(unknown, state)
		}
	}
	sort.Strings(missing)
	sort.Strings(unknown)

	for _, state := range missing {
		findings = append(findings, fmt.Sprintf(
			"state %q is declared in src/core/oauth/auth_context.go but has no row in the %q section of CLAUDE.md",
			state, agentDocsHeading))
	}
	for _, state := range unknown {
		findings = append(findings, fmt.Sprintf(
			"the %q section of CLAUDE.md has a row for state %q, which src/core/oauth/auth_context.go does not declare",
			agentDocsHeading, state))
	}

	return findings
}

// firstDifference names the line the two files start disagreeing at, because a
// whole-file diff in a test failure is unreadable and a bare "they differ" sends
// the reader to run the diff themselves.
func firstDifference(claude, agents string) string {
	claudeLines := strings.Split(claude, "\n")
	agentsLines := strings.Split(agents, "\n")

	for i := 0; i < len(claudeLines) || i < len(agentsLines); i++ {
		c, a := "<end of file>", "<end of file>"
		if i < len(claudeLines) {
			c = claudeLines[i]
		}
		if i < len(agentsLines) {
			a = agentsLines[i]
		}
		if c != a {
			return fmt.Sprintf("CLAUDE.md and AGENTS.md differ at line %d; they are co-maintained copies and must be identical\n\tCLAUDE.md: %s\n\tAGENTS.md: %s",
				i+1, c, a)
		}
	}
	// Unreachable while the caller compares the contents first, and cheaper to
	// state than to leave as a nil return somebody has to reason about.
	return "CLAUDE.md and AGENTS.md differ, but no differing line was found"
}

// declaredAuthStates returns the unquoted value of every AuthState* string
// declaration in the file. The declarations live under `var (` today; const is
// read the same way so that tightening them to constants is not a guard change.
//
// Parsing rather than grepping is the point: a regex over the source would
// equally match the name in a comment, in a test fixture, or in the handler that
// assigns it, and the roster has to be the declarations exactly.
func declaredAuthStates(path string) (map[string]bool, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}

	states := map[string]bool{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || (gen.Tok != token.VAR && gen.Tok != token.CONST) {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if !strings.HasPrefix(name.Name, "AuthState") || i >= len(value.Values) {
					continue
				}
				lit, ok := value.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				unquoted, err := strconv.Unquote(lit.Value)
				if err != nil {
					continue
				}
				states[unquoted] = true
			}
		}
	}
	return states, nil
}

// agentDocsSection returns the lines between the heading and the next heading at
// the same level or above, which is where the roster has to live.
func agentDocsSection(doc string) ([]string, bool) {
	lines := strings.Split(doc, "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimRight(line, " \t") == agentDocsHeading {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil, false
	}
	for i := start; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "### ") || strings.HasPrefix(lines[i], "## ") {
			return lines[start:i], true
		}
	}
	return lines[start:], true
}

// rosterStates reads the first cell of every table row in the section. The
// header and separator rows contribute nothing because their first cells are not
// backticked tokens, and a continuation row's empty first cell contributes
// nothing either.
func rosterStates(section []string) map[string]bool {
	states := map[string]bool{}
	for _, line := range section {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cells := strings.Split(trimmed, "|")
		if len(cells) < 2 {
			continue
		}
		if m := agentDocsStateCell.FindStringSubmatch(strings.TrimSpace(cells[1])); m != nil {
			states[m[1]] = true
		}
	}
	return states
}
