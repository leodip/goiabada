package guard

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

// AssertAgentDocs keeps the instruction entry points small and consistent: AGENTS.md is the
// canonical guide, CLAUDE.md is its checked copy, and root links reach existing reference files. The
// 10 KiB budget leaves room below Codex's default 32 KiB project-instruction cap; the old 111 KiB
// file was cut off before its test commands. The line budget also discourages dense root prose.
//
// The authentication guide's state roster is exactly the AuthState* string constants declared in
// auth_context.go. States declared with var are findings, since reassignment could move a gate
// underneath its callers (#436). The roster once omitted level1_existing_session and described a
// machine that had changed while tests stayed green (#252). Check membership, not transitions:
// reconstructing the state graph here would be a second implementation of the ceremony.
//
// A copy loads when Claude starts in a module without external-import approval; a symlink would
// require extra Git setup on Windows. Authors edit AGENTS.md and copy it, not two separate guides.
//
// Scope is the source root's parent. The core and both server unit tiers call this guard.
func AssertAgentDocs(t *testing.T) {
	t.Helper()

	assertAgentDocs(t, filepath.Dir(SourceRoot(t)))
}

// assertAgentDocs is the reporting half, taking the repository root as a parameter and failing
// through a Reporter so a rule test can drive it against a fixture tree. See Reporter in guard.go.
func assertAgentDocs(r Reporter, repoRoot string) {
	r.Helper()

	for _, f := range checkAgentDocs(repoRoot) {
		r.Errorf("%s", f)
	}
}

const (
	agentDocsAuthGuide = "docs/development/authentication.md"
	agentDocsHeading   = "### Auth States (State Machine)"
	agentDocsMaxBytes  = 10 * 1024
	agentDocsMaxLines  = 200
)

// Root references are ordinary Markdown links, so they can be checked without loading the linked
// guides into every agent session. Anchors are stripped for the file-existence check.
var agentDocsLink = regexp.MustCompile(`\]\(([^)\s]+)\)`)

// agentDocsStateCell matches a first table cell that is exactly one backticked
// state value. It is deliberately narrower than "a backticked token anywhere in
// the row": the accepted-by table repeats most state values in its Accepts
// column, so a rule that accepted any occurrence in the section would still pass
// after a state's assigned-by row was deleted. The first column of the
// assigned-by table carries a state value or nothing, which is what makes it
// readable as a roster; route cells like `/auth/pwd` do not match.
var agentDocsStateCell = regexp.MustCompile("^`([a-z0-9_]+)`$")

// checkAgentDocs returns findings for the entry points, references and roster, with roster
// differences sorted so the message is stable. It returns strings
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
		findings = append(findings, "CLAUDE.md must match AGENTS.md; run cp AGENTS.md CLAUDE.md from the repository root")
	}
	if agentsErr == nil {
		findings = append(findings, checkAgentEntry(root, agents)...)
	}
	authGuide, authGuideErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(agentDocsAuthGuide)))
	if authGuideErr != nil {
		findings = append(findings, fmt.Sprintf("reading %s: %v", agentDocsAuthGuide, authGuideErr))
	}

	declared, variables, declErr := declaredAuthStates(filepath.Join(root, "src", "authserver", "internal", "ceremony", "auth_context.go"))
	for _, name := range variables {
		findings = append(findings, fmt.Sprintf(
			"src/authserver/internal/ceremony/auth_context.go declares %s with var; the ceremony's states must be constants, declared in its const block",
			name))
	}
	switch {
	case declErr != nil:
		findings = append(findings, fmt.Sprintf("reading src/authserver/internal/ceremony/auth_context.go: %v", declErr))
	case len(declared) == 0:
		// A parse that finds nothing would otherwise make every roster check
		// pass vacuously, which is the one direction a guard like this fails in
		// silently.
		findings = append(findings, "src/authserver/internal/ceremony/auth_context.go declares no AuthState* string constants")
	}

	if authGuideErr != nil || declErr != nil || len(declared) == 0 {
		return findings
	}

	section, ok := agentDocsSection(string(authGuide))
	if !ok {
		findings = append(findings, fmt.Sprintf("%s has no %q section", agentDocsAuthGuide, agentDocsHeading))
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
			"state %q is declared in src/authserver/internal/ceremony/auth_context.go but has no row in the %q section of %s",
			state, agentDocsHeading, agentDocsAuthGuide))
	}
	for _, state := range unknown {
		findings = append(findings, fmt.Sprintf(
			"the %q section of %s has a row for state %q, which src/authserver/internal/ceremony/auth_context.go does not declare",
			agentDocsHeading, agentDocsAuthGuide, state))
	}

	return findings
}

// checkAgentEntry checks the material every session must receive, without following imports or
// recursively reading reference guides. A missing root or guide is reported by checkAgentDocs.
func checkAgentEntry(root string, agents []byte) []string {
	var findings []string
	if strings.TrimSpace(string(agents)) == "" {
		findings = append(findings, "AGENTS.md must not be empty")
	}
	if len(agents) > agentDocsMaxBytes {
		findings = append(findings, fmt.Sprintf("AGENTS.md is %d bytes; limit is %d bytes; move detail to a development guide", len(agents), agentDocsMaxBytes))
	}
	lines := strings.Count(strings.TrimSuffix(string(agents), "\n"), "\n") + 1
	if lines > agentDocsMaxLines {
		findings = append(findings, fmt.Sprintf("AGENTS.md is %d lines; limit is %d lines; move detail to a development guide", lines, agentDocsMaxLines))
	}
	linkedAuthGuide := false
	seen := map[string]bool{}
	for _, match := range agentDocsLink.FindAllStringSubmatch(string(agents), -1) {
		target, _, _ := strings.Cut(match[1], "#")
		if target == "" || strings.Contains(target, "://") || seen[target] {
			continue
		}
		seen[target] = true
		if target == agentDocsAuthGuide {
			linkedAuthGuide = true
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(target))); err != nil {
			findings = append(findings, fmt.Sprintf("AGENTS.md reference %q: %v", target, err))
		}
	}
	if !linkedAuthGuide {
		findings = append(findings, "AGENTS.md must link to "+agentDocsAuthGuide)
	}
	return findings
}

// declaredAuthStates returns the unquoted value of every AuthState* string
// constant in the file, and, in declaration order, the name of every AuthState*
// identifier the file declares with var instead. A var contributes no state: the
// roster is read from constants only, and the caller reports each var as a
// finding. The value has to be a string literal, typed or untyped, so a
// conversion such as AuthState("x") is not read and trips the caller's
// no-constants finding if it is the only form left.
//
// Parsing rather than grepping is the point: a regex over the source would
// equally match the name in a comment, in a test fixture, or in the handler that
// assigns it, and the roster has to be the declarations exactly.
func declaredAuthStates(path string) (map[string]bool, []string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, nil, err
	}

	states := map[string]bool{}
	var variables []string
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
				if !strings.HasPrefix(name.Name, "AuthState") {
					continue
				}
				if gen.Tok == token.VAR {
					variables = append(variables, name.Name)
					continue
				}
				if i >= len(value.Values) {
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
	return states, variables, nil
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
		if strings.HasPrefix(lines[i], "### ") || strings.HasPrefix(lines[i], "## ") || strings.HasPrefix(lines[i], "# ") {
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
