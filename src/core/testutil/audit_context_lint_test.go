package testutil

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditLogContext_TheRule plants every shape the rule decides on in one fixture tree and
// pins the whole answer, refusals and admissions together, the way TestSlogConvention_TheRuleTable
// does. Each refusal is asserted by file, line and finding rather than by the count, so a case
// that started failing for another reason — a fixture that stopped parsing, a walk that stopped
// reaching it — shows up as the wrong line rather than as a green test (testing.md section 6).
func TestAuditLogContext_TheRule(t *testing.T) {
	tree := newFixtureTree(t)

	// ---- refused: a context carrying nothing, in a request-path package --------------------------

	tree.write("authserver/internal/handlers/caught.go", `package handlers

import (
	"context"
	"net/http"
)

type logger interface {
	Log(ctx context.Context, event string, details map[string]interface{})
}

func background(auditLogger logger) {
	auditLogger.Log(context.Background(), "user_login", nil)
}

func todo(auditLogger logger) {
	auditLogger.Log(context.TODO(), "user_login", nil)
}

func parenthesised(auditLogger logger, r *http.Request) {
	(auditLogger).Log((context.Background()), "user_login", nil)
}
`)

	// The one rename that would carry the refused shape past a rule reading the literal text
	// "context.Background". Both constructors are planted under the alias, because a rule that
	// resolved the import for one and not the other would pass this file on the strength of the
	// half it did resolve.
	tree.write("core/auditlog/aliased.go", `package auditlog

import (
	stdctx "context"
)

type logger interface {
	Log(ctx stdctx.Context, event string, details map[string]interface{})
}

func aliasedBackground(auditLogger logger) {
	auditLogger.Log(stdctx.Background(), "user_login", nil)
}

func aliasedTodo(auditLogger logger) {
	auditLogger.Log(stdctx.TODO(), "user_login", nil)
}
`)

	// ---- admitted: the request's context, however it is reached ---------------------------------

	// r.Context() and a ctx the enclosing function holds are the two shapes the 126 call sites
	// actually use, and neither resolves to an imported package's function. context.Background()
	// passed to something that is not .Log is not this rule's business: only the first argument of
	// a .Log call is read, so the same expression in a second position falls through.
	tree.write("authserver/internal/handlers/passed.go", `package handlers

import (
	"context"
	"net/http"
)

type logger interface {
	Log(ctx context.Context, event string, details map[string]interface{})
}

func fromRequest(auditLogger logger, r *http.Request) {
	auditLogger.Log(r.Context(), "user_login", nil)
}

func fromContext(auditLogger logger, ctx context.Context) {
	auditLogger.Log(ctx, "user_login", nil)
}

func notFirst(auditLogger logger, ctx context.Context, other func(string, context.Context)) {
	auditLogger.Log(ctx, "user_login", nil)
	other("user_login", context.Background())
}

func notLog(ctx context.Context, other interface{ Warn(context.Context) }) {
	other.Warn(context.Background())
}
`)

	// Outside slogRequestPathDirs: a startup pass has no request, so a Background context is the
	// honest answer there and the rule says nothing about it. The scope filter drops it before it
	// is parsed, which is why it is not among the walked files counted below.
	tree.write("core/config/startup.go", `package config

import "context"

type logger interface {
	Log(ctx context.Context, event string, details map[string]interface{})
}

func load(auditLogger logger) {
	auditLogger.Log(context.Background(), "configuration_loaded", nil)
}
`)

	// The same refused shape in a test file inside a listed directory, which slogExemptByPath
	// skips for both guards: a test drives the logger with whatever context the case needs.
	tree.write("authserver/internal/handlers/exempt_test.go", `package handlers

import "context"

type testLogger interface {
	Log(ctx context.Context, event string, details map[string]interface{})
}

func inTest(auditLogger testLogger) {
	auditLogger.Log(context.Background(), "user_login", nil)
}
`)

	// And in a mocks directory, generated scaffolding that raises nothing.
	tree.write("core/middleware/mocks/exempt.go", `package mocks

import "context"

type logger interface {
	Log(ctx context.Context, event string, details map[string]interface{})
}

func inMock(auditLogger logger) {
	auditLogger.Log(context.Background(), "user_login", nil)
}
`)

	violations, files, err := findAuditLogContextViolations(tree.root, nil)
	require.NoError(t, err)
	assert.Equal(t, 3, files, "every non-exempt fixture in a request-path package is walked")

	got := make([]string, 0, len(violations))
	for _, v := range violations {
		got = append(got, found(v))
	}
	want := []string{
		"authserver/internal/handlers/caught.go:13 context.Background() passed to .Log in a request-path package",
		"authserver/internal/handlers/caught.go:17 context.TODO() passed to .Log in a request-path package",
		"authserver/internal/handlers/caught.go:21 context.Background() passed to .Log in a request-path package",
		"core/auditlog/aliased.go:12 context.Background() passed to .Log in a request-path package",
		"core/auditlog/aliased.go:16 context.TODO() passed to .Log in a request-path package",
	}
	sort.Strings(want)
	sort.Strings(got)
	assert.Equal(t, want, got)
}

// TestAuditLogContext_TheTreeItself is the guard over the real tree, and it is what the three
// server-side callers run. Here as well as there so a change to this package is caught by its own
// tier rather than only by the two servers'.
func TestAuditLogContext_TheTreeItself(t *testing.T) {
	AssertAuditLogContext(t)
}
