package testutil

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRequestPathContext_TheRule plants every shape the rule decides on in one fixture tree and
// pins the whole answer, refusals and admissions together, the way TestAuditLogContext_TheRule
// does. Each refusal is asserted by file, line and finding rather than by the count, so a case
// that started failing for another reason — a fixture that stopped parsing, a walk that stopped
// reaching it — shows up as the wrong line rather than as a green test (testing.md section 6).
func TestRequestPathContext_TheRule(t *testing.T) {
	tree := newFixtureTree(t)

	// ---- refused: a context carrying nothing, constructed in a request-path package -------------

	// Wherever it is constructed, and whatever it is handed to: the rule reads the construction
	// rather than an argument position, which is what separates it from AssertAuditLogContext.
	// The package-level var is the case slogPlainAdmitted answers the same way: a call outside
	// any function declaration has no name for the owners table to admit.
	tree.write("authserver/internal/data/commondb/caught.go", `package commondb

import (
	"context"
	"database/sql"
)

var atInit = context.Background()

type database interface {
	GetUserById(ctx context.Context, tx *sql.Tx, id int64) error
}

func background(d database) {
	_ = d.GetUserById(context.Background(), nil, 1)
}

func todo(d database) {
	_ = d.GetUserById(context.TODO(), nil, 1)
}

func notAnArgument() context.Context {
	ctx := (context.Background())
	return ctx
}
`)

	// The one rename that would carry the refused shape past a rule reading the literal text
	// "context.Background". Both constructors are planted under the alias, because a rule that
	// resolved the import for one and not the other would pass this file on the strength of the
	// half it did resolve. It sits on the core side of slogRequestPathDirs so that half of the
	// walk proves something too.
	tree.write("adminconsole/internal/apiclient/aliased.go", `package apiclient

import (
	stdctx "context"
)

func aliasedBackground() stdctx.Context {
	return stdctx.Background()
}

func aliasedTodo() stdctx.Context {
	return stdctx.TODO()
}
`)

	// ---- admitted: the request's context, however it is reached ---------------------------------

	// r.Context() and a ctx the enclosing function holds are the two shapes the migrated call
	// sites actually use, and neither resolves to an imported package's function.
	tree.write("adminconsole/internal/handlers/passed.go", `package handlers

import (
	"context"
	"net/http"
)

type api interface {
	GetUserById(ctx context.Context, id int64) error
}

func fromRequest(apiClient api, r *http.Request) {
	_ = apiClient.GetUserById(r.Context(), 1)
}

func fromContext(apiClient api, ctx context.Context) {
	_ = apiClient.GetUserById(ctx, 1)
}

func derived(apiClient api, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 0)
	defer cancel()
	_ = apiClient.GetUserById(ctx, 1)
}
`)

	// The owners table, in the file and under the name requestContextOwners lists. The same
	// function name in another file of the same package is refused, which is what "scope is the
	// file" buys: an admission cannot leak to a namesake.
	tree.write("core/sessionstore/server_side_store.go", `package sessionstore

import (
	"context"
	"net/http"
)

func requestContext(r *http.Request) context.Context {
	if r == nil {
		return context.Background()
	}
	return r.Context()
}
`)
	tree.write("core/sessionstore/namesake.go", `package sessionstore

import (
	"context"
	"net/http"
)

func requestContext2(r *http.Request) context.Context {
	if r == nil {
		return context.Background()
	}
	return r.Context()
}
`)

	// The resolver rather than a rule of its own: a package named for something other than its
	// directory, imported unaliased beside stdlib context. Go binds the package clause, so this
	// one binds "vendored" and the context below is still stdlib. Reading the last element of the
	// path instead would record this path under "context" and walk the refused call past.
	tree.write("core/vendored/context/pkg.go", `package vendored

func Helper() string { return "x" }
`)
	tree.write("authserver/internal/handlers/path_base_collision.go", `package handlers

import (
	"context"

	"github.com/leodip/goiabada/core/vendored/context"
)

func collide() context.Context {
	_ = vendored.Helper()
	return context.Background()
}
`)

	// Outside slogRequestPathDirs: a worker and a startup pass have no request above them, so a
	// Background context is the honest answer there and the rule says nothing about it. The scope
	// filter drops them before they are parsed, which is why they are not among the walked files
	// counted below.
	tree.write("authserver/internal/workers/background_worker.go", `package workers

import "context"

func run() context.Context {
	return context.Background()
}
`)
	tree.write("authserver/internal/data/migrator/migrator.go", `package migrator

import "context"

func migrate() context.Context {
	return context.TODO()
}
`)

	// The same refused shape in a test file inside a listed directory, which slogExemptByPath
	// skips for all three guards over this list: a test drives the code under it with whatever
	// context the case needs.
	tree.write("authserver/internal/data/commondb/exempt_test.go", `package commondb

import "context"

func inTest() context.Context {
	return context.Background()
}
`)

	// And in a mocks directory, generated scaffolding that starts nothing.
	tree.write("adminconsole/internal/handlers/mocks/exempt.go", `package mocks

import "context"

func inMock() context.Context {
	return context.Background()
}
`)

	violations, files, err := findRequestPathContextViolations(tree.root, nil)
	require.NoError(t, err)
	assert.Equal(t, 6, files, "every non-exempt fixture in a request-path package is walked")

	got := make([]string, 0, len(violations))
	for _, v := range violations {
		got = append(got, found(v))
	}
	want := []string{
		"adminconsole/internal/apiclient/aliased.go:8 context.Background() in a request-path package",
		"adminconsole/internal/apiclient/aliased.go:12 context.TODO() in a request-path package",
		"authserver/internal/data/commondb/caught.go:8 context.Background() in a request-path package",
		"authserver/internal/data/commondb/caught.go:15 context.Background() in a request-path package",
		"authserver/internal/data/commondb/caught.go:19 context.TODO() in a request-path package",
		"authserver/internal/data/commondb/caught.go:23 context.Background() in a request-path package",
		"authserver/internal/handlers/path_base_collision.go:11 context.Background() in a request-path package",
		"core/sessionstore/namesake.go:10 context.Background() in a request-path package",
	}
	sort.Strings(want)
	sort.Strings(got)
	assert.Equal(t, want, got)
}

// TestRequestPathContext_TheTreeItself is the guard over the real tree, and it is what the two
// server-side callers run. Here as well as there so a change to this package is caught by its own
// tier rather than only by the two servers'.
func TestRequestPathContext_TheTreeItself(t *testing.T) {
	AssertRequestPathContext(t)
}

// Seam 2: the reporting half. The case above asserts on what findRequestPathContextViolations
// returned, and the real callers walk a tree that is clean, so the lines that turn a violation
// into a failure would otherwise be reached by three tiers and observed failing by none.

// TestRequestPathContext_TheGuardFailsOnABackgroundContext drives the reporting half. The message
// is the whole remedy: what is wrong with a Background context here is not visible at the call
// site — it compiles, it runs, and the work it starts simply cannot be cancelled by the request
// that asked for it.
func TestRequestPathContext_TheGuardFailsOnABackgroundContext(t *testing.T) {
	tree := newFixtureTree(t)
	tree.write("authserver/internal/data/commondb/db.go", `package commondb

import "context"

func query() context.Context {
	return context.Background()
}
`)

	report := RunGuard(func(r Reporter) { assertRequestPathContext(r, tree.root, nil) })

	require.True(t, report.Failed(), "a Background context in a request-path package passed the guard")
	assert.False(t, report.Stopped, "a violation is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/data/commondb/db.go:6")
	assert.Contains(t, report.Text(), "context.Background()")
	assert.Contains(t, report.Text(), "1 request context violation(s)")
	assert.Contains(t, report.Text(), "r.Context()")
	assert.Contains(t, report.Text(), "requestContextOwners")
	assert.Contains(t, report.Text(), "#386")
}

// TestRequestPathContext_TheGuardPassesARequestContext is the other direction, over the shape the
// rule exists to admit.
func TestRequestPathContext_TheGuardPassesARequestContext(t *testing.T) {
	tree := newFixtureTree(t)
	tree.write("adminconsole/internal/handlers/handler.go", `package handlers

import (
	"context"
	"net/http"
)

type api interface {
	GetUserById(ctx context.Context, id int64) error
}

func handle(apiClient api, r *http.Request) {
	_ = apiClient.GetUserById(r.Context(), 1)
}
`)

	report := RunGuard(func(r Reporter) { assertRequestPathContext(r, tree.root, nil) })

	assert.False(t, report.Failed(), "a request context failed the guard: %s", report.Text())
}

// TestRequestPathContext_TheGuardIsFatalOnAnEmptyWalk pins the seam. This guard's scope makes it
// as likely as AssertAuditLogContext's to trip: the walk counts only files in a request-path
// package, so a directory dropping off slogRequestPathDirs empties it without emptying the tree.
func TestRequestPathContext_TheGuardIsFatalOnAnEmptyWalk(t *testing.T) {
	tree := newFixtureTree(t)
	tree.write("core/elsewhere/ok.go", "package elsewhere\n")

	report := RunGuard(func(r Reporter) { assertRequestPathContext(r, tree.root, nil) })

	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked no non-test Go files in a request-path package under")
}
