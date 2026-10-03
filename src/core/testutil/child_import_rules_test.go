package testutil

// The rule table AssertNoParentImport enforces, over fixture trees written into a temp directory
// and walked through the same finder and reporting half the two real callers reach.
//
// The synthetic half exists because the real half cannot fail informatively: the auth server's
// children have imported nothing of their parent since #387, so the call over the real tree passes
// whether the rule still fires or has quietly stopped matching anything. The fixtures keep the
// auth server's paths because those are the shapes the rule was written against, and the guard
// itself names no application.

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureParent and fixtureChildren stand in for a caller's arguments.
const fixtureParent = "github.com/leodip/goiabada/authserver/internal/handlers"

var fixtureChildren = []string{
	"authserver/internal/handlers/apihandlers",
	"authserver/internal/handlers/accounthandlers",
}

// renderParentImports renders findings as "<file>:<line>" so a failure names what was missed or
// over-matched rather than printing a struct.
func renderParentImports(found []parentImport) []string {
	out := make([]string, 0, len(found))
	for _, f := range found {
		out = append(out, f.file+":"+strconv.Itoa(f.line))
	}
	return out
}

// TestNoParentImport_ReadsImportsAndNotText holds each shape the auth server's tree contains, so
// a finder that has quietly stopped matching anything is caught here rather than trusted.
func TestNoParentImport_ReadsImportsAndNotText(t *testing.T) {
	root := t.TempDir()

	// Accepted: a child package's own path, which has the refused one as a prefix. A substring
	// match would report every file in both packages.
	writeFixture(t, root, fixtureChildren[0]+"/handler_api_users_crud.go", `package apihandlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers/thing"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
)

var _ = http.MethodGet
var _ = thing.Name
var _ = otpcredential.Remove
`)
	// Accepted: the refused path spelled in a string that is not an import, which is what the auth
	// server's api_error_code_lint_test.go does as a directory scope for the error-code lint.
	writeFixture(t, root, fixtureChildren[0]+"/api_error_code_lint_test.go", `package apihandlers

import "testing"

var fixtureDirs = []string{"authserver/internal/handlers"}

func TestScope(t *testing.T) { _ = fixtureDirs }
`)
	// Accepted: a locally declared port of the same shape, which is the whole point of the rule.
	writeFixture(t, root, fixtureChildren[1]+"/interfaces.go", `package accounthandlers

import "context"

type AuditLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}
`)
	// Accepted: the parent importing itself, and a package outside the scope importing the parent.
	// routes.go does the second and must go on doing it.
	writeFixture(t, root, "authserver/internal/handlers/handler_token.go", `package handlers

import "github.com/leodip/goiabada/authserver/internal/handlers"

var _ = handlers.PageRenderer(nil)
`)
	writeFixture(t, root, "authserver/internal/server/routes.go", `package server

import "github.com/leodip/goiabada/authserver/internal/handlers"

var _ = handlers.HandleTokenPost
`)
	// Accepted: a subdirectory of a covered package, which the rule deliberately does not descend
	// into. The admin console's handlers/mocks is the case that matters: the parent's generated
	// double, which the children's tests use and are allowed to.
	writeFixture(t, root, fixtureChildren[0]+"/sub/thing.go", `package sub

import "github.com/leodip/goiabada/authserver/internal/handlers"

var _ = handlers.PageRenderer(nil)
`)

	// Rejected: the plain import, the aliased one that no selector-spelling census would see, and
	// a test file, which the rule covers too.
	writeFixture(t, root, fixtureChildren[0]+"/handler_api_settings_email.go", `package apihandlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/handlers"
)

var _ = http.MethodPut
var _ = handlers.PageRenderer(nil)
`)
	writeFixture(t, root, fixtureChildren[0]+"/handler_api_permissions.go", `package apihandlers

import (
	srvhandlers "github.com/leodip/goiabada/authserver/internal/handlers"
)

var _ = srvhandlers.AuditLogger(nil)
`)
	writeFixture(t, root, fixtureChildren[1]+"/handler_account_register_test.go", `package accounthandlers

import (
	"testing"

	"github.com/leodip/goiabada/authserver/internal/handlers"
)

func TestRegister(t *testing.T) { _ = handlers.PageRenderer(nil) }
`)

	found, files, err := findParentImports(root, fixtureParent, fixtureChildren)
	require.NoError(t, err)
	assert.Equal(t, 6, files, "the finder parsed the wrong number of files")
	assert.ElementsMatch(t, []string{
		fixtureChildren[0] + "/handler_api_settings_email.go:6",
		fixtureChildren[0] + "/handler_api_permissions.go:4",
		fixtureChildren[1] + "/handler_account_register_test.go:6",
	}, renderParentImports(found), "the finder matched the wrong set")
}

// TestNoParentImport_FailsOnTheEdge drives the reporting half: the case above asserts on what the
// finder returned, and the lines that turn a finding into a failure are reached only here.
func TestNoParentImport_FailsOnTheEdge(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, fixtureChildren[0]+"/handler_api_users_crud.go", `package apihandlers

import "github.com/leodip/goiabada/authserver/internal/handlers"

var _ = handlers.AuditLogger(nil)
`)
	writeFixture(t, root, fixtureChildren[1]+"/interfaces.go", "package accounthandlers\n")

	report := RunGuard(func(r Reporter) {
		assertNoParentImport(r, root, fixtureParent, fixtureChildren)
	})

	require.True(t, report.Failed(), "a child package importing the parent passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), fixtureChildren[0]+"/handler_api_users_crud.go:3")
	assert.Contains(t, report.Text(), fixtureParent)
	assert.Contains(t, report.Text(), "#387")
	// The failure says what to do instead, so the reader declares a port rather than deleting the
	// call that provoked this.
	assert.Contains(t, report.Text(), "interfaces.go")
}

// TestNoParentImport_PassesACleanTree is the other direction, over the shape both of the auth
// server's children have today.
func TestNoParentImport_PassesACleanTree(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, fixtureChildren[0]+"/interfaces.go", `package apihandlers

import (
	"context"

	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
)

type AuditLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}

type EmailSender interface {
	SendEmail(ctx context.Context, input *emaildelivery.SendEmailInput) error
}
`)
	writeFixture(t, root, fixtureChildren[1]+"/handler_account_activate.go", `package accounthandlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/emaillinks"
)

var _ = http.MethodGet
var _ = emaillinks.SaveLinkMarker
`)

	report := RunGuard(func(r Reporter) {
		assertNoParentImport(r, root, fixtureParent, fixtureChildren)
	})

	assert.False(t, report.Failed(), "a clean tree failed the guard: %s", report.Text())
}

// TestNoParentImport_IsFatalOnAnEmptyRead pins the walk that reached nothing. Every child emptying
// out takes the whole walk with it, and a guard that reported a clean pass on directories it never
// read would be the quiet pass every rule here is written to avoid.
func TestNoParentImport_IsFatalOnAnEmptyRead(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, fixtureChildren[0]+"/notes.md", "the API handlers moved\n")
	writeFixture(t, root, fixtureChildren[1]+"/notes.md", "the account handlers moved\n")

	report := RunGuard(func(r Reporter) {
		assertNoParentImport(r, root, fixtureParent, fixtureChildren)
	})

	require.True(t, report.Stopped, "an empty read must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "read no Go files under")
	assert.Contains(t, report.Fatal, fixtureChildren[0])
	assert.Contains(t, report.Fatal, fixtureChildren[1])
}

// TestNoParentImport_IsFatalOnNoChildren pins the call that names no child at all, which reads
// nothing and would otherwise pass.
func TestNoParentImport_IsFatalOnNoChildren(t *testing.T) {
	report := RunGuard(func(r Reporter) {
		assertNoParentImport(r, t.TempDir(), fixtureParent, nil)
	})

	require.True(t, report.Stopped, "a call naming no child must be fatal rather than a pass")
}

// TestNoParentImport_IsFatalWhenADirectoryIsGone is the other way the scope disappears, and it is
// answered as a read error rather than as an empty directory. The two are worth telling apart: a
// package holding no Go any more is a fact about the tree, and a directory that is not there at all
// is a caller's argument nobody updated.
func TestNoParentImport_IsFatalWhenADirectoryIsGone(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, fixtureChildren[0]+"/interfaces.go", "package apihandlers\n")

	report := RunGuard(func(r Reporter) {
		assertNoParentImport(r, root, fixtureParent, fixtureChildren)
	})

	require.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "reading the child packages")
	assert.Contains(t, report.Fatal, fixtureChildren[1])
	assert.NotContains(t, report.Fatal, "read no Go files")
}
