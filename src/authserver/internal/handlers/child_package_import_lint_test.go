package handlers

// The one place the two child handler packages are held to "a sibling does not import the parent".
//
// apihandlers and accounthandlers sit under this directory and serve their own routes. Neither
// needs anything this package declares, and yet 39 of their production files imported it, for one
// reason: the collaborator ports lived here. handlers.AuditLogger, handlers.HttpHelper and five
// more were declared in the parent because the parent happened to be the first package that needed
// them, so every child handler compiled against a transport package sitting above it and took a
// port eight methods wide to call one of them.
//
// #387 gave each child its own interfaces.go, naming only what that package calls, and the import
// went with them. That is acceptance bullet 5 of the issue, and an import list is the only honest
// way to state it: a census run once proves the edge was gone once, and the next handler written
// from an older one puts it straight back.
//
// The rule covers test files as well as production ones. The bullet says production; there is no
// test in either package naming the path either, and a test that did would rebuild the edge in
// that package's own test binary while the production census still read zero.
//
// It reads and parses files and nothing else: no database, no git, no network.

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parentHandlersPath is the import path no file under childHandlerDirs may name.
const parentHandlersPath = "github.com/leodip/goiabada/authserver/internal/handlers"

// childHandlerDirs are the packages the rule covers, relative to the source root, forward slashes.
//
// Each directory only, not its subtree: neither has a subpackage today, and a walk that descended
// would silently start covering one the day somebody adds it, under a rule written for these two.
var childHandlerDirs = []string{
	"authserver/internal/handlers/apihandlers",
	"authserver/internal/handlers/accounthandlers",
}

// parentImport is one import of the parent package from a file that may not name it.
type parentImport struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
}

// findParentImports parses every Go file directly under each of dirs and reports each import of
// refused. It returns the number of files it parsed, so the reporting half can tell "nothing to
// report" from "nothing was read".
//
// Imports are parsed rather than matched as text, which is what makes the rule say what it means.
// The child packages' own paths have the refused one as a prefix, so a substring match would call
// every file in apihandlers an offence; an alias binds a different name to the same path and must
// still count, which spelling-based matching on "handlers." misses -- handler_api_permissions.go
// imported it as srvhandlers and no census keyed on the selector ever saw it; and
// api_error_code_lint_test.go names "authserver/internal/handlers" twice as a directory scope for
// the error-code lint, in a string that is not an import and must not count.
func findParentImports(root string, dirs []string, refused string) ([]parentImport, int, error) {
	var found []parentImport
	files := 0

	for _, dir := range dirs {
		start := filepath.Join(root, filepath.FromSlash(dir))

		entries, err := os.ReadDir(start)
		if err != nil {
			return nil, 0, err
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			path := filepath.Join(start, entry.Name())

			fset := token.NewFileSet()
			file, pErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if pErr != nil {
				// A file that does not parse is a compile error the build tier owns, and
				// reporting it here would send the reader to the wrong place.
				continue
			}
			files++

			rel := dir + "/" + entry.Name()
			for _, spec := range file.Imports {
				if spec.Path == nil {
					continue
				}
				imported, uErr := strconv.Unquote(spec.Path.Value)
				if uErr != nil {
					continue
				}
				if imported != refused {
					continue
				}
				found = append(found, parentImport{
					file: rel,
					line: fset.Position(spec.Pos()).Line,
				})
			}
		}
	}

	return found, files, nil
}

// TestHandlers_ChildPackagesDoNotImportTheParent holds the real tree to the rule. It is acceptance
// bullet 5 of #387 in its checkable form.
func TestHandlers_ChildPackagesDoNotImportTheParent(t *testing.T) {
	assertNoParentImport(t, testutil.SourceRoot(t), childHandlerDirs, parentHandlersPath)
}

// assertNoParentImport is the reporting half, taking the root and the scope as parameters and
// failing through a testutil.Reporter so a rule test can drive it against a fixture tree. Without
// that seam these lines are reached only by the call above, which walks a tree that passes.
func assertNoParentImport(r testutil.Reporter, root string, dirs []string, refused string) {
	r.Helper()

	found, files, err := findParentImports(root, dirs, refused)
	if err != nil {
		r.Fatalf("reading the child handler packages under %s: %v", root, err)
	}
	// Two directories that somehow held no Go files would read nothing and otherwise pass,
	// which is the one way a guard like this fails silently in the direction that matters.
	if files == 0 {
		r.Fatalf("read no Go files under %s", strings.Join(dirs, ", "))
	}

	if len(found) == 0 {
		return
	}
	lines := make([]string, 0, len(found))
	for _, f := range found {
		lines = append(lines, f.file+":"+strconv.Itoa(f.line))
	}

	r.Errorf("%d file(s) under the child handler packages import %s:\n\t%s\n\n"+
		"A sibling handler package takes its collaborators as ports it declares itself, in its own "+
		"interfaces.go, naming only the methods it calls (#386, #387). Importing the parent brings "+
		"back the edge #387 removed and, with it, a port declared for somebody else's call sites: "+
		"apihandlers calls one of HttpHelper's eight methods and accounthandlers three. Add the "+
		"method to that package's own port instead.",
		len(found), refused, strings.Join(lines, "\n\t"))
}

// TestHandlers_ChildImportGuard_ReadsImportsAndNotText is the synthetic half: a temp tree holding
// each shape the real tree contains, so a checker that has quietly stopped matching anything is
// caught here rather than trusted.
func TestHandlers_ChildImportGuard_ReadsImportsAndNotText(t *testing.T) {
	root := t.TempDir()

	// Accepted: a child package's own path, which has the refused one as a prefix. A substring
	// match would report every file in both packages.
	writeChildImportFixture(t, root, childHandlerDirs[0]+"/handler_api_users_crud.go", `package apihandlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers/thing"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
)

var _ = http.MethodGet
var _ = thing.Name
var _ = otpcredential.Remove
`)
	// Accepted: the refused path spelled in a string that is not an import, which is exactly what
	// api_error_code_lint_test.go does twice as a directory scope for the error-code lint.
	writeChildImportFixture(t, root, childHandlerDirs[0]+"/api_error_code_lint_test.go", `package apihandlers

import "testing"

var fixtureDirs = []string{"authserver/internal/handlers"}

func TestScope(t *testing.T) { _ = fixtureDirs }
`)
	// Accepted: a locally declared port of the same shape, which is the whole point of the change.
	writeChildImportFixture(t, root, childHandlerDirs[1]+"/interfaces.go", `package accounthandlers

import "context"

type AuditLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}
`)
	// Accepted: the parent importing itself, and a package outside the scope importing the parent.
	// routes.go does the second and must go on doing it.
	writeChildImportFixture(t, root, "authserver/internal/handlers/handler_token.go", `package handlers

import "github.com/leodip/goiabada/authserver/internal/handlers"

var _ = handlers.HttpHelper(nil)
`)
	writeChildImportFixture(t, root, "authserver/internal/server/routes.go", `package server

import "github.com/leodip/goiabada/authserver/internal/handlers"

var _ = handlers.HandleTokenPost
`)
	// Accepted: a subdirectory of a covered package, which the rule deliberately does not descend
	// into.
	writeChildImportFixture(t, root, childHandlerDirs[0]+"/sub/thing.go", `package sub

import "github.com/leodip/goiabada/authserver/internal/handlers"

var _ = handlers.HttpHelper(nil)
`)

	// Rejected: the plain import, the aliased one that no selector-spelling census would see, and
	// a test file, which the rule covers too.
	writeChildImportFixture(t, root, childHandlerDirs[0]+"/handler_api_settings_email.go", `package apihandlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/handlers"
)

var _ = http.MethodPut
var _ = handlers.HttpHelper(nil)
`)
	writeChildImportFixture(t, root, childHandlerDirs[0]+"/handler_api_permissions.go", `package apihandlers

import (
	srvhandlers "github.com/leodip/goiabada/authserver/internal/handlers"
)

var _ = srvhandlers.AuditLogger(nil)
`)
	writeChildImportFixture(t, root, childHandlerDirs[1]+"/handler_account_register_test.go", `package accounthandlers

import (
	"testing"

	"github.com/leodip/goiabada/authserver/internal/handlers"
)

func TestRegister(t *testing.T) { _ = handlers.HttpHelper(nil) }
`)

	found, files, err := findParentImports(root, childHandlerDirs, parentHandlersPath)
	require.NoError(t, err)
	require.NotZero(t, files)

	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, f.file+":"+strconv.Itoa(f.line))
	}
	assert.ElementsMatch(t, []string{
		childHandlerDirs[0] + "/handler_api_settings_email.go:6",
		childHandlerDirs[0] + "/handler_api_permissions.go:4",
		childHandlerDirs[1] + "/handler_account_register_test.go:6",
	}, got, "the checker matched the wrong set")
}

// TestHandlers_ChildImportGuard_FailsOnTheEdge is the third half. The case above asserts on what
// findParentImports returned; the lines that turn a finding into a failure are reached only by
// TestHandlers_ChildPackagesDoNotImportTheParent, which walks a tree that passes.
func TestHandlers_ChildImportGuard_FailsOnTheEdge(t *testing.T) {
	root := t.TempDir()
	writeChildImportFixture(t, root, childHandlerDirs[0]+"/handler_api_users_crud.go", `package apihandlers

import "github.com/leodip/goiabada/authserver/internal/handlers"

var _ = handlers.AuditLogger(nil)
`)
	writeChildImportFixture(t, root, childHandlerDirs[1]+"/interfaces.go", "package accounthandlers\n")

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoParentImport(r, root, childHandlerDirs, parentHandlersPath)
	})

	require.True(t, report.Failed(), "a child package importing the parent passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), childHandlerDirs[0]+"/handler_api_users_crud.go:3")
	assert.Contains(t, report.Text(), parentHandlersPath)
	assert.Contains(t, report.Text(), "#387")
	// The failure says what to do instead, so the reader declares a port rather than deleting the
	// call that provoked this.
	assert.Contains(t, report.Text(), "interfaces.go")
}

// TestHandlers_ChildImportGuard_PassesACleanTree is the other direction, over the shape both
// packages have today.
func TestHandlers_ChildImportGuard_PassesACleanTree(t *testing.T) {
	root := t.TempDir()
	writeChildImportFixture(t, root, childHandlerDirs[0]+"/interfaces.go", `package apihandlers

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
	writeChildImportFixture(t, root, childHandlerDirs[1]+"/handler_account_activate.go", `package accounthandlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/emaillinks"
)

var _ = http.MethodGet
var _ = emaillinks.SaveLinkMarker
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoParentImport(r, root, childHandlerDirs, parentHandlersPath)
	})

	assert.False(t, report.Failed(), "a clean tree failed the guard: %s", report.Text())
}

// TestHandlers_ChildImportGuard_IsFatalOnAnEmptyRead pins the seam. The scope is two directories,
// so both packages emptying out takes the whole walk with it, and a guard that reported a clean
// pass on directories it never read would be the quiet pass every rule here is written to avoid.
func TestHandlers_ChildImportGuard_IsFatalOnAnEmptyRead(t *testing.T) {
	root := t.TempDir()
	writeChildImportFixture(t, root, childHandlerDirs[0]+"/notes.md", "the API handlers moved\n")
	writeChildImportFixture(t, root, childHandlerDirs[1]+"/notes.md", "the account handlers moved\n")

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoParentImport(r, root, childHandlerDirs, parentHandlersPath)
	})

	require.True(t, report.Stopped, "an empty read must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "read no Go files under")
	assert.Contains(t, report.Fatal, childHandlerDirs[0])
	assert.Contains(t, report.Fatal, childHandlerDirs[1])
}

// TestHandlers_ChildImportGuard_IsFatalWhenADirectoryIsGone is the other way the scope disappears,
// and it is answered as a read error rather than as an empty directory. The two are worth telling
// apart: a package holding no Go any more is a fact about the tree, and a directory that is not
// there at all is a scope constant nobody updated.
func TestHandlers_ChildImportGuard_IsFatalWhenADirectoryIsGone(t *testing.T) {
	root := t.TempDir()
	writeChildImportFixture(t, root, childHandlerDirs[0]+"/interfaces.go", "package apihandlers\n")

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoParentImport(r, root, childHandlerDirs, parentHandlersPath)
	})

	require.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "reading the child handler packages")
	assert.NotContains(t, report.Fatal, "read no Go files")
}

// writeChildImportFixture writes one file into a fixture tree, creating its directories.
func writeChildImportFixture(t *testing.T, root, rel, src string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
}
