package testutil

// Seam 2: the rule table AssertNoLegacyErrors enforces, over fixture source text written into a
// temp tree and walked through the same function the real caller uses.
//
// The synthetic half exists because the real half cannot fail informatively. A guard that has
// quietly stopped matching anything passes on a clean tree exactly as it passes on a correct one,
// and by stage 5 the tree is clean by construction, so the only thing left holding the rule would
// be a test that never proves it can fire (#279).

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoLegacyErrors_TheRuleTable writes one fixture per row of the rule and asserts the exact
// set of findings, with lines. Every "caught" fixture is a way the tree used to construct an
// error; every "passed" fixture is a shape that must survive the sweep untouched.
func TestNoLegacyErrors_TheRuleTable(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	}

	// ---- caught ------------------------------------------------------------------------------

	// The import itself is the finding, whatever it is called at the call site.
	write("core/caught/plain_import.go", `package caught

import "github.com/pkg/errors"

func plainImport() error { return errors.New("x") }
`)
	write("core/caught/aliased_import.go", `package caught

import pkgerrors "github.com/pkg/errors"

func aliasedImport(err error) error { return pkgerrors.WithStack(err) }
`)

	// The stackless stdlib constructors, in a function body.
	write("core/caught/stdlib_new.go", `package caught

import "errors"

func stdlibNew() error { return errors.New("x") }
`)
	write("core/caught/fmt_errorf.go", `package caught

import "fmt"

func fmtErrorf() error { return fmt.Errorf("x %d", 1) }
`)
	write("core/caught/stdlib_join.go", `package caught

import "errors"

func stdlibJoin(a, b error) error { return errors.Join(a, b) }
`)

	// Resolution is by import path: this is core/data/mssqldb/db.go's shape, and a check matching
	// the literal text "errors." walks straight past it.
	write("core/caught/goerrors_alias.go", `package caught

import goerrors "errors"

func aliased() error { return goerrors.New("x") }
`)

	// The redundant outer WithStack, under the package's own name and under another.
	write("core/caught/redundant_withstack.go", `package caught

import "github.com/leodip/goiabada/core/errs"

func redundantNew() error { return errs.WithStack(errs.New("x")) }

func redundantErrorf() error { return errs.WithStack(errs.Errorf("x %d", 1)) }
`)
	write("core/caught/renamed_errs.go", `package caught

import e "github.com/leodip/goiabada/core/errs"

func renamedNew() error { return e.WithStack(e.New("x")) }

func renamedErrorf() error { return e.WithStack(e.Errorf("x %d", 1)) }
`)

	// A func literal assigned to a package variable is a function body: it runs when it is
	// called, not at init, so the sentinel exemption must not reach into it.
	write("core/caught/package_var_funclit.go", `package caught

import "errors"

var makeErr = func() error { return errors.New("x") }
`)

	// Build constraints that can still be true in a production build. "linux" says nothing about
	// production, and "linux || !production" is true on every production Linux build, so a check
	// that evaluated production alone would exempt both.
	write("core/caught/build_linux.go", `//go:build linux

package caught

import "errors"

func onLinux() error { return errors.New("x") }
`)
	write("core/caught/build_linux_or_not_production.go", `//go:build linux || !production

package caught

import "errors"

func onLinuxOrDev() error { return errors.New("x") }
`)

	// ---- passed ------------------------------------------------------------------------------

	// A package-level sentinel keeps stdlib errors.New: a stack captured at init would record the
	// initializing goroutine and masquerade as the origin of every error wrapping the sentinel.
	write("core/passed/sentinel_block.go", `package passed

import "errors"

var (
	ErrNoAuthContext = errors.New("no auth context")
	ErrGone          = errors.New("gone")
)
`)
	write("core/passed/sentinel_single.go", `package passed

import "fmt"

var errTemplate = fmt.Errorf("template %s missing", "x")
`)

	// The replacement itself, and generated or hand-written mock scaffolding.
	write("core/errs/internal.go", `package errs

import "errors"

func internal() error { return errors.New("x") }
`)
	write("core/passed/mocks/database_mock.go", `package mocks

import "fmt"

func mocked() error { return fmt.Errorf("x") }
`)

	// Excluded from every production build.
	write("core/passed/build_not_production.go", `//go:build !production

package passed

import "errors"

func devOnly() error { return errors.New("x") }
`)
	write("core/passed/build_not_production_and_tools.go", `//go:build !production && tools

package passed

import "errors"

func toolsOnly() error { return errors.New("x") }
`)

	// benign_sentinel_lint_test.go's shape: a test file whose raw string spells the import path.
	// Parsing is what tells a literal from a live import; a text search reports this one.
	write("core/passed/benign_sentinel_lint_test.go", "package passed\n\nconst fixture = `import \"github.com/pkg/errors\"`\n\nfunc spellsIt() string { return fixture }\n")

	// New on a package that is not stdlib errors.
	write("core/passed/other_new.go", `package passed

import "github.com/leodip/goiabada/core/uuidutil"

func other() string { return uuidutil.New() }
`)

	// A file that does not parse is a compile error the build tier owns.
	write("core/passed/unparseable.go", `package passed

func broken( {
`)

	uses, files, err := findLegacyErrorUses(root, nil)
	require.NoError(t, err)
	assert.Equal(t, 14, files,
		"every non-test, parseable, production-reachable fixture outside core/errs and mocks is parsed")
	assert.Equal(t, []string{
		"core/caught/aliased_import.go:3 " + `import "github.com/pkg/errors"`,
		"core/caught/build_linux.go:7 stdlib errors.New",
		"core/caught/build_linux_or_not_production.go:7 stdlib errors.New",
		"core/caught/fmt_errorf.go:5 fmt.Errorf",
		"core/caught/goerrors_alias.go:5 stdlib errors.New",
		"core/caught/package_var_funclit.go:5 stdlib errors.New",
		"core/caught/plain_import.go:3 " + `import "github.com/pkg/errors"`,
		"core/caught/redundant_withstack.go:5 errs.WithStack(errs.New(...))",
		"core/caught/redundant_withstack.go:7 errs.WithStack(errs.Errorf(...))",
		"core/caught/renamed_errs.go:5 errs.WithStack(errs.New(...))",
		"core/caught/renamed_errs.go:7 errs.WithStack(errs.Errorf(...))",
		"core/caught/stdlib_join.go:5 stdlib errors.Join",
		"core/caught/stdlib_new.go:5 stdlib errors.New",
	}, describe(uses))

	// The per-module scoping stages 2, 4 and 5 lean on: the same rule, one subtree at a time.
	scoped, scopedFiles, err := findLegacyErrorUses(root, []string{"core/passed"})
	require.NoError(t, err)
	assert.Equal(t, 3, scopedFiles)
	assert.Empty(t, describe(scoped), "the caught subtree is outside the named directory")
}

// TestNoLegacyErrors_TheTreeItself is the real half, scoped to the modules that have moved: core
// and the authserver, both of which now construct every error through errs. The admin console
// still imports pkg/errors, so naming it here would fail on work that has not happened yet; it is
// added as its sweep lands, and that last one drops the arguments so the whole tree is held.
//
// Every module's tier holds the same scope rather than only its own subtree, for the reason
// AssertGofmted's three callers do: the guard is about the source root, and a stale construction
// is worth catching in whichever tier runs first.
//
// core/testutil is a live instance of the row the parser exists for: errors_lint.go names the
// pkg/errors import path in a comment and in a string literal, and neither is an import.
// core/data/benign_sentinel_lint_test.go spells it inside a raw string, and being a test file it
// is out of scope twice over.
func TestNoLegacyErrors_TheTreeItself(t *testing.T) {
	AssertNoLegacyErrors(t, "core", "authserver")
}

// describe renders findings as "file:line what", which is what a reader compares. The fix text is
// guidance and would make this table churn every time the wording improved.
func describe(uses []legacyErrorUse) []string {
	if len(uses) == 0 {
		return nil
	}
	out := make([]string, 0, len(uses))
	for _, u := range uses {
		out = append(out, u.file+":"+strconv.Itoa(u.line)+" "+u.what)
	}
	return out
}
