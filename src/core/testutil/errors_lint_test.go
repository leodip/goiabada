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

	// The same three constructors reached without a direct pkg.Fn(...) call. Each produces the
	// identical stackless error one indirection later, and each walked straight past the rule
	// until the final review demonstrated all four (#279).
	write("core/caught/value_new.go", `package caught

import "errors"

func valueNew() error {
	mk := errors.New
	return mk("x")
}
`)
	write("core/caught/value_join.go", `package caught

import "errors"

func valueJoin(a, b error) error {
	join := errors.Join
	return join(a, b)
}
`)
	write("core/caught/callback_errorf.go", `package caught

import "fmt"

func apply(f func(string, ...any) error) error { return f("x %s", "y") }

func callbackErrorf() error { return apply(fmt.Errorf) }
`)
	// One pair of brackets, and the callee is no longer a bare selector.
	write("core/caught/paren_callee.go", `package caught

import "errors"

func parenCallee() error { return (errors.New)("x") }
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

	// The exemption read in the other direction: a sentinel must keep stdlib errors.New, so an
	// errs constructor in the same position is refused. This is the shape that got past the rule
	// while it was only written down, in four real sentinels (#279 decision 5).
	//
	// One row per constructor that attaches frames, and errs.Wrap is here despite being an odd
	// thing to write at init: the point of enumerating them is that no constructor is a way
	// around the rule.
	write("core/caught/package_var_errs.go", `package caught

import "github.com/leodip/goiabada/core/errs"

var (
	ErrGone     = errs.New("gone")
	ErrTemplate = errs.Errorf("template %s missing", "x")
	ErrWrapped  = errs.Wrap(ErrGone, "wrapped")
)
`)

	// The same rule reached through the three indirections a package initializer has. All of them
	// run on the init goroutine and all three were silent while the rule read only the initializer
	// expression, which is what the final review's round 3 established: the exemption is about
	// what runs at init, not about what is written in the initializer.
	//
	//   - an immediately invoked function literal, which is a function body that does run at init;
	//   - a constructor bound to a package name and called through that name, which leaves a bare
	//     identifier with no selector for the rule to resolve. Caught as a value, at the binding,
	//     which is the position that can be pointed at;
	//   - a function declared in the same file and called by an initializer, followed
	//     transitively.
	write("core/caught/package_var_iife.go", `package caught

import "github.com/leodip/goiabada/core/errs"

var ErrFromIIFE = func() error { return errs.New("x") }()
`)
	write("core/caught/package_var_alias.go", `package caught

import "github.com/leodip/goiabada/core/errs"

var newErr = errs.New

var ErrFromAlias = newErr("x")
`)
	write("core/caught/package_var_helper.go", `package caught

import "github.com/leodip/goiabada/core/errs"

func buildSentinel() error { return errs.New("x") }

func viaAnother() error { return buildSentinel() }

var ErrFromHelper = viaAnother()
`)

	// A dot import binds New, Join and Errorf unqualified, so nothing is left for a rule that
	// reads pkg.Fn(...) and the whole file walks past it. The import is the finding, so all three
	// forms below are caught at line 3 and the call on the line after it needs no separate row.
	write("core/caught/dot_import_errors.go", `package caught

import . "errors"

func dotNew() error { return New("x") }
`)
	write("core/caught/dot_import_fmt.go", `package caught

import . "fmt"

func dotErrorf() error { return Errorf("x %d", 1) }
`)
	write("core/caught/dot_import_errs.go", `package caught

import . "github.com/leodip/goiabada/core/errs"

var ErrDotGone = New("gone")
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

	// The dot-import rule names three packages rather than the form: a dot import of anything
	// else hides no constructor this file refuses, and refusing it would be a style rule wearing
	// this one's error message.
	write("core/passed/dot_import_other.go", `package passed

import . "github.com/leodip/goiabada/core/uuidutil"

func dotOther() string { return New() }
`)

	// The value rule names three constructors, not the two packages: errs.New is the replacement
	// and carries a stack wherever it is called from, and errors.Is matches rather than
	// constructs. Refusing either would be this rule's error message on a style opinion.
	write("core/passed/constructor_values.go", `package passed

import (
	"errors"

	"github.com/leodip/goiabada/core/errs"
)

func errsValue() func(string) error { return errs.New }

func matcherValue() func(error, error) bool { return errors.Is }
`)

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
	assert.Equal(t, 27, files,
		"every non-test, parseable, production-reachable fixture outside core/errs and mocks is parsed")
	assert.Equal(t, []string{
		"core/caught/aliased_import.go:3 " + `import "github.com/pkg/errors"`,
		"core/caught/build_linux.go:7 stdlib errors.New",
		"core/caught/build_linux_or_not_production.go:7 stdlib errors.New",
		"core/caught/callback_errorf.go:7 fmt.Errorf as a value",
		"core/caught/dot_import_errors.go:3 " + `dot import of "errors"`,
		"core/caught/dot_import_errs.go:3 " + `dot import of "github.com/leodip/goiabada/core/errs"`,
		"core/caught/dot_import_fmt.go:3 " + `dot import of "fmt"`,
		"core/caught/fmt_errorf.go:5 fmt.Errorf",
		"core/caught/goerrors_alias.go:5 stdlib errors.New",
		"core/caught/package_var_alias.go:5 errs.New as a value",
		"core/caught/package_var_errs.go:6 errs.New in a package-level var",
		"core/caught/package_var_errs.go:7 errs.Errorf in a package-level var",
		"core/caught/package_var_errs.go:8 errs.Wrap in a package-level var",
		"core/caught/package_var_funclit.go:5 stdlib errors.New",
		"core/caught/package_var_helper.go:5 errs.New in a package-level var",
		"core/caught/package_var_iife.go:5 errs.New in a package-level var",
		"core/caught/paren_callee.go:5 stdlib errors.New",
		"core/caught/plain_import.go:3 " + `import "github.com/pkg/errors"`,
		"core/caught/redundant_withstack.go:5 errs.WithStack(errs.New(...))",
		"core/caught/redundant_withstack.go:7 errs.WithStack(errs.Errorf(...))",
		"core/caught/renamed_errs.go:5 errs.WithStack(errs.New(...))",
		"core/caught/renamed_errs.go:7 errs.WithStack(errs.Errorf(...))",
		"core/caught/stdlib_join.go:5 stdlib errors.Join",
		"core/caught/stdlib_new.go:5 stdlib errors.New",
		"core/caught/value_join.go:6 stdlib errors.Join as a value",
		"core/caught/value_new.go:6 stdlib errors.New as a value",
	}, describe(uses))

	// The per-module scoping stages 2, 4 and 5 lean on: the same rule, one subtree at a time.
	scoped, scopedFiles, err := findLegacyErrorUses(root, []string{"core/passed"})
	require.NoError(t, err)
	assert.Equal(t, 5, scopedFiles)
	assert.Empty(t, describe(scoped), "the caught subtree is outside the named directory")
}

// TestNoLegacyErrors_TheTreeItself is the real half, and it is unscoped: every module has moved,
// so the whole source root is held, cmd/goiabada-setup and any module added later included. The
// call carried "core", "authserver" while the sweep was in flight, because naming a module that
// had not moved would have failed on work that had not happened; dropping the arguments is what
// measures goal 1 of #279, and it is stronger than any grep because it resolves the name written
// at each call site through the file's own imports.
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
	AssertNoLegacyErrors(t)
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
