package data

// The one place the repository is held to "a benign migrator sentinel is matched by identity,
// never by errors.Is".
//
// The rule exists because the runner joins rather than replaces. Migrator.run defers its unlock
// and, when the unlock fails, joins that failure onto whatever the operation returned; withConn
// does the same with a failed connection close. So an Up() at head on a database whose migration
// lock did not come back answers errors.Join(ErrNoChange, unlockErr), and errors.Is finds
// ErrNoChange inside it. A caller testing that way logs "no need to migrate the database", starts
// the server, and leaves a session-scoped lock held for the life of the process, which every
// other migrator on that database then waits on: indefinitely on PostgreSQL and SQL Server.
//
// migrator.IsNoChange and migrator.IsNilVersion are identity tests, which the joined error fails
// and the bare sentinel passes. There are six production sites today, four engine wrappers and
// two in the authserver migrate command, and the fifth engine somebody adds later is exactly the
// one a comment would not reach. This test makes it a compile-time-adjacent fact instead (#268).
//
// It reads and parses files and nothing else: no database, no git, no network, so it runs in the
// core tier on every CI job rather than only the four database ones.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/require"
)

// benignSentinels are the migrator errors that mean "nothing happened, and that is fine". Both
// can arrive joined with a real failure, and neither has a caller that wants the joined one.
// ErrLocked and the two typed errors are absent deliberately: they ARE failures, so a caller
// matching one is asking whether it is in there, which is what errors.Is is for.
var benignSentinels = map[string]bool{
	"ErrNoChange":   true,
	"ErrNilVersion": true,
}

// errorsIsOnBenignSentinel is one errors.Is call whose target is one of those sentinels.
type errorsIsOnBenignSentinel struct {
	// file is relative to the root the walk started from, forward slashes.
	file     string
	line     int
	sentinel string
}

// findErrorsIsOnBenignSentinels walks root for non-test Go files and reports every errors.Is call
// whose second argument names one of the sentinels above.
//
// The receiver is resolved through the file's own imports rather than matched against the
// spelling "errors", because the spelling is not the package. mssqldb/db.go already imports the
// standard package as goerrors, so a checker keyed on the identifier walks straight past
// goerrors.Is(err, migrator.ErrNoChange) in the one file most likely to grow it, and reports
// nothing at all (#268).
//
// Test files are not walked. A test asserting the sentinel is reachable inside a wrapped error is
// asking exactly the question errors.Is answers, and migrator's own package tests do that on
// purpose to show what the identity check is protecting against.
//
// Parsing rather than grepping, for the same reason the BeginTransaction lint parses: the
// identifiers appear in comments and in doc strings all over this package, and a text search
// would report the sentences explaining the rule as violations of it.
func findErrorsIsOnBenignSentinels(root string) ([]errorsIsOnBenignSentinel, int, error) {
	var found []errorsIsOnBenignSentinel
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, path, nil, 0)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns, and reporting
			// it here would send the reader to the wrong place.
			return nil
		}
		files++
		errorsIdents := errorsPackageIdents(file)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			fun, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || fun.Sel.Name != "Is" {
				return true
			}
			pkg, ok := fun.X.(*ast.Ident)
			if !ok || !errorsIdents[pkg.Name] {
				return true
			}
			if name, is := benignSentinelName(call.Args[1]); is {
				found = append(found, errorsIsOnBenignSentinel{
					file: rel, line: fset.Position(call.Pos()).Line, sentinel: name,
				})
			}
			return true
		})
		return nil
	})
	return found, files, err
}

// errorsPackageIdents returns the identifiers this file binds to a package whose Is is the
// standard one: "errors", and github.com/pkg/errors, whose Is forwards to it and which 220 files
// under src/ import. Both spell their default identifier "errors", and either one aliased is the
// same hazard under a different name.
//
// A dot import is deliberately outside this: it would bind Is with no receiver at all, and a bare
// call cannot be attributed to a package without type information, which is a tier above what
// this test buys with go/parser alone. Nothing under src/ dot-imports either package. Neither is
// a function value assigned from errors.Is, for the same reason; the boundary is the direct call.
func errorsPackageIdents(file *ast.File) map[string]bool {
	idents := make(map[string]bool, 1)
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || (path != "errors" && path != "github.com/pkg/errors") {
			continue
		}
		switch {
		case spec.Name == nil:
			// Both paths end in "errors", which is the identifier an unaliased import binds.
			idents["errors"] = true
		case spec.Name.Name == "_" || spec.Name.Name == ".":
			// A blank import binds nothing to call through, and a dot import is out of reach
			// above. Neither is a receiver, so neither belongs in this set.
		default:
			idents[spec.Name.Name] = true
		}
	}
	return idents
}

// benignSentinelName reads the target of an errors.Is call. Both spellings count: migrator.X from
// outside the package and a bare X from inside it.
func benignSentinelName(arg ast.Expr) (string, bool) {
	switch target := arg.(type) {
	case *ast.SelectorExpr:
		return target.Sel.Name, benignSentinels[target.Sel.Name]
	case *ast.Ident:
		return target.Name, benignSentinels[target.Name]
	}
	return "", false
}

// TestNoErrorsIsOnABenignMigratorSentinel holds the real tree to the rule.
func TestNoErrorsIsOnABenignMigratorSentinel(t *testing.T) {
	root := testutil.SourceRoot(t)

	found, files, err := findErrorsIsOnBenignSentinels(root)
	require.NoError(t, err)
	// A root that somehow held no Go files walks nothing and would otherwise pass, which is the
	// one way a guard like this fails silently in the direction that matters.
	require.NotZero(t, files, "walked no Go files under %s", root)

	if len(found) == 0 {
		return
	}
	lines := make([]string, 0, len(found))
	for _, f := range found {
		lines = append(lines, f.file+":"+itoa(f.line)+" ("+f.sentinel+")")
	}
	t.Fatalf("%d errors.Is call(s) on a benign migrator sentinel:\n\t%s\n\n"+
		"Use migrator.IsNoChange or migrator.IsNilVersion instead. The runner JOINS a failed "+
		"unlock, or a failed connection close, onto whatever the operation returned, so the "+
		"sentinel arrives inside an error that also carries a real failure. errors.Is finds it "+
		"there and reports the operation as successful, which on the four engine wrappers means "+
		"starting the server with the migration lock still held against every other process on "+
		"the database (#268).",
		len(found), strings.Join(lines, "\n\t"))
}

// TestNoErrorsIsOnABenignMigratorSentinel_TheCheckerReadsTheTarget is the synthetic half: a temp
// tree with each shape the real tree contains, so a checker that has quietly stopped matching
// anything, or started matching the errors it should leave alone, is caught here rather than
// trusted.
func TestNoErrorsIsOnABenignMigratorSentinel_TheCheckerReadsTheTarget(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	}

	// Accepted: the identity helpers, errors.Is on an error that is NOT benign, and the names
	// inside a comment and a string.
	write("core/data/sqlitedb/db.go", `package sqlitedb

import (
	"errors"

	"github.com/leodip/goiabada/core/data/migrator"
	"github.com/leodip/goiabada/core/data/matcher"
)

// errors.Is(err, migrator.ErrNoChange) in a comment is not a call.
const message = "errors.Is(err, migrator.ErrNilVersion)"

func migrate(m *migrator.Migrator) error {
	err := m.Up()
	if migrator.IsNoChange(err) {
		return nil
	}
	if errors.Is(err, migrator.ErrLocked) {
		return err
	}
	if matcher.Is(err, migrator.ErrNoChange) {
		return nil
	}
	return err
}
`)
	found, files, err := findErrorsIsOnBenignSentinels(root)
	require.NoError(t, err)
	require.Equal(t, 1, files)
	require.Empty(t, found,
		"the helpers, a non-benign target, a comment, a string and an Is on some other package are all fine")

	// Refused: both spellings of both sentinels, qualified and bare.
	write("core/data/mysqldb/db.go", `package mysqldb

import (
	"errors"

	"github.com/leodip/goiabada/core/data/migrator"
)

func migrate(m *migrator.Migrator) error {
	err := m.Up()
	if errors.Is(err, migrator.ErrNoChange) {
		return nil
	}
	_, _, verr := m.Version()
	if errors.Is(verr, migrator.ErrNilVersion) {
		return nil
	}
	return err
}
`)
	write("core/data/migrator/inside.go", `package migrator

import "errors"

func isNothingToDo(err error) bool { return errors.Is(err, ErrNoChange) }
`)
	// goerrors is not a hypothetical spelling: mssqldb/db.go imports the standard package under
	// exactly this name today, so a checker keyed on the identifier "errors" misses the one file
	// where the mistake is nearest to hand. The migrator import is aliased too, because the target
	// is read by selector name and must not depend on the package's spelling either.
	write("core/data/mssqldb/db.go", `package mssqldb

import (
	goerrors "errors"

	mig "github.com/leodip/goiabada/core/data/migrator"
)

func migrate(m *mig.Migrator) error {
	err := m.Up()
	if goerrors.Is(err, mig.ErrNoChange) {
		return nil
	}
	_, _, verr := m.Version()
	if goerrors.Is(verr, mig.ErrNilVersion) {
		return nil
	}
	return err
}
`)
	// github.com/pkg/errors is imported by 220 files under src/ and binds the same identifier an
	// unaliased standard import does. Its Is forwards to the standard one, so it finds the
	// sentinel inside the join in exactly the same way and is the same defect.
	write("core/data/postgresdb/db.go", `package postgresdb

import (
	"github.com/pkg/errors"

	"github.com/leodip/goiabada/core/data/migrator"
)

func migrate(m *migrator.Migrator) error {
	err := m.Up()
	if errors.Is(err, migrator.ErrNoChange) {
		return nil
	}
	return err
}
`)
	// And a test file carrying the same call, which is walked past rather than reported.
	write("core/data/mysqldb/db_test.go", `package mysqldb

import (
	"errors"

	"github.com/leodip/goiabada/core/data/migrator"
)

func assertNoChange(err error) bool { return errors.Is(err, migrator.ErrNoChange) }
`)

	found, files, err = findErrorsIsOnBenignSentinels(root)
	require.NoError(t, err)
	require.Equal(t, 5, files, "the five non-test files, and not the _test.go beside them")

	seen := make([]string, 0, len(found))
	for _, f := range found {
		seen = append(seen, f.file+" "+f.sentinel)
	}
	sort.Strings(seen)
	require.Equal(t, []string{
		"core/data/migrator/inside.go ErrNoChange",
		"core/data/mssqldb/db.go ErrNilVersion",
		"core/data/mssqldb/db.go ErrNoChange",
		"core/data/mysqldb/db.go ErrNilVersion",
		"core/data/mysqldb/db.go ErrNoChange",
		"core/data/postgresdb/db.go ErrNoChange",
	}, seen, "both sentinels under every spelling of both errors packages, and nothing from the test file")
}
