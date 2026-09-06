package data

// The one place the repository is held to "every transaction is opened through
// RunInTransaction".
//
// The rule exists because no lock order is imposed anywhere in the tree: two transactions on the
// same account can take the same rows in opposite orders, and the engine then aborts one of them
// as a deadlock victim. RunInTransaction is where that abort is answered, by rerunning the body,
// so a transaction opened with a bare BeginTransaction is one the retry never covers (#301). A
// rule that lived only in a comment would hold until the next owner was written by someone who
// had not read it; this test makes it a compile-time-adjacent fact instead.
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
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runInTransactionOwners are the files allowed to call BeginTransaction: the helper's own body,
// and the four dialect wrappers that forward to it. Relative to the source root, forward slashes.
// Nothing else is exempt, and the list is not the place to put a new owner: an owner that cannot
// be written as a closure is a design question, not an exemption.
var runInTransactionOwners = map[string]bool{
	"core/data/commondb/db.go":   true,
	"core/data/sqlitedb/db.go":   true,
	"core/data/mysqldb/db.go":    true,
	"core/data/postgresdb/db.go": true,
	"core/data/mssqldb/db.go":    true,
}

// bareBeginTransactionCall is one call expression selecting BeginTransaction in a file that is
// not allowed to make it.
type bareBeginTransactionCall struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
}

// findBareBeginTransactionCalls walks root for non-test Go files and reports every CALL to a
// method or function named BeginTransaction outside the exempt set. Declarations are not calls:
// the Database interface declares BeginTransaction and keeps it, since the helper and the tests
// that interleave transactions by hand need it, and the generated mock declares two more, so a
// search for the identifier in the text would report three files that must stay exactly as they
// are. Parsing is what tells a call from a declaration, a comment or a string.
func findBareBeginTransactionCalls(root string, exempt map[string]bool) ([]bareBeginTransactionCall, int, error) {
	var calls []bareBeginTransactionCall
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
		if exempt[rel] {
			return nil
		}
		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, path, nil, 0)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns, and reporting
			// it here would send the reader to the wrong place.
			return nil
		}
		files++
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				if fun.Sel.Name == "BeginTransaction" {
					calls = append(calls, bareBeginTransactionCall{file: rel, line: fset.Position(call.Pos()).Line})
				}
			case *ast.Ident:
				if fun.Name == "BeginTransaction" {
					calls = append(calls, bareBeginTransactionCall{file: rel, line: fset.Position(call.Pos()).Line})
				}
			}
			return true
		})
		return nil
	})
	return calls, files, err
}

// TestNoBareBeginTransaction holds the real tree to the rule.
func TestNoBareBeginTransaction(t *testing.T) {
	root := testutil.SourceRoot(t)

	calls, files, err := findBareBeginTransactionCalls(root, runInTransactionOwners)
	require.NoError(t, err)
	// A root that somehow held no Go files walks nothing and would otherwise pass, which is the
	// one way a guard like this fails silently in the direction that matters.
	require.NotZero(t, files, "walked no Go files under %s", root)

	if len(calls) == 0 {
		return
	}
	lines := make([]string, 0, len(calls))
	for _, c := range calls {
		lines = append(lines, c.file+":"+itoa(c.line))
	}
	t.Fatalf("%d bare BeginTransaction call(s) outside the helper:\n\t%s\n\n"+
		"Open the transaction through Database.RunInTransaction(func(tx *sql.Tx) error) instead. "+
		"It is the only place a deadlock is answered: the engine aborts one of two transactions "+
		"that took the same rows in opposite orders, and the helper reruns the body, so a "+
		"transaction opened with a bare BeginTransaction is one the retry never covers (#301). "+
		"The body has to be safe to rerun: keep its state inside the closure and write its audit "+
		"event after the helper returns.",
		len(calls), strings.Join(lines, "\n\t"))
}

// TestNoBareBeginTransaction_TheCheckerTellsACallFromADeclaration is the synthetic half: a temp
// tree with each shape the real tree contains, so a checker that has quietly stopped matching
// anything, or started matching declarations, is caught here rather than trusted.
func TestNoBareBeginTransaction_TheCheckerTellsACallFromADeclaration(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	}

	// Accepted: the interface declaration the agreement keeps, a mockery-shaped method
	// declaration, and the identifier inside a comment and inside a string.
	write("core/data/database.go", `package data

import "database/sql"

type Database interface {
	BeginTransaction() (*sql.Tx, error)
	RunInTransaction(fn func(tx *sql.Tx) error) error
}
`)
	write("core/data/mocks/database_mock.go", `package mocks

import "database/sql"

type Database struct{}

func (_mock *Database) BeginTransaction() (*sql.Tx, error) { return nil, nil }

type Database_Expecter struct{}

func (_e *Database_Expecter) BeginTransaction() *Database_Expecter { return _e }
`)
	write("authserver/internal/handlers/clean.go", `package handlers

// A comment naming BeginTransaction() is not a call.
const message = "BeginTransaction() failed"

func ok() string { return message }
`)
	// Accepted: a call inside an exempt file.
	write("core/data/commondb/db.go", `package commondb

import "database/sql"

type CommonDatabase struct{ DB *sql.DB }

func (d *CommonDatabase) BeginTransaction() (*sql.Tx, error) { return d.DB.Begin() }

func (d *CommonDatabase) runTransactionOnce() error { _, err := d.BeginTransaction(); return err }
`)
	// Accepted: a test file, which interleaves transactions by hand.
	write("authserver/tests/data/interleave_test.go", `package data

func interleave(db interface{ BeginTransaction() error }) error { return db.BeginTransaction() }
`)
	// Reported: a real call in production code, through a selector and through a bare identifier.
	write("authserver/internal/handlers/owner.go", `package handlers

type db interface{ BeginTransaction() error }

func owner(d db) error {
	return d.BeginTransaction()
}
`)
	write("core/user/local.go", `package user

func BeginTransaction() error { return nil }

func owner() error { return BeginTransaction() }
`)

	calls, files, err := findBareBeginTransactionCalls(root, runInTransactionOwners)
	require.NoError(t, err)
	assert.Equal(t, 5, files, "every non-test file outside the exempt set is parsed")
	assert.Equal(t, []bareBeginTransactionCall{
		{file: "authserver/internal/handlers/owner.go", line: 6},
		{file: "core/user/local.go", line: 5},
	}, calls)
}

// itoa avoids importing strconv for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
