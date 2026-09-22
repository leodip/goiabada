package data

// The one place the repository is held to "every database operation reachable from production
// code takes a context and uses it".
//
// #386 gave all 215 Database methods a leading ctx and turned the two SQL chokepoints, ExecSql
// and QuerySql, plus BeginTransaction, into their *Context forms. That is a state the tree was
// put into once; this guard is what stops it coming back. Two rules, both narrow:
//
//  1. No bare Query, QueryRow, Exec or Begin anywhere under authserver/internal/data in
//     production code. The *Context form of each is the one that can be cancelled, and the
//     non-context form is the shape a new query is written in by anyone copying an old one.
//
//  2. No context.Background() and no context.TODO() inside commondb. Every method there has a
//     ctx parameter, so a root opened in the middle of the package is a caller's context being
//     dropped on the floor -- which is exactly what the bridge stages 4 to 8 burnt down did,
//     deliberately and temporarily.
//
// THERE IS NO OWNER EXEMPTION, and that is the decision this file records rather than the
// obvious one. The sketch this replaces planned to exempt the startup owners -- the four
// adapters' connection and DDL paths, the migrator, schemadump -- which would have shipped a
// tree where the goal above was false by design with a lint certifying it. Startup may own a
// ROOT context; the database operation still has to receive one and use it. So those sites take
// their *Context form with a context.Background() their own constructor or command declares,
// outside this package's commondb scope, and the exemption list that would have rotted does not
// exist.
//
// It reads and parses files and nothing else: no database, no git, no network, so it runs in the
// authserver internal tier on every CI job rather than only the four database ones.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sqlContextRoot is the subtree rule 1 covers, relative to the source root, forward slashes.
const sqlContextRoot = "authserver/internal/data"

// commondbRoot is the subtree rule 2 covers. Narrower than sqlContextRoot on purpose: the four
// adapters' constructors and the migrator command own a root context legitimately, and commondb
// is the package where every function already has one handed to it.
const commondbRoot = "authserver/internal/data/commondb"

// bareSQLSelectors are the four database/sql calls that cannot be cancelled. Their *Context
// counterparts -- QueryContext, QueryRowContext, ExecContext, BeginTx -- are what the tree uses.
// Matched as a selector name through the parser rather than as text, so QuerySql, ExecSql and
// BeginTransaction, which are this package's own context-taking wrappers, are not caught by a
// prefix.
var bareSQLSelectors = map[string]string{
	"Query":    "QueryContext",
	"QueryRow": "QueryRowContext",
	"Exec":     "ExecContext",
	"Begin":    "BeginTx",
}

// sqlContextViolation is one refused site, located, with the rule it broke.
type sqlContextViolation struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
	// what names the call as written, and fix names the call it should have been.
	what string
	fix  string
}

// findSQLContextViolations walks root and reports both rules over every non-test Go file under
// the two subtrees above. Mocks are walked like anything else: a generated file cannot contain
// either shape, and exempting a directory is how one stops being checked after somebody puts
// something else in it.
func findSQLContextViolations(root string) ([]sqlContextViolation, int, error) {
	var found []sqlContextViolation
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
		inSQL := withinLintScope(rel, sqlContextRoot)
		inCommon := withinLintScope(rel, commondbRoot)
		if !inSQL && !inCommon {
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
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			line := fset.Position(call.Pos()).Line
			if inSQL {
				if fix, refused := bareSQLSelectors[sel.Sel.Name]; refused {
					found = append(found, sqlContextViolation{
						file: rel, line: line,
						what: sel.Sel.Name + "(...)", fix: fix + "(ctx, ...)",
					})
				}
			}
			if inCommon {
				pkg, isIdent := sel.X.(*ast.Ident)
				if isIdent && pkg.Name == "context" &&
					(sel.Sel.Name == "Background" || sel.Sel.Name == "TODO") {
					found = append(found, sqlContextViolation{
						file: rel, line: line,
						what: "context." + sel.Sel.Name + "()", fix: "the caller's ctx",
					})
				}
			}
			return true
		})
		return nil
	})
	return found, files, err
}

// withinLintScope is the path-prefix match the two roots are compared with, written so that a
// directory named commondbx is not read as being inside commondb.
func withinLintScope(rel, scope string) bool {
	return rel == scope || strings.HasPrefix(rel, scope+"/")
}

// TestSQLCallsTakeAContext holds the real tree to both rules.
func TestSQLCallsTakeAContext(t *testing.T) {
	assertSQLCallsTakeAContext(t, testutil.SourceRoot(t))
}

// assertSQLCallsTakeAContext is the reporting half, taking the root as a parameter and failing
// through a testutil.Reporter so a rule test can drive it against a fixture tree. Without that
// seam these lines are reached only by the call above, which walks a tree #386 left clean, so a
// defect in them disables the guard with nothing going red.
func assertSQLCallsTakeAContext(r testutil.Reporter, root string) {
	r.Helper()

	found, files, err := findSQLContextViolations(root)
	if err != nil {
		r.Fatalf("walking %s: %v", root, err)
	}
	// A root that somehow held no Go files walks nothing and would otherwise pass, which is the
	// one way a guard like this fails silently in the direction that matters.
	if files == 0 {
		r.Fatalf("walked no non-test Go files under %s", root)
	}
	if len(found) == 0 {
		return
	}

	lines := make([]string, 0, len(found))
	for _, v := range found {
		lines = append(lines, v.file+":"+strconv.Itoa(v.line)+": "+v.what+" -- use "+v.fix)
	}
	r.Errorf("%d database call(s) that cannot be cancelled, in %d non-test file(s):\n\t%s\n\n"+
		"Every database query, command and transaction entry point reachable from production "+
		"code takes a context and uses it, so the four bare database/sql calls are refused "+
		"under %s and a root context is refused inside %s, where every function is handed the "+
		"caller's. A startup owner may declare a root -- a constructor, main, or a one-shot "+
		"command -- and passes it in; what it may not do is open one where the statement lands "+
		"(#386).",
		len(found), files, strings.Join(lines, "\n\t"), sqlContextRoot, commondbRoot)
}

// TestSQLCallsTakeAContext_TheCheckerTellsTheShapesApart is the synthetic half: a temp tree with
// each shape the real tree contains, so a checker that has quietly stopped matching anything, or
// started matching the context-taking wrappers, is caught here rather than trusted.
func TestSQLCallsTakeAContext_TheCheckerTellsTheShapesApart(t *testing.T) {
	root := t.TempDir()

	// Accepted: the *Context forms, this package's own wrappers whose names merely begin with
	// the refused ones, and a root context declared by an adapter's constructor.
	writeLintFixture(t, root, "authserver/internal/data/commondb/db.go", `package commondb

import (
	"context"
	"database/sql"
)

type CommonDatabase struct{ DB *sql.DB }

func (d *CommonDatabase) ExecSql(ctx context.Context, tx *sql.Tx, s string) error {
	_, err := d.DB.ExecContext(ctx, s)
	return err
}

func (d *CommonDatabase) QuerySql(ctx context.Context, tx *sql.Tx, s string) error {
	_, err := d.DB.QueryContext(ctx, s)
	return err
}

func (d *CommonDatabase) BeginTransaction(ctx context.Context) (*sql.Tx, error) {
	return d.DB.BeginTx(ctx, nil)
}

func (d *CommonDatabase) both(ctx context.Context) error {
	if err := d.ExecSql(ctx, nil, "x"); err != nil {
		return err
	}
	return d.QuerySql(ctx, nil, "y")
}
`)
	writeLintFixture(t, root, "authserver/internal/data/sqlitedb/db.go", `package sqlitedb

import (
	"context"
	"database/sql"
)

func New(db *sql.DB) error {
	ctx := context.Background()
	_, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON;")
	return err
}
`)
	// Accepted: outside both scopes altogether.
	writeLintFixture(t, root, "authserver/internal/handlers/elsewhere.go", `package handlers

import (
	"context"
	"database/sql"
)

func loose(db *sql.DB) error {
	_ = context.Background()
	_, err := db.Exec("SELECT 1")
	return err
}
`)
	// Reported: all four bare calls, in an adapter rather than in commondb, which is the shape
	// the rejected exemption list would have admitted.
	writeLintFixture(t, root, "authserver/internal/data/mysqldb/startup.go", `package mysqldb

import "database/sql"

func startup(db *sql.DB) error {
	_, _ = db.Exec("CREATE DATABASE x")
	_, _ = db.Query("SELECT 1")
	_ = db.QueryRow("SELECT 1")
	_, _ = db.Begin()
	return nil
}
`)
	// Reported: a root context opened inside commondb.
	writeLintFixture(t, root, "authserver/internal/data/commondb/group.go", `package commondb

import "context"

func bridge() context.Context {
	_ = context.TODO()
	return context.Background()
}
`)

	found, files, err := findSQLContextViolations(root)
	require.NoError(t, err)
	assert.Equal(t, 4, files, "every non-test file inside the two scopes is parsed")
	assert.Equal(t, []sqlContextViolation{
		{file: "authserver/internal/data/commondb/group.go", line: 6, what: "context.TODO()", fix: "the caller's ctx"},
		{file: "authserver/internal/data/commondb/group.go", line: 7, what: "context.Background()", fix: "the caller's ctx"},
		{file: "authserver/internal/data/mysqldb/startup.go", line: 6, what: "Exec(...)", fix: "ExecContext(ctx, ...)"},
		{file: "authserver/internal/data/mysqldb/startup.go", line: 7, what: "Query(...)", fix: "QueryContext(ctx, ...)"},
		{file: "authserver/internal/data/mysqldb/startup.go", line: 8, what: "QueryRow(...)", fix: "QueryRowContext(ctx, ...)"},
		{file: "authserver/internal/data/mysqldb/startup.go", line: 9, what: "Begin(...)", fix: "BeginTx(ctx, ...)"},
	}, found)
}

// TestSQLCallsTakeAContext_TheGuardFailsOnABareCall is the third half, and the one the two above
// leave out. Both assert on what findSQLContextViolations returned; the lines that turn a finding
// into a failure are reached only by TestSQLCallsTakeAContext, which walks a tree #386 left clean,
// so blinding them disables the guard with nothing going red.
func TestSQLCallsTakeAContext_TheGuardFailsOnABareCall(t *testing.T) {
	root := t.TempDir()
	writeLintFixture(t, root, "authserver/internal/data/postgresdb/db.go", `package postgresdb

import "database/sql"

func ddl(db *sql.DB) error {
	_, err := db.Exec("CREATE TABLE schema_migrations (version bigint)")
	return err
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertSQLCallsTakeAContext(r, root)
	})

	require.True(t, report.Failed(), "a bare Exec passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/data/postgresdb/db.go:6")
	assert.Contains(t, report.Text(), "ExecContext(ctx, ...)")
	assert.Contains(t, report.Text(), "#386")
}

// TestSQLCallsTakeAContext_TheGuardPassesTheContextForms is the other direction, over the shapes
// the rule exists to admit: the four *Context calls, and a startup owner declaring its own root
// outside commondb.
func TestSQLCallsTakeAContext_TheGuardPassesTheContextForms(t *testing.T) {
	root := t.TempDir()
	writeLintFixture(t, root, "authserver/internal/data/mssqldb/db.go", `package mssqldb

import (
	"context"
	"database/sql"
)

func startup(db *sql.DB) error {
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "x"); err != nil {
		return err
	}
	if _, err := db.QueryContext(ctx, "y"); err != nil {
		return err
	}
	_ = db.QueryRowContext(ctx, "z")
	_, err := db.BeginTx(ctx, nil)
	return err
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertSQLCallsTakeAContext(r, root)
	})

	assert.False(t, report.Failed(), "the *Context forms failed the guard: %s", report.Text())
}

// TestSQLCallsTakeAContext_TheGuardIsFatalOnAnEmptyWalk pins the seam the comment inside the
// guard names. A root holding no Go file under either scope reports nothing, which is
// indistinguishable from a tree whose every database call takes a context.
func TestSQLCallsTakeAContext_TheGuardIsFatalOnAnEmptyWalk(t *testing.T) {
	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertSQLCallsTakeAContext(r, t.TempDir())
	})

	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked no non-test Go files under")
}
