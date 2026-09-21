package data

// The one place the repository is held to "a method that holds a transaction passes it on".
//
// The rule exists because a read handed nil runs outside its caller's transaction. On MySQL,
// PostgreSQL and SQL Server it takes a second connection from the pool and answers from before
// the transaction's own uncommitted writes, so a paginated count can disagree with the page it
// accompanies. On SQLite, whose pool is capped at one connection, it blocks on the connection its
// own caller is holding and never returns at all (#413).
//
// Five commondb reads did exactly this. The fix at each was one word, which is precisely why it
// needs a guard: nothing about `nil` in an argument list looks wrong, and the next paginated
// getter will be written by copying the one beside it.
//
// It reads and parses files and nothing else: no database, no git, no network, so it runs in the
// authserver internal tier on every CI job rather than only the four database ones.

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

// escapedTransactionCall is one call that passed a literal nil where its enclosing method had a
// transaction of its own to hand over.
type escapedTransactionCall struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
	// callee is the method name whose transaction position took the nil, so the report names
	// what was dropped and not merely where.
	callee string
}

// findEscapedTransactions parses every non-test Go file under authserver/internal/data and reports
// each call, made on the enclosing method's own receiver, that passes the identifier nil in the
// callee's transaction position while the enclosing method declares a *sql.Tx parameter.
//
// The transaction position is read from the callee's declaration rather than assumed to be
// argument zero. That is what makes this rule survive the context migration unedited: once a
// method takes a context first, the transaction is argument 1, and d.QuerySql(ctx, nil, sql) is
// the same defect written one position along. A hardcoded index would pass it in silence.
//
// It returns the findings and the count of files parsed, because a walk that reached nothing
// reports nothing, which is indistinguishable from a tree that passes every transaction on.
func findEscapedTransactions(root string) ([]escapedTransactionCall, int, error) {
	dir := filepath.Join(root, filepath.FromSlash("authserver/internal/data"))
	if _, err := os.Stat(dir); err != nil {
		// A root holding no data package walks nothing. The reporting half turns that into a
		// Fatalf; reporting it as an error here would send the reader to the wrong place.
		return nil, 0, nil
	}

	type parsedFile struct {
		rel  string
		fset *token.FileSet
		file *ast.File
	}
	var parsed []parsedFile

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
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
		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, path, nil, 0)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns.
			return nil
		}
		parsed = append(parsed, parsedFile{rel: filepath.ToSlash(rel), fset: fset, file: file})
		return nil
	})
	if err != nil {
		return nil, 0, err
	}

	// First pass: where each declared name keeps its transaction. A name can be declared more
	// than once -- commondb declares a method and an engine adapter overrides it -- and during
	// the context migration the two can disagree about the position for as long as it takes the
	// batch to land. Holding every declared position rather than one is what keeps the rule
	// sighted across that window: a nil at any of them is a dropped transaction.
	txPositions := map[string]map[int]bool{}
	for _, pf := range parsed {
		for _, decl := range pf.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			idx, found := txParameterIndex(fn.Type)
			if !found {
				continue
			}
			if txPositions[fn.Name.Name] == nil {
				txPositions[fn.Name.Name] = map[int]bool{}
			}
			txPositions[fn.Name.Name][idx] = true
		}
	}

	// Second pass: the calls themselves.
	var findings []escapedTransactionCall
	for _, pf := range parsed {
		for _, decl := range pf.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			receiver := receiverIdent(fn)
			if receiver == "" {
				continue
			}
			if _, holdsTx := txParameterIndex(fn.Type); !holdsTx {
				// Nothing to hand over. IsEmpty and ScanEmailCase are here, and they are not
				// sites: a method with no transaction of its own passing nil is asking for the
				// pool's next connection, which is the only thing it could mean.
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				// Rooted at the receiver, so d.QuerySql(...) counts and so would any
				// selector chain starting there.
				if leftmostIdent(sel.X) != receiver {
					return true
				}
				for idx := range txPositions[sel.Sel.Name] {
					if idx >= len(call.Args) {
						continue
					}
					if ident, ok := call.Args[idx].(*ast.Ident); ok && ident.Name == "nil" {
						findings = append(findings, escapedTransactionCall{
							file:   pf.rel,
							line:   pf.fset.Position(call.Pos()).Line,
							callee: sel.Sel.Name,
						})
						return true
					}
				}
				return true
			})
		}
	}

	return findings, len(parsed), nil
}

// txParameterIndex returns the argument position of the signature's *sql.Tx parameter, counting
// grouped names as the separate arguments they are.
func txParameterIndex(sig *ast.FuncType) (int, bool) {
	if sig == nil || sig.Params == nil {
		return 0, false
	}
	pos := 0
	for _, field := range sig.Params.List {
		if isSQLTxPointer(field.Type) {
			return pos, true
		}
		names := len(field.Names)
		if names == 0 {
			names = 1
		}
		pos += names
	}
	return 0, false
}

// isSQLTxPointer matches the type *sql.Tx by spelling. go/types would be exact, but every file
// this walks imports database/sql under its own name, and a local package aliased to sql would be
// a finding worth having anyway.
func isSQLTxPointer(expr ast.Expr) bool {
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "sql" && sel.Sel.Name == "Tx"
}

// receiverIdent is the name a method calls itself by, or "" for a plain function or a receiver
// declared without a name.
func receiverIdent(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 {
		return ""
	}
	name := fn.Recv.List[0].Names[0].Name
	if name == "_" {
		return ""
	}
	return name
}

// leftmostIdent walks a selector chain down to the identifier it is rooted at, so d.Inner.X
// answers "d".
func leftmostIdent(expr ast.Expr) string {
	for {
		switch e := expr.(type) {
		case *ast.Ident:
			return e.Name
		case *ast.SelectorExpr:
			expr = e.X
		default:
			return ""
		}
	}
}

// TestNoEscapedTransactions holds the real tree to the rule.
func TestNoEscapedTransactions(t *testing.T) {
	assertNoEscapedTransactions(t, testutil.SourceRoot(t))
}

// assertNoEscapedTransactions is the reporting half, taking the root as a parameter and failing
// through a testutil.Reporter so a rule test can drive it against a fixture tree. Without that
// seam these lines are reached only by the call above, which walks a tree that is clean, so a
// defect in them disables the guard with nothing going red.
func assertNoEscapedTransactions(r testutil.Reporter, root string) {
	r.Helper()

	findings, files, err := findEscapedTransactions(root)
	if err != nil {
		r.Fatalf("walking %s: %v", root, err)
	}
	if files == 0 {
		r.Fatalf("walked no Go files under %s", root)
	}

	if len(findings) == 0 {
		return
	}
	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		lines = append(lines, f.file+":"+itoa(f.line)+" drops the transaction into "+f.callee)
	}
	r.Errorf("%d call(s) passing nil where the enclosing method holds a transaction:\n\t%s\n\n"+
		"Pass the tx the method was given. A read handed nil runs outside its caller's "+
		"transaction: on MySQL, PostgreSQL and SQL Server it takes a second connection and "+
		"answers from before that transaction's own writes, so a count can disagree with the "+
		"page it accompanies; on SQLite, whose pool holds one connection, it blocks on the "+
		"connection its caller is already holding and never returns (#413). A method with no "+
		"transaction of its own has nothing to hand over and is not a site.",
		len(findings), strings.Join(lines, "\n\t"))
}

// TestNoEscapedTransactions_TheGuardFailsOnADroppedTransaction is the must-fail half, over both
// shapes the rule has to catch: today's, where the transaction is argument zero, and the one the
// context migration leaves behind, where it is argument one. The second is in a tree of its own
// because the two declarations of QuerySql would otherwise be a single name with two positions,
// which is a different property and is not what this case is measuring.
func TestNoEscapedTransactions_TheGuardFailsOnADroppedTransaction(t *testing.T) {
	// Today's shape: the transaction is argument zero, and the rule is not special-cased to the
	// two SQL chokepoints -- a getter dropping it is the same defect.
	root := t.TempDir()
	writeLintFixture(t, root, "authserver/internal/data/commondb/db.go", `package commondb

import "database/sql"

type CommonDatabase struct{}

func (d *CommonDatabase) QuerySql(tx *sql.Tx, query string, args ...any) (*sql.Rows, error) {
	return nil, nil
}

func (d *CommonDatabase) GetPermissionsByIds(tx *sql.Tx, ids []int64) ([]int64, error) {
	return nil, nil
}
`)
	writeLintFixture(t, root, "authserver/internal/data/commondb/user.go", `package commondb

import "database/sql"

func (d *CommonDatabase) SearchUsersPaginated(tx *sql.Tx, query string) error {
	_, err := d.QuerySql(nil, query)
	return err
}

func (d *CommonDatabase) ClientLoadPermissions(tx *sql.Tx, ids []int64) error {
	_, err := d.GetPermissionsByIds(nil, ids)
	return err
}
`)
	// The adapters reach the shared implementation through an embedded field, so the receiver is
	// the root of a longer selector chain.
	writeLintFixture(t, root, "authserver/internal/data/postgresdb/user.go", `package postgresdb

import "database/sql"

type PostgresDatabase struct{ CommonDB *anything }

type anything struct{}

func (d *PostgresDatabase) GetUsersByPermissionIdPaginated(tx *sql.Tx, query string) error {
	_, err := d.CommonDB.QuerySql(nil, query)
	return err
}
`)

	findings, files, err := findEscapedTransactions(root)
	require.NoError(t, err)
	assert.Equal(t, 3, files, "every non-test file under the data package is parsed")
	assert.Equal(t, []escapedTransactionCall{
		{file: "authserver/internal/data/commondb/user.go", line: 6, callee: "QuerySql"},
		{file: "authserver/internal/data/commondb/user.go", line: 11, callee: "GetPermissionsByIds"},
		{file: "authserver/internal/data/postgresdb/user.go", line: 10, callee: "QuerySql"},
	}, findings)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoEscapedTransactions(r, root)
	})
	require.True(t, report.Failed(), "a dropped transaction passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/data/commondb/user.go:6")
	assert.Contains(t, report.Text(), "authserver/internal/data/commondb/user.go:11")
	assert.Contains(t, report.Text(), "authserver/internal/data/postgresdb/user.go:10")
	assert.Contains(t, report.Text(), "#413")

	// The post-context shape, in its own tree: the transaction is argument one, and the call
	// fails only if the position came from the callee's declaration rather than from a constant.
	afterRoot := t.TempDir()
	writeLintFixture(t, afterRoot, "authserver/internal/data/commondb/db.go", `package commondb

import (
	"context"
	"database/sql"
)

type CommonDatabase struct{}

func (d *CommonDatabase) QuerySql(ctx context.Context, tx *sql.Tx, query string) (*sql.Rows, error) {
	return nil, nil
}

func (d *CommonDatabase) GetGroupMembersPaginated(ctx context.Context, tx *sql.Tx, query string) error {
	_, err := d.QuerySql(ctx, nil, query)
	return err
}
`)

	afterFindings, afterFiles, err := findEscapedTransactions(afterRoot)
	require.NoError(t, err)
	assert.Equal(t, 1, afterFiles)
	assert.Equal(t, []escapedTransactionCall{
		{file: "authserver/internal/data/commondb/db.go", line: 15, callee: "QuerySql"},
	}, afterFindings)
}

// TestNoEscapedTransactions_TheGuardPassesTheShapesItMustAdmit is the other direction: the same
// calls handing the transaction over, the two real methods that hold none, and a nil that lands
// somewhere other than a transaction position.
func TestNoEscapedTransactions_TheGuardPassesTheShapesItMustAdmit(t *testing.T) {
	root := t.TempDir()
	writeLintFixture(t, root, "authserver/internal/data/commondb/db.go", `package commondb

import "database/sql"

type CommonDatabase struct{}

func (d *CommonDatabase) QuerySql(tx *sql.Tx, query string, args ...any) (*sql.Rows, error) {
	return nil, nil
}

func (d *CommonDatabase) GetPermissionsByIds(tx *sql.Tx, ids []int64) ([]int64, error) {
	return nil, nil
}

func (d *CommonDatabase) GetSettingsById(tx *sql.Tx, id int64) (any, error) {
	return nil, nil
}

// IsEmpty holds no transaction, so its nil is the pool's next connection and not a dropped one.
func (d *CommonDatabase) IsEmpty() (bool, error) {
	_, err := d.GetSettingsById(nil, 1)
	return false, err
}

// ScanEmailCase is the same shape at the other chokepoint.
func (d *CommonDatabase) ScanEmailCase() error {
	_, err := d.QuerySql(nil, "select 1")
	return err
}
`)
	writeLintFixture(t, root, "authserver/internal/data/commondb/user.go", `package commondb

import "database/sql"

func (d *CommonDatabase) SearchUsersPaginated(tx *sql.Tx, query string) error {
	_, err := d.QuerySql(tx, query)
	if err != nil {
		return err
	}
	_, err = d.GetPermissionsByIds(tx, nil)
	return err
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoEscapedTransactions(r, root)
	})

	assert.False(t, report.Failed(), "a passed transaction failed the guard: %s", report.Text())
}

// TestNoEscapedTransactions_TheGuardIsFatalOnAnEmptyWalk pins the seam the guard's own comment
// names. A root holding no data package reports nothing, which is indistinguishable from a tree
// that hands every transaction on.
func TestNoEscapedTransactions_TheGuardIsFatalOnAnEmptyWalk(t *testing.T) {
	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoEscapedTransactions(r, t.TempDir())
	})

	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked no Go files under")
}
