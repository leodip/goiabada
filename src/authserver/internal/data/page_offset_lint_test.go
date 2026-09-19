package data

// The one place the data layer is held to "every SQL offset is computed by
// commondb.PageOffset".
//
// The rule exists because the offset is a multiplication over a number that
// arrives from a URL. Seven paginated reads each wrote out "(page-1)*pageSize",
// guarded only by "page < 1", so "?page=9223372036854775807" wrapped the
// product negative -- and a negative offset is not caught anywhere below. Six
// of the seven went through sqlbuilder, whose Offset drops the clause when its
// argument is negative (select.go:316), so those queries ran with no offset and
// returned the FIRST page's rows labelled as the page asked for. The seventh,
// the SQL Server audit log override, formats the number into the statement and
// has no such guard, so SQL Server rejected it and the API answered 500 (#305).
// PageOffset saturates instead, and every one of the seven returns the empty
// page that any other page past the end returns.
//
// That split is why this is a test rather than a comment: the two halves fail
// so differently that fixing the one you noticed leaves the other in place, and
// a reader fixing "the offset" by hand would have found six of the seven. The
// next paginated read, or the next dialect override, is the one this catches.
//
// It reads and parses files and nothing else: no database, no git, no network,
// so it runs in the authserver internal tier on every CI job rather than only
// the four database ones.

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

// pageOffsetOwner is the one file allowed to compute the offset: PageOffset's
// own body. Relative to the source root, forward slashes. It is not the place
// to put a second owner -- a read that cannot use PageOffset is a design
// question, not an exemption.
const pageOffsetOwner = "core/data/commondb/pagination.go"

// pageOffsetRoot is the subtree the rule covers: the data layer, where an
// offset becomes SQL. Page arithmetic above it lands in a slice or a page bar
// rather than in a query, and answers to its own rules.
const pageOffsetRoot = "core/data"

// handRolledOffset is one "(x - 1) * y" expression in a file that is not
// allowed to hold it.
type handRolledOffset struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
	text string
}

// findHandRolledOffsets walks root for non-test Go files under sub and reports
// every expression of the shape "(x - 1) * y", which is the page offset written
// out by hand.
//
// Both operands of the multiplication are examined, not just the left one:
// multiplication commutes, so "pageSize * (page - 1)" is the same offset and
// the same overflow, and a checker that reads only the left side is one
// keystroke away from being silently useless.
//
// Parentheses are unwrapped, so "(page-1)*size" and "((p)-1)*n" both match. The
// operand names are not inspected: the shape is the whole signal, and a read
// that wanted this arithmetic for something other than an offset would still be
// clearer calling PageOffset or naming what it is.
func findHandRolledOffsets(root, sub, owner string) ([]handRolledOffset, int, error) {
	var found []handRolledOffset
	files := 0

	err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(sub)),
		func(path string, d fs.DirEntry, err error) error {
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
			if rel == owner {
				return nil
			}

			fset := token.NewFileSet()
			file, pErr := parser.ParseFile(fset, path, nil, 0)
			if pErr != nil {
				// A file that does not parse is a compile error the build tier
				// owns, and reporting it here would send the reader to the
				// wrong place.
				return nil
			}
			files++

			ast.Inspect(file, func(n ast.Node) bool {
				mul, ok := n.(*ast.BinaryExpr)
				if !ok || mul.Op != token.MUL {
					return true
				}
				text, ok := offsetText(mul)
				if !ok {
					return true
				}
				found = append(found, handRolledOffset{
					file: rel,
					line: fset.Position(mul.Pos()).Line,
					text: text,
				})
				return true
			})
			return nil
		})

	return found, files, err
}

// unparen strips the parentheses an expression is written with, so the shape is
// matched rather than the spelling.
func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// minusOne reports whether e is "x - 1", and returns the x if it is.
func minusOne(e ast.Expr) (ast.Expr, bool) {
	sub, ok := unparen(e).(*ast.BinaryExpr)
	if !ok || sub.Op != token.SUB {
		return nil, false
	}
	lit, ok := unparen(sub.Y).(*ast.BasicLit)
	if !ok || lit.Kind != token.INT || lit.Value != "1" {
		return nil, false
	}
	return sub.X, true
}

// offsetText reports whether the multiplication is a page offset, and renders
// it the way it is written -- either side may hold the subtraction -- so the
// failure sends the reader to the expression rather than to the file. It does
// not pull in a printer for that: the operand names around the operators are
// enough to recognise the line.
func offsetText(mul *ast.BinaryExpr) (string, bool) {
	if x, ok := minusOne(mul.X); ok {
		return "(" + identText(x) + " - 1) * " + identText(mul.Y), true
	}
	if y, ok := minusOne(mul.Y); ok {
		return identText(mul.X) + " * (" + identText(y) + " - 1)", true
	}
	return "", false
}

func identText(e ast.Expr) string {
	switch v := unparen(e).(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return identText(v.X) + "." + v.Sel.Name
	case *ast.BasicLit:
		return v.Value
	default:
		return "?"
	}
}

// TestNoHandRolledPageOffset holds the real tree to the rule.
func TestNoHandRolledPageOffset(t *testing.T) {
	assertNoHandRolledPageOffset(t, testutil.SourceRoot(t), pageOffsetRoot, pageOffsetOwner)
}

// assertNoHandRolledPageOffset is the reporting half, taking the root and the scope as parameters
// and failing through a testutil.Reporter so a rule test can drive it against a fixture tree.
// Without that seam these lines are reached only by the call above, which walks a tree that has
// been clean since #305.
func assertNoHandRolledPageOffset(r testutil.Reporter, root, sub, owner string) {
	r.Helper()

	found, files, err := findHandRolledOffsets(root, sub, owner)
	if err != nil {
		r.Fatalf("walking %s: %v", root, err)
	}
	// A root that somehow held no Go files walks nothing and would otherwise
	// pass, which is the one way a guard like this fails silently in the
	// direction that matters.
	if files == 0 {
		r.Fatalf("walked no Go files under %s/%s", root, sub)
	}

	if len(found) == 0 {
		return
	}
	lines := make([]string, 0, len(found))
	for _, f := range found {
		lines = append(lines, f.file+":"+itoa(f.line)+": "+f.text)
	}
	r.Errorf("%d hand-rolled page offset(s) under %s:\n\t%s\n\n"+
		"Compute the offset with commondb.PageOffset(page, pageSize) instead. The page number "+
		"arrives from a \"?page=\" query parameter, and at a page near math.MaxInt this product "+
		"wraps negative. Nothing below catches that: sqlbuilder drops the OFFSET clause when it "+
		"is negative, so the query returns the FIRST page's rows labelled as the page asked "+
		"for, and a dialect override that formats the number into SQL itself gets the engine's "+
		"refusal and a 500 (#305). PageOffset saturates at the largest offset that fits, which "+
		"is past the end of any table, so the read returns the empty page it should.",
		len(found), sub, strings.Join(lines, "\n\t"))
}

// TestNoHandRolledPageOffset_TheCheckerMatchesTheShapeAndNotTheSpelling is the
// synthetic half: a temp tree holding each shape the real tree contains, so a
// checker that has quietly stopped matching anything, or started matching the
// call that replaced it, is caught here rather than trusted.
func TestNoHandRolledPageOffset_TheCheckerMatchesTheShapeAndNotTheSpelling(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	}

	// Accepted: the call that replaced the arithmetic, in both the forms the
	// tree uses -- handed to the builder, and named first for a format string.
	write("core/data/commondb/group.go", `package commondb

func page(page, pageSize int) int {
	return PageOffset(page, pageSize)
}
`)
	write("authserver/internal/data/mssqldb/audit_log.go", `package mssqldb

import "fmt"

func page(page, pageSize int) string {
	offset := commondb.PageOffset(page, pageSize)
	return fmt.Sprintf("OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", offset, pageSize)
}
`)
	// Accepted: the owner's own body, which is where the arithmetic lives.
	write("core/data/commondb/pagination.go", `package commondb

func PageOffset(page, pageSize int) int {
	return (page - 1) * pageSize
}
`)
	// Accepted: arithmetic that is not this shape. Subtracting something other
	// than 1, and multiplying without subtracting, are not page offsets --
	// written both ways round, so widening the checker to both operands did not
	// widen what it matches.
	write("core/data/commondb/other.go", `package commondb

func sizes(a, b int) (int, int, int, int, int, int) {
	return (a - 2) * b, a * b, (a + 1) * b, b * (a - 2), b * a, b * (a + 1)
}
`)
	// Accepted: the identifier inside a comment and inside a string.
	write("core/data/commondb/comment.go", `package commondb

// A comment writing (page - 1) * pageSize is not arithmetic.
const message = "(page - 1) * pageSize"

func ok() string { return message }
`)
	// Accepted: outside the subtree the rule covers.
	write("adminconsole/internal/handlers/slice.go", `package handlers

func window(page, pageSize int) int {
	return (page - 1) * pageSize
}
`)

	// Rejected: the seven shapes the tree held, spelled every way they were.
	write("core/data/commondb/user.go", `package commondb

func offsetA(page, pageSize int) int {
	return (page - 1) * pageSize
}
`)
	write("core/data/commondb/user_session.go", `package commondb

func offsetB(p, n int) int {
	return (p-1)*n
}
`)
	write("authserver/internal/data/postgresdb/audit_log.go", `package postgresdb

func offsetC(page, pageSize int) int {
	offset := ((page) - 1) * pageSize
	return offset
}
`)
	write("authserver/internal/data/mysqldb/group.go", `package mysqldb

type params struct{ Page, Size int }

func offsetD(p params) int {
	return (p.Page - 1) * p.Size
}
`)
	// Rejected: the same offset with the operands the other way round. It is
	// the same arithmetic and the same overflow, and it is what a checker
	// reading only the left operand lets through.
	write("authserver/internal/data/sqlitedb/user.go", `package sqlitedb

func offsetE(page, pageSize int) int {
	return pageSize * (page - 1)
}
`)

	found, files, err := findHandRolledOffsets(root, pageOffsetRoot, pageOffsetOwner)
	require.NoError(t, err)
	require.NotZero(t, files)

	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, f.file+":"+itoa(f.line))
	}
	assert.ElementsMatch(t, []string{
		"core/data/commondb/user.go:4",
		"core/data/commondb/user_session.go:4",
		"authserver/internal/data/postgresdb/audit_log.go:4",
		"authserver/internal/data/mysqldb/group.go:6",
		"authserver/internal/data/sqlitedb/user.go:4",
	}, got, "the checker matched the wrong set")

	// And the failure names the expression, so the reader is sent to the line
	// rather than to the file.
	byFile := map[string]string{}
	for _, f := range found {
		byFile[f.file] = f.text
	}
	assert.Equal(t, "(page - 1) * pageSize", byFile["core/data/commondb/user.go"])
	assert.Equal(t, "(p.Page - 1) * p.Size", byFile["authserver/internal/data/mysqldb/group.go"])
	// And the commuted one is rendered the way it is written, rather than
	// silently normalised into the other order.
	assert.Equal(t, "pageSize * (page - 1)", byFile["authserver/internal/data/sqlitedb/user.go"])
}

// TestNoHandRolledPageOffset_TheGuardFailsOnArithmetic is the third half. The case above asserts on
// what findHandRolledOffsets returned; the lines that turn a match into a failure are reached only
// by TestNoHandRolledPageOffset, which walks a tree that has been clean since #305.
func TestNoHandRolledPageOffset_TheGuardFailsOnArithmetic(t *testing.T) {
	root := t.TempDir()
	writeLintFixture(t, root, "authserver/internal/data/mysqldb/users.go", `package mysqldb

func window(page, pageSize int) int {
	return (page - 1) * pageSize
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoHandRolledPageOffset(r, root, pageOffsetRoot, pageOffsetOwner)
	})

	require.True(t, report.Failed(), "hand-rolled offset arithmetic passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/data/mysqldb/users.go:4")
	assert.Contains(t, report.Text(), "commondb.PageOffset(page, pageSize)")
	assert.Contains(t, report.Text(), "#305")
}

// TestNoHandRolledPageOffset_TheGuardPassesTheHelper is the other direction, over the call that
// replaced the arithmetic.
func TestNoHandRolledPageOffset_TheGuardPassesTheHelper(t *testing.T) {
	root := t.TempDir()
	writeLintFixture(t, root, "authserver/internal/data/mysqldb/users.go", `package mysqldb

func window(page, pageSize int) int {
	return commondb.PageOffset(page, pageSize)
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoHandRolledPageOffset(r, root, pageOffsetRoot, pageOffsetOwner)
	})

	assert.False(t, report.Failed(), "a PageOffset call failed the guard: %s", report.Text())
}

// TestNoHandRolledPageOffset_TheGuardIsFatalOnAnEmptyWalk pins the seam, and this guard's scope
// makes it the likeliest of the four here to trip it: the walk is one subdirectory, so the Go
// moving out from under it empties the walk without emptying the repository.
func TestNoHandRolledPageOffset_TheGuardIsFatalOnAnEmptyWalk(t *testing.T) {
	root := t.TempDir()
	writeLintFixture(t, root, "core/data/notes.md", "the queries moved out of here\n")
	writeLintFixture(t, root, "core/elsewhere/users.go", "package elsewhere\n")

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoHandRolledPageOffset(r, root, pageOffsetRoot, pageOffsetOwner)
	})

	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked no Go files under")
	assert.Contains(t, report.Fatal, pageOffsetRoot, "the fatal names the scope that covered nothing")
}

// TestNoHandRolledPageOffset_AScopeThatIsNotThereIsFatalToo is the other way this guard's one
// subdirectory disappears, and it is answered as a walk error rather than as an empty scope. The
// two are worth telling apart: a directory holding no Go any more is a fact about the tree, and a
// directory that is not there at all is a scope constant nobody updated.
func TestNoHandRolledPageOffset_AScopeThatIsNotThereIsFatalToo(t *testing.T) {
	root := t.TempDir()
	writeLintFixture(t, root, "core/elsewhere/users.go", "package elsewhere\n")

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoHandRolledPageOffset(r, root, pageOffsetRoot, pageOffsetOwner)
	})

	require.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "walking ")
	assert.NotContains(t, report.Fatal, "walked no Go files")
}

// writeLintFixture writes one file into a fixture tree, creating its directories. The three lint
// guards in this package share it, and each of their reporting halves is driven through
// testutil.RunGuard against trees it builds.
func writeLintFixture(t *testing.T, root, rel, src string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
}
