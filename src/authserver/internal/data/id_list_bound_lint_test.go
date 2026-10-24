package data

// The one place the repository is held to "an id-list lookup reads its ids in the batches one
// statement can carry".
//
// Every id in an IN list is a bound parameter, and SQL Server refuses a statement carrying more
// than 2,100 of them with error 8003. A lookup that puts a caller's whole list into one statement
// therefore answers a valid request with an error once the list is long enough, which is what the
// three session list endpoints did until #373 bounded GetClientsByIds, and what twelve more
// lookups in the same package went on doing because the fix was made where somebody noticed the
// crash. commondb.forEachIdBatch is where the budget lives now, and this is what keeps the
// thirteenth from being written without it.
//
// The rule is decidable from syntax: a function in commondb that builds an IN list must also call
// forEachIdBatch. It is stated at the function rather than at the call because the two shapes in
// the package differ -- ten pass a literal to forEachIdBatch directly and readEmailGroup passes a
// variable holding one -- and both are the same fact about the function.
//
// What it cannot see is a function that calls forEachIdBatch and then builds its IN list from the
// whole list anyway. That one is caught by the data tier, which asks each lookup for more ids than
// one statement can bind and expects its rows: TestGetClientsByIds_MoreIdsThanOneStatementCanCarry
// and its twelve siblings.
//
// It reads and parses files and nothing else: no database, no git, no network, so it runs in the
// authserver internal tier on every CI job rather than only the four database ones.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unboundedIdList is one function that builds an IN list without reaching the batching helper.
type unboundedIdList struct {
	// file is relative to the root the walk started from, forward slashes.
	file     string
	line     int
	function string
}

// findUnboundedIdLists walks root for non-test Go files and reports every function whose body
// contains a call that writes an IN list and no call to forEachIdBatch. One call writes one:
// inList, the helper every statement spells its IN list with, called as a function or as a method
// (#644). Until #644 a method named In did too, which is how the query builder the data layer used
// then spelled an IN list on a select builder and on an update builder alike.
//
// It returns the number of functions that build an IN list at all, not the number of files, so an
// empty walk and a walk that reached files holding no IN list are the same answer: nothing was
// checked.
func findUnboundedIdLists(root string) ([]unboundedIdList, int, error) {
	var findings []unboundedIdList
	builders := 0

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
			// A file that does not parse is a compile error the build tier owns, and reporting it
			// here would send the reader to the wrong place.
			return nil
		}

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			inLine, batched := 0, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					if fun.Sel.Name == "inList" && inLine == 0 {
						inLine = fset.Position(call.Pos()).Line
					}
				case *ast.Ident:
					if fun.Name == "inList" && inLine == 0 {
						inLine = fset.Position(call.Pos()).Line
					}
					if fun.Name == "forEachIdBatch" {
						batched = true
					}
				}
				return true
			})
			if inLine == 0 {
				continue
			}
			builders++
			if batched {
				continue
			}
			findings = append(findings, unboundedIdList{file: rel, line: inLine, function: fn.Name.Name})
		}
		return nil
	})

	return findings, builders, err
}

// TestIdListsAreBoundedByOneStatement holds the real tree to the rule.
func TestIdListsAreBoundedByOneStatement(t *testing.T) {
	assertIdListsAreBounded(t, filepath.Join(guard.SourceRoot(t), "authserver", "internal", "data", "commondb"))
}

// assertIdListsAreBounded is the reporting half, taking the root as a parameter and failing
// through a guard.Reporter so a rule test can drive it against a fixture tree. Without that
// seam these lines are reached only by the call above, which walks a tree that is clean, so a
// defect in them disables the guard with nothing going red.
func assertIdListsAreBounded(r guard.Reporter, root string) {
	r.Helper()

	findings, builders, err := findUnboundedIdLists(root)
	if err != nil {
		r.Fatalf("walking %s: %v", root, err)
	}
	// A root holding no IN list at all checks nothing and would otherwise pass, which is the one
	// way a guard like this fails silently in the direction that matters.
	if builders == 0 {
		r.Fatalf("found no IN lists under %s; inList's name or the package layout has moved", root)
	}

	if len(findings) == 0 {
		return
	}
	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		lines = append(lines, f.file+":"+strconv.Itoa(f.line)+": "+f.function)
	}
	sort.Strings(lines)
	r.Errorf("%d of %d function(s) building an IN list do not reach forEachIdBatch:\n\t%s\n\n"+
		"Issue the query inside forEachIdBatch(ids, func(batch []int64) error { ... }) and build "+
		"the IN list from batch. Every id in an IN list is a bound parameter, and SQL Server "+
		"refuses a statement carrying more than 2,100 of them with error 8003, so an unbounded "+
		"list answers a valid request with an error once the caller holds enough ids (#373). The "+
		"new lookup also owes a data tier case that asks for more ids than one statement can bind "+
		"and expects its rows, in the shape of TestGetClientsByIds_MoreIdsThanOneStatementCanCarry.",
		len(findings), builders, strings.Join(lines, "\n\t"))
}

// TestIdListsAreBounded_TheCheckerTellsABatchedLookupFromAnUnboundedOne is the synthetic half: a
// temp tree with each shape the real package contains, so a checker that has quietly stopped
// matching anything is caught here rather than trusted.
func TestIdListsAreBounded_TheCheckerTellsABatchedLookupFromAnUnboundedOne(t *testing.T) {
	root := t.TempDir()

	// Accepted: the literal passed straight to the helper, which is how most of the lookups read.
	writeLintFixture(t, root, "batched.go", "package commondb\n\n"+
		"func forEachIdBatch(ids []int64, fn func(batch []int64) error) error { return fn(ids) }\n\n"+
		"func inList(dialect string, column string, first, n int) string { return column }\n\n"+
		"func batched(ids []int64) error {\n"+
		"\treturn forEachIdBatch(ids, func(batch []int64) error {\n"+
		"\t\t_ = \"SELECT id FROM t WHERE \" + inList(\"sqlite\", \"id\", 1, len(batch))\n"+
		"\t\treturn nil\n"+
		"\t})\n"+
		"}\n")

	// Accepted: the literal held in a variable and handed over afterwards.
	writeLintFixture(t, root, "indirect.go", "package commondb\n\n"+
		"func indirect(ids []int64) error {\n"+
		"\tread := func(batch []int64) error {\n"+
		"\t\t_ = inList(\"mysql\", \"id\", 1, len(batch))\n"+
		"\t\treturn nil\n"+
		"\t}\n"+
		"\treturn forEachIdBatch(ids, read)\n"+
		"}\n")

	// Accepted: a function with no IN list at all is not a lookup.
	writeLintFixture(t, root, "unrelated.go", "package commondb\n\n"+
		"func unrelated() string { return \"SELECT id FROM t WHERE id = ?\" }\n")

	// Accepted: a test file, which may query however it likes.
	writeLintFixture(t, root, "lookup_test.go", "package commondb\n\n"+
		"func fixture(ids []int64) string { return inList(\"sqlite\", \"id\", 1, len(ids)) }\n")

	// Not an IN list: a method named In. It was the query builder's spelling of one, and the
	// builder is gone (#644), so a method of that name is whatever its own type says it is.
	writeLintFixture(t, root, "builder_in.go", "package commondb\n\n"+
		"type set interface{ In(string, ...interface{}) bool }\n\n"+
		"func member(s set, ids []int64) bool { return s.In(\"id\", ids) }\n")

	// Reported: an IN list written with inList over the caller's whole list, as a function and
	// as a method.
	writeLintFixture(t, root, "unbounded.go", "package commondb\n\n"+
		"func unbounded(ids []int64) string {\n"+
		"\treturn \"SELECT id FROM t WHERE \" + inList(\"sqlite\", \"id\", 1, len(ids))\n"+
		"}\n\n"+
		"func unboundedMethod(d db, ids []int64) string {\n"+
		"\treturn d.inList(\"id\", len(ids))\n"+
		"}\n")

	findings, builders, err := findUnboundedIdLists(root)
	require.NoError(t, err)
	assert.Equal(t, 4, builders, "every non-test function building an IN list is counted, and only those")
	assert.Equal(t, []unboundedIdList{
		{file: "unbounded.go", line: 4, function: "unbounded"},
		{file: "unbounded.go", line: 8, function: "unboundedMethod"},
	}, findings)
}

// TestIdListsAreBounded_TheGuardFailsOnAnUnboundedLookup is the third half, and the one the two
// above leave out. Both assert on what findUnboundedIdLists returned; the lines that turn a
// finding into a failure are reached only by TestIdListsAreBoundedByOneStatement, which walks a
// tree that is clean, so blinding them disables the guard with nothing going red.
func TestIdListsAreBounded_TheGuardFailsOnAnUnboundedLookup(t *testing.T) {
	root := t.TempDir()
	writeLintFixture(t, root, "lookup.go", "package commondb\n\n"+
		"func inList(dialect string, column string, first, n int) string { return column }\n\n"+
		"func unbounded(ids []int64) string {\n"+
		"\treturn inList(\"sqlite\", \"id\", 1, len(ids))\n"+
		"}\n")

	report := guard.Run(func(r guard.Reporter) {
		assertIdListsAreBounded(r, root)
	})

	require.True(t, report.Failed(), "an unbounded IN list passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "lookup.go:6: unbounded")
	assert.Contains(t, report.Text(), "forEachIdBatch")
	assert.Contains(t, report.Text(), "#373")
}

// TestIdListsAreBounded_TheGuardPassesABatchedLookup is the other direction, over the shape the
// rule exists to admit.
func TestIdListsAreBounded_TheGuardPassesABatchedLookup(t *testing.T) {
	root := t.TempDir()
	writeLintFixture(t, root, "lookup.go", "package commondb\n\n"+
		"func inList(dialect string, column string, first, n int) string { return column }\n\n"+
		"func forEachIdBatch(ids []int64, fn func(batch []int64) error) error { return fn(ids) }\n\n"+
		"func batched(ids []int64) error {\n"+
		"\treturn forEachIdBatch(ids, func(batch []int64) error {\n"+
		"\t\t_ = inList(\"sqlite\", \"id\", 1, len(batch))\n"+
		"\t\treturn nil\n"+
		"\t})\n"+
		"}\n")

	report := guard.Run(func(r guard.Reporter) {
		assertIdListsAreBounded(r, root)
	})

	assert.False(t, report.Failed(), "a batched lookup failed the guard: %s", report.Text())
}

// TestIdListsAreBounded_TheGuardIsFatalOnAWalkThatFoundNoInList pins the seam the guard's own
// comment names. A root holding no IN list reports nothing, which is indistinguishable from a
// package whose every lookup is batched.
func TestIdListsAreBounded_TheGuardIsFatalOnAWalkThatFoundNoInList(t *testing.T) {
	report := guard.Run(func(r guard.Reporter) {
		assertIdListsAreBounded(r, t.TempDir())
	})

	require.True(t, report.Stopped, "a walk that found no IN list must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "found no IN lists under")
}
