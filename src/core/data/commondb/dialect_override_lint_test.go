package commondb

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestCommonDatabase_NoSelfCallToAnOverriddenMethod is the structural half of the defect the
// final review of #283 found: a method call this package makes on its own receiver can never
// reach a dialect's override of that method, and on two of the four engines the override is the
// only implementation that works.
//
// WHY THE CALL CANNOT REACH THE OVERRIDE. PostgresDatabase and MsSQLDatabase hold
// *CommonDatabase as a named field, CommonDB, rather than embedding it, and they satisfy the
// Database interface by declaring all 212 methods themselves. Most are one-line delegations to
// d.CommonDB.X(...); a few are not, because the engine needs different SQL. Go resolves
// d.X(...) inside this package against *CommonDatabase at compile time, so a self-call always
// takes the common implementation whatever the caller's real dialect is. There is no dynamic
// dispatch to fall back on.
//
// WHAT THAT COSTS, measured rather than imagined. commondb.BackfillLowercaseEmails called
// d.CreateAuditLog to record a forced logout. CreateAuditLog ends at result.LastInsertId(),
// which is exactly why the two engines override it with RETURNING id and OUTPUT INSERTED.id:
// pgx's stdlib wrapper and go-mssqldb both refuse that call. So on PostgreSQL and SQL Server the
// audit row landed and committed, the id read then failed, and the pass logged
// "failed to persist audit log to database" over a row that was in fact persisted. Every test
// stayed green, because a test can only see that the row exists. The cost was not the row: it
// was that a real persistence failure became indistinguishable from normal operation, on two of
// four engines, in the one table an operator audits.
//
// THE FIX FOR THAT CALL SITE WAS ONE FUNCTION. This test is here because nothing stopped the
// next one. The trap is invisible in review (the call reads like any other), invisible in the
// type system (it compiles, and it is the right method name), and invisible to the whole
// four-engine test suite unless a test happens to assert on log output. A caller that actually
// used the returned id would get a hard error rather than a false alarm.
//
// THE BOUNDARY, stated because it decides what this file is worth. It compares method NAMES: a
// name declared by either dialect with a body that is not a single delegation to
// d.CommonDB.<same name>(...) is treated as divergent, and this package may not call it on
// itself. That over-approximates, deliberately. A dialect method that diverges for a reason
// unrelated to the caller is still a method whose behaviour depends on which engine is running,
// and a self-call to one is still engine-dependent behaviour written as though it were not, so
// it is worth a look either way. What it does NOT see is a call made through a value that is not
// the receiver, or a method name assembled at run time; neither is how this regression happens.
// The way it happens is somebody writing d.SomethingObvious(...) in this package, which is
// exactly the shape below.
func TestCommonDatabase_NoSelfCallToAnOverriddenMethod(t *testing.T) {
	divergent := map[string][]string{}
	for _, dialect := range []struct{ dir, recvType string }{
		{"../postgresdb", "PostgresDatabase"},
		{"../mssqldb", "MsSQLDatabase"},
	} {
		for name := range divergentMethods(t, dialect.dir, dialect.recvType) {
			divergent[name] = append(divergent[name], dialect.recvType)
		}
	}
	if len(divergent) == 0 {
		t.Fatal("no divergent dialect method was found at all, so this test could not fail and is not measuring anything; the parse or the delegation shape has changed")
	}

	offenders := []string{}
	for _, call := range selfCalls(t, ".") {
		if owners, ok := divergent[call.method]; ok {
			sort.Strings(owners)
			offenders = append(offenders, call.pos+": d."+call.method+"(...) takes the "+
				"MySQL/SQLite implementation always, but "+strings.Join(owners, " and ")+
				" override it")
		}
	}

	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("%d self-call(s) in commondb resolve to an implementation two engines replace:\n  %s\n\n"+
			"Each one runs the wrong SQL on the engine that overrode it, silently. Give this package "+
			"its own unexported helper that does what the caller actually needs (see "+
			"insertAuditLogWithoutId, which exists for this reason), or take the value through the "+
			"Database interface where the override applies.",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}

// divergentMethods returns the methods one dialect declares on recvType whose body is anything
// other than a single delegation to d.CommonDB.<same name>(...).
func divergentMethods(t *testing.T, dir string, recvType string) map[string]bool {
	t.Helper()

	out := map[string]bool{}
	for _, file := range goFiles(t, dir) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Body == nil {
				continue
			}
			star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			ident, ok := star.X.(*ast.Ident)
			if !ok || ident.Name != recvType {
				continue
			}
			if !delegatesToCommonDB(fn) {
				out[fn.Name.Name] = true
			}
		}
	}
	return out
}

// delegatesToCommonDB reports whether fn's whole body is one statement handing the same method
// name to the embedded common implementation, which is the shape that makes an override no
// override at all.
func delegatesToCommonDB(fn *ast.FuncDecl) bool {
	if len(fn.Body.List) != 1 {
		return false
	}

	var call *ast.CallExpr
	switch stmt := fn.Body.List[0].(type) {
	case *ast.ReturnStmt:
		if len(stmt.Results) != 1 {
			return false
		}
		call, _ = stmt.Results[0].(*ast.CallExpr)
	case *ast.ExprStmt:
		call, _ = stmt.X.(*ast.CallExpr)
	}
	if call == nil {
		return false
	}

	// d.CommonDB.<name>(...)
	outer, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || outer.Sel.Name != fn.Name.Name {
		return false
	}
	inner, ok := outer.X.(*ast.SelectorExpr)
	if !ok || inner.Sel.Name != "CommonDB" {
		return false
	}
	return true
}

type selfCall struct {
	method string
	pos    string
}

// selfCalls returns every call this package makes on a *CommonDatabase receiver, as d.X(...).
func selfCalls(t *testing.T, dir string) []selfCall {
	t.Helper()

	out := []selfCall{}
	for _, file := range goFiles(t, dir) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Body == nil {
				continue
			}
			star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			ident, ok := star.X.(*ast.Ident)
			if !ok || ident.Name != "CommonDatabase" {
				continue
			}
			// An unnamed receiver cannot be called through, so there is nothing to find.
			if len(fn.Recv.List[0].Names) != 1 {
				continue
			}
			receiver := fn.Recv.List[0].Names[0].Name
			if receiver == "_" {
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
				x, ok := sel.X.(*ast.Ident)
				if !ok || x.Name != receiver {
					return true
				}
				out = append(out, selfCall{
					method: sel.Sel.Name,
					pos:    fileSet.Position(sel.Sel.Pos()).String(),
				})
				return true
			})
		}
	}
	return out
}

// fileSet is shared so a position printed in a failure names the file it came from.
var fileSet = token.NewFileSet()

// goFiles parses every non-test Go source in dir. Test sources are excluded on purpose: a test
// may call anything it likes, and only shipped code can carry this defect to an operator.
func goFiles(t *testing.T, dir string) []*ast.File {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("unable to read %s, which this guard has to enumerate in full: %v", dir, err)
	}

	out := []*ast.File{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("unable to parse %s: %v", filepath.Join(dir, name), err)
		}
		out = append(out, file)
	}
	if len(out) == 0 {
		t.Fatalf("no Go source found in %s, so this guard would pass by finding nothing", dir)
	}
	return out
}
