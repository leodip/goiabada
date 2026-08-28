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
// d.CommonDB.<same name>(...) is treated as divergent, and this package may not take it on a
// *CommonDatabase anywhere. That over-approximates, deliberately. A dialect method that diverges
// for a reason unrelated to the caller is still a method whose behaviour depends on which engine
// is running, and a self-call to one is still engine-dependent behaviour written as though it
// were not, so it is worth a look either way.
//
// WHAT COUNTS AS THE CALL is wider than d.M(...) on the receiver, and deliberately so. A guard
// keyed to one spelling guards the spelling rather than the defect: x := d; x.M(...), a
// package-level helper taking *CommonDatabase, a closure capturing either, and the method value
// f := d.M all resolve statically to the same common implementation and cost the same two engines
// the same wrong SQL, while reading no more suspiciously than the shape that actually shipped. So
// selfCalls tracks the names known to hold a *CommonDatabase rather than the receiver's name, and
// states there what remains outside it.
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
			offenders = append(offenders, call.pos+": ."+call.method+" on a *CommonDatabase takes "+
				"the MySQL/SQLite implementation always, but "+strings.Join(owners, " and ")+
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

// selfCalls returns every method this package takes on a *CommonDatabase value, wherever the value
// came from and whether or not the result is called on the spot.
//
// It tracks NAMES KNOWN TO HOLD ONE rather than the enclosing method's receiver: a receiver
// declared *CommonDatabase, a parameter declared *CommonDatabase on a method, a plain function or
// a function literal, and any local aliased from one of those (x := d, var x = d, and a var
// declared *CommonDatabase outright). A function literal inherits the names its enclosing function
// had, because a closure over d is d. Every selector taken on such a name is reported, so the
// method value f := d.M counts as much as the call d.M(...) does; the value is the dangerous part
// and calling it later is a formality.
//
// WHAT IS STILL OUTSIDE IT, by construction rather than by oversight: a *CommonDatabase reached
// through a struct field, a map, a slice, or the return of a call, where no name in the function
// says what the value is. Closing that class needs go/types over a loaded package instead of a
// parse of one, which means golang.org/x/tools, a dependency this repository is deliberately
// shedding rather than adding (#268-#281). The trade is worth naming: what is covered is every
// shape a person writes by hand while believing they are calling the method that runs, and what is
// not is the shapes where the value's type is already invisible to the reader too.
//
// The over-approximation also runs the other way, since a selector is matched by name alone: a
// FIELD on CommonDatabase sharing a name with a divergent dialect method would be reported. There
// are three fields (DB, Flavor, logSQL), none of them a method name on either dialect, so the case
// is theoretical today and a false report would name a line and be dismissed in a second.
func selfCalls(t *testing.T, dir string) []selfCall {
	t.Helper()

	out := []selfCall{}
	for _, file := range goFiles(t, dir) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			holders := map[string]bool{}
			addCommonDatabaseNames(holders, fn.Recv)
			addCommonDatabaseNames(holders, fn.Type.Params)
			scanForSelfCalls(holders, fn.Body, &out)
		}
	}
	return out
}

// addCommonDatabaseNames records every name in fields declared *CommonDatabase. An unnamed or
// blank one cannot be called through, so there is nothing to record.
func addCommonDatabaseNames(holders map[string]bool, fields *ast.FieldList) {
	if fields == nil {
		return
	}
	for _, field := range fields.List {
		if !isCommonDatabasePointer(field.Type) {
			continue
		}
		for _, name := range field.Names {
			if name.Name != "_" {
				holders[name.Name] = true
			}
		}
	}
}

// isCommonDatabasePointer reports whether expr is written *CommonDatabase. Inside this package the
// type is always spelled unqualified, so there is no selector form to accept.
func isCommonDatabasePointer(expr ast.Expr) bool {
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	ident, ok := star.X.(*ast.Ident)
	return ok && ident.Name == "CommonDatabase"
}

// scanForSelfCalls walks one function body carrying the names known to hold a *CommonDatabase,
// growing that set as aliases appear and reporting the selectors taken on any of them. The walk is
// pre-order, which is the order Go requires anyway: an alias is declared before it can be used.
//
// It descends into function literals itself, with a copy of the current names, and then stops the
// outer walk entering them a second time. Copying rather than sharing keeps a parameter that
// shadows an outer name from leaking back out.
func scanForSelfCalls(holders map[string]bool, body *ast.BlockStmt, out *[]selfCall) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			inner := map[string]bool{}
			for name := range holders {
				inner[name] = true
			}
			addCommonDatabaseNames(inner, node.Type.Params)
			scanForSelfCalls(inner, node.Body, out)
			return false

		case *ast.AssignStmt:
			// x := d, and x = d. Only a bare name on the right aliases the value; anything
			// else is a call or a field read, which is the class named in selfCalls' comment.
			for i, rhs := range node.Rhs {
				if i >= len(node.Lhs) {
					break
				}
				ident, ok := rhs.(*ast.Ident)
				if !ok || !holders[ident.Name] {
					continue
				}
				if lhs, ok := node.Lhs[i].(*ast.Ident); ok && lhs.Name != "_" {
					holders[lhs.Name] = true
				}
			}

		case *ast.ValueSpec:
			// var x *CommonDatabase, whatever it is assigned, and var x = d.
			for i, name := range node.Names {
				if name.Name == "_" {
					continue
				}
				if isCommonDatabasePointer(node.Type) {
					holders[name.Name] = true
					continue
				}
				if i < len(node.Values) {
					if ident, ok := node.Values[i].(*ast.Ident); ok && holders[ident.Name] {
						holders[name.Name] = true
					}
				}
			}

		case *ast.SelectorExpr:
			ident, ok := node.X.(*ast.Ident)
			if !ok || !holders[ident.Name] {
				return true
			}
			*out = append(*out, selfCall{
				method: node.Sel.Name,
				pos:    fileSet.Position(node.Sel.Pos()).String(),
			})
		}
		return true
	})
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
