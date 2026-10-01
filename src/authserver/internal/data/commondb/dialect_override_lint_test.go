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

	"github.com/leodip/goiabada/core/testutil"
)

// TestDatabase_NoSelfCallToAnOverriddenMethod is the structural half of the defect the
// final review of #283 found: a method call this package makes on its own receiver can never
// reach a dialect's override of that method, and on two of the four engines the override is the
// only implementation that works.
//
// WHY THE CALL CANNOT REACH THE OVERRIDE. The four engine adapters embed *Database and
// declare only the methods their engine needs different SQL for; everything else is promoted
// from this package (#416). Promotion is resolved at compile time and is not dispatch: Go
// resolves d.X(...) inside this package against *Database, so a self-call takes the
// common implementation whatever the caller's real dialect is. Embedding reads as though it
// were inheritance and is not, which is why the trap survived the shape change that removed
// the 801 hand-written delegations.
//
// WHAT THAT COSTS, measured rather than imagined. commondb.BackfillLowercaseEmails called
// d.CreateAuditLog to record a forced logout. CreateAuditLog ended at result.LastInsertId(),
// which is exactly why the two engines overrode it with RETURNING id and OUTPUT INSERTED.id:
// pgx's stdlib wrapper and go-mssqldb both refuse that call. So on PostgreSQL and SQL Server the
// audit row landed and committed, the id read then failed, and the pass logged
// "failed to persist audit log to database" over a row that was in fact persisted. Every test
// stayed green, because a test can only see that the row exists. The cost was not the row: it
// was that a real persistence failure became indistinguishable from normal operation, on two of
// four engines, in the one table an operator audits.
//
// THE FIX FOR THAT CALL SITE WAS ONE FUNCTION, an unexported insert that stopped at the
// statement instead of reading the id back. Both it and its caller are gone: #351 replaced the
// backfill with a migration and a pre-flight, so this package emits no audit event at all any
// more. This test is here because nothing stopped the next one. The trap is invisible in review
// (the call reads like any other), invisible in the type system (it compiles, and it is the
// right method name), and invisible to the whole four-engine test suite unless a test happens to
// assert on log output. A caller that actually used the returned id would get a hard error
// rather than a false alarm.
//
// THAT PARTICULAR DIVERGENCE IS GONE, and the guard is not. #416 gave Database an
// InsertReturningIdSQL hook, so the id an INSERT reports comes back through one shared helper and
// the fifty Create* overrides that carried the difference were deleted. A self-call to
// CreateAuditLog is safe today. The next divergent method is what this reads for.
//
// THE BOUNDARY, stated because it decides what this file is worth. It compares method NAMES: a
// name any dialect declares at all is treated as divergent, and this package may not take it on
// a *Database anywhere. Declaring one is the whole signal since #416, because embedding
// left a dialect no reason to write a method out except that the engine needs a different one.
// That over-approximates, deliberately. A dialect method that diverges for a reason unrelated
// to the caller is still a method whose behaviour depends on which engine is running, and a
// self-call to one is still engine-dependent behaviour written as though it were not, so it is
// worth a look either way.
//
// WHAT COUNTS AS THE CALL is wider than d.M(...) on the receiver, and deliberately so. A guard
// keyed to one spelling guards the spelling rather than the defect: x := d; x.M(...), a
// package-level helper taking *Database, a closure capturing either, and the method value
// f := d.M all resolve statically to the same common implementation and cost the overriding
// engines the same wrong SQL, while reading no more suspiciously than the shape that actually
// shipped. So selfCalls tracks the names known to hold a *Database rather than the
// receiver's name, and states there what remains outside it.
func TestDatabase_NoSelfCallToAnOverriddenMethod(t *testing.T) {
	// The dialects are located from the source root rather than by counting "../" from
	// here. #354 moved the four engine adapters to authserver/internal/data while commondb
	// stayed in core, so they stopped being siblings, and they are siblings again once #359
	// moves this package to sit beside them. The ascent is what every other tree-wide guard
	// in this repository uses, and it is the spelling that survives both moves; "../mssqldb"
	// survives neither, and worse, it never writes the path a move sweeps for, so the sweep
	// that repointed the other five constants could not have found it. This one was found by
	// running the tier.
	root := testutil.SourceRoot(t)
	divergent := map[string][]string{}
	// All four, not just the two #283 cost. Before #416 sqlitedb and mysqldb declared every
	// method, so "declares it" said nothing about them and the guard could only read the two
	// that held a named field. Now every dialect declares only its overrides, so all four
	// answer the same question and an override reaching one engine is as much a divergence as
	// one reaching two.
	for _, dialect := range []struct{ dir, recvType string }{
		{filepath.Join(root, "authserver", "internal", "data", "sqlitedb"), "SQLiteDatabase"},
		{filepath.Join(root, "authserver", "internal", "data", "mysqldb"), "MySQLDatabase"},
		{filepath.Join(root, "authserver", "internal", "data", "postgresdb"), "PostgresDatabase"},
		{filepath.Join(root, "authserver", "internal", "data", "mssqldb"), "MsSQLDatabase"},
	} {
		methods := divergentMethods(t, dialect.dir, dialect.recvType)
		// Per dialect and not only in total: every engine declares at least DeleteOldAuditLogs,
		// so an empty answer means recvType no longer names the adapter, and that engine's
		// overrides would drop out of the guard while the other three kept it passing (#438).
		if len(methods) == 0 {
			t.Fatalf("no method declared on *%s in %s; the adapter type was renamed and this table was not", dialect.recvType, dialect.dir)
		}
		for name := range methods {
			divergent[name] = append(divergent[name], dialect.recvType)
		}
	}

	// Every method here reaches the database through d.ExecSQL or d.QuerySQL, so a walk that finds
	// no selector on a *Database at all has stopped recognising the type, which is what renaming it
	// without isDatabasePointer would do, and it would then pass on any tree (#438).
	calls := selfCalls(t, ".")
	if len(calls) == 0 {
		t.Fatal("no selector taken on a *Database in commondb, so this test could not fail; isDatabasePointer no longer names the type")
	}

	offenders := []string{}
	for _, call := range calls {
		if owners, ok := divergent[call.method]; ok {
			sort.Strings(owners)
			offenders = append(offenders, call.pos+": ."+call.method+" on a *Database takes "+
				"the common implementation always, but "+strings.Join(owners, " and ")+
				" override it")
		}
	}

	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("%d self-call(s) in commondb resolve to an implementation an engine replaces:\n  %s\n\n"+
			"Each one runs the wrong SQL on the engine that overrode it, silently. Give this package "+
			"its own unexported helper that does what the caller actually needs and no more -- the "+
			"divergence is usually a value the caller never wanted -- or take the value through the "+
			"Database interface, where the override applies.",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}

// divergentMethods returns every method one dialect declares on recvType. Since #416 the
// adapters embed *Database, so a method written out by hand is an override by
// construction: there is nothing else it could be.
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
			out[fn.Name.Name] = true
		}
	}
	return out
}

type selfCall struct {
	method string
	pos    string
}

// selfCalls returns every method this package takes on a *Database value, wherever the value
// came from and whether or not the result is called on the spot.
//
// It tracks NAMES KNOWN TO HOLD ONE rather than the enclosing method's receiver: a receiver
// declared *Database, a parameter declared *Database on a method, a plain function or
// a function literal, and any local aliased from one of those (x := d, var x = d, and a var
// declared *Database outright). A function literal inherits the names its enclosing function
// had, because a closure over d is d. Every selector taken on such a name is reported, so the
// method value f := d.M counts as much as the call d.M(...) does; the value is the dangerous part
// and calling it later is a formality.
//
// WHAT IS STILL OUTSIDE IT, by construction rather than by oversight: a *Database reached
// through a struct field, a map, a slice, or the return of a call, where no name in the function
// says what the value is. Closing that class needs go/types over a loaded package instead of a
// parse of one, which means golang.org/x/tools, a dependency this repository is deliberately
// shedding rather than adding (#268-#281). The trade is worth naming: what is covered is every
// shape a person writes by hand while believing they are calling the method that runs, and what is
// not is the shapes where the value's type is already invisible to the reader too.
//
// The over-approximation also runs the other way, since a selector is matched by name alone: a
// FIELD on Database sharing a name with a divergent dialect method would be reported. There
// are eight fields (DB, Flavor, logSQL, IsDeadlock, IsUniqueViolation, InsertReturningIdSQL,
// ExplicitIdInsertSQL, sleep), none of them a method name on any dialect, so the case
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
			addDatabaseNames(holders, fn.Recv)
			addDatabaseNames(holders, fn.Type.Params)
			scanForSelfCalls(holders, fn.Body, &out)
		}
	}
	return out
}

// addDatabaseNames records every name in fields declared *Database. An unnamed or
// blank one cannot be called through, so there is nothing to record.
func addDatabaseNames(holders map[string]bool, fields *ast.FieldList) {
	if fields == nil {
		return
	}
	for _, field := range fields.List {
		if !isDatabasePointer(field.Type) {
			continue
		}
		for _, name := range field.Names {
			if name.Name != "_" {
				holders[name.Name] = true
			}
		}
	}
}

// isDatabasePointer reports whether expr is written *Database. Inside this package the
// type is always spelled unqualified, so there is no selector form to accept.
func isDatabasePointer(expr ast.Expr) bool {
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	ident, ok := star.X.(*ast.Ident)
	return ok && ident.Name == "Database"
}

// scanForSelfCalls walks one function body carrying the names known to hold a *Database,
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
			addDatabaseNames(inner, node.Type.Params)
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
			// var x *Database, whatever it is assigned, and var x = d.
			for i, name := range node.Names {
				if name.Name == "_" {
					continue
				}
				if isDatabasePointer(node.Type) {
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
