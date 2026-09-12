package integrationtests

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestIntegration_UserFixturesDrawUniqueEmails refuses a hardcoded address in a
// models.User fixture anywhere in this tier.
//
// users.email is UNIQUE, and a fixture address is only safe while every row
// carrying it is deleted again. Two things make that assumption fail. Within a
// run, two fixtures sharing one address collide the moment either one's cleanup
// is missed -- which is how api_users_search_test.go's helper used to fail, three
// fixed addresses shared by five tests, where one missed cleanup cascaded into
// every later caller. Across runs, run-tests.sh drops the sqlite file on its EXIT
// trap but never drops goiabada_integration on mysql, postgres or mssql, so a row
// leaked there fails the same test on every run afterwards, with a UNIQUE
// violation raised from a fixture rather than from the behaviour under test.
//
// A cleanup can always be missed -- a t.FailNow between the insert and the defer,
// a panic, a killed run -- so the guard is on the address rather than on the
// cleanup. uniqueEmail(addr) keeps the descriptive literal, so a leftover row
// still names the test that wrote it, and adds a run that makes two calls of it
// distinct.
//
// The rule is deliberately scoped to models.User composite literals, which is
// what reaches database.CreateUser. An address in an api.*Request literal is
// exempt, because the five that remain in this tier all sit in requests asserted
// to be rejected (400, 401, 404): nothing reaches the database, and in two of
// them the literal text -- 65 bytes, over the validator's limit of 60 -- is the
// thing under test. A request that is expected to succeed persists its address
// like any fixture and is written with uniqueEmail by hand.
//
// The instrument's limit, stated because it decides what this file is worth: it
// asserts a spelling is absent, not that the replacement is correct. An address
// assembled at run time from a constant is invisible to it. That is chosen: this
// regression arrives by copy-paste from a neighbouring test, and a copy carries
// the literal.
func TestIntegration_UserFixturesDrawUniqueEmails(t *testing.T) {
	// go test runs with the package directory as the working directory. It is a
	// variable rather than an inline argument so a mutation can point the walk at
	// a tree with no fixtures in it and show the floor below is live.
	root := "."

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading the tier: %v", err)
	}

	fset := token.NewFileSet()
	literals, fixtures := 0, 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(root, entry.Name())
		file, pErr := parser.ParseFile(fset, path, nil, 0)
		if pErr != nil {
			t.Fatalf("parsing %s: %v", path, pErr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isModelsUser(lit.Type) {
				return true
			}
			fixtures++
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if name, ok := kv.Key.(*ast.Ident); !ok || name.Name != "Email" {
					continue
				}
				value, ok := kv.Value.(*ast.BasicLit)
				if !ok || value.Kind != token.STRING {
					continue
				}
				addr, uErr := strconv.Unquote(value.Value)
				if uErr != nil || !strings.Contains(addr, "@") {
					continue
				}
				literals++
				t.Errorf("%s:%d: models.User fixture hardcodes the address %q. "+
					"users.email is UNIQUE and a leaked row outlives its run on "+
					"mysql, postgres and mssql, so every later run collides on it; "+
					"write uniqueEmail(%q) instead",
					filepath.ToSlash(path), fset.Position(value.Pos()).Line, addr, addr)
			}
			return true
		})
	}

	if literals != 0 {
		return
	}
	// A walk that covers nothing passes while guarding nothing, which is how this
	// kind of instrument dies quietly. The floor is the number of models.User
	// literals the tier held when the sweep landed, rounded down hard: it catches
	// a walk pointed at the wrong tree or a parser that silently stopped, without
	// failing every time a test is added or removed.
	if fixtures < 100 {
		t.Errorf("walked %d models.User fixtures, which is too few for this tier to "+
			"have been read; the walk is looking at the wrong tree", fixtures)
	}
}

// isModelsUser reports whether a composite literal's type is models.User, which
// is the fixture shape that reaches database.CreateUser. It accepts the bare
// literal; &models.User{...} is an ast.UnaryExpr wrapping the same node, which
// ast.Inspect reaches on its own.
func isModelsUser(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "User" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "models"
}

// TestIntegration_UniqueEmailDrawsADistinctAddress pins uniqueEmail itself.
//
// The lint above asserts the spelling, and the fixtures assert their behaviour
// through it, but neither notices a uniqueEmail that returns its argument
// unchanged: the call sites read the same, and every fixture still passes
// because no two of them share a literal any more. This is the only test that
// fails on that, which is why it exists.
func TestIntegration_UniqueEmailDrawsADistinctAddress(t *testing.T) {
	const addr = "testuser@attr-update-validation.test"

	first, second := uniqueEmail(addr), uniqueEmail(addr)
	if first == second {
		t.Fatalf("two calls returned the same address %q, so fixtures still collide", first)
	}
	if first == addr {
		t.Fatalf("the address came back unchanged as %q", first)
	}

	for _, got := range []string{first, second} {
		// The literal survives in the result, which is the whole reason a fixture
		// keeps spelling a descriptive address: a row left behind still names the
		// test that wrote it.
		if !strings.HasPrefix(got, "testuser-") || !strings.HasSuffix(got, "@attr-update-validation.test") {
			t.Errorf("%q does not carry its label: the local part and the domain must both survive", got)
		}
		if strings.Count(got, "@") != 1 {
			t.Errorf("%q is not a single address", got)
		}
		// validators.email_validator refuses an address over 60 bytes, and fixtures
		// reach the endpoints that run it. This is the tier's longest label, so the
		// run added here has to leave it inside the limit.
		if len(got) > 60 {
			t.Errorf("%q is %d bytes, over the validator's limit of 60", got, len(got))
		}
	}
}
