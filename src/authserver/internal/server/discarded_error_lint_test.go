package server

// The one place the auth server is held to "a hash, an encryption or a key generation that failed
// is never mistaken for one that succeeded".
//
// The seeder hashed the first admin's password with `passwordHash, _ := passwordhash.Hash(...)`.
// An over-long GOIABADA_ADMIN_PASSWORD made bcrypt refuse, the blank identifier swallowed the
// refusal, and the admin was stored with an empty hash: an account nobody could sign in to, created
// by the one path that exists to make an account somebody can. #211 fixed the same shape by grep,
// and #409 found it again the same way. Each function listed here returns a zero value beside its
// error, and every one of those zero values is a valid thing to store: an empty hash, an empty
// ciphertext, a key of no bytes.
//
// errcheck, which the lint tier runs, already refuses a listed call used as a bare statement. It
// leaves the blank identifier alone unless check-blank is on, and check-blank would also refuse
// every deliberate `_ = f.Close()` in the tree, which is why this rule is a list and not a switch.
//
// It reads and parses files and nothing else: no database, no git, no network.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// discardedErrorScope is the tree the rule covers, relative to the source root, forward slashes.
// Every listed function is internal to the auth server, so no other module could name one.
const discardedErrorScope = "authserver"

// discardedErrorModuleParent is what a directory under the source root is prefixed with to make
// its import path: the auth server's module is github.com/leodip/goiabada/authserver, rooted at
// src/authserver.
const discardedErrorModuleParent = "github.com/leodip/goiabada/"

// discardedErrorFuncs is every function whose error may not be discarded, by import path. Each
// returns a value beside the error whose zero is storable: a hash, a ciphertext, a plaintext, a key
// or a key pair. A function joins the list when the same holds of it.
var discardedErrorFuncs = map[string][]string{
	"github.com/leodip/goiabada/authserver/internal/passwordhash": {"Hash"},
	"github.com/leodip/goiabada/authserver/internal/encryption": {
		"EncryptData", "DecryptData", "EncryptText", "DecryptText",
		"EncryptIDTokenHintJWE", "DecryptIDTokenHintJWE", "RandomKey",
	},
	"github.com/leodip/goiabada/authserver/internal/rsakey":      {"Generate"},
	"github.com/leodip/goiabada/authserver/internal/signingkeys": {"NewKeyPair", "ParsePrivateKey"},
}

// discardedError is one call whose error result is bound to the blank identifier.
type discardedError struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
	// fn is the function called, as package.Name.
	fn string
}

// findDiscardedErrors walks root/scope for non-test Go files and reports every assignment or var
// declaration whose single right-hand side calls a listed function and whose last left-hand name,
// the error's position, is the blank identifier. It returns the number of files it parsed, so the
// reporting half can tell "nothing to report" from "nothing was read".
//
// A call is resolved through the file's own imports rather than by spelling, so an alias cannot
// hide one and a same-named function in an unlisted package is not one. Inside a listed package a
// bare call to a listed name is the package calling itself, which is how the rotator calls
// NewKeyPair; a dot import is resolved the same way.
func findDiscardedErrors(root, scope string, listed map[string][]string) ([]discardedError, int, error) {
	start := filepath.Join(root, filepath.FromSlash(scope))

	var found []discardedError
	files := 0

	err := filepath.WalkDir(start, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if p != start && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}

		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns.
			return nil
		}
		files++

		rel, rErr := filepath.Rel(root, p)
		if rErr != nil {
			return rErr
		}
		rel = filepath.ToSlash(rel)

		resolve := discardedErrorResolver(file, discardedErrorModuleParent+path.Dir(rel), listed)
		report := func(pos token.Pos, lastName ast.Expr, value ast.Expr) {
			if ident, ok := lastName.(*ast.Ident); !ok || ident.Name != "_" {
				return
			}
			call, ok := ast.Unparen(value).(*ast.CallExpr)
			if !ok {
				return
			}
			if fn, ok := resolve(call.Fun); ok {
				found = append(found, discardedError{file: rel, line: fset.Position(pos).Line, fn: fn})
			}
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				if len(n.Rhs) == 1 && len(n.Lhs) > 0 {
					report(n.Pos(), n.Lhs[len(n.Lhs)-1], n.Rhs[0])
				}
			case *ast.ValueSpec:
				if len(n.Values) == 1 && len(n.Names) > 0 {
					report(n.Pos(), n.Names[len(n.Names)-1], n.Values[0])
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return found, files, nil
}

// discardedErrorResolver returns a function naming the listed function a call expression reaches
// from this file, as package.Name, or false.
func discardedErrorResolver(file *ast.File, ownPath string, listed map[string][]string) func(ast.Expr) (string, bool) {
	isListed := func(importPath, name string) bool {
		for _, n := range listed[importPath] {
			if n == name {
				return true
			}
		}
		return false
	}

	// The names this file binds to a listed package, and the listed packages it dot-imports.
	byName := map[string]string{}
	var bare []string
	if _, ok := listed[ownPath]; ok {
		bare = append(bare, ownPath)
	}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		if _, ok := listed[importPath]; !ok {
			continue
		}
		switch {
		case spec.Name == nil:
			// Every listed package's name is its directory's.
			byName[path.Base(importPath)] = importPath
		case spec.Name.Name == ".":
			bare = append(bare, importPath)
		case spec.Name.Name != "_":
			byName[spec.Name.Name] = importPath
		}
	}

	return func(fun ast.Expr) (string, bool) {
		switch fun := ast.Unparen(fun).(type) {
		case *ast.SelectorExpr:
			pkg, ok := fun.X.(*ast.Ident)
			if !ok {
				return "", false
			}
			importPath, ok := byName[pkg.Name]
			if ok && isListed(importPath, fun.Sel.Name) {
				return path.Base(importPath) + "." + fun.Sel.Name, true
			}
		case *ast.Ident:
			for _, importPath := range bare {
				if isListed(importPath, fun.Name) {
					return path.Base(importPath) + "." + fun.Name, true
				}
			}
		}
		return "", false
	}
}

// TestDiscardedErrors_NoneInTheAuthServer holds the real tree to the rule. It is #409 item 4 in
// its checkable form.
func TestDiscardedErrors_NoneInTheAuthServer(t *testing.T) {
	assertNoDiscardedErrors(t, testutil.SourceRoot(t), discardedErrorScope, discardedErrorFuncs)
}

// assertNoDiscardedErrors is the reporting half, taking the root, the scope and the list as
// parameters and failing through a testutil.Reporter so a rule test can drive it against a fixture
// tree. Without that seam these lines are reached only by the call above, which walks a tree that
// passes.
func assertNoDiscardedErrors(r testutil.Reporter, root, scope string, listed map[string][]string) {
	r.Helper()

	found, files, err := findDiscardedErrors(root, scope, listed)
	if err != nil {
		r.Fatalf("walking %s: %v", filepath.Join(root, filepath.FromSlash(scope)), err)
	}
	// A scope that somehow held no production Go files reads nothing and would otherwise pass.
	if files == 0 {
		r.Fatalf("read no production Go files under %s", scope)
	}

	if len(found) == 0 {
		return
	}
	lines := make([]string, 0, len(found))
	for _, f := range found {
		lines = append(lines, f.file+":"+strconv.Itoa(f.line)+": "+f.fn)
	}
	sort.Strings(lines)

	r.Errorf("%d call(s) under %s discard the error of a hash, an encryption or a key generation:\n\t%s\n\n"+
		"Each of these returns a zero value beside its error, and every one of those zero values is a "+
		"valid thing to store: an empty hash, an empty ciphertext, a key of no bytes. Handle the error. "+
		"The seeder stored its first admin with an empty password hash exactly this way (#409).",
		len(found), scope, strings.Join(lines, "\n\t"))
}

// TestDiscardedErrors_Finder_ReadsTheImportsAndNotTheSpelling is the synthetic half: a temp tree
// holding every shape the rule catches and every neighbour it must leave alone, so a finder that
// has quietly stopped matching anything is caught here rather than trusted.
func TestDiscardedErrors_Finder_ReadsTheImportsAndNotTheSpelling(t *testing.T) {
	root := t.TempDir()

	// Caught: the seeder's own shape, an aliased import, a dot import, a var declaration, a
	// reassignment, and a listed package calling itself by bare name.
	writeDiscardedErrorFixture(t, root, "authserver/internal/data/seeder.go", `package data

import (
	ph "github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/encryption"
)

var key, _ = encryption.RandomKey(32)

func seed(p string) {
	hash, _ := ph.Hash(p)
	_ = hash
	var ct []byte
	ct, _ = (encryption.EncryptData)(p)
	_, _ = encryption.DecryptData(ct)
}
`)
	writeDiscardedErrorFixture(t, root, "authserver/internal/bootstrap/keys.go", `package bootstrap

import . "github.com/leodip/goiabada/authserver/internal/rsakey"

func keys() {
	m, _ := Generate(1024, "kid")
	_ = m
}
`)
	writeDiscardedErrorFixture(t, root, "authserver/internal/signingkeys/rotator.go", `package signingkeys

func rotate() {
	kp, _ := NewKeyPair(1, 1024)
	_ = kp
}
`)

	// Passed: the error kept; the error kept while another result is discarded; a test file; a
	// same-named function in an unlisted package; a listed name reached through an unlisted
	// package; an unlisted discard; a bare call to a listed name outside its package; and a
	// blank import.
	writeDiscardedErrorFixture(t, root, "authserver/internal/handlers/register.go", `package handlers

import (
	"os"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	other "github.com/leodip/goiabada/authserver/internal/otherhash"
	_ "github.com/leodip/goiabada/authserver/internal/encryption"
)

func Hash(string) (string, error) { return "", nil }

func register(p string) error {
	hash, err := passwordhash.Hash(p)
	if err != nil {
		return err
	}
	_ = hash
	_, err = signingkeys.ParsePrivateKey(nil)
	if err != nil {
		return err
	}
	h2, _ := other.Hash(p)
	h3, _ := Hash(p)
	n, _ := strconv.Atoi(p)
	f, _ := os.Open(p)
	_ = f.Close()
	_, _, _ = h2, h3, n
	return nil
}
`)
	writeDiscardedErrorFixture(t, root, "authserver/internal/passwordhash/passwordhash_test.go", `package passwordhash

func helper() {
	h, _ := Hash("x")
	_ = h
}
`)

	found, files, err := findDiscardedErrors(root, discardedErrorScope, discardedErrorFuncs)
	require.NoError(t, err)
	assert.Equal(t, 4, files, "the test file is not read, the other four are")

	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, f.file+":"+strconv.Itoa(f.line)+": "+f.fn)
	}
	assert.ElementsMatch(t, []string{
		"authserver/internal/data/seeder.go:8: encryption.RandomKey",
		"authserver/internal/data/seeder.go:11: passwordhash.Hash",
		"authserver/internal/data/seeder.go:14: encryption.EncryptData",
		"authserver/internal/data/seeder.go:15: encryption.DecryptData",
		"authserver/internal/bootstrap/keys.go:6: rsakey.Generate",
		"authserver/internal/signingkeys/rotator.go:4: signingkeys.NewKeyPair",
	}, got, "the finder matched the wrong set")
}

// TestDiscardedErrors_Guard_FailsOnADiscard is the third half. The case above asserts on what
// findDiscardedErrors returned; the lines that turn a finding into a failure are reached only by
// TestDiscardedErrors_NoneInTheAuthServer, which walks a tree that passes.
func TestDiscardedErrors_Guard_FailsOnADiscard(t *testing.T) {
	root := t.TempDir()
	writeDiscardedErrorFixture(t, root, "authserver/internal/data/seeder.go", `package data

import "github.com/leodip/goiabada/authserver/internal/passwordhash"

func seed(p string) string {
	hash, _ := passwordhash.Hash(p)
	return hash
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoDiscardedErrors(r, root, discardedErrorScope, discardedErrorFuncs)
	})

	require.True(t, report.Failed(), "the seeder's discarded hash error passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/data/seeder.go:6: passwordhash.Hash")
	assert.Contains(t, report.Text(), "#409")
}

// TestDiscardedErrors_Guard_PassesAKeptError is the other direction.
func TestDiscardedErrors_Guard_PassesAKeptError(t *testing.T) {
	root := t.TempDir()
	writeDiscardedErrorFixture(t, root, "authserver/internal/data/seeder.go", `package data

import "github.com/leodip/goiabada/authserver/internal/passwordhash"

func seed(p string) (string, error) {
	hash, err := passwordhash.Hash(p)
	if err != nil {
		return "", err
	}
	return hash, nil
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoDiscardedErrors(r, root, discardedErrorScope, discardedErrorFuncs)
	})

	assert.False(t, report.Failed(), "a kept error failed the guard: %s", report.Text())
}

// TestDiscardedErrors_Guard_IsFatalOnAnEmptyRead pins the seam: a walk that read nothing is a
// failure, not a clean pass.
func TestDiscardedErrors_Guard_IsFatalOnAnEmptyRead(t *testing.T) {
	root := t.TempDir()
	writeDiscardedErrorFixture(t, root, "authserver/README.md", "no Go here\n")
	writeDiscardedErrorFixture(t, root, "authserver/internal/data/seeder_test.go", "package data\n")

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoDiscardedErrors(r, root, discardedErrorScope, discardedErrorFuncs)
	})

	require.True(t, report.Stopped, "an empty read must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "read no production Go files under authserver")
}

// TestDiscardedErrors_EveryListedFunctionReturnsAnError holds the list to the real tree. A listed
// name that has been renamed or deleted guards nothing, and the finder cannot tell: it would match
// no call and report a clean tree. So each entry has to be a top-level function its package still
// declares, with error as its last result, which is the position the finder reads.
func TestDiscardedErrors_EveryListedFunctionReturnsAnError(t *testing.T) {
	root := testutil.SourceRoot(t)

	for importPath, names := range discardedErrorFuncs {
		dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(importPath, discardedErrorModuleParent)))
		entries, err := os.ReadDir(dir)
		require.NoError(t, err, "the listed package %s is not at %s", importPath, dir)

		declared := map[string]bool{}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			file, pErr := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, entry.Name()), nil, parser.SkipObjectResolution)
			require.NoError(t, pErr)
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || fn.Type.Results == nil {
					continue
				}
				results := fn.Type.Results.List
				if last, ok := results[len(results)-1].Type.(*ast.Ident); ok && last.Name == "error" {
					declared[fn.Name.Name] = true
				}
			}
		}

		for _, name := range names {
			assert.True(t, declared[name], "%s.%s is listed but %s declares no such function returning an error last",
				path.Base(importPath), name, importPath)
		}
	}
}

// writeDiscardedErrorFixture writes one file into a fixture tree, creating its directories.
func writeDiscardedErrorFixture(t *testing.T, root, rel, src string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(src), 0o644))
}
