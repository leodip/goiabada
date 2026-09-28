package server

// The one place the auth server is held to "a hash, an encryption or a key generation that failed
// is never mistaken for one that succeeded".
//
// The seeder hashed the first admin's password with `passwordHash, _ := passwordhash.Hash(...)`.
// An over-long GOIABADA_ADMIN_PASSWORD made bcrypt refuse, the blank identifier swallowed the
// refusal, and the admin was stored with an empty hash: an account nobody could sign in to, created
// by the one path that exists to make an account somebody can. #211 fixed the same shape by grep,
// and #409 found it again the same way. Each function and method listed here returns a zero value
// beside its error, and every one of those zero values is a valid thing to store: an empty hash, an
// empty ciphertext, a key of no bytes.
//
// errcheck, which the lint tier runs, already refuses a listed call used as a bare statement. It
// leaves the blank identifier alone unless check-blank is on, and check-blank would also refuse
// every deliberate `_ = f.Close()` in the tree, which is why this rule is a list and not a switch.
//
// It reads, parses and type-checks files and nothing else: no database, no git, no network.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
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

// discardedErrorFuncs is every package-level function whose error may not be discarded, by import
// path. Each returns a value beside the error whose zero is storable: a hash, a ciphertext, a
// plaintext, a key or a key pair. A function joins the list when the same holds of it.
var discardedErrorFuncs = map[string][]string{
	"github.com/leodip/goiabada/authserver/internal/passwordhash": {"Hash"},
	"github.com/leodip/goiabada/authserver/internal/encryption": {
		"EncryptData", "DecryptData", "EncryptText", "DecryptText", "RandomKey",
	},
	"github.com/leodip/goiabada/authserver/internal/idtokenhint": {"Encrypt", "Decrypt"},
	"github.com/leodip/goiabada/authserver/internal/rsakey":      {"Generate"},
	"github.com/leodip/goiabada/authserver/internal/signingkeys": {"NewKeyPair", "ParsePrivateKey"},
}

// discardedErrorMethod is one method whose error may not be discarded, named by the import path of
// the package declaring its receiver's type, that type's name, and the method's.
type discardedErrorMethod struct {
	pkg, recv, name string
}

// discardedErrorMethods is every method whose error may not be discarded. The data cipher is a
// value its consumers hold (#434), so its calls are spelled c.Decrypt, s.dataCipher.Encrypt or
// anything else a receiver can be named, and no file's imports say which is which. They are
// resolved through go/types by the receiver's type instead: an unrelated type's Decrypt is not one,
// and a promoted method or a method expression is.
var discardedErrorMethods = []discardedErrorMethod{
	{"github.com/leodip/goiabada/authserver/internal/encryption", "DataCipher", "Encrypt"},
	{"github.com/leodip/goiabada/authserver/internal/encryption", "DataCipher", "Decrypt"},
}

// discardedError is one call whose error result is bound to the blank identifier.
type discardedError struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
	// fn is the function or method called, as package.Name or (*package.Type).Name; for a receiver
	// the walk could not type it is the method name alone.
	fn string
}

// findDiscardedErrors walks root/scope for non-test Go files and reports every assignment or var
// declaration whose single right-hand side calls a listed function or method and whose last
// left-hand name, the error's position, is the blank identifier. It also returns, as unresolved,
// every such discard calling a listed method's name on a receiver whose type the checker could not
// determine, and the number of files it parsed, so the reporting half can tell "nothing to report"
// from "nothing was read".
//
// A function call is resolved through the file's own imports rather than by spelling, so an alias
// cannot hide one and a same-named function in an unlisted package is not one. Inside a listed
// package a bare call to a listed name is the package calling itself, which is how the rotator
// calls NewKeyPair; a dot import is resolved the same way. A method call is resolved by type: each
// directory's files are type-checked, one group per package clause, against an importer that reads
// the listed methods' packages from root and stubs every other path.
func findDiscardedErrors(
	root, scope string, listed map[string][]string, methods []discardedErrorMethod,
) (found, unresolved []discardedError, files int, err error) {
	start := filepath.Join(root, filepath.FromSlash(scope))

	byDir := map[string][]string{}
	err = filepath.WalkDir(start, func(p string, d fs.DirEntry, walkErr error) error {
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
		byDir[filepath.Dir(p)] = append(byDir[filepath.Dir(p)], p)
		return nil
	})
	if err != nil {
		return nil, nil, 0, err
	}

	methodNames := map[string]bool{}
	sourcePackages := map[string]bool{}
	for _, m := range methods {
		methodNames[m.name] = true
		sourcePackages[m.pkg] = true
	}
	imp := newDiscardedErrorPackages(root, sourcePackages)

	dirs := make([]string, 0, len(byDir))
	for dir := range byDir {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	for _, dir := range dirs {
		relDir, rErr := filepath.Rel(root, dir)
		if rErr != nil {
			return nil, nil, 0, rErr
		}
		pkgPath := discardedErrorModuleParent + filepath.ToSlash(relDir)

		fset := token.NewFileSet()
		byPackage := map[string][]*ast.File{}
		var packageOrder []string
		for _, p := range byDir[dir] {
			file, pErr := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if pErr != nil {
				// A file that does not parse is a compile error the build tier owns.
				continue
			}
			files++
			clause := file.Name.Name
			if _, ok := byPackage[clause]; !ok {
				packageOrder = append(packageOrder, clause)
			}
			byPackage[clause] = append(byPackage[clause], file)
		}

		for _, clause := range packageOrder {
			group := byPackage[clause]
			info := discardedErrorTypes(pkgPath, fset, group, imp, methodNames)
			for _, file := range group {
				rel, rErr := filepath.Rel(root, fset.Position(file.Pos()).Filename)
				if rErr != nil {
					return nil, nil, 0, rErr
				}
				rel = filepath.ToSlash(rel)
				f, u := discardedErrorsIn(file, fset, rel, pkgPath, info, listed, methods, methodNames)
				found = append(found, f...)
				unresolved = append(unresolved, u...)
			}
		}
	}
	return found, unresolved, files, nil
}

// discardedErrorTypes type-checks one package's files and returns what the checker resolved, or nil
// when no file in it selects a listed method's name, which is the sound text pre-filter: a method
// call spells its name, so a group spelling none holds no call the method half could report.
func discardedErrorTypes(
	pkgPath string, fset *token.FileSet, group []*ast.File, imp types.Importer, methodNames map[string]bool,
) *types.Info {
	selects := false
	for _, file := range group {
		ast.Inspect(file, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && methodNames[sel.Sel.Name] {
				selects = true
			}
			return !selects
		})
	}
	if !selects {
		return nil
	}

	info := &types.Info{Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{
		Importer: imp,
		// Every package but the listed methods' is a stub, so the checker has plenty to say about
		// members it never read. Discarding it keeps the check running to the end; what this guard
		// asks survives, because a receiver's type either came from a package that was read or is
		// reported as unresolved.
		Error:                    func(error) {},
		DisableUnusedImportCheck: true,
	}
	// The returned error is the first one Error already saw; info is filled in either way.
	_, _ = conf.Check(pkgPath, fset, group, info)
	return info
}

// discardedErrorsIn applies the rule to one parsed file. info is nil when the pre-filter skipped
// its package, in which case no method call is there to resolve.
func discardedErrorsIn(
	file *ast.File, fset *token.FileSet, rel, pkgPath string, info *types.Info,
	listed map[string][]string, methods []discardedErrorMethod, methodNames map[string]bool,
) (found, unresolved []discardedError) {
	resolve := discardedErrorResolver(file, pkgPath, listed)

	report := func(pos token.Pos, lastName ast.Expr, value ast.Expr) {
		if ident, ok := lastName.(*ast.Ident); !ok || ident.Name != "_" {
			return
		}
		call, ok := ast.Unparen(value).(*ast.CallExpr)
		if !ok {
			return
		}
		line := fset.Position(pos).Line
		if fn, matched := resolve(call.Fun); matched {
			found = append(found, discardedError{file: rel, line: line, fn: fn})
			return
		}
		sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok || !methodNames[sel.Sel.Name] || info == nil {
			return
		}
		if obj := info.Uses[sel.Sel]; obj != nil {
			if fn, ok := discardedErrorMethodCalled(obj, methods); ok {
				found = append(found, discardedError{file: rel, line: line, fn: fn})
			}
			return
		}
		// pkg.Decrypt(x) is a package's function, which the import half has already judged.
		if base, isIdent := sel.X.(*ast.Ident); isIdent {
			if _, isPkg := info.Uses[base].(*types.PkgName); isPkg {
				return
			}
		}
		unresolved = append(unresolved, discardedError{file: rel, line: line, fn: sel.Sel.Name})
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
	return found, unresolved
}

// discardedErrorMethodCalled reports whether obj is a listed method, found by its receiver's named
// type whether declared on the type or its pointer, and names it.
func discardedErrorMethodCalled(obj types.Object, methods []discardedErrorMethod) (string, bool) {
	fn, ok := obj.(*types.Func)
	if !ok {
		return "", false
	}
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || sig.Recv() == nil {
		return "", false
	}
	recv := sig.Recv().Type()
	pointer := false
	if ptr, isPtr := recv.(*types.Pointer); isPtr {
		recv, pointer = ptr.Elem(), true
	}
	named, ok := recv.(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return "", false
	}
	for _, m := range methods {
		if named.Obj().Pkg().Path() == m.pkg && named.Obj().Name() == m.recv && fn.Name() == m.name {
			if pointer {
				return "(*" + path.Base(m.pkg) + "." + m.recv + ")." + m.name, true
			}
			return path.Base(m.pkg) + "." + m.recv + "." + m.name, true
		}
	}
	return "", false
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

// discardedErrorPackages is the importer the method half type-checks against: each package in
// source is read from the source root, and every other path is an empty stub. A receiver whose type
// came through a stub is therefore reported as unresolved rather than guessed at.
//
// core/testutil's stubPackages, behind the context-value and dead-interface guards, is the twin of
// the stub half. It stays unexported there because exporting it for this one caller would add a
// core symbol, and an OWNERSHIP.md row, for about twenty lines (#434).
type discardedErrorPackages struct {
	root   string
	source map[string]bool
	fset   *token.FileSet
	made   map[string]*types.Package
}

func newDiscardedErrorPackages(root string, source map[string]bool) *discardedErrorPackages {
	return &discardedErrorPackages{root: root, source: source, fset: token.NewFileSet(), made: map[string]*types.Package{}}
}

func (p *discardedErrorPackages) Import(importPath string) (*types.Package, error) {
	if made, ok := p.made[importPath]; ok {
		return made, nil
	}
	if !p.source[importPath] {
		pkg := types.NewPackage(importPath, discardedErrorPackageName(importPath))
		pkg.MarkComplete()
		p.made[importPath] = pkg
		return pkg, nil
	}

	dir := filepath.Join(p.root, filepath.FromSlash(strings.TrimPrefix(importPath, discardedErrorModuleParent)))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, errs.Wrapf(err, "reading %s from the source root", importPath)
	}
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, pErr := parser.ParseFile(p.fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if pErr != nil {
			return nil, errs.Wrapf(pErr, "parsing %s", name)
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		return nil, errs.Errorf("%s has no production Go files under the source root", importPath)
	}
	conf := types.Config{
		Importer:                 p,
		Error:                    func(error) {},
		DisableUnusedImportCheck: true,
	}
	pkg, _ := conf.Check(importPath, p.fset, files, nil)
	if pkg == nil {
		return nil, errs.Errorf("type-checking %s produced no package", importPath)
	}
	pkg.MarkComplete()
	p.made[importPath] = pkg
	return pkg, nil
}

// discardedErrorMajorVersion is a module path's major-version element, which is never the name.
var discardedErrorMajorVersion = regexp.MustCompile(`^v[0-9]+$`)

// discardedErrorPackageName guesses a stubbed path's package name as core/testutil's
// inventedPackageName does, and is as harmless when wrong: a name that does not match only leaves
// that package's selectors unresolved, and a stub declares nothing to resolve anyway.
func discardedErrorPackageName(importPath string) string {
	elems := strings.Split(importPath, "/")
	base := elems[len(elems)-1]
	if discardedErrorMajorVersion.MatchString(base) && len(elems) > 1 {
		base = elems[len(elems)-2]
	}
	if i := strings.Index(base, "."); i > 0 {
		base = base[:i]
	}
	base = strings.ReplaceAll(base, "-", "")
	if base == "" {
		return "p"
	}
	return base
}

// TestDiscardedErrors_NoneInTheAuthServer holds the real tree to the rule. It is #409 item 4 in
// its checkable form.
func TestDiscardedErrors_NoneInTheAuthServer(t *testing.T) {
	assertNoDiscardedErrors(t, testutil.SourceRoot(t), discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
}

// assertNoDiscardedErrors is the reporting half, taking the root, the scope and the lists as
// parameters and failing through a testutil.Reporter so a rule test can drive it against a fixture
// tree. Without that seam these lines are reached only by the call above, which walks a tree that
// passes.
func assertNoDiscardedErrors(
	r testutil.Reporter, root, scope string, listed map[string][]string, methods []discardedErrorMethod,
) {
	r.Helper()

	found, unresolved, files, err := findDiscardedErrors(root, scope, listed, methods)
	if err != nil {
		r.Fatalf("walking %s: %v", filepath.Join(root, filepath.FromSlash(scope)), err)
	}
	// A scope that somehow held no production Go files reads nothing and would otherwise pass.
	if files == 0 {
		r.Fatalf("read no production Go files under %s", scope)
	}

	if len(found) > 0 {
		r.Errorf("%d call(s) under %s discard the error of a hash, an encryption or a key generation:\n\t%s\n\n"+
			"Each of these returns a zero value beside its error, and every one of those zero values is a "+
			"valid thing to store: an empty hash, an empty ciphertext, a key of no bytes. Handle the error. "+
			"The seeder stored its first admin with an empty password hash exactly this way (#409).",
			len(found), scope, discardedErrorLines(found))
	}
	if len(unresolved) > 0 {
		r.Errorf("%d call(s) under %s discard the error of a method named like the data cipher's, on a "+
			"receiver whose type this walk cannot resolve:\n\t%s\n\n"+
			"The data cipher's methods are found by their receiver's type, and a receiver typed through a "+
			"package this walk does not read cannot be told from the cipher. Keep the error, or give the "+
			"receiver a type the walk can see, such as a *encryption.DataCipher parameter or field (#434).",
			len(unresolved), scope, discardedErrorLines(unresolved))
	}
}

// discardedErrorLines renders findings one per line, sorted, as file:line: name.
func discardedErrorLines(found []discardedError) string {
	lines := make([]string, 0, len(found))
	for _, f := range found {
		lines = append(lines, f.file+":"+strconv.Itoa(f.line)+": "+f.fn)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n\t")
}

// discardedErrorCipherFixture is the listed receiver's package in a fixture tree, declaring what
// the importer reads: the type and its two methods, and a second type sharing a method name.
const discardedErrorCipherFixture = `package encryption

type DataCipher struct{ key []byte }

func (c *DataCipher) Encrypt(plaintext string) ([]byte, error) { return nil, nil }

func (c *DataCipher) Decrypt(ciphertext []byte) (string, error) { return "", nil }

type Envelope struct{}

func (Envelope) Decrypt(ciphertext []byte) (string, error) { return "", nil }
`

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

	// Caught by type: the data cipher's methods through a parameter, a struct field, an embedded
	// field and a method expression, and through an aliased import; and idtokenhint's functions.
	writeDiscardedErrorFixture(t, root, "authserver/internal/encryption/cipher.go", discardedErrorCipherFixture)
	writeDiscardedErrorFixture(t, root, "authserver/internal/otpcredential/seed.go", `package otpcredential

import "github.com/leodip/goiabada/authserver/internal/encryption"

type store struct {
	cipher *encryption.DataCipher
}

type wrapped struct {
	*encryption.DataCipher
}

func param(c *encryption.DataCipher, ct []byte) {
	pt, _ := c.Decrypt(ct)
	_ = pt
}

func (s store) field(p string) {
	var ct, _ = s.cipher.Encrypt(p)
	_ = ct
}

func embedded(w wrapped, ct []byte) {
	_, _ = w.Decrypt(ct)
}

func expression(c *encryption.DataCipher, p string) {
	_, _ = (*encryption.DataCipher).Encrypt(c, p)
}
`)
	writeDiscardedErrorFixture(t, root, "authserver/internal/emaildelivery/sender.go", `package emaildelivery

import enc "github.com/leodip/goiabada/authserver/internal/encryption"

func send(c *enc.DataCipher, ct []byte) {
	password, _ := c.Decrypt(ct)
	_ = password
}

func open(e enc.Envelope, ct []byte) {
	body, _ := e.Decrypt(ct)
	_ = body
}
`)

	// Passed: the error kept; the error kept while another result is discarded; a test file; a
	// same-named function in an unlisted package; a listed name reached through an unlisted
	// package; an unlisted discard; a bare call to a listed name outside its package; a blank
	// import; a Decrypt on a type named DataCipher in an unlisted package, and on another type in
	// the listed one (emaildelivery's open); a cipher method whose error is kept; and an unlisted
	// package's Decrypt function, which is not a receiver at all. Unresolved: a Decrypt on a
	// receiver typed through a package the walk stubs.
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
	writeDiscardedErrorFixture(t, root, "authserver/internal/handlers/logout.go", `package handlers

import (
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/idtokenhint"
	"github.com/leodip/goiabada/authserver/internal/sessionstuff"
)

type DataCipher struct{}

func (DataCipher) Decrypt([]byte) (string, error) { return "", nil }

func logout(c *encryption.DataCipher, s sessionstuff.Store, hint, secret string, ct []byte) error {
	token, _ := idtokenhint.Decrypt(hint, secret)
	other, _ := DataCipher{}.Decrypt(ct)
	kept, err := c.Decrypt(ct)
	if err != nil {
		return err
	}
	opaque, _ := s.Decrypt(ct)
	plain, _ := sessionstuff.Decrypt(ct)
	_, _, _, _, _ = token, other, kept, opaque, plain
	return nil
}
`)
	writeDiscardedErrorFixture(t, root, "authserver/internal/passwordhash/passwordhash_test.go", `package passwordhash

func helper() {
	h, _ := Hash("x")
	_ = h
}
`)

	found, unresolved, files, err := findDiscardedErrors(root, discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
	require.NoError(t, err)
	assert.Equal(t, 8, files, "the test file is not read, the other eight are")

	assert.ElementsMatch(t, []string{
		"authserver/internal/data/seeder.go:8: encryption.RandomKey",
		"authserver/internal/data/seeder.go:11: passwordhash.Hash",
		"authserver/internal/data/seeder.go:14: encryption.EncryptData",
		"authserver/internal/data/seeder.go:15: encryption.DecryptData",
		"authserver/internal/bootstrap/keys.go:6: rsakey.Generate",
		"authserver/internal/signingkeys/rotator.go:4: signingkeys.NewKeyPair",
		"authserver/internal/otpcredential/seed.go:14: (*encryption.DataCipher).Decrypt",
		"authserver/internal/otpcredential/seed.go:19: (*encryption.DataCipher).Encrypt",
		"authserver/internal/otpcredential/seed.go:24: (*encryption.DataCipher).Decrypt",
		"authserver/internal/otpcredential/seed.go:28: (*encryption.DataCipher).Encrypt",
		"authserver/internal/emaildelivery/sender.go:6: (*encryption.DataCipher).Decrypt",
		"authserver/internal/handlers/logout.go:14: idtokenhint.Decrypt",
	}, discardedErrorStrings(found), "the finder matched the wrong set")
	assert.ElementsMatch(t, []string{
		"authserver/internal/handlers/logout.go:20: Decrypt",
	}, discardedErrorStrings(unresolved), "the finder judged the wrong receivers unresolvable")
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
		assertNoDiscardedErrors(r, root, discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
	})

	require.True(t, report.Failed(), "the seeder's discarded hash error passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/data/seeder.go:6: passwordhash.Hash")
	assert.Contains(t, report.Text(), "#409")
}

// TestDiscardedErrors_Guard_FailsOnADiscardedCipherError is the same through a method: what the
// finder resolves by type reaches the same failure.
func TestDiscardedErrors_Guard_FailsOnADiscardedCipherError(t *testing.T) {
	root := t.TempDir()
	writeDiscardedErrorFixture(t, root, "authserver/internal/encryption/cipher.go", discardedErrorCipherFixture)
	writeDiscardedErrorFixture(t, root, "authserver/internal/otpcredential/seed.go", `package otpcredential

import "github.com/leodip/goiabada/authserver/internal/encryption"

func stored(c *encryption.DataCipher, ct []byte) string {
	seed, _ := c.Decrypt(ct)
	return seed
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoDiscardedErrors(r, root, discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
	})

	require.True(t, report.Failed(), "a discarded Decrypt error passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/otpcredential/seed.go:6: (*encryption.DataCipher).Decrypt")
	assert.NotContains(t, report.Text(), "cannot resolve", "a typed receiver was reported as unresolved")
}

// TestDiscardedErrors_Guard_FailsOnAnUnresolvedReceiver pins the other refusal: a discard the walk
// cannot judge fails rather than passing on a guess.
func TestDiscardedErrors_Guard_FailsOnAnUnresolvedReceiver(t *testing.T) {
	root := t.TempDir()
	writeDiscardedErrorFixture(t, root, "authserver/internal/encryption/cipher.go", discardedErrorCipherFixture)
	writeDiscardedErrorFixture(t, root, "authserver/internal/handlers/logout.go", `package handlers

import "github.com/leodip/goiabada/authserver/internal/sessionstuff"

func logout(s sessionstuff.Store, ct []byte) string {
	v, _ := s.Encrypt(ct)
	return v
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoDiscardedErrors(r, root, discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
	})

	require.True(t, report.Failed(), "a discard on an unresolvable receiver passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/handlers/logout.go:6: Encrypt")
	assert.Contains(t, report.Text(), "whose type this walk cannot resolve")
	assert.Contains(t, report.Text(), "#434")
}

// TestDiscardedErrors_Guard_PassesAKeptError is the other direction, through a function and a
// method.
func TestDiscardedErrors_Guard_PassesAKeptError(t *testing.T) {
	root := t.TempDir()
	writeDiscardedErrorFixture(t, root, "authserver/internal/encryption/cipher.go", discardedErrorCipherFixture)
	writeDiscardedErrorFixture(t, root, "authserver/internal/data/seeder.go", `package data

import (
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
)

func seed(c *encryption.DataCipher, p string) (string, []byte, error) {
	hash, err := passwordhash.Hash(p)
	if err != nil {
		return "", nil, err
	}
	ct, err := c.Encrypt(p)
	if err != nil {
		return "", nil, err
	}
	return hash, ct, nil
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertNoDiscardedErrors(r, root, discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
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
		assertNoDiscardedErrors(r, root, discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
	})

	require.True(t, report.Stopped, "an empty read must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "read no production Go files under authserver")
}

// TestDiscardedErrors_EveryListedFunctionReturnsAnError holds both lists to the real tree. A listed
// name that has been renamed or deleted guards nothing, and the finder cannot tell: it would match
// no call and report a clean tree. So each function entry has to be a top-level function its
// package still declares, and each method entry a method its package declares on the named type or
// its pointer, with error as the last result, which is the position the finder reads.
func TestDiscardedErrors_EveryListedFunctionReturnsAnError(t *testing.T) {
	root := testutil.SourceRoot(t)

	want := map[string][]string{}
	for importPath, names := range discardedErrorFuncs {
		want[importPath] = append(want[importPath], names...)
	}
	for _, m := range discardedErrorMethods {
		want[m.pkg] = append(want[m.pkg], m.recv+"."+m.name)
	}

	for importPath, names := range want {
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
				if !ok || fn.Type.Results == nil {
					continue
				}
				results := fn.Type.Results.List
				if last, ok := results[len(results)-1].Type.(*ast.Ident); !ok || last.Name != "error" {
					continue
				}
				key := fn.Name.Name
				if fn.Recv != nil {
					recv := fn.Recv.List[0].Type
					if star, isStar := recv.(*ast.StarExpr); isStar {
						recv = star.X
					}
					ident, isIdent := recv.(*ast.Ident)
					if !isIdent {
						continue
					}
					key = ident.Name + "." + key
				}
				declared[key] = true
			}
		}

		for _, name := range names {
			assert.True(t, declared[name], "%s.%s is listed but %s declares no such function or method returning an error last",
				path.Base(importPath), name, importPath)
		}
	}
}

// discardedErrorStrings renders findings for comparison, unsorted.
func discardedErrorStrings(found []discardedError) []string {
	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, f.file+":"+strconv.Itoa(f.line)+": "+f.fn)
	}
	return got
}

// writeDiscardedErrorFixture writes one file into a fixture tree, creating its directories.
func writeDiscardedErrorFixture(t *testing.T, root, rel, src string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(src), 0o644))
}
