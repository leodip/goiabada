//go:build !race

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
// It reads the auth server's module type-checked through core/pkgload and nothing else: no
// database, no git, no network.

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/pkgload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

// discardedErrorScope is the tree the rule covers, relative to the source root, forward slashes:
// the auth server's module. Every listed function is internal to the auth server, so no other
// module could name one.
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
		"EncryptText", "DecryptText", "RandomKey",
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
// anything else a receiver can be named. They are matched by the method object called instead: an
// unrelated type's Decrypt is not one, and a promoted method or a method expression is. So is the
// method of that name called through an interface the cipher's type implements, since the value
// behind it may be the cipher (#420). The interface is the one the call goes through, which may
// embed the one declaring the method and ask for more than the cipher has.
var discardedErrorMethods = []discardedErrorMethod{
	{"github.com/leodip/goiabada/authserver/internal/encryption", "DataCipher", "Encrypt"},
	{"github.com/leodip/goiabada/authserver/internal/encryption", "DataCipher", "Decrypt"},
}

// discardedError is one call whose error result is bound to the blank identifier.
type discardedError struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
	// fn is the function or method called, as package.Name, (*package.Type).Name, or
	// package.Interface.Name with the listed type implementing it.
	fn string
}

// findDiscardedErrors reads the module at root/scope and reports every assignment or var
// declaration in a production file whose single right-hand side calls a listed function or method
// and whose last left-hand name, the error's position, is the blank identifier. It also returns the
// number of production files it read, so the reporting half can tell "nothing to report" from
// "nothing was read".
//
// A call is matched by the object it calls, never by spelling: an alias or a dot import cannot
// hide a listed function, a same-named function elsewhere is not one, and a listed package calling
// itself by bare name, as the rotator calls NewKeyPair, is one.
//
// The module is read through pkgload as every release build selects its files, and as the test
// machine's default build does, and what they find is merged: a discard in a file only Windows
// compiles is shipped all the same, and one in a development-only file runs in the development
// server (#420). A file only a race build or a custom tag selects is read by none of them. A
// package that does not load or type-check is an error naming it, since a discard in it would go
// unseen.
func findDiscardedErrors(
	root, scope string, listed map[string][]string, methods []discardedErrorMethod,
) (found []discardedError, files int, err error) {
	modRoot := filepath.Join(root, filepath.FromSlash(scope))

	// The loads are independent go command runs, so they run at once; the first error in build order
	// is the one returned. A build that selects no package of the module adds nothing.
	builds := append(pkgload.ReleaseBuilds(), pkgload.Build{})
	loaded := make([][]*packages.Package, len(builds))
	loadErrs := make([]error, len(builds))
	var wg sync.WaitGroup
	for i, build := range builds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			loaded[i], loadErrs[i] = pkgload.Load(modRoot, build)
		}()
	}
	wg.Wait()

	readFiles := map[string]bool{}
	// seen holds each finding's position; a file several builds select is read once per build.
	seen := map[token.Position]bool{}
	for i := range builds {
		if loadErrs[i] != nil && !errors.Is(loadErrs[i], pkgload.ErrNoPackages) {
			return nil, 0, loadErrs[i]
		}
		listedTypes := discardedErrorListedTypes(loaded[i], methods)
		for _, p := range loaded[i] {
			for _, file := range p.Syntax {
				name := p.Fset.File(file.Pos()).Name()
				readFiles[name] = true
				rel, rErr := filepath.Rel(root, name)
				if rErr != nil {
					return nil, 0, rErr
				}
				for _, d := range discardedErrorsIn(file, p.TypesInfo, listed, methods, listedTypes) {
					at := p.Fset.Position(d.pos)
					if seen[at] {
						continue
					}
					seen[at] = true
					found = append(found, discardedError{file: filepath.ToSlash(rel), line: at.Line, fn: d.fn})
				}
			}
		}
	}
	return found, len(readFiles), nil
}

// discardedErrorListedTypes looks up each listed method's receiver type in one build's packages, by
// the method's index. A listed method whose package the build does not hold has no entry.
func discardedErrorListedTypes(pkgs []*packages.Package, methods []discardedErrorMethod) map[int]*types.Named {
	byPath := map[string]*types.Package{}
	for _, p := range pkgs {
		byPath[p.PkgPath] = p.Types
	}
	listedTypes := map[int]*types.Named{}
	for i, m := range methods {
		pkg := byPath[m.pkg]
		if pkg == nil {
			continue
		}
		if tn, ok := pkg.Scope().Lookup(m.recv).(*types.TypeName); ok {
			if named, ok := tn.Type().(*types.Named); ok {
				listedTypes[i] = named
			}
		}
	}
	return listedTypes
}

// discardedErrorQualifier writes a type's package by its name, as a finding names a function.
func discardedErrorQualifier(p *types.Package) string { return p.Name() }

// discardedErrorSite is one discard of a listed call within a file, before its position is made
// relative.
type discardedErrorSite struct {
	pos token.Pos
	fn  string
}

// discardedErrorsIn applies the rule to one type-checked file.
func discardedErrorsIn(
	file *ast.File, info *types.Info,
	listed map[string][]string, methods []discardedErrorMethod, listedTypes map[int]*types.Named,
) []discardedErrorSite {
	var found []discardedErrorSite
	report := func(pos token.Pos, lastName ast.Expr, value ast.Expr) {
		if ident, ok := lastName.(*ast.Ident); !ok || ident.Name != "_" {
			return
		}
		call, ok := ast.Unparen(value).(*ast.CallExpr)
		if !ok {
			return
		}
		var callee *ast.Ident
		var through types.Type
		switch fun := ast.Unparen(call.Fun).(type) {
		case *ast.Ident:
			callee = fun
		case *ast.SelectorExpr:
			callee = fun.Sel
			if sel, hasSelection := info.Selections[fun]; hasSelection {
				through = discardedErrorDispatchType(sel)
			}
		default:
			return
		}
		fn, ok := info.Uses[callee].(*types.Func)
		if !ok {
			return
		}
		if name, ok := discardedErrorCalled(fn, through, listed, methods, listedTypes); ok {
			found = append(found, discardedErrorSite{pos: pos, fn: name})
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
	return found
}

// discardedErrorDispatchType returns the type whose method a selection calls: the receiver
// expression's own type, or the embedded field the method is promoted from. For a method of an
// interface it is the interface the call goes through, which may embed the interface that
// declared the method and ask for more.
func discardedErrorDispatchType(sel *types.Selection) types.Type {
	t := sel.Recv()
	index := sel.Index()
	for _, i := range index[:len(index)-1] {
		if ptr, ok := t.Underlying().(*types.Pointer); ok {
			t = ptr.Elem()
		}
		st, ok := t.Underlying().(*types.Struct)
		if !ok {
			return nil
		}
		t = st.Field(i).Type()
	}
	return t
}

// discardedErrorCalled reports whether fn is a listed function, a listed method found by its
// receiver's named type whether declared on the type or its pointer, or the method of a listed
// method's name of an interface a listed type implements, and names it. through is the type the
// call dispatches on, when the call is a selection: a method of an interface is judged by the
// interface it is called through, not by the one that declared it.
func discardedErrorCalled(
	fn *types.Func, through types.Type,
	listed map[string][]string, methods []discardedErrorMethod, listedTypes map[int]*types.Named,
) (string, bool) {
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || fn.Pkg() == nil {
		return "", false
	}
	if sig.Recv() == nil {
		for _, name := range listed[fn.Pkg().Path()] {
			if name == fn.Name() {
				return fn.Pkg().Name() + "." + fn.Name(), true
			}
		}
		return "", false
	}

	recv := sig.Recv().Type()
	if _, ok := recv.Underlying().(*types.Interface); ok {
		if through != nil {
			recv = through
		}
		iface, ok := recv.Underlying().(*types.Interface)
		if !ok {
			return "", false
		}
		for i, m := range methods {
			named := listedTypes[i]
			if named == nil || fn.Name() != m.name {
				continue
			}
			implementer := named.Obj().Pkg().Name() + "." + m.recv
			if !types.Implements(named, iface) {
				if !types.Implements(types.NewPointer(named), iface) {
					continue
				}
				implementer = "*" + implementer
			}
			return types.TypeString(recv, discardedErrorQualifier) + "." + fn.Name() + ", which " + implementer + " implements", true
		}
		return "", false
	}

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

// TestDiscardedErrors_NoneInTheAuthServer holds the real tree to the rule. It is #409 item 4 in
// its checkable form.
func TestDiscardedErrors_NoneInTheAuthServer(t *testing.T) {
	assertNoDiscardedErrors(t, guard.SourceRoot(t), discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
}

// assertNoDiscardedErrors is the reporting half, taking the root, the scope and the lists as
// parameters and failing through a guard.Reporter so a rule test can drive it against a fixture
// tree. Without that seam these lines are reached only by the call above, which walks a tree that
// passes.
func assertNoDiscardedErrors(
	r guard.Reporter, root, scope string, listed map[string][]string, methods []discardedErrorMethod,
) {
	r.Helper()

	found, files, err := findDiscardedErrors(root, scope, listed, methods)
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

// discardedErrorCipherFixture is the listed receiver's package in a fixture tree: the type and its
// two methods, and a second type sharing a method name.
const discardedErrorCipherFixture = `package encryption

type DataCipher struct{ key []byte }

func (c *DataCipher) Encrypt(plaintext string) ([]byte, error) { return nil, nil }

func (c *DataCipher) Decrypt(ciphertext []byte) (string, error) { return "", nil }

type Envelope struct{}

func (Envelope) Decrypt(ciphertext []byte) (string, error) { return "", nil }
`

// discardedErrorListedFixtures are the listed functions' packages in a fixture tree, each declaring
// its listed names with the error last, so the tree compiles and the finder has objects to match.
var discardedErrorListedFixtures = map[string]string{
	"authserver/internal/encryption/text.go": `package encryption

func EncryptText(plaintext string, key []byte) ([]byte, error) { return nil, nil }

func DecryptText(ciphertext []byte, key []byte) (string, error) { return "", nil }

func RandomKey(n int) ([]byte, error) { return nil, nil }
`,
	"authserver/internal/passwordhash/passwordhash.go": `package passwordhash

func Hash(password string) (string, error) { return "", nil }
`,
	"authserver/internal/idtokenhint/idtokenhint.go": `package idtokenhint

func Encrypt(hint, secret string) (string, error) { return "", nil }

func Decrypt(hint, secret string) (string, error) { return "", nil }
`,
	"authserver/internal/rsakey/rsakey.go": `package rsakey

type Material struct{}

func Generate(bits int, kid string) (Material, error) { return Material{}, nil }
`,
	"authserver/internal/signingkeys/keypair.go": `package signingkeys

type KeyPair struct{}

func NewKeyPair(seed []byte, id int64, bits int) (*KeyPair, error) { return nil, nil }

func ParsePrivateKey(pem, passphrase []byte) (*KeyPair, error) { return nil, nil }
`,
}

// writeDiscardedErrorModule writes the auth server's module and the listed packages into a fixture
// tree, and makes the tree loadable, so a case adds only the files it is about.
func writeDiscardedErrorModule(t *testing.T, root string) {
	t.Helper()
	writeDiscardedErrorFixture(t, root, "authserver/go.mod", "module github.com/leodip/goiabada/authserver\n")
	require.NoError(t, pkgload.MakeLoadable(root))
	writeDiscardedErrorFixture(t, root, "authserver/internal/encryption/cipher.go", discardedErrorCipherFixture)
	for rel, src := range discardedErrorListedFixtures {
		writeDiscardedErrorFixture(t, root, rel, src)
	}
}

// TestDiscardedErrors_Finder_MatchesTheObjectCalled is the synthetic half: a temp tree holding
// every shape the rule catches and every neighbour it must leave alone, so a finder that has
// quietly stopped matching anything is caught here rather than trusted.
func TestDiscardedErrors_Finder_MatchesTheObjectCalled(t *testing.T) {
	root := t.TempDir()
	writeDiscardedErrorModule(t, root)

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
	ct, _ = (encryption.EncryptText)(p, key)
	_, _ = encryption.DecryptText(ct, key)
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
	kp, _ := NewKeyPair(nil, 1, 1024)
	_ = kp
}
`)

	// Caught by type: the data cipher's methods through a parameter, a struct field, an embedded
	// field and a method expression, and through an aliased import; and idtokenhint's functions.
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
	// the listed one (emaildelivery's open); a cipher method whose error is kept; an unlisted
	// type's Decrypt method in another package; and an unlisted package's Decrypt function.
	writeDiscardedErrorFixture(t, root, "authserver/internal/otherhash/otherhash.go", `package otherhash

func Hash(string) (string, error) { return "", nil }
`)
	writeDiscardedErrorFixture(t, root, "authserver/internal/sessionstuff/sessionstuff.go", `package sessionstuff

type Store struct{}

func (Store) Decrypt([]byte) (string, error) { return "", nil }

func Decrypt([]byte) (string, error) { return "", nil }
`)
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
	_, err = signingkeys.ParsePrivateKey(nil, nil)
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

	found, files, err := findDiscardedErrors(root, discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
	require.NoError(t, err)
	assert.Equal(t, 15, files, "the test file is not read, the other fifteen are")

	assert.ElementsMatch(t, []string{
		"authserver/internal/data/seeder.go:8: encryption.RandomKey",
		"authserver/internal/data/seeder.go:11: passwordhash.Hash",
		"authserver/internal/data/seeder.go:14: encryption.EncryptText",
		"authserver/internal/data/seeder.go:15: encryption.DecryptText",
		"authserver/internal/bootstrap/keys.go:6: rsakey.Generate",
		"authserver/internal/signingkeys/rotator.go:4: signingkeys.NewKeyPair",
		"authserver/internal/otpcredential/seed.go:14: (*encryption.DataCipher).Decrypt",
		"authserver/internal/otpcredential/seed.go:19: (*encryption.DataCipher).Encrypt",
		"authserver/internal/otpcredential/seed.go:24: (*encryption.DataCipher).Decrypt",
		"authserver/internal/otpcredential/seed.go:28: (*encryption.DataCipher).Encrypt",
		"authserver/internal/emaildelivery/sender.go:6: (*encryption.DataCipher).Decrypt",
		"authserver/internal/handlers/logout.go:14: idtokenhint.Decrypt",
	}, discardedErrorStrings(found), "the finder matched the wrong set")
}

// TestDiscardedErrors_Guard_FailsOnADiscard is the third half. The case above asserts on what
// findDiscardedErrors returned; the lines that turn a finding into a failure are reached only by
// TestDiscardedErrors_NoneInTheAuthServer, which walks a tree that passes.
func TestDiscardedErrors_Guard_FailsOnADiscard(t *testing.T) {
	root := t.TempDir()
	writeDiscardedErrorModule(t, root)
	writeDiscardedErrorFixture(t, root, "authserver/internal/data/seeder.go", `package data

import "github.com/leodip/goiabada/authserver/internal/passwordhash"

func seed(p string) string {
	hash, _ := passwordhash.Hash(p)
	return hash
}
`)

	report := guard.Run(func(r guard.Reporter) {
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
	writeDiscardedErrorModule(t, root)
	writeDiscardedErrorFixture(t, root, "authserver/internal/otpcredential/seed.go", `package otpcredential

import "github.com/leodip/goiabada/authserver/internal/encryption"

func stored(c *encryption.DataCipher, ct []byte) string {
	seed, _ := c.Decrypt(ct)
	return seed
}
`)

	report := guard.Run(func(r guard.Reporter) {
		assertNoDiscardedErrors(r, root, discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
	})

	require.True(t, report.Failed(), "a discarded Decrypt error passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/otpcredential/seed.go:6: (*encryption.DataCipher).Decrypt")
}

// discardedErrorSealingFixture declares, in a package other than the cipher's, an interface the
// data cipher implements and two it does not: Opener's Decrypt takes a string, the cipher's a
// slice of bytes, and SizedSealer embeds Sealer but also asks for a Size the cipher lacks.
const discardedErrorSealingFixture = `package sealing

type Sealer interface {
	Encrypt(plaintext string) ([]byte, error)
	Decrypt(ciphertext []byte) (string, error)
}

type Opener interface {
	Decrypt(ciphertext string) (string, error)
}

type SizedSealer interface {
	Sealer
	Size() int
}
`

// A listed method called through an interface the data cipher implements may be the cipher at run
// time, so its discarded error is refused like the cipher's own (#420 decision 13).
func TestDiscardedErrors_Guard_FailsOnACipherMethodThroughAnInterfaceTheCipherImplements(t *testing.T) {
	root := t.TempDir()
	writeDiscardedErrorModule(t, root)
	writeDiscardedErrorFixture(t, root, "authserver/internal/sealing/sealing.go", discardedErrorSealingFixture)
	writeDiscardedErrorFixture(t, root, "authserver/internal/otpcredential/seed.go", `package otpcredential

import "github.com/leodip/goiabada/authserver/internal/sealing"

func stored(s sealing.Sealer, ct []byte) string {
	seed, _ := s.Decrypt(ct)
	return seed
}
`)

	report := guard.Run(func(r guard.Reporter) {
		assertNoDiscardedErrors(r, root, discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
	})

	require.True(t, report.Failed(), "a discarded Decrypt error through an interface the cipher implements passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(),
		"authserver/internal/otpcredential/seed.go:6: sealing.Sealer.Decrypt, which *encryption.DataCipher implements")
}

// An interface the data cipher does not implement cannot hold it, so a method of the same name
// through it is an unrelated type's, and its discard is not this rule's.
func TestDiscardedErrors_Guard_PassesAMethodThroughAnInterfaceTheCipherDoesNotImplement(t *testing.T) {
	root := t.TempDir()
	writeDiscardedErrorModule(t, root)
	writeDiscardedErrorFixture(t, root, "authserver/internal/sealing/sealing.go", discardedErrorSealingFixture)
	writeDiscardedErrorFixture(t, root, "authserver/internal/otpcredential/seed.go", `package otpcredential

import "github.com/leodip/goiabada/authserver/internal/sealing"

func stored(o sealing.Opener, ct string) string {
	seed, _ := o.Decrypt(ct)
	return seed
}
`)

	report := guard.Run(func(r guard.Reporter) {
		assertNoDiscardedErrors(r, root, discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
	})

	assert.False(t, report.Failed(), "a method of an interface the cipher does not implement failed the guard: %s", report.Text())
}

// The interface a method is called through is the receiver's own, not the one that declared the
// method: SizedSealer gets Decrypt from Sealer, which the cipher implements, but SizedSealer itself
// cannot hold the cipher, so its discard is not this rule's.
func TestDiscardedErrors_Guard_PassesAMethodThroughAnInterfaceEmbeddingOneTheCipherImplements(t *testing.T) {
	root := t.TempDir()
	writeDiscardedErrorModule(t, root)
	writeDiscardedErrorFixture(t, root, "authserver/internal/sealing/sealing.go", discardedErrorSealingFixture)
	writeDiscardedErrorFixture(t, root, "authserver/internal/otpcredential/seed.go", `package otpcredential

import "github.com/leodip/goiabada/authserver/internal/sealing"

func stored(s sealing.SizedSealer, ct []byte) string {
	seed, _ := s.Decrypt(ct)
	return seed
}
`)

	report := guard.Run(func(r guard.Reporter) {
		assertNoDiscardedErrors(r, root, discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
	})

	assert.False(t, report.Failed(), "a method of an interface the cipher does not implement failed the guard: %s", report.Text())
}

// TestDiscardedErrors_Guard_PassesAKeptError is the other direction, through a function and a
// method.
func TestDiscardedErrors_Guard_PassesAKeptError(t *testing.T) {
	root := t.TempDir()
	writeDiscardedErrorModule(t, root)
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

	report := guard.Run(func(r guard.Reporter) {
		assertNoDiscardedErrors(r, root, discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
	})

	assert.False(t, report.Failed(), "a kept error failed the guard: %s", report.Text())
}

// A discard in a file only one of the builds selects is still shipped, or runs in the development
// server, so the walk reads every release build and the default build and merges what they find
// (#420 decision 11).
func TestDiscardedErrors_Finder_ReadsAFileOnlyOneBuildSelects(t *testing.T) {
	const discard = `
package data

import "github.com/leodip/goiabada/authserver/internal/passwordhash"

func seed(p string) string {
	hash, _ := passwordhash.Hash(p)
	return hash
}
`
	for _, tc := range []struct{ name, constraint string }{
		{"another platform's release build", "//go:build windows\n"},
		{"the production tag", "//go:build production\n"},
		{"the default build only", "//go:build !production\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeDiscardedErrorModule(t, root)
			writeDiscardedErrorFixture(t, root, "authserver/internal/data/seeder.go", tc.constraint+discard)

			found, files, err := findDiscardedErrors(root, discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
			require.NoError(t, err)

			assert.Equal(t, []string{"authserver/internal/data/seeder.go:8: passwordhash.Hash"},
				discardedErrorStrings(found), "found once however many builds select the file")
			assert.Equal(t, 7, files, "the six listed packages' files and the seeder, each counted once")
		})
	}
}

// A package that does not compile cannot be read whole, and a discard in it would pass unseen, so
// the walk stops and names it (#420 decision 3).
func TestDiscardedErrors_Guard_IsFatalOnAPackageThatDoesNotCompile(t *testing.T) {
	root := t.TempDir()
	writeDiscardedErrorModule(t, root)
	writeDiscardedErrorFixture(t, root, "authserver/internal/broken/broken.go", "package broken\n\nfunc Broken() int { return \"x\" }\n")

	report := guard.Run(func(r guard.Reporter) {
		assertNoDiscardedErrors(r, root, discardedErrorScope, discardedErrorFuncs, discardedErrorMethods)
	})

	require.True(t, report.Stopped, "a package that does not compile must be fatal rather than read in part")
	assert.Contains(t, report.Fatal, "github.com/leodip/goiabada/authserver/internal/broken")
	assert.Contains(t, report.Fatal, "does not load or type-check")
}

// TestDiscardedErrors_Guard_IsFatalOnAnEmptyRead pins the seam: a walk that read nothing is a
// failure, not a clean pass.
func TestDiscardedErrors_Guard_IsFatalOnAnEmptyRead(t *testing.T) {
	root := t.TempDir()
	writeDiscardedErrorFixture(t, root, "authserver/go.mod", "module github.com/leodip/goiabada/authserver\n")
	require.NoError(t, pkgload.MakeLoadable(root))
	writeDiscardedErrorFixture(t, root, "authserver/README.md", "no Go here\n")

	report := guard.Run(func(r guard.Reporter) {
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
	root := guard.SourceRoot(t)

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
