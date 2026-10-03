package testutil

import (
	"bytes"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/internal/refgraph"
)

// ContextValueExemption is one production file allowed to read or write a context value itself,
// outside the accessor package. Reason is required: an exemption is a decision somebody made, and
// the guard refuses one that does not say what it was.
type ContextValueExemption struct {
	// File is relative to the module root, forward slashes.
	File   string
	Reason string
}

// contextValueSourcePackages are the standard library packages the importer reads from GOROOT
// source rather than stubbing. context declares what a site is: WithValue and the Value method.
// net/http declares Request.Context, which is how a handler or middleware reaches its request's
// context, so without it r.Context().Value(k) -- the rate limiter's shape -- would be a receiver
// of unknown type. Every other path is a stub, as in AssertNotCalledArity's importer, because a
// value whose type came through a stub is reported rather than guessed at.
var contextValueSourcePackages = map[string]bool{
	"context":  true,
	"net/http": true,
}

// contextValueSelector is the spelling every site carries, context.WithValue or a Value method,
// and so the sound text pre-filter on type-checking a directory.
const contextValueSelector = "Value"

// AssertContextValuesThroughAccessors refuses a context.WithValue call, and a Value call on a
// context.Context, in any production file of module outside accessorDir and the exempted files.
//
// The Go context documentation asks two things of a package storing request-scoped values: define
// the key as an unexported type, and provide type-safe accessors for the values stored under it.
// The auth server did neither before #433: four keys exported from one constants file, 70
// production lines calling Value with them, 44 of those an unchecked type assertion that panics
// when the value is absent, and a consent-delete audit event reading an untyped "subject" key
// nothing ever wrote, so every such row named nobody. #433 moved all four values behind
// internal/reqctx, whose readers answer (T, bool) over an unexported key. That holds only as long
// as nothing reaches around it, and a raw read compiles against any key it can name -- including a
// string literal, which is exactly how the consent defect was written.
//
// A site is found by the object an identifier binds to, never by spelling: ctx.Value, an aliased
// or dot-imported context, a type embedding context.Context and promoting its Value, and a method
// value taken without a call all resolve to the same two objects. A one-argument Value call whose
// receiver the walk cannot resolve is reported rather than skipped, since it may be a context read
// and a guard that skips what it cannot answer is a guard that narrows itself.
//
// module is relative to the source root ("authserver"); accessorDir and each exemption's File are
// relative to the module. Test files are not walked: a test builds contexts through the accessors
// too, but what the rule protects is the production channel. Both applications call it, each with
// its own internal/reqctx: the auth server since #433 and the admin console since #440.
func AssertContextValuesThroughAccessors(
	t *testing.T, module, accessorDir string, exemptions ...ContextValueExemption,
) {
	t.Helper()

	assertContextValuesThroughAccessors(t, SourceRoot(t), module, accessorDir, exemptions)
}

// assertContextValuesThroughAccessors is the reporting half, taking the root as a parameter and
// failing through a Reporter so a rule test can drive it against a fixture tree. See Reporter in
// guard.go.
func assertContextValuesThroughAccessors(r Reporter, root, module, accessorDir string, exemptions []ContextValueExemption) {
	r.Helper()

	walk, err := findContextValueSites(root, module, accessorDir, exemptions)
	if err != nil {
		r.Fatalf("walking %s: %v", filepath.Join(root, filepath.FromSlash(module)), err)
	}
	// A walk that reached no site at all -- not even the accessor package's own -- has stopped
	// guarding: a module argument naming no Go source, or a tree whose accessors were renamed away.
	if walk.sites == 0 {
		r.Fatalf("walked no context.WithValue or context Value call under %s", module)
	}

	for _, p := range walk.problems {
		r.Errorf("%s", p)
	}
	for _, b := range walk.blocked {
		r.Errorf("%s:%d: %s", b.file, b.line, b.why)
	}

	if len(walk.findings) == 0 {
		return
	}
	lines := make([]string, 0, len(walk.findings))
	for _, f := range walk.findings {
		lines = append(lines, f.file+":"+strconv.Itoa(f.line)+": "+f.what)
	}
	r.Errorf("%d raw context value read(s) or write(s) outside %s:\n\t%s\n\n"+
		"Request-scoped values go through %s's typed accessors, which read an unexported key and "+
		"answer (T, bool), so an absent value is a branch the caller writes rather than a panic "+
		"or a silent zero, and a key nobody writes cannot be read at all. Add an accessor there, "+
		"or, for a key private to one file, an exemption carrying its reason (#433).",
		len(walk.findings), accessorDir, strings.Join(lines, "\n\t"), accessorDir)
}

// contextValueFinding is one site outside the accessor package and the exempted files.
type contextValueFinding struct {
	// file is relative to the module root, forward slashes.
	file string
	line int
	what string
}

// contextValueWalk is everything one walk found.
type contextValueWalk struct {
	findings []contextValueFinding
	blocked  []unresolvedShape
	// problems are the findings about the call itself: exemptions and the accessor directory.
	problems []string
	// sites counts every site reached, inside the accessor package and exemptions included.
	sites int
}

// findContextValueSites type-checks every production directory of the module that spells a site
// and sorts each site into allowed and refused.
func findContextValueSites(
	root, module, accessorDir string, exemptions []ContextValueExemption,
) (contextValueWalk, error) {
	var walk contextValueWalk

	modRoot := filepath.Join(root, filepath.FromSlash(module))
	modPath, err := refgraph.ModulePath(filepath.Join(modRoot, "go.mod"))
	if err != nil {
		return walk, err
	}
	imp, err := newContextPackages()
	if err != nil {
		return walk, err
	}

	dirs, err := productionDirsSpelling(modRoot, contextValueSelector)
	if err != nil {
		return walk, err
	}

	exempt := map[string]bool{}
	for _, e := range exemptions {
		if strings.TrimSpace(e.Reason) == "" {
			walk.problems = append(walk.problems, "exemption "+e.File+" carries no reason; "+
				"say why this file may hold a raw context value, or remove it")
		}
		exempt[e.File] = true
	}

	perFile := map[string]int{}
	for _, dir := range dirs {
		pkgPath := modPath
		if rel := relativeTo(modRoot, dir); rel != "." {
			pkgPath = modPath + "/" + rel
		}
		sites, blocked, cErr := contextValueSitesIn(modRoot, dir, pkgPath, imp)
		if cErr != nil {
			return walk, cErr
		}
		walk.blocked = append(walk.blocked, blocked...)
		for _, s := range sites {
			walk.sites++
			perFile[s.file]++
			if path.Dir(s.file) == accessorDir || exempt[s.file] {
				continue
			}
			walk.findings = append(walk.findings, s)
		}
	}

	// Both directions, as AssertArchitecture holds its exceptions: an exemption left standing for a
	// file that no longer needs it is permission the next edit to that file inherits silently.
	for _, e := range exemptions {
		if perFile[e.File] == 0 {
			walk.problems = append(walk.problems, "exemption "+e.File+" names a file holding no "+
				"context value read or write; remove the exemption")
		}
	}
	accessorSites := 0
	for file, n := range perFile {
		if path.Dir(file) == accessorDir {
			accessorSites += n
		}
	}
	if walk.sites > 0 && accessorSites == 0 {
		walk.problems = append(walk.problems, "accessor package "+accessorDir+" holds no "+
			"context value read or write, so it is not where this module's accessors are")
	}

	sortByFileLine := func(file func(i int) string, line func(i int) int) func(i, j int) bool {
		return func(i, j int) bool {
			if file(i) != file(j) {
				return file(i) < file(j)
			}
			return line(i) < line(j)
		}
	}
	sort.Slice(walk.findings, sortByFileLine(
		func(i int) string { return walk.findings[i].file }, func(i int) int { return walk.findings[i].line }))
	sort.Slice(walk.blocked, sortByFileLine(
		func(i int) string { return walk.blocked[i].file }, func(i int) int { return walk.blocked[i].line }))
	sort.Strings(walk.problems)
	return walk, nil
}

// productionDirsSpelling collects the directories under modRoot holding a non-test Go file whose
// text contains word, skipping a nested module, which is another module's to guard.
func productionDirsSpelling(modRoot, word string) ([]string, error) {
	seen := map[string]bool{}
	var found []string
	err := filepath.WalkDir(modRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedDir(d.Name()) {
				return fs.SkipDir
			}
			if p != modRoot {
				if _, sErr := os.Stat(filepath.Join(p, "go.mod")); sErr == nil {
					return fs.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		dir := filepath.Dir(p)
		if seen[dir] {
			return nil
		}
		raw, rErr := os.ReadFile(p)
		if rErr != nil {
			return errs.Wrapf(rErr, "reading %s", p)
		}
		if !bytes.Contains(raw, []byte(word)) {
			return nil
		}
		seen[dir] = true
		found = append(found, dir)
		return nil
	})
	if err != nil {
		return nil, errs.Wrapf(err, "walking %s", modRoot)
	}
	sort.Strings(found)
	return found, nil
}

// contextValueSitesIn type-checks one directory's production files, one group per package clause,
// and returns every site in them and every Value call it could not decide.
func contextValueSitesIn(
	modRoot, dir, pkgPath string, imp *contextPackages,
) ([]contextValueFinding, []unresolvedShape, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, errs.Wrapf(err, "reading %s", dir)
	}

	fset := token.NewFileSet()
	byPackage := map[string][]*ast.File{}
	var packageOrder []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, pErr := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns.
			continue
		}
		clause := file.Name.Name
		if _, ok := byPackage[clause]; !ok {
			packageOrder = append(packageOrder, clause)
		}
		byPackage[clause] = append(byPackage[clause], file)
	}

	var sites []contextValueFinding
	var blocked []unresolvedShape
	for _, clause := range packageOrder {
		group := byPackage[clause]
		info := &types.Info{
			Uses: map[*ast.Ident]types.Object{},
		}
		conf := types.Config{
			Importer: imp,
			// Every package but context and net/http is a stub, so the checker has plenty to say
			// about members it never read. Discarding it keeps the check running to the end; what
			// this guard asks survives, because a context's type comes from one of the two
			// packages that were read.
			Error:                    func(error) {},
			DisableUnusedImportCheck: true,
		}
		// The returned error is the first one Error already saw; info is filled in either way.
		_, _ = conf.Check(pkgPath, fset, group, info)

		for _, file := range group {
			s, b := contextValueSitesInFile(file, fset, info, modRoot)
			sites = append(sites, s...)
			blocked = append(blocked, b...)
		}
	}
	return sites, blocked, nil
}

// contextValueSitesInFile applies the rule to one checked file.
func contextValueSitesInFile(
	file *ast.File, fset *token.FileSet, info *types.Info, modRoot string,
) ([]contextValueFinding, []unresolvedShape) {
	var sites []contextValueFinding
	var blocked []unresolvedShape

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			if what, ok := contextValueObject(info.Uses[node]); ok {
				position := fset.Position(node.Pos())
				sites = append(sites, contextValueFinding{
					file: relativeTo(modRoot, position.Filename),
					line: position.Line,
					what: what,
				})
			}
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != contextValueSelector || len(node.Args) != 1 {
				return true
			}
			if info.Uses[sel.Sel] != nil {
				return true
			}
			// pkg.Value(x) is a function of some package, not a method on a value.
			if base, isIdent := sel.X.(*ast.Ident); isIdent {
				if _, isPkg := info.Uses[base].(*types.PkgName); isPkg {
					return true
				}
			}
			position := fset.Position(node.Pos())
			blocked = append(blocked, unresolvedShape{
				file: relativeTo(modRoot, position.Filename),
				line: position.Line,
				why: "a Value call on a receiver whose type this walk cannot resolve, so it cannot " +
					"tell whether this reads a context; give the receiver a type the walk can see " +
					"(a context.Context parameter, or r.Context())",
			})
		}
		return true
	})
	return sites, blocked
}

// contextValueObject reports whether obj is one of the two objects a site binds to, and names it.
func contextValueObject(obj types.Object) (string, bool) {
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "context" {
		return "", false
	}
	sig, _ := fn.Type().(*types.Signature)
	isMethod := sig != nil && sig.Recv() != nil
	switch {
	case !isMethod && fn.Name() == "WithValue":
		return "context.WithValue", true
	case isMethod && fn.Name() == contextValueSelector:
		return "a context Value read", true
	}
	return "", false
}

// contextPackages is the importer the rule type-checks against: the two packages in
// contextValueSourcePackages read from GOROOT source with the build constraints of this build,
// every other path an empty stub.
type contextPackages struct {
	goroot string
	stub   *stubPackages
	made   map[string]*types.Package
	fset   *token.FileSet
}

func newContextPackages() (*contextPackages, error) {
	goroot := build.Default.GOROOT
	if _, err := os.Stat(filepath.Join(goroot, "src", "context")); err != nil {
		// Without context's source every site is invisible and the walk would pass vacuously, so
		// this is the walk failing, not a package to stub.
		return nil, errs.Wrapf(err, "reading the context package from GOROOT %q", goroot)
	}
	return &contextPackages{
		goroot: goroot,
		stub:   newStubPackages(),
		made:   map[string]*types.Package{},
		fset:   token.NewFileSet(),
	}, nil
}

func (c *contextPackages) Import(importPath string) (*types.Package, error) {
	if made, ok := c.made[importPath]; ok {
		return made, nil
	}
	if !contextValueSourcePackages[importPath] {
		return c.stub.Import(importPath)
	}

	dir := filepath.Join(c.goroot, "src", filepath.FromSlash(importPath))
	bp, err := build.Default.ImportDir(dir, 0)
	if err != nil {
		return nil, errs.Wrapf(err, "reading %s from GOROOT", importPath)
	}
	files := make([]*ast.File, 0, len(bp.GoFiles))
	for _, name := range bp.GoFiles {
		file, pErr := parser.ParseFile(c.fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if pErr != nil {
			return nil, errs.Wrapf(pErr, "parsing %s", name)
		}
		files = append(files, file)
	}
	conf := types.Config{
		Importer:                 c,
		Error:                    func(error) {},
		DisableUnusedImportCheck: true,
	}
	pkg, _ := conf.Check(importPath, c.fset, files, nil)
	if pkg == nil {
		return nil, errs.Errorf("type-checking %s from GOROOT produced no package", importPath)
	}
	pkg.MarkComplete()
	c.made[importPath] = pkg
	return pkg, nil
}
