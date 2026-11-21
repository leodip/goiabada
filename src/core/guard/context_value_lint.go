package guard

import (
	"errors"
	"go/token"
	"go/types"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/leodip/goiabada/core/internal/refgraph"
	"github.com/leodip/goiabada/core/pkgload"
	"golang.org/x/tools/go/packages"
)

// ContextValueExemption is one production file allowed to read or write a context value itself,
// outside the accessor package. Reason is required: an exemption is a decision somebody made, and
// the guard refuses one that does not say what it was.
type ContextValueExemption struct {
	// File is relative to the module root, forward slashes.
	File   string
	Reason string
}

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
// value taken without a call all resolve to the same two objects, and so does a Value call on a
// context another package returned.
//
// The module is read through pkgload as every release build selects its files, and as the test
// machine's default build does, and what they find is merged: a raw read in a file only Windows
// compiles is shipped all the same, and one in a development-only file runs in the development
// server (#420). A file only a race build or a custom tag selects is read by neither. A package
// that does not load or type-check is fatal, naming it, since a raw read in it would go unseen.
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
	// problems are the findings about the call itself: exemptions and the accessor directory.
	problems []string
	// sites counts every site reached, inside the accessor package and exemptions included.
	sites int
}

// findContextValueSites reads every site the module's production files hold and sorts each into
// allowed and refused.
func findContextValueSites(
	root, module, accessorDir string, exemptions []ContextValueExemption,
) (contextValueWalk, error) {
	var walk contextValueWalk

	modRoot := filepath.Join(root, filepath.FromSlash(module))
	if _, err := refgraph.ModulePath(filepath.Join(modRoot, "go.mod")); err != nil {
		return walk, err
	}
	sites, err := contextValueSitesIn(modRoot)
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
	for _, s := range sites {
		walk.sites++
		perFile[s.file]++
		if path.Dir(s.file) == accessorDir || exempt[s.file] {
			continue
		}
		walk.findings = append(walk.findings, s)
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

	sort.Slice(walk.findings, func(i, j int) bool {
		if walk.findings[i].file != walk.findings[j].file {
			return walk.findings[i].file < walk.findings[j].file
		}
		return walk.findings[i].line < walk.findings[j].line
	})
	sort.Strings(walk.problems)
	return walk, nil
}

// contextValueSitesIn loads the module rooted at modRoot for every release build and the default
// build, and returns every site their production files hold, once each however many builds select
// its file. The loads are requested at once and pkgload runs the go command for one at a time;
// the first error in build order is the one returned. A build that selects no package of the module adds nothing.
func contextValueSitesIn(modRoot string) ([]contextValueFinding, error) {
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

	seen := map[token.Position]bool{}
	var sites []contextValueFinding
	for i := range builds {
		if loadErrs[i] != nil && !errors.Is(loadErrs[i], pkgload.ErrNoPackages) {
			return nil, loadErrs[i]
		}
		for _, p := range loaded[i] {
			for ident, obj := range p.TypesInfo.Uses {
				what, ok := contextValueObject(obj)
				if !ok {
					continue
				}
				// The physical position, not one a //line directive maps: the file a site is in is what
				// the accessor directory and the exemptions are about, and two files mapping to one
				// line are two sites.
				at := p.Fset.PositionFor(ident.Pos(), false)
				if seen[at] {
					continue
				}
				seen[at] = true
				sites = append(sites, contextValueFinding{
					file: relativeTo(modRoot, at.Filename),
					line: at.Line,
					what: what,
				})
			}
		}
	}
	return sites, nil
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
	case isMethod && fn.Name() == "Value":
		return "a context Value read", true
	}
	return "", false
}
