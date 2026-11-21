package guard

import (
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/pkgload"
	"golang.org/x/tools/go/packages"
)

// testifyMockImportPath is testify's mock package, whose Mock every generated double embeds and
// whose AssertNotCalled is the assertion this guard holds.
const testifyMockImportPath = "github.com/stretchr/testify/mock"

// notCalledSelector is the name of testify's assertion. A site is a call of that method of
// testify's Mock, decided by the object the selector binds to: a method of the name on another
// type is no site, whatever package declares it or what that package is called.
const notCalledSelector = "AssertNotCalled"

// AssertNotCalledArity refuses a testify AssertNotCalled whose matcher count differs from the
// number of parameters the named method takes on the mock the assertion is made against.
//
// testify matches a recorded call on the method name AND the whole argument list:
// Arguments.Diff compares position by position and counts a length difference as a difference
// like any other. So AssertNotCalled(t, "Log") against a Log that takes three parameters asks
// whether a three-argument call equals a zero-argument one, the answer is no whatever the subject
// did, and the assertion passes. The compiler sees a variadic call and says nothing. The tier
// stays green. The test reads as a guarantee and is not one.
//
// This is verified rather than suspected. While landing #386 two such sites were given their real
// arity, and one failed at once: handler_auth_issue_test.go asserted GetUserById was not called on
// the empty-id_token_hint path, while the handler has read the user unconditionally since #241's
// live permission check. That assertion had been false since #241 landed and had never once said
// so (#421).
//
// The count it holds them to is the mock's own method, not the interface's, because the mock's
// method is what records the call: mockery generates a body that passes exactly its own parameters
// to Mock.Called, so the recorded argument list is that method's parameter list and nothing else.
// The two agree by construction today -- a generated double satisfies the interface it was
// generated from -- and when they ever disagree, the recorded list is the one testify compares
// against.
//
// Four shapes are reported rather than passed over, because each one is an assertion that cannot
// be shown to hold and a guard that skips what it cannot answer is a guard that narrows itself:
//
//   - a method named through anything but a string literal, which is an arity no walk can read.
//     The one such site in this tree was a helper looping over names its callers passed, and it
//     was vacuous at every one of them;
//   - a name the receiver's type declares no method for, which is an assertion that can never
//     match anything and so passes unconditionally -- the same defect as a wrong count, reached by
//     a typo instead;
//   - a variadic method, whose recorded length testify's own matching rules decide rather than the
//     signature. There is none in this tree, which is what makes refusing one free;
//   - matchers spread from a slice with ..., whose number the call does not show. There is none
//     in this tree either.
//
// It does not widen to AssertCalled, whose failure mode is the opposite and is loud: an arity
// mismatch there makes the assertion fail on every run, so no such site can survive a green tier.
// Nor to On(...), where a stub that matches nothing makes the call panic. AssertNotCalled is the
// only one of the three that fails silently, which is the whole reason it needs a guard (#421).
//
// Each module holding a walked directory is read through pkgload as the test build of the machine
// the tests run on, where the assertions are: a test for another platform does not run there
// (#420). A package anywhere in such a module that does not load or type-check is fatal, naming
// it, because the assertions in it would go unread.
//
// Passing dirs restricts the walk to those subdirectories of the source root, forward slashes and
// relative to it, exactly as AssertSlogConvention's and AssertNoDeadInterfaces' parameter does.
func AssertNotCalledArity(t *testing.T, dirs ...string) {
	t.Helper()

	assertNotCalledArity(t, SourceRoot(t), dirs)
}

// assertNotCalledArity is the reporting half, taking the root as a parameter and failing through a
// Reporter so a rule test can drive it against a fixture tree. See Reporter in guard.go.
func assertNotCalledArity(r Reporter, root string, dirs []string) {
	r.Helper()

	findings, refused, sites, err := findNotCalledArity(root, dirs)
	if err != nil {
		r.Fatalf("walking %s: %v", root, err)
	}
	// A walk that reached no assertion passes vacuously. That is the one way this guard stops
	// guarding with nothing going red, and it is reachable two ways: a dirs argument that no
	// longer names any Go source, and a tree that has stopped writing the assertion altogether.
	// The second wants the guard deleted rather than left standing over nothing.
	if sites == 0 {
		r.Fatalf("walked no %s call under %s (dirs: %s)",
			notCalledSelector, root, strings.Join(dirs, ", "))
	}

	// A shape this walk cannot hold to an arity is reported rather than skipped: a false failure
	// gets investigated, a false pass is a guard that has quietly stopped guarding.
	for _, x := range refused {
		r.Errorf("%s:%d: %s", x.file, x.line, x.why)
	}

	if len(findings) == 0 {
		return
	}

	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		lines = append(lines, f.file+":"+strconv.Itoa(f.line)+": "+
			notCalledSelector+"(t, \""+f.method+"\", ...) passes "+strconv.Itoa(f.given)+
			" matcher(s) to "+f.recv+"."+f.method+", which takes "+strconv.Itoa(f.want))
	}
	r.Errorf("%d %s assertion(s) that can never fail:\n\t%s\n\n"+
		"testify matches a recorded call on the method name and the whole argument list, so an "+
		"assertion carrying the wrong number of matchers compares lists that can never be equal "+
		"and passes whatever the subject did. Give each one a matcher per parameter -- "+
		"mock.Anything where the value does not matter -- and then read what the assertion says "+
		"once it is live, because a site that has been vacuous for months may be asserting "+
		"something the handler stopped doing long ago (#421).",
		len(findings), notCalledSelector, strings.Join(lines, "\n\t"))
}

// notCalledFinding is one assertion whose matcher count does not match the method it names.
type notCalledFinding struct {
	// file is relative to the source root, forward slashes.
	file string
	line int
	// recv is the receiver's type as the reader wrote it, qualified by package name.
	recv   string
	method string
	// given is the matcher count at the site, want the method's parameter count.
	given int
	want  int
}

// notCalledRefusal is an assertion this walk reached and cannot hold to an arity, located.
type notCalledRefusal struct {
	// file is relative to the source root, forward slashes.
	file string
	line int
	why  string
}

// findNotCalledArity loads each module holding a directory under dirs and applies the rule to every
// site in those directories. It returns the findings, the shapes it refuses, and the number of
// sites it reached.
func findNotCalledArity(root string, dirs []string) ([]notCalledFinding, []notCalledRefusal, int, error) {
	walked, err := declaringDirs(root, dirs)
	if err != nil {
		return nil, nil, 0, err
	}
	order, byModule, err := dirsByModule(root, walked)
	if err != nil {
		return nil, nil, 0, err
	}

	var findings []notCalledFinding
	var refused []notCalledRefusal
	// seen keeps one site once: the test build type-checks a package a second time with its
	// internal tests, so a file appears in two packages.
	seen := map[token.Position]bool{}
	for _, modRoot := range order {
		pkgs, lErr := pkgload.Load(modRoot, pkgload.Build{Tests: true})
		// A module the build selects no package of holds no site; the site count reports an empty
		// walk once every module has been read.
		if errors.Is(lErr, pkgload.ErrNoPackages) {
			continue
		}
		if lErr != nil {
			return nil, nil, len(seen), lErr
		}
		for _, p := range pkgs {
			for _, file := range p.Syntax {
				// The file's own name, not one a //line directive maps its package clause to: the
				// directory a file is in is what the caller's dirs are about.
				if !byModule[modRoot][filepath.Dir(pkgload.Position(p, file.Pos()).Filename)] {
					continue
				}
				f, r := notCalledSitesIn(file, p, root, seen)
				findings = append(findings, f...)
				refused = append(refused, r...)
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].file != findings[j].file {
			return findings[i].file < findings[j].file
		}
		return findings[i].line < findings[j].line
	})
	sort.Slice(refused, func(i, j int) bool {
		if refused[i].file != refused[j].file {
			return refused[i].file < refused[j].file
		}
		return refused[i].line < refused[j].line
	})
	return findings, refused, len(seen), nil
}

// isNotCalledSite reports whether a selector names testify's own AssertNotCalled, promoted through
// a double's embedded Mock or called on a Mock directly.
func isNotCalledSite(info *types.Info, sel *ast.SelectorExpr) bool {
	if sel.Sel.Name != notCalledSelector {
		return false
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == testifyMockImportPath
}

// notCalledSitesIn applies the rule to every site in one checked file that seen has not counted.
func notCalledSitesIn(
	file *ast.File, p *packages.Package, root string, seen map[token.Position]bool,
) ([]notCalledFinding, []notCalledRefusal) {
	info, pkg := p.TypesInfo, p.Types
	var findings []notCalledFinding
	var refused []notCalledRefusal

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		// Parentheses around the selector, (m.AssertNotCalled)(t, ...), change nothing about the call.
		sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok || !isNotCalledSite(info, sel) {
			return true
		}
		// The physical position, not one a //line directive maps: two files mapping to one line are
		// two sites, and a site is reported at its own file's line.
		position := pkgload.Position(p, call.Pos())
		if seen[position] {
			return true
		}
		seen[position] = true

		rel := relativeTo(root, position.Filename)
		refuse := func(why string) {
			refused = append(refused, notCalledRefusal{file: rel, line: position.Line, why: why})
		}

		// A spread final argument hands testify the slice's elements, whose number the call does
		// not show: counted as one matcher, an empty spread would pass and a full one be a finding.
		if call.Ellipsis.IsValid() {
			refuse(notCalledSelector + " spreads its matchers from a slice with ..., so no walk " +
				"can read how many it passes; pass each matcher as an argument of its own")
			return true
		}

		// A method expression, (*doubles.Database).AssertNotCalled(db, t, ...), takes the receiver
		// as its first argument; the assertion's own arguments follow it.
		args := call.Args
		if s, isSel := info.Selections[sel]; isSel && s.Kind() == types.MethodExpr && len(args) > 0 {
			args = args[1:]
		}

		var lit *ast.BasicLit
		if len(args) >= 2 {
			lit, _ = args[1].(*ast.BasicLit)
		}
		if lit == nil || lit.Kind != token.STRING {
			refuse(notCalledSelector + " names its method through an expression rather than a " +
				"string literal, so no walk can read the arity it should carry; spell the name " +
				"at the site, or assert over the mock's recorded Calls, which match on the name " +
				"alone")
			return true
		}
		// A string literal in a package that type-checked always unquotes.
		method, _ := strconv.Unquote(lit.Value)

		// The double's Mock field named, d.Mock.AssertNotCalled: the method the name means is the
		// double's, and the walk reads it on the type the call is written on, which here is Mock.
		if field, isField := ast.Unparen(sel.X).(*ast.SelectorExpr); isField {
			if s, isSel := info.Selections[field]; isSel && s.Kind() == types.FieldVal && isTestifyMock(s.Obj().Type()) {
				refuse(notCalledSelector + "(t, \"" + method + "\", ...) is called on the Mock field " +
					types.ExprString(field) + " rather than on the double, a form this walk does not read, " +
					"since the method it names is the double's; call " + types.ExprString(field.X) + "." +
					notCalledSelector + " instead")
				return true
			}
		}

		recvType := info.TypeOf(sel.X)
		obj, _, _ := types.LookupFieldOrMethod(recvType, true, pkg, method)
		fn, ok := obj.(*types.Func)
		if !ok {
			refuse(notCalledSelector + "(t, \"" + method + "\", ...) names a method " +
				typeName(recvType, pkg) + " does not declare, so it can never match a recorded " +
				"call and passes whatever the subject did")
			return true
		}
		sig := fn.Type().(*types.Signature)
		if sig.Variadic() {
			refuse(notCalledSelector + "(t, \"" + method + "\", ...) names a variadic method, " +
				"whose recorded argument list depends on what the double spreads into Called " +
				"rather than on its signature; assert over the mock's recorded Calls instead")
			return true
		}

		want := sig.Params().Len()
		given := len(args) - 2
		if want != given {
			findings = append(findings, notCalledFinding{
				file:   rel,
				line:   position.Line,
				recv:   typeName(recvType, pkg),
				method: method,
				given:  given,
				want:   want,
			})
		}
		return true
	})

	return findings, refused
}

// isTestifyMock reports whether t is testify's Mock or a pointer to it.
func isTestifyMock(t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == testifyMockImportPath &&
		named.Obj().Name() == "Mock"
}

// typeName renders a type the way the file that named it reads, qualified by package name rather
// than by import path, so a finding points at datamocks.Database and not at the whole path.
func typeName(typ types.Type, pkg *types.Package) string {
	qualifier := func(p *types.Package) string {
		if pkg != nil && p == pkg {
			return ""
		}
		return p.Name()
	}
	return types.TypeString(typ, qualifier)
}
