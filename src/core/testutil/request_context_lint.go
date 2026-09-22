package testutil

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
)

// AssertRequestPathContext refuses a context.Background() or context.TODO() call written in a
// non-test file inside the directories slogRequestPathDirs lists, outside the functions
// requestContextOwners names.
//
// #386 gave every one of the 215 Database methods and every one of the 106 admin console API
// methods a leading context, so that a cancelled request stops the work it started and every
// record it produces carries request_id. The compiler forces each of those call sites to pass
// *a* context. What no compiler forces is that the context is the request's, and a site written
// database.GetUserById(context.Background(), tx, id) compiles, satisfies every other guard here,
// and gives back exactly the uncancellable, uncorrelated call the issue exists to remove. This is
// the only thing that makes "every operation reachable from production code is cancellable by the
// request that asked for it" a fact rather than a claim.
//
// Scope is the request-path directories rather than the whole tree, for the reason
// slogRequestPathDirs already carries: in a package a request runs through, a request context is
// in reach by construction. Elsewhere -- a startup pass, a worker, a migration, a command -- a
// Background context is the honest answer and is admitted rather than refused, which is why the
// four engine adapters' connection contexts, the migrator's, the workers' and both main
// packages' are untouched by this and stay that way.
//
// This is the wider half of #386's guard 2. The narrower half, no bare .Query, .Exec or .Begin
// in commondb, is authserver/internal/data's sql_context_lint_test.go, which sits beside the
// data the rule is about; the two halves landed at different stages because the SQL one was
// satisfiable five stages before this one was.
//
// It does not replace AssertAuditLogContext, even though every shape that guard refuses is also a
// context.Background() in a request-path package today. The two part company the moment this rule
// admits an owner: an admitted function may still not write an audit record under a context
// carrying nothing, and only the narrower guard says so. Both run, and a site that breaks both is
// reported twice with the two remedies it owes.
//
// Passing dirs restricts the walk to those subdirectories of the source root, forward slashes and
// relative to it, exactly as AssertSlogConvention's and AssertAuditLogContext's parameter does.
// The scope filter is applied either way, so a file outside slogRequestPathDirs is walked and
// admitted rather than skipped.
func AssertRequestPathContext(t *testing.T, dirs ...string) {
	t.Helper()

	assertRequestPathContext(t, SourceRoot(t), dirs)
}

// assertRequestPathContext is the reporting half, taking the root as a parameter and failing
// through a Reporter so a rule test can drive it against a fixture tree. See Reporter in guard.go.
func assertRequestPathContext(r Reporter, root string, dirs []string) {
	r.Helper()

	violations, files, err := findRequestPathContextViolations(root, dirs)
	if err != nil {
		r.Fatalf("walking %s: %v", root, err)
	}
	// A scope that held no Go files walks nothing and would otherwise pass, which is the one way
	// a guard like this fails silently in the direction that matters.
	if files == 0 {
		r.Fatalf("walked no non-test Go files in a request-path package under %s (dirs: %s)",
			root, strings.Join(dirs, ", "))
	}
	if len(violations) == 0 {
		return
	}

	lines := make([]string, 0, len(violations))
	for _, v := range violations {
		lines = append(lines, v.file+":"+strconv.Itoa(v.line)+": "+v.what+" -- "+v.fix)
	}
	r.Errorf("%d request context violation(s) in %d non-test file(s) in a request-path package:\n\t%s\n\n"+
		"Work started while serving a request runs under that request's context, so cancelling "+
		"the request stops it and every record it writes carries the request id: pass "+
		"r.Context(), or the ctx the enclosing function already holds. A Background or TODO "+
		"context compiles, outlives the request that asked for it, and produces a record no "+
		"operator can join to it. A site that genuinely has no request above it -- a startup "+
		"pass, a worker, a command -- belongs outside these directories, or in "+
		"requestContextOwners with the reason (#386).",
		len(violations), files, strings.Join(lines, "\n\t"))
}

// findRequestPathContextViolations walks the tree and applies the rule to every non-test file in a
// request-path package, in the shape findAuditLogContextViolations uses: same roots, same path and
// build constraint exemptions, same sorted output, so one answer about what production code means
// holds for all three guards over this list.
func findRequestPathContextViolations(root string, dirs []string) ([]slogViolation, int, error) {
	roots := []string{root}
	if len(dirs) > 0 {
		roots = roots[:0]
		for _, dir := range dirs {
			roots = append(roots, filepath.Join(root, filepath.FromSlash(dir)))
		}
	}

	var violations []slogViolation
	files := 0
	for _, start := range roots {
		err := filepath.WalkDir(start, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return errs.Wrapf(relErr, "relating %s to %s", path, root)
			}
			rel = filepath.ToSlash(rel)
			if slogExemptByPath(rel) || !slogRequestPath(rel) {
				return nil
			}
			fset := token.NewFileSet()
			// ParseComments because the build constraint is a comment, and a file excluded from
			// every production build is exempt.
			file, pErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if pErr != nil {
				// A file that does not parse is a compile error the build tier owns, and
				// reporting it here would send the reader to the wrong place.
				return nil
			}
			if exemptByBuildConstraint(file, fset) {
				return nil
			}
			files++
			violations = append(violations, requestContextViolationsInFile(file, fset, rel)...)
			return nil
		})
		if err != nil {
			return nil, files, err
		}
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].file != violations[j].file {
			return violations[i].file < violations[j].file
		}
		if violations[i].line != violations[j].line {
			return violations[i].line < violations[j].line
		}
		return violations[i].what < violations[j].what
	})
	return violations, files, nil
}

// requestContextViolationsInFile applies the rule to one parsed file, one top-level declaration at
// a time so the enclosing function is known and requestContextOwners can be consulted. A call
// outside any function declaration -- in a package-level var, say -- has no name to admit and is
// refused, which is slogPlainAdmitted's answer to the same question.
func requestContextViolationsInFile(file *ast.File, fset *token.FileSet, rel string) []slogViolation {
	var violations []slogViolation

	// importPaths maps the name a file actually writes at a call site to the path it imports, so
	// an aliased context resolves like any other. Without it `import stdctx "context"` followed
	// by stdctx.Background() is invisible to the rule, which is the one rename that would carry
	// the refused shape past it.
	importPaths := bindImports(file, auditWatchedImports)

	for _, decl := range file.Decls {
		enclosing := ""
		if fn, ok := decl.(*ast.FuncDecl); ok {
			enclosing = fn.Name.Name
		}
		if enclosing != "" && requestContextOwner(rel, enclosing) {
			continue
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			path, name, resolved := qualifiedCall(call, importPaths)
			if !resolved || path != contextImportPath || !auditLogRefusedContexts[name] {
				return true
			}
			violations = append(violations, slogViolation{
				file: rel,
				line: fset.Position(call.Pos()).Line,
				what: "context." + name + "() in a request-path package",
				fix: "pass the request's context down instead: r.Context(), or the ctx the " +
					"enclosing function already holds",
			})
			return true
		})
	}

	return violations
}

// requestContextOwner reports whether a top-level function named name in the file rel is listed in
// requestContextOwners.
func requestContextOwner(rel, name string) bool {
	for _, site := range requestContextOwners {
		if site.name == name && rel == site.scope {
			return true
		}
	}
	return false
}

// requestContextOwners is the admission table, in slogPlainSites' shape: the file that declares the
// function, relative to the source root, so an admission cannot leak to a namesake elsewhere in the
// package, and the function name.
//
// One entry. sessionstore's store is called both from a handler, which has a request, and from the
// backend's own maintenance paths, which do not, and requestContext is the one function that says
// so: given no request it returns a background context rather than pretending to a cancellation
// signal it was never handed. Nothing in the store requires a request; the context only ever
// carries what a backend may use to save itself work.
var requestContextOwners = []slogPlainSite{
	{scope: "core/sessionstore/server_side_store.go", name: "requestContext"},
}
