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

// AssertAuditLogContext refuses a .Log call whose first argument is context.Background() or
// context.TODO(), inside the directories slogRequestPathDirs lists.
//
// The compiler already forces every one of AuditLogger.Log's 126 call sites to pass a context,
// which is what #328 replaced the signature for. What no compiler forces is that the context is
// the request's, and that is the whole value of the change: a site written
// auditLogger.Log(context.Background(), ...) compiles, satisfies every other guard in this
// package and sloglint alike, and produces exactly the uncorrelated audit record the issue
// exists to remove. sloglint reads slog's own calls, not ours, so it cannot see this shape at
// all (#328 decision 3).
//
// Scope is deliberately the request-path directories rather than the two audit packages: the
// rule is about a call site, and a call site in a package a request runs through has a request
// context in reach by construction. Elsewhere — a startup pass, a worker, a command — a
// Background context is the honest answer, which is why core/data/commondb's backfill passes one
// and is not refused here.
//
// The rule matches on the selector name alone, so it covers slog.Log as well as auditLogger.Log
// and any future method by that name. That is wider than the issue and correct for the same
// reason: a record written under a Background context in a request-path package carries no
// request id whichever function wrote it.
//
// Passing dirs restricts the walk to those subdirectories of the source root, forward slashes
// and relative to it, exactly as AssertSlogConvention's parameter does. The scope filter is
// applied either way, so a file outside slogRequestPathDirs is walked and admitted rather than
// skipped, and the fixture case proving that is a check of the filter rather than of the walk.
func AssertAuditLogContext(t *testing.T, dirs ...string) {
	t.Helper()

	root := SourceRoot(t)

	violations, files, err := findAuditLogContextViolations(root, dirs)
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	// A scope that held no Go files walks nothing and would otherwise pass, which is the one way
	// a guard like this fails silently in the direction that matters.
	if files == 0 {
		t.Fatalf("walked no non-test Go files in a request-path package under %s (dirs: %s)",
			root, strings.Join(dirs, ", "))
	}
	if len(violations) == 0 {
		return
	}

	lines := make([]string, 0, len(violations))
	for _, v := range violations {
		lines = append(lines, v.file+":"+strconv.Itoa(v.line)+": "+v.what+" -- "+v.fix)
	}
	t.Errorf("%d audit context violation(s) in %d non-test file(s) in a request-path package:\n\t%s\n\n"+
		"An audit event raised while serving a request carries that request's context, so the "+
		"installed handler correlates it to the request: pass r.Context(), or the ctx the "+
		"enclosing function already holds. A Background or TODO context compiles and produces a "+
		"record no operator can join to the request that caused it (#328).",
		len(violations), files, strings.Join(lines, "\n\t"))
}

// findAuditLogContextViolations walks the tree and applies the rule to every non-test file in a
// request-path package, in the shape findSlogViolations uses: same roots, same path and build
// constraint exemptions, same sorted output, so one answer about what production code means holds
// for both guards.
func findAuditLogContextViolations(root string, dirs []string) ([]slogViolation, int, error) {
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
			violations = append(violations, auditLogContextViolationsInFile(file, fset, rel)...)
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

// auditLogContextViolationsInFile applies the rule to one parsed file.
func auditLogContextViolationsInFile(file *ast.File, fset *token.FileSet, rel string) []slogViolation {
	var violations []slogViolation

	// importPaths maps the name a file actually writes at a call site to the path it imports, so
	// an aliased context resolves like any other. Without it `import stdctx "context"` followed
	// by stdctx.Background() is invisible to the rule, which is the one rename that would carry
	// the refused shape past it.
	importPaths := map[string]string{}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := defaultImportName(path)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "." || name == "_" {
			continue
		}
		importPaths[name] = path
	}

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := unparen(call.Fun).(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != auditLogMethodName || len(call.Args) == 0 {
			return true
		}
		// A qualified call as the first argument, so x.Log(ctx, ...) and x.Log(r.Context(), ...)
		// both fall straight through: neither resolves to an imported package's function.
		first, isCall := unparen(call.Args[0]).(*ast.CallExpr)
		if !isCall {
			return true
		}
		path, name, resolved := qualifiedCall(first, importPaths)
		if !resolved || path != contextImportPath || !auditLogRefusedContexts[name] {
			return true
		}
		violations = append(violations, slogViolation{
			file: rel,
			line: fset.Position(first.Pos()).Line,
			what: "context." + name + "() passed to ." + auditLogMethodName +
				" in a request-path package",
			fix: "pass the request's context: r.Context(), or the ctx the enclosing function " +
				"already holds, so the record carries the request id",
		})
		return true
	})

	return violations
}

const (
	contextImportPath = "context"
	// auditLogMethodName is matched on the selector alone, per the header: the rule is about the
	// context a record is written under, not about which type declared the method.
	auditLogMethodName = "Log"
)

// auditLogRefusedContexts is the two constructors of a context carrying nothing. They are one
// rule rather than two because they differ only in what a reader is meant to infer about intent,
// and the record they produce is identical.
var auditLogRefusedContexts = map[string]bool{
	"Background": true,
	"TODO":       true,
}
