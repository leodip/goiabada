package refgraph

import (
	"go/ast"
	"go/build/constraint"
	"go/token"
	"sort"
	"strings"
)

// ExemptByBuildConstraint reports whether the file's //go:build expression cannot be true in any
// build that sets the production tag. Every other tag in the expression is free, so each
// assignment of them is evaluated with production true and the file is exempt only when all of
// them come out false.
//
// Evaluating with production alone would be wrong in both directions: it would exempt
// "linux || !production", which is true on every production Linux build, and it would walk
// "!production && tools", which can never be part of one.
func ExemptByBuildConstraint(file *ast.File, fset *token.FileSet) bool {
	expr := buildConstraint(file, fset)
	if expr == nil {
		return false
	}
	free := freeTags(expr)
	// A pathological expression is walked rather than exempted: 2^n assignments is the cost of
	// the answer, and refusing to pay it must never be the permissive direction.
	if len(free) > 12 {
		return false
	}
	for assignment := 0; assignment < 1<<len(free); assignment++ {
		values := make(map[string]bool, len(free))
		for i, tag := range free {
			values[tag] = assignment&(1<<i) != 0
		}
		satisfied := expr.Eval(func(tag string) bool {
			if tag == "production" {
				return true
			}
			return values[tag]
		})
		if satisfied {
			return false
		}
	}
	return true
}

// buildConstraint returns the file's //go:build expression, or nil when it has none. Only comments
// above the package clause count, which is what go/build itself requires.
func buildConstraint(file *ast.File, fset *token.FileSet) constraint.Expr {
	packageLine := fset.Position(file.Package).Line
	for _, group := range file.Comments {
		if fset.Position(group.End()).Line >= packageLine {
			break
		}
		for _, comment := range group.List {
			if !constraint.IsGoBuild(comment.Text) {
				continue
			}
			expr, err := constraint.Parse(comment.Text)
			if err != nil {
				return nil
			}
			return expr
		}
	}
	return nil
}

// freeTags lists every tag in expr except production, deduplicated and in a stable order.
func freeTags(expr constraint.Expr) []string {
	seen := map[string]bool{}
	var tags []string
	var walk func(constraint.Expr)
	walk = func(e constraint.Expr) {
		switch x := e.(type) {
		case *constraint.TagExpr:
			if x.Tag == "production" || seen[x.Tag] {
				return
			}
			seen[x.Tag] = true
			tags = append(tags, x.Tag)
		case *constraint.NotExpr:
			walk(x.X)
		case *constraint.AndExpr:
			walk(x.X)
			walk(x.Y)
		case *constraint.OrExpr:
			walk(x.X)
			walk(x.Y)
		}
	}
	walk(expr)
	sort.Strings(tags)
	return tags
}

// Unparen strips the parentheses around an expression. (errors.New)("x") calls exactly what
// errors.New("x") calls, and a rule reading only the bare form is one pair of brackets away from
// being silent on it.
func Unparen(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

// LocalImportName returns the identifier a file binds an import path to. A blank or dot import
// binds no identifier a selector can name, so neither counts as a reference.
//
// declared is the package clause of the imported package, which is what Go binds when the import
// carries no alias -- the last segment of the path is only the usual spelling of it, not the rule.
// A caller that does not know the name passes "" and gets that usual spelling; the two differ
// exactly when a package is named for something other than its directory, and there every
// reference to it would otherwise be read as no reference at all. Final review round 3, finding 5.
func LocalImportName(file *ast.File, importPath, declared string) (string, bool) {
	for _, spec := range file.Imports {
		if spec.Path == nil || strings.Trim(spec.Path.Value, `"`) != importPath {
			continue
		}
		if spec.Name == nil {
			if declared != "" {
				return declared, true
			}
			return importPath[strings.LastIndex(importPath, "/")+1:], true
		}
		if spec.Name.Name == "_" || spec.Name.Name == "." {
			return "", false
		}
		return spec.Name.Name, true
	}
	return "", false
}

// SelectedNames lists the exported symbols selected off the given identifier.
func SelectedNames(file *ast.File, local string) []string {
	seen := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != local {
			return true
		}
		// A non-nil Obj means the parser resolved the name to a declaration in this file, so it is
		// something shadowing the import rather than the package.
		if ident.Obj != nil {
			return true
		}
		if sel.Sel.IsExported() {
			seen[sel.Sel.Name] = true
		}
		return true
	})

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
