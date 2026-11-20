package refgraph

import (
	"go/ast"
	"go/build/constraint"
	"go/token"
	"sort"
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
