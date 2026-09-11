package handlers

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
)

// TestHandlers_ApiClientErrorsReachTheClassifier refuses a console handler that decides for itself
// what an auth server API failure means.
//
// Every apiclient method funnels a non-2xx through parseAPIError, so "the row is gone", "you typed
// something the API refused" and "the API broke" all arrive at the caller as one
// *apiclient.APIError and are told apart only by its StatusCode. Three helpers do that telling
// apart, one per response shape: HandleAPIError for a page, HandleAPIErrorWithCallback for a page
// with a form to redraw, HandleAPIErrorJson for JSON. A guard that writes the error itself picks
// one meaning for all of them, and which meaning it picks is wrong in both directions:
//
//   - httpHelper.InternalServerError(w, r, err) or httpHelper.JsonError(w, r, err) turns an
//     upstream 404 into a 500. Following a stale link to a deleted client then tells the
//     administrator the server has broken, and spends a stack, a log record and a request id
//     saying so.
//   - A bare errors.As(err, &apiErr) followed by renderError(apiErr.Message) turns an upstream 404
//     or 500 into HTTP 200 with the API's sentence drawn as a form validation message, so a
//     missing entity reports success and a genuine server fault is never logged at all.
//
// Both were live when this lint was written, and both were written by copying the guard above
// them: the shape reads correct, compiles, and no test that does not inject an API status can tell
// the difference. That is what makes it a lint rather than a sweep (#279 decisions 11 and 13).
//
// The rule is one sentence: a guard on an error that came from apiClient must reach one of the
// three classifiers. It may route on a code first -- handler_admin_settings_email.go redraws its
// form for SMTP_NOT_ENABLED, handler_account_otp.go for its seven enrolment codes -- because those
// are codes a caller acts on, and the classifier is still what answers everything else.
//
// Two boundaries, stated rather than discovered later. The guard has to be the if statement that
// immediately follows the call or carries it in its own init, which is every guard in this tree and
// is what lets the rule be decided from syntax alone; an error stored, passed to another function
// and guarded there would not be seen. And the receiver is matched by the name apiClient, which is
// what every call site spells and what the handler signature binds.
func TestHandlers_ApiClientErrorsReachTheClassifier(t *testing.T) {
	// go test runs with the package directory as the working directory, so ".." is
	// src/adminconsole/internal.
	const root = "../handlers"

	fset := token.NewFileSet()
	var problems []string
	guards := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(path)
		ast.Inspect(file, func(n ast.Node) bool {
			block, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i := range block.List {
				guard, name := apiClientErrorGuard(block.List, i)
				if guard == nil {
					continue
				}
				if !guardAnswersTheRequest(guard.Body) {
					continue
				}
				guards++
				if blind := blindAPIErrorCatch(guard.Body); blind != nil {
					problems = append(problems, rel+":"+
						strconv.Itoa(fset.Position(blind.Pos()).Line)+": the error from "+name+
						" is caught here for every status, so 404 and 500 are answered as a "+
						"rejected value")
					continue
				}
				if guardReachesClassifier(guard.Body) {
					continue
				}
				problems = append(problems, rel+":"+
					strconv.Itoa(fset.Position(guard.Pos()).Line)+": the error from "+name+
					" is answered here without reaching HandleAPIError, "+
					"HandleAPIErrorWithCallback or HandleAPIErrorJson")
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	// A walk that matched no guard at all would pass while checking nothing, which is the one way
	// a rule like this fails in the direction that matters.
	if guards == 0 {
		t.Fatalf("found no apiClient error guards under %s; the receiver name or the guard shape has moved", root)
	}

	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("%d apiClient error guard(s) of %d answer the failure themselves:\n\t%s\n\n"+
			"Call handlers.HandleAPIError for a page, HandleAPIErrorWithCallback for a page with a "+
			"form to redraw, or HandleAPIErrorJson for JSON. Each routes 404 to the console's own "+
			"not-found answer, 400 (and 409, on the JSON one) to the caller, and everything else to "+
			"the 500 writer, which is where the stack and the request id belong (#279).",
			len(problems), guards, strings.Join(problems, "\n\t"))
	}
}

// apiClientErrorGuard reports the if statement guarding the error of an apiClient call at
// list[i], and the method it called. Two shapes carry every call site in this tree: the call in an
// assignment with the guard as the next statement, and the call in the guard's own init.
func apiClientErrorGuard(list []ast.Stmt, i int) (*ast.IfStmt, string) {
	switch stmt := list[i].(type) {
	case *ast.IfStmt:
		if stmt.Init == nil {
			return nil, ""
		}
		assign, ok := stmt.Init.(*ast.AssignStmt)
		if !ok {
			return nil, ""
		}
		name, ok := apiClientCallName(assign)
		if !ok || !condIsErrNotNil(stmt.Cond, errVarOf(assign)) {
			return nil, ""
		}
		return stmt, name
	case *ast.AssignStmt:
		name, ok := apiClientCallName(stmt)
		if !ok || i+1 >= len(list) {
			return nil, ""
		}
		next, ok := list[i+1].(*ast.IfStmt)
		if !ok || next.Init != nil || !condIsErrNotNil(next.Cond, errVarOf(stmt)) {
			return nil, ""
		}
		return next, name
	}
	return nil, ""
}

// apiClientCallName reports the apiClient method an assignment's right-hand side calls.
func apiClientCallName(assign *ast.AssignStmt) (string, bool) {
	if len(assign.Rhs) != 1 {
		return "", false
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	receiver, ok := sel.X.(*ast.Ident)
	if !ok || receiver.Name != "apiClient" {
		return "", false
	}
	return "apiClient." + sel.Sel.Name, true
}

// errVarOf is the name the assignment binds its last value to, which is the error by Go
// convention and is the variable the guard beside it tests.
func errVarOf(assign *ast.AssignStmt) string {
	if len(assign.Lhs) == 0 {
		return ""
	}
	ident, ok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name
}

// condIsErrNotNil reports whether a condition is exactly "<name> != nil". A guard that tests
// something else is not the shape this rule decides, and is left alone rather than guessed at.
func condIsErrNotNil(cond ast.Expr, name string) bool {
	if name == "" || name == "_" {
		return false
	}
	binary, ok := cond.(*ast.BinaryExpr)
	if !ok || binary.Op != token.NEQ {
		return false
	}
	left, ok := binary.X.(*ast.Ident)
	if !ok || left.Name != name {
		return false
	}
	right, ok := binary.Y.(*ast.Ident)
	return ok && right.Name == "nil"
}

// blindAPIErrorCatch reports an errors.As branch inside a guard that never looks at what it
// caught, and is therefore the whole of the failure rather than one code peeled off the front of
// it. A handler is allowed to answer a code a caller acts on itself -- the email settings form
// redraws on SMTP_NOT_ENABLED, the OTP form on its seven enrolment codes -- and those branches
// all name a Code or a StatusCode, so the classifier still answers everything they did not name.
// A branch that names neither takes 404 and 500 with it, and reaching the classifier afterwards no
// longer helps because nothing reaches it.
func blindAPIErrorCatch(body *ast.BlockStmt) *ast.IfStmt {
	var blind *ast.IfStmt
	ast.Inspect(body, func(n ast.Node) bool {
		branch, ok := n.(*ast.IfStmt)
		if !ok || blind != nil {
			return blind == nil
		}
		call, ok := branch.Cond.(*ast.CallExpr)
		if !ok {
			// A condition that is not the bare As call tests something else beside it, which is
			// the narrowing this rule asks for.
			return true
		}
		if sel, isSelector := call.Fun.(*ast.SelectorExpr); !isSelector || sel.Sel.Name != "As" {
			return true
		}
		if !inspectsAPIErrorStatus(branch.Body) {
			blind = branch
		}
		return blind == nil
	})
	return blind
}

// inspectsAPIErrorStatus reports whether a branch reads the caught error's Code or StatusCode
// anywhere, which is what tells "this one condition, by name" from "every failure the API can
// report".
func inspectsAPIErrorStatus(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "Code" || sel.Sel.Name == "StatusCode" {
			found = true
		}
		return !found
	})
	return found
}

// guardAnswersTheRequest reports whether a guard body decides what the caller sees. A guard that
// writes no response is not choosing a meaning for the failure and is out of this rule: the phone
// countries cache returns the error to its caller, which guards it again, and the client logo page
// logs a warning and renders without a logo, because the logo is optional and its absence is not a
// failure of the page. Inspecting the error's API status counts as answering even when the writing
// happens inside a closure, which is the broad errors.As catch this rule exists to refuse.
func guardAnswersTheRequest(body *ast.BlockStmt) bool {
	answers := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		switch name {
		case "InternalServerError", "NotFound", "JsonError", "JsonNotFound", "JsonBadRequestBody",
			"EncodeJson", "RenderTemplate", "Redirect", "As",
			"HandleAPIError", "HandleAPIErrorWithCallback", "HandleAPIErrorJson":
			answers = true
		}
		return !answers
	})
	return answers
}

// guardReachesClassifier reports whether the guard's body calls one of the three helpers anywhere
// in it. Anywhere rather than on every path, because a handler may answer a code a caller acts on
// first; what the rule holds is that the fall-through is the classifier and not a writer chosen by
// hand.
func guardReachesClassifier(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		switch name {
		case "HandleAPIError", "HandleAPIErrorWithCallback", "HandleAPIErrorJson":
			found = true
		}
		return !found
	})
	return found
}
