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
//
// The first boundary is enforced rather than assumed: an apiClient call no guard of that shape
// follows is itself a problem, because it is a call whose error this rule cannot see go anywhere.
// The theme list redrawn beside a refused UI theme form was one, written as `if ...; err == nil`,
// and it dropped the admin API's 401 with every other failure (#427, final review round 2).
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
		fileProblems, fileGuards := apiClientGuardProblems(fset, file, filepath.ToSlash(path))
		problems = append(problems, fileProblems...)
		guards += fileGuards
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
		t.Errorf("%d problem(s) across %d apiClient error guard(s):\n\t%s\n\n"+
			"Call handlers.HandleAPIError for a page, HandleAPIErrorWithCallback for a page with a "+
			"form to redraw, or HandleAPIErrorJson for JSON. Each routes 401 to the session-ended "+
			"route, 404 to the console's own not-found answer, 400 (and 409) to the caller, and "+
			"everything else to the 500 writer, which is where the stack and the request id belong "+
			"(#279, #427). A read the page can do without keeps its fallback for everything but "+
			"handlers.IsSessionEnded.",
			len(problems), guards, strings.Join(problems, "\n\t"))
	}
}

// apiClientGuardProblems is the rule over one file: every apiClient call guarded in a shape this
// rule reads, every guard that answers the request reaching a classifier without a blind catch in
// front of it, and every guard that does not answer handing the error back to its caller. It
// reports the problems and how many guards it matched, so the walk can refuse matching none.
func apiClientGuardProblems(fset *token.FileSet, file *ast.File, rel string) ([]string, int) {
	var problems []string
	guards := 0
	at := func(n ast.Node) string {
		return rel + ":" + strconv.Itoa(fset.Position(n.Pos()).Line) + ": "
	}

	guarded := map[*ast.CallExpr]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		// Statement lists are where a call and its guard sit side by side: a block, and the body
		// of a switch or select case, which is a list of its own rather than a block.
		var list []ast.Stmt
		switch stmts := n.(type) {
		case *ast.BlockStmt:
			list = stmts.List
		case *ast.CaseClause:
			list = stmts.Body
		case *ast.CommClause:
			list = stmts.Body
		default:
			return true
		}
		for i := range list {
			guard, ok := apiClientErrorGuard(list, i)
			if !ok {
				continue
			}
			guarded[guard.call] = true
			guards++
			body := guard.stmt.Body
			if !guardAnswersTheRequest(body) {
				if !guardReturnsTheError(body, guard.errVar) {
					problems = append(problems, at(guard.stmt)+"the error from "+guard.method+
						" is dropped here: a guard that writes no response hands the error back "+
						"to its caller, or an admin API 401 never signs the administrator out")
				}
				continue
			}
			if blind := blindAPIErrorCatch(body); blind != nil {
				problems = append(problems, at(blind)+"the error from "+guard.method+
					" is caught here for every status, so 404 and 500 are answered as a "+
					"rejected value")
				continue
			}
			if guardReachesClassifier(body) {
				continue
			}
			problems = append(problems, at(guard.stmt)+"the error from "+guard.method+
				" is answered here without reaching HandleAPIError, "+
				"HandleAPIErrorWithCallback or HandleAPIErrorJson")
		}
		return true
	})

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || guarded[call] {
			return true
		}
		if name, ok := apiClientMethod(call); ok {
			problems = append(problems, at(call)+"the error from "+name+
				" is not guarded by an `if err != nil` beside the call, so this rule cannot see "+
				"where it goes")
		}
		return true
	})

	return problems, guards
}

// apiClientGuard is an apiClient call and the if statement guarding its error.
type apiClientGuard struct {
	stmt   *ast.IfStmt
	call   *ast.CallExpr
	method string
	errVar string
}

// apiClientErrorGuard reports the guard on the error of an apiClient call at list[i]. Two shapes
// carry every call site in this tree: the call in an assignment with the guard as the next
// statement, and the call in the guard's own init.
func apiClientErrorGuard(list []ast.Stmt, i int) (apiClientGuard, bool) {
	var assign *ast.AssignStmt
	var stmt *ast.IfStmt
	switch s := list[i].(type) {
	case *ast.IfStmt:
		init, ok := s.Init.(*ast.AssignStmt)
		if !ok {
			return apiClientGuard{}, false
		}
		assign, stmt = init, s
	case *ast.AssignStmt:
		if i+1 >= len(list) {
			return apiClientGuard{}, false
		}
		next, ok := list[i+1].(*ast.IfStmt)
		if !ok || next.Init != nil {
			return apiClientGuard{}, false
		}
		assign, stmt = s, next
	default:
		return apiClientGuard{}, false
	}
	call, method, ok := apiClientCallName(assign)
	errVar := errVarOf(assign)
	if !ok || !condIsErrNotNil(stmt.Cond, errVar) {
		return apiClientGuard{}, false
	}
	return apiClientGuard{stmt: stmt, call: call, method: method, errVar: errVar}, true
}

// apiClientCallName reports the apiClient call an assignment's right-hand side makes, and the
// method it names.
func apiClientCallName(assign *ast.AssignStmt) (*ast.CallExpr, string, bool) {
	if len(assign.Rhs) != 1 {
		return nil, "", false
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return nil, "", false
	}
	name, ok := apiClientMethod(call)
	return call, name, ok
}

// apiClientMethod reports the method a call names on apiClient. Parentheses are stripped on the
// callee and the receiver, so a bracketed call is the call it brackets: the two passes above must
// agree on what an apiClient call is, or a bracket would drop a call out of both at once.
func apiClientMethod(call *ast.CallExpr) (string, bool) {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	receiver, ok := ast.Unparen(sel.X).(*ast.Ident)
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
		// Parentheses are stripped on both the condition and the callee: (errors.As(err, &e))
		// and (errors.As)(err, &e) catch exactly what the bare form catches, and a rule reading
		// only the bare form is one pair of brackets away from being silent on the widest catch
		// there is. The constructor lint lost the same bypass twice, in rounds 2 and 3.
		call, ok := ast.Unparen(branch.Cond).(*ast.CallExpr)
		if !ok {
			// A condition that is not the bare As call tests something else beside it, which is
			// the narrowing this rule asks for.
			return true
		}
		if sel, isSelector := ast.Unparen(call.Fun).(*ast.SelectorExpr); !isSelector || sel.Sel.Name != "As" {
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

// guardAnswersTheRequest reports whether a guard body decides what the caller sees. Inspecting the
// error's API status counts as answering even when the writing happens inside a closure, which is
// the broad errors.As catch this rule exists to refuse.
//
// A guard that writes no response is held to guardReturnsTheError instead. It used to be out of
// this rule altogether, on the reading that it chooses no meaning for the failure, and that stopped
// being true with #427 decision 17: a 401 means the administrator's session has ended however
// optional the read was. The client logo page logged it as a warning and rendered, until final
// review round 2 of #427; it now answers a 401 through HandleAPIError and keeps its warning for
// everything else, which makes it a guard that answers.
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

// guardReturnsTheError reports whether a guard that writes no response hands the error it caught
// back to its caller, wrapped or not, which is what the phone countries cache does: its two
// callers guard the error again and answer it through HandleAPIError. A return inside a closure
// in the guard is the closure's, not the guard's, and does not count.
func guardReturnsTheError(body *ast.BlockStmt, errVar string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			for _, result := range node.Results {
				ast.Inspect(result, func(m ast.Node) bool {
					switch leaf := m.(type) {
					case *ast.FuncLit:
						return false
					case *ast.Ident:
						found = found || leaf.Name == errVar
					}
					return !found
				})
			}
		}
		return !found
	})
	return found
}

// guardReachesClassifier reports whether the guard's body calls one of the three helpers anywhere
// in it. Anywhere rather than on every path, because a handler may answer a code a caller acts on
// first; what the rule holds is that the fall-through is the classifier and not a writer chosen by
// hand.
//
// ceiling: "anywhere" is existence, not ownership. A classifier call on one branch satisfies this
// for a sibling branch that answers the failure itself, and a classifier called for a different
// error satisfies it for the guarded one, so a hand-picked writer can still coexist with a
// delegating fall-through. Every one of the 213 production guards is the canonical top-level shape
// today and none exploits either gap, which is why this ships as a parse. Revisit when a guard
// needs a shape this cannot read, or when the rule is asked to hold code nobody on this repository
// wrote: closing it means control-flow analysis over the guard and matching the classifier's error
// argument against the one the guard caught, which is a type-checked pass rather than a parse
// (#279).
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

// TestHandlers_BlindCatchRuleTable holds blindAPIErrorCatch to its rule over source text, which is
// the only place the parenthesised forms can be exercised: no production guard is written that way
// today, so the walk above would pass whether or not the rule could see them.
//
// The brackets matter because they are free to add and silent to the reader. The constructor lint
// in core/testutil lost exactly this bypass twice -- rounds 2 and 3 of #279's final review -- once
// on the callee and once on the value, so the third report of it is a rule rather than a
// coincidence.
func TestHandlers_BlindCatchRuleTable(t *testing.T) {
	testCases := []struct {
		name  string
		body  string
		blind bool
	}{
		{
			name:  "a bare catch that reads nothing is blind",
			body:  "if errors.As(err, &apiErr) { httpHelper.JsonError(w, r, err); return }",
			blind: true,
		},
		{
			name:  "the same catch in brackets is the same catch",
			body:  "if (errors.As(err, &apiErr)) { httpHelper.JsonError(w, r, err); return }",
			blind: true,
		},
		{
			name:  "brackets around the callee, which calls what the bare form calls",
			body:  "if (errors.As)(err, &apiErr) { httpHelper.JsonError(w, r, err); return }",
			blind: true,
		},
		{
			name:  "a catch that names a StatusCode peels one condition off the front",
			body:  "if errors.As(err, &apiErr) { if apiErr.StatusCode == 409 { return } }",
			blind: false,
		},
		{
			name:  "a catch that names a Code does too",
			body:  "if errors.As(err, &apiErr) { if apiErr.Code == \"SMTP_NOT_ENABLED\" { return } }",
			blind: false,
		},
		{
			name:  "a condition testing something beside the As call is already narrowed",
			body:  "if errors.As(err, &apiErr) && apiErr.StatusCode == 400 { return }",
			blind: false,
		},
		{
			name:  "a guard with no As call in it at all",
			body:  "httpHelper.JsonError(w, r, err)",
			blind: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			src := "package p\nfunc f() {\n" + testCase.body + "\n}\n"
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "fixture.go", src, 0)
			if err != nil {
				t.Fatalf("parsing the fixture: %v", err)
			}
			fn := file.Decls[0].(*ast.FuncDecl)

			blind := blindAPIErrorCatch(fn.Body) != nil
			if blind != testCase.blind {
				t.Errorf("blindAPIErrorCatch = %v, want %v, for:\n\t%s", blind, testCase.blind, testCase.body)
			}
		})
	}
}

// TestHandlers_ApiClientGuardRuleTable holds apiClientGuardProblems to its rules over source text.
// Its first two rows are the two shapes #427's final review round 2 found dropping the admin API's
// 401, each as it was before the fix, and the two rows after them are the same reads as they are
// now. The walk above cannot show either rule failing, because nothing in the tree breaks them.
func TestHandlers_ApiClientGuardRuleTable(t *testing.T) {
	testCases := []struct {
		name     string
		body     string
		guards   int
		problems []string // one substring per problem, in the order the finder reports them
	}{
		{
			name: "an optional read that logs and carries on drops the 401 with the rest",
			body: `logoInfo, err := apiClient.GetClientLogo(ctx, token, id)
				if err != nil {
					slog.WarnContext(ctx, "unable to fetch the client logo info", "error", err)
				}`,
			guards:   1,
			problems: []string{"GetClientLogo is dropped here"},
		},
		{
			name: "a read guarded on err == nil is a call this rule cannot see the error of",
			body: `if apiResp, err := apiClient.GetSettingsUITheme(ctx, token); err == nil {
					uiThemes = apiResp.AvailableThemes
				}`,
			problems: []string{"GetSettingsUITheme is not guarded"},
		},
		{
			name: "the optional read that answers a 401 and warns on the rest",
			body: `logoInfo, err := apiClient.GetClientLogo(ctx, token, id)
				if err != nil {
					if handlers.IsSessionEnded(err) {
						handlers.HandleAPIError(httpHelper, w, r, err)
						return
					}
					slog.WarnContext(ctx, "unable to fetch the client logo info", "error", err)
				}`,
			guards: 1,
		},
		{
			name: "the redraw that answers a 401 and carries on without the list otherwise",
			body: `apiResp, err := apiClient.GetSettingsUITheme(ctx, token)
				if err != nil {
					if handlers.IsSessionEnded(err) {
						handlers.HandleAPIError(httpHelper, w, r, err)
						return
					}
				} else {
					uiThemes = apiResp.AvailableThemes
				}`,
			guards: 1,
		},
		{
			name: "a guard that hands the error back is its caller's to answer",
			body: `data, err := apiClient.GetPhoneCountries(ctx, token)
				if err != nil {
					return nil, err
				}`,
			guards: 1,
		},
		{
			name: "wrapped on the way back is still handed back",
			body: `data, err := apiClient.GetPhoneCountries(ctx, token)
				if err != nil {
					return nil, errs.Wrap(err, "reading the phone countries")
				}`,
			guards: 1,
		},
		{
			name: "a return of something else is not the error handed back",
			body: `data, err := apiClient.GetPhoneCountries(ctx, token)
				if err != nil {
					return nil, nil
				}`,
			guards:   1,
			problems: []string{"GetPhoneCountries is dropped here"},
		},
		{
			name: "a closure returning the error is the closure's return, not the guard's",
			body: `data, err := apiClient.GetPhoneCountries(ctx, token)
				if err != nil {
					later = func() error { return err }
				}`,
			guards:   1,
			problems: []string{"GetPhoneCountries is dropped here"},
		},
		{
			name:     "a call whose error is discarded outright",
			body:     `_, _ = apiClient.GetPhoneCountries(ctx, token)`,
			problems: []string{"GetPhoneCountries is not guarded"},
		},
		{
			name:     "a call inside another expression",
			body:     `use(apiClient.GetPhoneCountries(ctx, token))`,
			problems: []string{"GetPhoneCountries is not guarded"},
		},
		{
			name: "brackets around the receiver and the callee hide neither the call nor the drop",
			body: `logoInfo, err := ((apiClient).GetClientLogo)(ctx, token, id)
				if err != nil {
					slog.WarnContext(ctx, "unable to fetch the client logo info", "error", err)
				}`,
			guards:   1,
			problems: []string{"GetClientLogo is dropped here"},
		},
		{
			name: "a guard in a switch case is read like one in a block",
			body: `switch mode {
				case "logo":
					logoInfo, err := apiClient.GetClientLogo(ctx, token, id)
					if err != nil {
						httpHelper.InternalServerError(w, r, err)
						return
					}
				}`,
			guards:   1,
			problems: []string{"GetClientLogo is answered here without reaching"},
		},
		{
			name: "a guard that answers without a classifier is still refused",
			body: `client, err := apiClient.GetClientById(ctx, token, id)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}`,
			guards:   1,
			problems: []string{"GetClientById is answered here without reaching"},
		},
		{
			name: "a blind catch in front of the classifier is still refused",
			body: `client, err := apiClient.GetClientById(ctx, token, id)
				if err != nil {
					if errors.As(err, &apiErr) {
						renderError(apiErr.Message)
						return
					}
					handlers.HandleAPIError(httpHelper, w, r, err)
					return
				}`,
			guards:   1,
			problems: []string{"GetClientById is caught here for every status"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			src := "package p\nfunc f() {\n" + testCase.body + "\n}\n"
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "fixture.go", src, 0)
			if err != nil {
				t.Fatalf("parsing the fixture: %v", err)
			}

			problems, guards := apiClientGuardProblems(fset, file, "fixture.go")

			if guards != testCase.guards {
				t.Errorf("guards = %d, want %d", guards, testCase.guards)
			}
			if len(problems) != len(testCase.problems) {
				t.Fatalf("problems = %q, want %d of them, matching %q", problems, len(testCase.problems), testCase.problems)
			}
			for i, want := range testCase.problems {
				if !strings.Contains(problems[i], want) {
					t.Errorf("problem %d = %q, want it to say %q", i, problems[i], want)
				}
			}
		})
	}
}
