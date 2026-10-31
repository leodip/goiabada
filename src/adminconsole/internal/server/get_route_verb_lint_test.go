package server

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/guard"
)

// TestInitRoutes_NoGetIsNamedForAStateChange refuses a GET in the console's route table whose
// handler is named for a state change.
//
// A GET is the one method the origin check never reads, and the console's session cookie is Lax,
// which rides any site's top-level navigation, so a GET that changes state can be triggered by any
// link on any page. That was #411: GET /auth/logout signed the administrator out of the console
// and of SSO with nothing to click. The issue asked for this guard beside the fix, so that the
// next one, written by copying an old handler or by wiring a POST's handler to r.Get, fails here
// rather than in a review.
//
// The evidence is the handler's name, split into its CamelCase words, so HandleSettingsGet does
// not read as Set and HandleSessionEndedGet does not read as End. A handler that is named for a
// verb and changes nothing is exempted below, by package and name, with the reason it is read-only;
// an exemption that matches no registered GET fails too, so the list cannot outlive the routes.
//
// Where it stops: a name is not a behaviour. A GET that changes state under a read-only name, as
// HandleSessionEndedGet does (guarded by fetch metadata instead, #411), is out of this check's
// reach, and so is an inline func literal, which has no name to read.
func TestInitRoutes_NoGetIsNamedForAStateChange(t *testing.T) {
	assertNoStateChangingGets(t, filepath.Join(guard.SourceRoot(t), getRouteTable), getVerbExemptions)
}

// getRouteTable is the file the console's routes are registered in, relative to the source root.
const getRouteTable = "adminconsole/internal/server/routes.go"

// mutatingVerbs are the CamelCase words a GET's handler name may not contain.
var mutatingVerbs = []string{
	"Add", "Clear", "Create", "Delete", "Disable", "Edit", "Enable", "Generate", "Logout",
	"Remove", "Reset", "Revoke", "Rotate", "Save", "Send", "Set", "Update",
}

// getVerbExemptions are the GETs named for a verb that change nothing, keyed by package and handler
// name, each with the reason it is read-only.
var getVerbExemptions = map[string]string{
	"accounthandlers.HandleLogoutConfirmGet": "renders the sign-out confirmation; it is handed no " +
		"session store, and the POST beside it signs out (#411)",
	"adminclienthandlers.HandleDeleteGet":        "renders the delete confirmation; the POST deletes",
	"adminresourcehandlers.HandleDeleteGet":      "renders the delete confirmation; the POST deletes",
	"admingrouphandlers.HandleDeleteGet":         "renders the delete confirmation; the POST deletes",
	"adminuserhandlers.HandleDeleteGet":          "renders the delete confirmation; the POST deletes",
	"adminlegaldocumenthandlers.HandleDeleteGet": "renders the delete confirmation; the POST deletes",
	"admingrouphandlers.HandleAttributesAddGet":  "renders the add-attribute form; the POST adds",
	"adminuserhandlers.HandleAttributesAddGet":   "renders the add-attribute form; the POST adds",
	"admingrouphandlers.HandleAttributesEditGet": "renders the edit-attribute form; the POST " +
		"saves",
	"adminuserhandlers.HandleAttributesEditGet": "renders the edit-attribute form; the POST saves",
	"admingrouphandlers.HandleMembersAddGet":    "renders the add-member search page; a POST adds",
	"adminresourcehandlers.HandleUsersWithPermissionAddGet": "renders the user search page that " +
		"grants a permission; a POST grants it",
	"adminclienthandlers.HandleGenerateNewSecretGet": "answers a random value for the form to show; " +
		"it stores nothing, and the authentication POST saves a secret",
	"adminsettingshandlers.HandleEmailSendTestGet": "renders the send-test form; the POST sends",
}

// stateChangingGet is one GET registration the walk refused, located.
type stateChangingGet struct {
	line    int
	pattern string
	handler string
	verb    string
}

// assertNoStateChangingGets is the reporting half, taking the route table and the exemptions as
// parameters and failing through a guard.Reporter so a rule test can drive it against a fixture.
func assertNoStateChangingGets(r guard.Reporter, routeTable string, exemptions map[string]string) {
	r.Helper()

	found, unused, gets, err := findStateChangingGets(routeTable, exemptions)
	if err != nil {
		r.Fatalf("%v", err)
	}
	// A walk that read no GET would pass while checking nothing.
	if gets == 0 {
		r.Fatalf("found no GET registration in %s; the walk is no longer reaching the route table, "+
			"or the registration shape has moved", routeTable)
	}

	for _, f := range found {
		r.Errorf("%s:%d: GET %s is answered by %s, which is named for a state change (%s). A GET is "+
			"never read by the origin check and any site's link carries the Lax session cookie to it, "+
			"which was #411: register the change as a POST, and keep the GET for a page that changes "+
			"nothing. If the handler changes nothing, add it to getVerbExemptions with the reason",
			routeTable, f.line, f.pattern, f.handler, f.verb)
	}
	for _, key := range unused {
		r.Errorf("getVerbExemptions names %s, which no GET in %s registers: remove the entry", key, routeTable)
	}
}

// findStateChangingGets parses the route table and returns every GET whose handler is named for a
// mutating verb and not exempted, every exemption no GET used, and how many GETs it read.
func findStateChangingGets(routeTable string, exemptions map[string]string) ([]stateChangingGet, []string, int, error) {
	src, err := os.ReadFile(routeTable)
	if err != nil {
		return nil, nil, 0, errs.Wrapf(err, "reading %s", routeTable)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, routeTable, src, 0)
	if err != nil {
		return nil, nil, 0, errs.Wrapf(err, "parsing %s", routeTable)
	}

	var found []stateChangingGet
	used := map[string]bool{}
	gets := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Get" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		gets++

		handler := handlerName(call.Args[1])
		if handler == "" {
			return true
		}
		_, name, _ := strings.Cut(handler, ".")
		for _, word := range camelWords(name) {
			for _, verb := range mutatingVerbs {
				if word != verb {
					continue
				}
				if _, exempt := exemptions[handler]; exempt {
					used[handler] = true
					return true
				}
				found = append(found, stateChangingGet{
					line: fset.Position(call.Pos()).Line, pattern: pattern, handler: handler, verb: verb,
				})
				return true
			}
		}
		return true
	})

	var unused []string
	for key := range exemptions {
		if !used[key] {
			unused = append(unused, key)
		}
	}
	sort.Strings(unused)
	return found, unused, gets, nil
}

// handlerName is the package-qualified name of the function a handler expression calls to build
// the handler, such as accounthandlers.HandleLogoutConfirmGet, or "" for a func literal.
func handlerName(expr ast.Expr) string {
	if call, ok := expr.(*ast.CallExpr); ok {
		expr = call.Fun
	}
	switch fn := expr.(type) {
	case *ast.SelectorExpr:
		if pkg, ok := fn.X.(*ast.Ident); ok {
			return pkg.Name + "." + fn.Sel.Name
		}
		return fn.Sel.Name
	case *ast.Ident:
		return "." + fn.Name
	}
	return ""
}

// camelWords splits a Go identifier into its CamelCase words: an upper-case letter starts a word
// after a lower-case letter or a digit, and so does the last letter of an upper-case run that a
// lower-case letter follows, so HandleOAuth2FlowsGet is Handle, O, Auth2, Flows, Get.
func camelWords(name string) []string {
	runes := []rune(name)
	var words []string
	start := 0
	for i := 1; i < len(runes); i++ {
		if !unicode.IsUpper(runes[i]) {
			continue
		}
		prev := runes[i-1]
		nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
		if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
			words = append(words, string(runes[start:i]))
			start = i
		}
	}
	return append(words, string(runes[start:]))
}

func TestCamelWords_SplitsWholeWords(t *testing.T) {
	assert.Equal(t, []string{"Handle", "Settings", "Get"}, camelWords("HandleSettingsGet"))
	assert.Equal(t, []string{"Handle", "Session", "Ended", "Get"}, camelWords("HandleSessionEndedGet"))
	assert.Equal(t, []string{"Handle", "O", "Auth2", "Flows", "Get"}, camelWords("HandleOAuth2FlowsGet"))
	assert.Equal(t, []string{"Handle", "Redirect", "UR", "Is", "Get"}, camelWords("HandleRedirectURIsGet"))
}

// getRouteFixture writes a route table and returns its path.
func getRouteFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "routes.go")
	require.NoError(t, os.WriteFile(path, []byte("package server\n\nfunc (s *Server) initRoutes(root *routing.Router) {\n"+body+"}\n"), 0o644))
	return path
}

func TestGetRouteVerbs_TheGuardPassesATreeOfReadOnlyGets(t *testing.T) {
	routeTable := getRouteFixture(t, `
	root.With(baseAuth...).Get("/", handlers.HandleIndexGet(authHelper))
	r.Get("/settings", adminsettingshandlers.HandleSettingsGet(httpHelper))
	r.Get("/clients/{clientId}/delete", adminclienthandlers.HandleDeleteGet(httpHelper))
	r.Post("/clients/{clientId}/delete", adminclienthandlers.HandleDeletePost(httpHelper))
	r.Get("/account/", func(w http.ResponseWriter, r *http.Request) {})
`)

	report := guard.Run(func(r guard.Reporter) {
		assertNoStateChangingGets(r, routeTable, map[string]string{
			"adminclienthandlers.HandleDeleteGet": "renders the confirmation",
		})
	})

	assert.False(t, report.Failed(), "a table of read-only GETs failed the guard: %s", report.Text())
}

func TestGetRouteVerbs_TheGuardFailsOnAGetNamedForAStateChange(t *testing.T) {
	routeTable := getRouteFixture(t, `
	r.Get("/logout", accounthandlers.HandleLogoutPost(httpHelper))
	r.Get("/groups/{groupId}/delete", admingrouphandlers.HandleDeleteGet(httpHelper))
`)

	report := guard.Run(func(r guard.Reporter) {
		// Exempted in another package only, which is why the key carries the package.
		assertNoStateChangingGets(r, routeTable, map[string]string{
			"adminclienthandlers.HandleDeleteGet": "renders the confirmation",
		})
	})

	require.True(t, report.Failed(), "a GET wired to a sign-out passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	require.Len(t, report.Errors, 3, report.Text())
	assert.Contains(t, report.Errors[0], "routes.go:5: GET /logout is answered by accounthandlers.HandleLogoutPost")
	assert.Contains(t, report.Errors[0], "(Logout)")
	assert.Contains(t, report.Errors[1], "routes.go:6: GET /groups/{groupId}/delete is answered by admingrouphandlers.HandleDeleteGet")
	assert.Contains(t, report.Errors[2], "getVerbExemptions names adminclienthandlers.HandleDeleteGet, which no GET")
}

func TestGetRouteVerbs_TheGuardIsFatalOnAWalkThatReachedNothing(t *testing.T) {
	routeTable := getRouteFixture(t, `
	r.Post("/logout", accounthandlers.HandleLogoutPost(httpHelper))
`)

	report := guard.Run(func(r guard.Reporter) {
		assertNoStateChangingGets(r, routeTable, nil)
	})

	require.True(t, report.Stopped, "a walk that read no GET must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "found no GET registration in")
}

// Every verb the guard promises to refuse, spelled here rather than read from mutatingVerbs, so a
// verb dropped or misspelled there fails this table. Each registration is tried both directly on a
// router and chained through root.With(...), the shape the console's base routes are mounted with.
func TestGetRouteVerbs_TheGuardRefusesEveryPromisedVerbInEitherRegistrationShape(t *testing.T) {
	promised := []string{
		"Add", "Clear", "Create", "Delete", "Disable", "Edit", "Enable", "Generate", "Logout",
		"Remove", "Reset", "Revoke", "Rotate", "Save", "Send", "Set", "Update",
	}
	shapes := map[string]string{
		"direct":  `r.Get("/thing", somehandlers.Handle%sThingPost(httpHelper))`,
		"chained": `root.With(baseAuth...).Get("/thing", somehandlers.Handle%sThingPost(httpHelper))`,
	}

	for _, verb := range promised {
		for shape, registration := range shapes {
			t.Run(verb+" "+shape, func(t *testing.T) {
				routeTable := getRouteFixture(t, "\n\t"+fmt.Sprintf(registration, verb)+"\n")

				report := guard.Run(func(r guard.Reporter) {
					assertNoStateChangingGets(r, routeTable, nil)
				})

				require.Len(t, report.Errors, 1, "GET answered by Handle%sThingPost passed the guard: %s", verb, report.Text())
				assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
				assert.Contains(t, report.Errors[0], "routes.go:5: GET /thing is answered by somehandlers.Handle"+verb+"ThingPost")
				assert.Contains(t, report.Errors[0], "("+verb+")")
			})
		}
	}
}
