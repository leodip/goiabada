package web

import (
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/guard"
)

// The buttons the console builds in script (#562, section 6 and decision 9).
//
// A button built in script is a plain button. A <button> with no type is a submit button, so a row
// button inside a form submitted it, and Enter in the form's text box clicked the first one: on the
// two user search pages it opened the first listed user's confirmation, or, with no rows, submitted
// the search form itself. Every button built with createElement("button") sets its type to "button"
// in the block that builds it, and the two search forms prevent their own submission, so Enter in
// their search box does nothing beyond the search typing already runs.
//
// Lexical, like the checks in static_lint_test.go, because no tier runs JavaScript: the code is read
// through guard.ReadScripts, as the dialog markup rule reads it.

// buttonFault is one script-built button that can submit a form, located.
type buttonFault struct {
	path string
	line int
	why  string
}

// buttonCalls counts what a walk reached.
type buttonCalls struct {
	files, created int
}

// findButtonFaults walks fsys and returns every script-built button that can submit a form.
func findButtonFaults(fsys fs.FS) ([]buttonFault, buttonCalls, error) {
	scripts, files, err := guard.ReadScripts(fsys)
	n := buttonCalls{files: files}
	var faults []buttonFault
	for _, s := range scripts {
		faults = append(faults, buttonFaultsIn(s.Path, s.Tokens, &n)...)
	}
	return faults, n, err
}

// buttonFaultsIn applies the rule to one script's tokens.
func buttonFaultsIn(path string, toks []guard.ScriptToken, n *buttonCalls) []buttonFault {
	var faults []buttonFault
	at := func(i int) guard.ScriptToken {
		if i >= 0 && i < len(toks) {
			return toks[i]
		}
		return guard.ScriptToken{}
	}
	report := func(t guard.ScriptToken, why string) {
		faults = append(faults, buttonFault{path: path, line: t.Line, why: why})
	}

	for i, t := range toks {
		// document.createElement("button")
		if !t.Is(guard.ScriptIdent, "createElement") || !at(i-1).Is(guard.ScriptPunct, ".") ||
			!at(i+1).Is(guard.ScriptPunct, "(") || !at(i+2).Is(guard.ScriptString, "button") ||
			!at(i+3).Is(guard.ScriptPunct, ")") {
			continue
		}
		n.created++
		name := ""
		if at(i-2).Is(guard.ScriptIdent, "document") && at(i-3).Is(guard.ScriptPunct, "=") &&
			at(i-4).Kind == guard.ScriptIdent {
			name = at(i - 4).Text
		}
		if name == "" {
			report(t, "a button is built in script without being named, so its type cannot be read; "+
				"assign it and set its type to \"button\" (#562)")
			continue
		}
		if !setsPlainType(toks, i+4, name) {
			report(t, fmt.Sprintf("%s is built in script and never made type \"button\" in the block "+
				"that builds it; a button with no type submits the form it sits in, and Enter in "+
				"that form clicks it (#562)", name))
		}
	}
	return faults
}

// setsPlainType reports whether toks, from from to the end of the block it is in, set name's type
// to "button", as `name.type = "button"` or `name.setAttribute("type", "button")`.
func setsPlainType(toks []guard.ScriptToken, from int, name string) bool {
	depth := 0
	for j := from; j+5 < len(toks); j++ {
		switch {
		case toks[j].Is(guard.ScriptPunct, "{"):
			depth++
		case toks[j].Is(guard.ScriptPunct, "}"):
			depth--
			if depth < 0 {
				return false
			}
		}
		if !toks[j].Is(guard.ScriptIdent, name) || !toks[j+1].Is(guard.ScriptPunct, ".") {
			continue
		}
		if toks[j+2].Is(guard.ScriptIdent, "type") && toks[j+3].Is(guard.ScriptPunct, "=") &&
			toks[j+4].Is(guard.ScriptString, "button") {
			return true
		}
		if j+7 < len(toks) && toks[j+2].Is(guard.ScriptIdent, "setAttribute") && toks[j+3].Is(guard.ScriptPunct, "(") &&
			toks[j+4].Is(guard.ScriptString, "type") && toks[j+5].Is(guard.ScriptPunct, ",") &&
			toks[j+6].Is(guard.ScriptString, "button") && toks[j+7].Is(guard.ScriptPunct, ")") {
			return true
		}
	}
	return false
}

// TestScriptButtons_PlainAndNamed holds every page and script this server serves to the rule: every
// script-built button is type "button". Five are built in script: the Remove buttons of
// client-uri-list.js, permission-list.js and user-groups.js, user-search.js's Add, and
// resource-permissions.js's Edit and Remove.
func TestScriptButtons_PlainAndNamed(t *testing.T) {
	assertScriptButtons(t, buttonCalls{created: 5}, templateFS, withoutVendored{staticFS})
}

// assertScriptButtons is the reporting half. A walk that reached no file in one of the trees, or
// fewer button calls than least counts, is fatal: a call renamed out of this check's reach would
// otherwise pass it vacuously.
func assertScriptButtons(r guard.Reporter, least buttonCalls, trees ...fs.FS) {
	r.Helper()

	var faults []buttonFault
	var total buttonCalls
	for _, tree := range trees {
		f, n, err := findButtonFaults(tree)
		if err != nil {
			r.Fatalf("walking for pages and scripts: %v", err)
		}
		if n.files == 0 {
			r.Fatalf("reached no .html or .js file in one of the trees; this rule is checking nothing")
		}
		faults = append(faults, f...)
		total.created += n.created
	}
	for _, f := range faults {
		r.Errorf("%s:%d: %s", f.path, f.line, f.why)
	}
	if total.created < least.created {
		r.Fatalf("reached %d createElement(\"button\") calls, fewer than the %d served; a call was "+
			"renamed out of this rule's reach", total.created, least.created)
	}
}

// buttonPage is one page whose script is src.
func buttonPage(src string) fstest.MapFS {
	return fstest.MapFS{"template/page.html": &fstest.MapFile{Data: []byte("<script>\n" + src + "\n</script>\n")}}
}

// TestScriptButtons_TheRule drives the finder over fixture pages: each shape the rule wants passes,
// and each way of breaking it, the pages as they were before #562 among them, is reported.
func TestScriptButtons_TheRule(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"a row button made plain by its type", `const b = document.createElement("button");
b.type = "button";`, nil},
		{"a row button made plain through setAttribute", `if (x) {
  var b = document.createElement("button");
  b.setAttribute("type", "button");
}`, nil},
		{"before #562: a row button with no type", `const addToGroupButton = document.createElement("button");
addToGroupButton.setAttribute("class", "btn btn-xs btn-primary");`,
			[]string{"addToGroupButton is built in script and never made type \"button\""}},
		{"a row button made a submit button", `const b = document.createElement("button");
b.type = "submit";`, []string{"b is built in script and never made type \"button\""}},
		{"another button's type is set", `const a = document.createElement("button");
const b = document.createElement("button");
b.type = "button";`, []string{"a is built in script and never made type \"button\""}},
		{"the type is set outside the block that builds it", `function f() {
  const b = document.createElement("button");
}
b.type = "button";`, []string{"b is built in script and never made type \"button\""}},
		{"a button built unnamed", `cell.appendChild(document.createElement("button"));`,
			[]string{"a button is built in script without being named"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			faults, _, err := findButtonFaults(buttonPage(tc.src))
			require.NoError(t, err)
			var got []string
			for _, f := range faults {
				got = append(got, f.why)
			}
			require.Len(t, got, len(tc.want), strings.Join(got, "\n"))
			for i, w := range tc.want {
				assert.Contains(t, got[i], w)
			}
		})
	}
}

// TestScriptButtons_AWalkThatReachesNothingCountsNothing pins the counts the reporting half reads:
// a tree with no page reaches no file, and a page with no button counts none.
func TestScriptButtons_AWalkThatReachesNothingCountsNothing(t *testing.T) {
	_, n, err := findButtonFaults(fstest.MapFS{})
	require.NoError(t, err)
	assert.Zero(t, n.files)

	_, n, err = findButtonFaults(buttonPage(`const a = 1;`))
	require.NoError(t, err)
	assert.Equal(t, 1, n.files)
	assert.Zero(t, n.created)
}

// buttonsOK is a page that keeps the rule, with one script-built button.
const buttonsOK = `const b = document.createElement("button");
b.type = "button";`

// TestScriptButtons_FailsOnAFault drives the reporting half: a refused button reaches Errorf naming
// its file and line, and the walk goes on.
func TestScriptButtons_FailsOnAFault(t *testing.T) {
	fsys := fstest.MapFS{
		"template/ok.html":  buttonPage(buttonsOK)["template/page.html"],
		"template/bad.html": buttonPage(`const addButton = document.createElement("button");`)["template/page.html"],
	}

	report := guard.Run(func(r guard.Reporter) {
		assertScriptButtons(r, buttonCalls{created: 1}, fsys)
	})

	assert.False(t, report.Stopped, report.Text())
	require.Len(t, report.Errors, 1, report.Text())
	assert.Contains(t, report.Errors[0], `template/bad.html:2: addButton is built in script and never made type "button"`)
}

// TestScriptButtons_PassesOnACleanTree is the other direction.
func TestScriptButtons_PassesOnACleanTree(t *testing.T) {
	report := guard.Run(func(r guard.Reporter) {
		assertScriptButtons(r, buttonCalls{created: 1}, buttonPage(buttonsOK))
	})

	assert.False(t, report.Failed(), report.Text())
}

// unreadableFS is a tree whose walk fails.
type unreadableFS struct{}

func (unreadableFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
}

// TestScriptButtons_AWalkThatReachesNothingIsFatal pins the walk's own failures, where every rule
// would pass vacuously: a tree that cannot be read, a tree with no page or script, and trees whose
// pages build fewer buttons than the least the caller names.
func TestScriptButtons_AWalkThatReachesNothingIsFatal(t *testing.T) {
	ok := buttonPage(buttonsOK)
	least := buttonCalls{created: 1}

	for name, tc := range map[string]struct {
		trees []fs.FS
		least buttonCalls
	}{
		"an unreadable tree":        {[]fs.FS{ok, unreadableFS{}}, least},
		"an empty tree":             {[]fs.FS{ok, fstest.MapFS{}}, least},
		"fewer buttons than served": {[]fs.FS{ok}, buttonCalls{created: 2}},
		"no button call at all":     {[]fs.FS{buttonPage(`const a = 1;`)}, least},
	} {
		t.Run(name, func(t *testing.T) {
			report := guard.Run(func(r guard.Reporter) { assertScriptButtons(r, tc.least, tc.trees...) })
			assert.True(t, report.Stopped, report.Text())
		})
	}
}

// searchPages are the two pages whose search box sits in a form beside the rows it lists. Enter in
// the box submitted that form natively, reloading the page with nothing found, until #562. Each now
// holds the box in #userSearchForm, the form pages/user-search.js binds, whose submit the script
// turns into a search (#617). The rule reads both halves: the page's form is that one and the page
// loads the script, and the script prevents the native submit.
var searchPages = []string{
	"template/admin_groups_members_add.html",
	"template/admin_resources_users_with_permission_add.html",
}

var (
	formOpenRe       = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	searchInputRe    = regexp.MustCompile(`(?is)<input\b[^>]*\bid="search"[^>]*>`)
	searchFormIdRe   = regexp.MustCompile(`(?is)\bid="userSearchForm"`)
	searchScriptRe   = regexp.MustCompile(`/static/pages/user-search\.js`)
	preventsSubmitRe = regexp.MustCompile(`(?s)searchForm\.addEventListener\("submit", function \(event\) \{\s*event\.preventDefault\(\);`)
)

// searchFormFault returns why the form holding the page's search box can submit natively, or "",
// and false when the page holds no search box in a form.
func searchFormFault(page string) (string, bool) {
	input := searchInputRe.FindStringIndex(page)
	if input == nil {
		return "", false
	}
	var open []int
	for _, f := range formOpenRe.FindAllStringIndex(page, -1) {
		if f[0] < input[0] {
			open = f
		}
	}
	if open == nil || strings.Contains(strings.ToLower(page[open[1]:input[0]]), "</form") {
		return "", false
	}
	if !searchFormIdRe.MatchString(page[open[0]:open[1]]) {
		return "the form holding the search box is not #userSearchForm, whose submit user-search.js stops; " +
			"Enter in the box then submits it (#562)", true
	}
	if !searchScriptRe.MatchString(page) {
		return "the page does not load user-search.js, which stops the form's submit (#562)", true
	}
	return "", true
}

// searchScriptFault returns why user-search.js lets its form submit natively, or "".
func searchScriptFault(script string) string {
	if !preventsSubmitRe.MatchString(script) {
		return "user-search.js no longer prevents its form's submit; Enter in the box then submits it (#562)"
	}
	return ""
}

// TestSearchForms_NeverSubmitNatively holds the two real search pages, and their script, to the rule.
func TestSearchForms_NeverSubmitNatively(t *testing.T) {
	for _, p := range searchPages {
		b, err := templateFS.ReadFile(p)
		require.NoError(t, err)
		why, ok := searchFormFault(string(b))
		require.True(t, ok, "%s: no search box in a form; this check cannot read it", p)
		if why != "" {
			t.Errorf("%s: %s", p, why)
		}
	}
	script, err := staticFS.ReadFile("static/pages/user-search.js")
	require.NoError(t, err)
	if why := searchScriptFault(string(script)); why != "" {
		t.Error(why)
	}
}

// TestSearchForms_TheRule drives the finders over fixture pages and scripts.
func TestSearchForms_TheRule(t *testing.T) {
	const input = `<input id="search" type="search" name="search">`
	const script = `<script src="/static/pages/user-search.js" defer></script>`
	cases := []struct {
		name   string
		page   string
		read   bool
		faulty bool
	}{
		{"before #562: a form that submits", `<form method="post">` + input + `</form>`, true, true},
		{"the script's form, the script loaded", script + `<form id="userSearchForm" role="search">` + input + `</form>`, true, false},
		{"the script's form, the script not loaded", `<form id="userSearchForm" role="search">` + input + `</form>`, true, true},
		{"another form, the script loaded", script + `<form id="otherForm">` + input + `</form>`, true, true},
		{"the script's form is an earlier one", script + `<form id="userSearchForm"></form><form method="post">` + input + `</form>`, true, true},
		{"a search box in no form", `<form id="userSearchForm"></form>` + input, false, false},
		{"no search box", `<form method="post"><input id="name"></form>`, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			why, ok := searchFormFault(tc.page)
			assert.Equal(t, tc.read, ok)
			assert.Equal(t, tc.faulty, why != "", why)
		})
	}

	assert.Empty(t, searchScriptFault("searchForm.addEventListener(\"submit\", function (event) {\n  event.preventDefault();\n  search();\n});"))
	assert.NotEmpty(t, searchScriptFault("searchForm.addEventListener(\"submit\", function (event) {\n  search();\n});"),
		"a submit listener that searches without stopping the submit lets the page reload")
	assert.NotEmpty(t, searchScriptFault(""), "a script with no submit listener stops nothing")
}
