package web

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/i18n"
)

// The buttons the console builds in script (#562, section 6 and decision 9).
//
// An icon-only button has no text, so a screen reader announced the list editors' edit and remove
// buttons as "button" and nothing else (WCAG 2.2 success criteria 4.1.2 and 1.1.1). The icon builder
// in static/utils.js therefore takes a label and writes it as the button's aria-label and title,
// through setAttribute, so no label reaches an HTML parser (#120), and hides its SVG from assistive
// technology, which would otherwise read the drawing as an unnamed image. Its two wrappers take the
// label first and pass it on, and every call to them passes a label naming the action and the thing
// from the catalog and the row from the data, such as "Remove redirect URI " + uri.
//
// And a button built in script is a plain button. A <button> with no type is a submit button, so a
// row button inside a form submitted it, and Enter in the form's text box clicked the first one: on
// the two user search pages it opened the first listed user's confirmation, or, with no rows,
// submitted the search form itself. Every button built with createElement("button") sets its type
// to "button" in the block that builds it, and the two search forms prevent their own submission, so
// Enter in their search box does nothing beyond the search typing already runs.
//
// Lexical, like the checks in static_lint_test.go, because no tier runs JavaScript: the code is read
// through guard.ReadScripts, as the dialog markup rule reads it.

// iconBuilder is the icon builder, and labelledWrappers its two wrappers.
const iconBuilder = "createIconButton"

var labelledWrappers = []string{"createTrashCanButton", "createEditButton"}

// labelArg is where each builder takes its label.
var labelArg = map[string]int{iconBuilder: 2, "createTrashCanButton": 0, "createEditButton": 0}

// iconBuilderFaults returns what the icon builder and its wrappers in the JavaScript source src do
// against the rule above, and false when src declares no icon builder this check can read.
func iconBuilderFaults(src string) ([]string, bool) {
	params, body, ok := functionBody(src, iconBuilder)
	if !ok {
		return nil, false
	}
	var faults []string
	names := strings.Split(params, ",")
	if len(names) <= labelArg[iconBuilder] || strings.TrimSpace(names[labelArg[iconBuilder]]) != "label" {
		faults = append(faults, iconBuilder+" takes no label as its third parameter; an icon-only "+
			"button has no other name (#562)")
		return faults, true
	}
	toks := guard.TokenizeScript(body)

	button := createdAs(toks, "createElement", "button")
	svg := createdAs(toks, "createElementNS", "svg")
	if button == "" || svg == "" {
		return append(faults, iconBuilder+" builds no button or no svg this check can name"), true
	}

	labelled := map[string]bool{}
	hidden := false
	for i, tok := range toks {
		if !tok.Is(guard.ScriptIdent, "label") || (i > 0 && toks[i-1].Is(guard.ScriptPunct, ".")) {
			continue
		}
		attr, ok := setAttributeCall(toks, i, button)
		if ok && (attr == "aria-label" || attr == "title") && !labelled[attr] {
			labelled[attr] = true
			continue
		}
		faults = append(faults, iconBuilder+" reads its label other than as the button's aria-label "+
			"and title, through setAttribute; a label written any other way can reach an HTML "+
			"parser (#120, #562)")
		break
	}
	for _, attr := range []string{"aria-label", "title"} {
		if !labelled[attr] {
			faults = append(faults, iconBuilder+" does not write its label as the button's "+attr+
				" through setAttribute (#562)")
		}
	}
	for i := range toks {
		if toks[i].Is(guard.ScriptString, "true") {
			if attr, ok := setAttributeCall(toks, i, svg); ok && attr == "aria-hidden" {
				hidden = true
			}
		}
	}
	if !hidden {
		faults = append(faults, iconBuilder+" does not set aria-hidden=\"true\" on its svg; the drawing "+
			"would be read as an unnamed image (#562)")
	}

	for _, w := range labelledWrappers {
		params, body, ok := functionBody(src, w)
		if !ok {
			faults = append(faults, w+" is not declared; this check cannot read it")
			continue
		}
		first := strings.TrimSpace(strings.Split(params, ",")[0])
		if first != "label" {
			faults = append(faults, w+" does not take a label as its first parameter (#562)")
			continue
		}
		passed := false
		wt := guard.TokenizeScript(body)
		for i, tok := range wt {
			if tok.Is(guard.ScriptIdent, iconBuilder) && i+1 < len(wt) && wt[i+1].Is(guard.ScriptPunct, "(") {
				arg := callArgument(wt, i+2, labelArg[iconBuilder])
				passed = len(arg) == 1 && arg[0].Is(guard.ScriptIdent, "label")
			}
		}
		if !passed {
			faults = append(faults, w+" does not pass its label to "+iconBuilder+" (#562)")
		}
	}
	return faults, true
}

// createdAs returns the variable toks assign `document.<method>(..., "<tag>")` to, or "".
func createdAs(toks []guard.ScriptToken, method, tag string) string {
	for i := 0; i+6 < len(toks); i++ {
		if toks[i].Kind != guard.ScriptIdent || !toks[i+1].Is(guard.ScriptPunct, "=") ||
			!toks[i+2].Is(guard.ScriptIdent, "document") || !toks[i+3].Is(guard.ScriptPunct, ".") ||
			!toks[i+4].Is(guard.ScriptIdent, method) || !toks[i+5].Is(guard.ScriptPunct, "(") {
			continue
		}
		end := matching(toks, i+5)
		if end > 0 && toks[end-1].Is(guard.ScriptString, tag) {
			return toks[i].Text
		}
	}
	return ""
}

// setAttributeCall reports the attribute name when toks[i] is the second argument of
// `<elem>.setAttribute("<name>", toks[i])`.
func setAttributeCall(toks []guard.ScriptToken, i int, elem string) (string, bool) {
	if i < 6 || i+1 >= len(toks) || !toks[i+1].Is(guard.ScriptPunct, ")") || !toks[i-1].Is(guard.ScriptPunct, ",") ||
		toks[i-2].Kind != guard.ScriptString || !toks[i-3].Is(guard.ScriptPunct, "(") ||
		!toks[i-4].Is(guard.ScriptIdent, "setAttribute") || !toks[i-5].Is(guard.ScriptPunct, ".") ||
		!toks[i-6].Is(guard.ScriptIdent, elem) {
		return "", false
	}
	return toks[i-2].Text, true
}

// TestUtilsJS_TheIconButtonIsNamed holds the real, embedded utils.js to the builder's half of the rule.
func TestUtilsJS_TheIconButtonIsNamed(t *testing.T) {
	faults, ok := iconBuilderFaults(utilsJS(t))
	require.True(t, ok, "static/utils.js: function createIconButton not found, or its body cannot be read; "+
		"this check cannot read it (#562)")
	for _, f := range faults {
		t.Errorf("static/utils.js: %s", f)
	}
}

// iconBuilderSource is a builder that keeps the rule, for the fixtures below to break.
const iconBuilderSource = `function createIconButton(pathData, evenOdd, label, onclick, data) {
  const svgNS = "http://www.w3.org/2000/svg";
  const button = document.createElement("button");
  button.type = "button";
  button.setAttribute("aria-label", label);
  button.setAttribute("title", label);
  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("aria-hidden", "true");
  button.appendChild(svg);
  return button;
}

function createTrashCanButton(label, onclick, data) {
  return createIconButton(["M8"], true, label, onclick, data);
}

function createEditButton(label, onclick, data) {
  return createIconButton(["M5"], false, label, onclick, data);
}
`

// TestIconBuilder_TheRule drives the finder over fixtures: the shape the rule wants passes, and each
// way of breaking it, the builder as it was before #562 among them, is reported.
func TestIconBuilder_TheRule(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"the builder names its button and hides its svg", iconBuilderSource, nil},
		{"before #562: no label", `function createIconButton(pathData, evenOdd, onclick, data) {
  const button = document.createElement("button");
  const svg = document.createElementNS(svgNS, "svg");
  return button;
}
`, []string{"createIconButton takes no label as its third parameter"}},
		{"the label is written as markup", strings.Replace(iconBuilderSource,
			`button.setAttribute("title", label);`, `button.setAttribute("title", label);
  button.innerHTML = label;`, 1),
			[]string{"createIconButton reads its label other than as the button's aria-label and title"}},
		{"the label is not the aria-label", strings.Replace(iconBuilderSource,
			`button.setAttribute("aria-label", label);`, "", 1),
			[]string{`does not write its label as the button's aria-label`}},
		{"the label is not the title", strings.Replace(iconBuilderSource,
			`button.setAttribute("title", label);`, "", 1),
			[]string{`does not write its label as the button's title`}},
		{"the label is set on the svg", strings.Replace(iconBuilderSource,
			`button.setAttribute("title", label);`, `svg.setAttribute("title", label);`, 1),
			[]string{"reads its label other than as the button's aria-label and title",
				`does not write its label as the button's title`}},
		{"the svg is not hidden", strings.Replace(iconBuilderSource,
			`svg.setAttribute("aria-hidden", "true");`, "", 1),
			[]string{`does not set aria-hidden="true" on its svg`}},
		{"the svg is hidden as false", strings.Replace(iconBuilderSource,
			`svg.setAttribute("aria-hidden", "true");`, `svg.setAttribute("aria-hidden", "false");`, 1),
			[]string{`does not set aria-hidden="true" on its svg`}},
		{"a wrapper takes no label", strings.Replace(iconBuilderSource,
			`function createEditButton(label, onclick, data) {
  return createIconButton(["M5"], false, label, onclick, data);`, `function createEditButton(onclick, data) {
  return createIconButton(["M5"], false, "", onclick, data);`, 1),
			[]string{"createEditButton does not take a label as its first parameter"}},
		{"a wrapper drops its label", strings.Replace(iconBuilderSource,
			`createIconButton(["M8"], true, label, onclick, data)`, `createIconButton(["M8"], true, "", onclick, data)`, 1),
			[]string{"createTrashCanButton does not pass its label to createIconButton"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			faults, ok := iconBuilderFaults(tc.src)
			require.True(t, ok)
			require.Len(t, faults, len(tc.want), strings.Join(faults, "\n"))
			for i, w := range tc.want {
				assert.Contains(t, faults[i], w)
			}
		})
	}
}

// TestIconBuilder_ASourceWithoutTheBuilderIsNotRead pins the walk that reaches nothing.
func TestIconBuilder_ASourceWithoutTheBuilderIsNotRead(t *testing.T) {
	_, ok := iconBuilderFaults("function createButton(label) {}\n")
	assert.False(t, ok)
}

// buttonFault is one script-built button the rule refuses, located.
type buttonFault struct {
	path string
	line int
	why  string
}

// buttonCalls counts what a walk reached.
type buttonCalls struct {
	files, created, labelled int
}

// catalogHas reports whether key is in the English catalog, which the catalogs' parity test holds
// the other locale to.
type catalogHas func(key string) bool

func realCatalogHas(key string) bool {
	return i18n.Raw(i18n.WithLocale(context.Background(), true, "en"), key) != key
}

// findButtonFaults walks fsys and returns every script-built button that can submit a form, and
// every icon-button call that passes no label.
func findButtonFaults(fsys fs.FS, has catalogHas) ([]buttonFault, buttonCalls, error) {
	scripts, files, err := guard.ReadScripts(fsys)
	n := buttonCalls{files: files}
	var faults []buttonFault
	for _, s := range scripts {
		faults = append(faults, buttonFaultsIn(s.Path, s.Tokens, has, &n)...)
	}
	return faults, n, err
}

// buttonFaultsIn applies the rule to one script's tokens.
func buttonFaultsIn(path string, toks []guard.ScriptToken, has catalogHas, n *buttonCalls) []buttonFault {
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
		if t.Is(guard.ScriptIdent, "createElement") && at(i-1).Is(guard.ScriptPunct, ".") &&
			at(i+1).Is(guard.ScriptPunct, "(") && at(i+2).Is(guard.ScriptString, "button") &&
			at(i+3).Is(guard.ScriptPunct, ")") {
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
			continue
		}

		idx, ok := labelArg[t.Text]
		if t.Kind != guard.ScriptIdent || !ok || at(i-1).Is(guard.ScriptIdent, "function") {
			continue
		}
		if path == builderHome && t.Text == iconBuilder {
			// The wrappers' calls, which iconBuilderFaults holds to passing their label on.
			continue
		}
		if !at(i+1).Is(guard.ScriptPunct, "(") {
			report(t, t.Text+" is named other than in a call, so its label cannot be read (#562)")
			continue
		}
		n.labelled++
		if why := labelFault(callArgument(toks, i+2, idx), has); why != "" {
			report(t, t.Text+"'s label "+why+" (#562)")
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

// labelFault returns why the label argument arg does not name the action, the thing and the row, or
// "". A label opens with one quoted catalog lookup, the action and the thing in the administrator's
// language, joined by + to the row's value.
func labelFault(arg []guard.ScriptToken, has catalogHas) string {
	if len(arg) == 0 {
		return "is missing; an icon-only button has no other name"
	}
	first := arg[0]
	if first.Kind != guard.ScriptString || len(first.Actions) != 1 {
		return "does not open with a quoted catalog lookup naming the action and the thing"
	}
	m := catalogKeyRe.FindStringSubmatch(first.Actions[0])
	if m == nil {
		return "does not open with a quoted catalog lookup naming the action and the thing"
	}
	if !has(m[1]) {
		return fmt.Sprintf("names the catalog key %q, which the catalog does not hold", m[1])
	}
	if len(arg) < 3 || !arg[1].Is(guard.ScriptPunct, "+") {
		return "names no row; it must join the row's value to the action and the thing"
	}
	for _, tok := range arg[2:] {
		if tok.Kind == guard.ScriptIdent || tok.Kind == guard.ScriptValue {
			return ""
		}
	}
	return "names no row; it must join the row's value to the action and the thing"
}

// TestScriptButtons_PlainAndNamed holds every page and script this server serves to the rule: every
// script-built button is type "button", and every icon-button call passes a label. Seven buttons are
// built in script (the icon builder's, four row buttons, and the Remove buttons of the client list
// scripts, client-uri-list.js and permission-list.js) and five icon buttons are asked for (four list
// pages, one with both an edit and a remove button).
func TestScriptButtons_PlainAndNamed(t *testing.T) {
	assertScriptButtons(t, realCatalogHas, buttonCalls{created: 7, labelled: 5},
		templateFS, withoutVendored{staticFS})
}

// assertScriptButtons is the reporting half. A walk that reached no file in one of the trees, or
// fewer button calls than least counts, is fatal: a call renamed out of this check's reach would
// otherwise pass it vacuously.
func assertScriptButtons(r guard.Reporter, has catalogHas, least buttonCalls, trees ...fs.FS) {
	r.Helper()

	var faults []buttonFault
	var total buttonCalls
	for _, tree := range trees {
		f, n, err := findButtonFaults(tree, has)
		if err != nil {
			r.Fatalf("walking for pages and scripts: %v", err)
		}
		if n.files == 0 {
			r.Fatalf("reached no .html or .js file in one of the trees; this rule is checking nothing")
		}
		faults = append(faults, f...)
		total.created += n.created
		total.labelled += n.labelled
	}
	for _, f := range faults {
		r.Errorf("%s:%d: %s", f.path, f.line, f.why)
	}
	if total.created < least.created || total.labelled < least.labelled {
		r.Fatalf("reached %d createElement(\"button\") calls and %d icon-button calls, fewer than "+
			"the %d and %d served; a call was renamed out of this rule's reach", total.created,
			total.labelled, least.created, least.labelled)
	}
}

// buttonPage is one page whose script is src.
func buttonPage(src string) fstest.MapFS {
	return fstest.MapFS{"template/page.html": &fstest.MapFile{Data: []byte("<script>\n" + src + "\n</script>\n")}}
}

// fixtureCatalog holds one key.
func fixtureCatalog(key string) bool { return key == "adminconsole.page.remove_label" }

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
		{"a labelled remove button", `cell.replaceChildren(createTrashCanButton("{{ T $.ctx "adminconsole.page.remove_label" }} " + uri, deleteRedirectURI));`, nil},
		{"a labelled edit button whose row is a member", `createEditButton("{{ T $.ctx "adminconsole.page.remove_label" }} " + perm.permissionIdentifier, editPermission, { permissionid: perm.id });`, nil},
		{"the icon builder called with a label", `createIconButton(["M1"], true, "{{ T $.ctx "adminconsole.page.remove_label" }} " + uri, f);`, nil},
		{"before #562: no label", `cell.replaceChildren(createTrashCanButton(deleteRedirectURI));`,
			[]string{"createTrashCanButton's label does not open with a quoted catalog lookup"}},
		{"a label in English, not from the catalog", `createTrashCanButton("Remove redirect URI " + uri, deleteRedirectURI);`,
			[]string{"createTrashCanButton's label does not open with a quoted catalog lookup"}},
		{"a label naming no row", `createTrashCanButton("{{ T $.ctx "adminconsole.page.remove_label" }}", deleteRedirectURI);`,
			[]string{"createTrashCanButton's label names no row"}},
		{"a label naming a key the catalog lacks", `createEditButton("{{ T $.ctx "adminconsole.page.edit_label" }} " + uri, f);`,
			[]string{`createEditButton's label names the catalog key "adminconsole.page.edit_label"`}},
		{"the icon builder called with no label", `createIconButton(["M1"], true, f);`,
			[]string{"createIconButton's label does not open with a quoted catalog lookup"}},
		{"a wrapper called with nothing", `createTrashCanButton();`,
			[]string{"createTrashCanButton's label is missing"}},
		{"a wrapper aliased", `const make = createTrashCanButton;`,
			[]string{"createTrashCanButton is named other than in a call"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			faults, _, err := findButtonFaults(buttonPage(tc.src), fixtureCatalog)
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
	_, n, err := findButtonFaults(fstest.MapFS{}, fixtureCatalog)
	require.NoError(t, err)
	assert.Zero(t, n.files)

	_, n, err = findButtonFaults(buttonPage(`const a = 1;`), fixtureCatalog)
	require.NoError(t, err)
	assert.Equal(t, 1, n.files)
	assert.Zero(t, n.created)
	assert.Zero(t, n.labelled)
}

// buttonsOK is a page that keeps the rule, with one script-built button and one icon-button call.
const buttonsOK = `const b = document.createElement("button");
b.type = "button";
cell.replaceChildren(createTrashCanButton("{{ T $.ctx "adminconsole.page.remove_label" }} " + uri, f));`

// TestScriptButtons_FailsOnAFault drives the reporting half: a refused button reaches Errorf naming
// its file and line, and the walk goes on.
func TestScriptButtons_FailsOnAFault(t *testing.T) {
	fsys := fstest.MapFS{
		"template/ok.html":  buttonPage(buttonsOK)["template/page.html"],
		"template/bad.html": buttonPage(`const addButton = document.createElement("button");`)["template/page.html"],
	}

	report := guard.Run(func(r guard.Reporter) {
		assertScriptButtons(r, fixtureCatalog, buttonCalls{created: 1, labelled: 1}, fsys)
	})

	assert.False(t, report.Stopped, report.Text())
	require.Len(t, report.Errors, 1, report.Text())
	assert.Contains(t, report.Errors[0], `template/bad.html:2: addButton is built in script and never made type "button"`)
}

// TestScriptButtons_PassesOnACleanTree is the other direction.
func TestScriptButtons_PassesOnACleanTree(t *testing.T) {
	report := guard.Run(func(r guard.Reporter) {
		assertScriptButtons(r, fixtureCatalog, buttonCalls{created: 1, labelled: 1}, buttonPage(buttonsOK))
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
// pages build fewer buttons, or ask for fewer icon buttons, than the least the caller names.
func TestScriptButtons_AWalkThatReachesNothingIsFatal(t *testing.T) {
	ok := buttonPage(buttonsOK)
	least := buttonCalls{created: 1, labelled: 1}

	for name, tc := range map[string]struct {
		trees []fs.FS
		least buttonCalls
	}{
		"an unreadable tree":        {[]fs.FS{ok, unreadableFS{}}, least},
		"an empty tree":             {[]fs.FS{ok, fstest.MapFS{}}, least},
		"fewer buttons than served": {[]fs.FS{ok}, buttonCalls{created: 2, labelled: 1}},
		"fewer icon buttons":        {[]fs.FS{ok}, buttonCalls{created: 1, labelled: 2}},
		"no button call at all":     {[]fs.FS{buttonPage(`const a = 1;`)}, least},
	} {
		t.Run(name, func(t *testing.T) {
			report := guard.Run(func(r guard.Reporter) { assertScriptButtons(r, fixtureCatalog, tc.least, tc.trees...) })
			assert.True(t, report.Stopped, report.Text())
		})
	}
}

// searchPages are the two pages whose search box sits in a form beside the rows it lists.
var searchPages = []string{
	"template/admin_groups_members_add.html",
	"template/admin_resources_users_with_permission_add.html",
}

var (
	formOpenRe     = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	searchInputRe  = regexp.MustCompile(`(?is)<input\b[^>]*\bid="search"[^>]*>`)
	onsubmitRe     = regexp.MustCompile(`(?is)\bonsubmit="([^"]*)"`)
	preventsItsOwn = regexp.MustCompile(`^\s*(?:event\.preventDefault\(\)\s*;?|return\s+false\s*;?)\s*$`)
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
	m := onsubmitRe.FindStringSubmatch(page[open[0]:open[1]])
	if m == nil || !preventsItsOwn.MatchString(m[1]) {
		return "the form holding the search box can submit natively; Enter in the box then submits it " +
			"(#562)", true
	}
	return "", true
}

// TestSearchForms_NeverSubmitNatively holds the two real search pages to the rule.
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
}

// TestSearchForms_TheRule drives the finder over fixture pages.
func TestSearchForms_TheRule(t *testing.T) {
	const input = `<input id="search" type="text" name="search" onKeyUp="debouncedSearch();" />`
	cases := []struct {
		name   string
		page   string
		read   bool
		faulty bool
	}{
		{"before #562: a form that submits", `<form method="post">` + input + `</form>`, true, true},
		{"a form whose submit is prevented", `<form method="post" onsubmit="event.preventDefault();">` + input + `</form>`, true, false},
		{"a form that returns false", `<form onsubmit="return false">` + input + `</form>`, true, false},
		{"a form whose handler does something else", `<form onsubmit="search();">` + input + `</form>`, true, true},
		{"the preventing form is an earlier one", `<form onsubmit="event.preventDefault();"></form><form method="post">` + input + `</form>`, true, true},
		{"a search box in no form", `<form onsubmit="return false"></form>` + input, false, false},
		{"no search box", `<form method="post"><input id="name" /></form>`, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			why, ok := searchFormFault(tc.page)
			assert.Equal(t, tc.read, ok)
			assert.Equal(t, tc.faulty, why != "", why)
		})
	}
}
