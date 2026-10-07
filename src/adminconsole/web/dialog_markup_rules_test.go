package web

// The rule table assertDialogMessages enforces, over fstest.MapFS fixtures walked through the same
// finder and reporting half the real tree is. The real tree is clean, so it passes whether each rule
// still fires or has quietly stopped matching anything; every refused row below is a call the finder
// must report, and every allowed row one it must leave alone.

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/guard"
)

// fixtureMarkup stands in for the catalogs: a key carries markup when it says so.
func fixtureMarkup(key string) bool {
	return strings.Contains(key, "markup")
}

// dialogPage wraps body in a page the way the templates carry their code. Line 4 of a fixture page
// is the first line of its script body.
func dialogPage(body string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte("{{define \"body\"}}\n<div id=\"x\"></div>\n<script>\n" + body + "\n</script>\n{{end}}\n")}
}

// TestDialogMessages_TheRefusedShapes holds every shape the rule refuses.
func TestDialogMessages_TheRefusedShapes(t *testing.T) {
	fsys := fstest.MapFS{
		// dialogMarkup's parts named through anything but an array of catalog literals.
		"template/variable.html":     dialogPage(`showModalDialog("m", "t", dialogMarkup(parts, email));`),
		"template/concat.html":       dialogPage(`showModalDialog("m", "t", dialogMarkup(["{{ T $.ctx "a" }}" + email]));`),
		"template/action.html":       dialogPage(`showModalDialog("m", "t", dialogMarkup(["{{ .user.Email }}"]));`),
		"template/kv_action.html":    dialogPage(`showModalDialog("m", "t", dialogMarkup(["{{ T $.ctx "k" "name" .user.Email }}"]));`),
		"template/backtick.html":     dialogPage("showModalDialog(\"m\", \"t\", dialogMarkup([`<b>${email}</b>`]));"),
		"template/empty.html":        dialogPage(`showModalDialog("m", "t", dialogMarkup([]));`),
		"template/array_tail.html":   dialogPage(`showModalDialog("m", "t", dialogMarkup(["{{ T $.ctx "a" }}"].concat(extra)));`),
		"template/data_part.html":    dialogPage(`showModalDialog("m", "t", dialogMarkup(["{{ T $.ctx "a" }}", email]));`),
		"template/format_key.html":   dialogPage(`showModalDialog("m", "t", dialogMarkupFormat(key, { detail: err }));`),
		"template/format_act.html":   dialogPage(`showModalDialog("m", "t", dialogMarkupFormat("{{ .key }}", { detail: err }));`),
		"template/alias.html":        dialogPage(`const build = dialogMarkup;`),
		"static/alias.js":            {Data: []byte("const build = dialogMarkupFormat;\n")},
		"template/plain_markup.html": dialogPage(`showModalDialog("m", "t", "{{ T $.ctx "has.markup" }}");`),
		"template/split_markup.html": dialogPage(`showModalDialog("m", "t", "{{ T $.ctx "a" }}<span class='text-accent'>{{ T $.ctx "b.markup" }}</span>", function() {});`),
		"static/plain_markup.js":     {Data: []byte("showModalDialog(id, title, t(\"js.markup\"));\n")},
	}

	found, n, err := findDialogFaults(fsys, fixtureMarkup)
	require.NoError(t, err)
	assert.Equal(t, len(fsys), n.files)
	assert.Equal(t, []string{
		"static/alias.js:1",
		"static/plain_markup.js:1",
		"template/action.html:4",
		"template/alias.html:4",
		"template/array_tail.html:4",
		"template/backtick.html:4",
		"template/concat.html:4",
		"template/data_part.html:4",
		"template/empty.html:4",
		"template/format_act.html:4",
		"template/format_key.html:4",
		"template/kv_action.html:4",
		"template/plain_markup.html:4",
		"template/split_markup.html:4",
		"template/variable.html:4",
	}, renderDialogFaults(found))
}

// TestDialogMessages_TheAllowedShapes holds what the rule leaves alone: builder calls whose markup
// is catalog literals, with values after them; a plain message whose catalog text is text; a
// message carrying data, which is not a plain catalog message; the builders' own definitions; and
// the names in a comment or a string.
func TestDialogMessages_TheAllowedShapes(t *testing.T) {
	fsys := fstest.MapFS{
		"template/allowed.html": dialogPage(strings.Join([]string{
			`showModalDialog("m", "t", dialogMarkup(["{{ T $.ctx "has.markup" }}"]), function() {}, function() { go(); });`,
			`showModalDialog("m", "t", dialogMarkup(["{{ T $.ctx "a" }}<span class='text-accent'>{{ T $.ctx "b" }}</span>{{ T $.ctx "c.markup" }}"]));`,
			`showModalDialog("m", "t", dialogMarkup([`,
			`    "{{ T $.ctx "a" }}<span class='text-accent'>",`,
			`    "</span>{{ T $.ctx "b" }}",`,
			`], email));`,
			`showModalDialog("m", "t", "{{ T $.ctx "plain" }}");`,
			`showModalDialog("m", "t", "{{ T $.ctx "a.markup" }}" + email);`,
			`// dialogMarkup(parts) in a comment, and showModalDialog("m", "t", "{{ T $.ctx "has.markup" }}")`,
			`const s = "dialogMarkup(parts)";`,
		}, "\n")),
		"static/utils.js": {Data: []byte(strings.Join([]string{
			`function dialogMarkup(parts, ...values) {}`,
			`function dialogMarkupFormat(key, params) {}`,
			`function showModalDialog(id, title, message) {}`,
			`showModalDialog(id, t("js.error.error_title"), dialogMarkupFormat("js.error.unexpected", { detail: err }));`,
			`showModalDialog(id, t("js.error.session_expired_title"), t("js.error.session_expired_body"));`,
		}, "\n"))},
	}

	found, n, err := findDialogFaults(fsys, fixtureMarkup)
	require.NoError(t, err)
	assert.Equal(t, 2, n.files)
	assert.Equal(t, 7, n.dialogs)
	assert.Equal(t, 4, n.builders)
	assert.Empty(t, renderDialogFaults(found))
}

// TestDialogMessages_FailsOnAFault drives the reporting half: a refused call reaches Errorf naming
// its file and line.
func TestDialogMessages_FailsOnAFault(t *testing.T) {
	fsys := fstest.MapFS{
		"template/ok.html":  dialogPage(`showModalDialog("m", "t", dialogMarkup(["{{ T $.ctx "a" }}"]));`),
		"template/bad.html": dialogPage(`showModalDialog("m", "t", dialogMarkup(parts));`),
	}

	report := guard.Run(func(r guard.Reporter) { assertDialogMessages(r, fixtureMarkup, fsys) })

	assert.False(t, report.Stopped)
	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Errors[0], "template/bad.html:4: dialogMarkup's first argument is not an array")
}

// TestDialogMessages_PassesOnACleanTree is the other direction.
func TestDialogMessages_PassesOnACleanTree(t *testing.T) {
	fsys := fstest.MapFS{
		"template/ok.html": dialogPage(`showModalDialog("m", "t", dialogMarkup(["{{ T $.ctx "a" }}"]));`),
	}

	report := guard.Run(func(r guard.Reporter) { assertDialogMessages(r, fixtureMarkup, fsys) })

	assert.False(t, report.Failed(), report.Text())
}

// TestDialogMessages_AWalkThatReachesNothingIsFatal pins the walk's own failures: a tree with no
// page or script, and trees with pages but no dialog or no builder call, where every rule passes
// vacuously.
func TestDialogMessages_AWalkThatReachesNothingIsFatal(t *testing.T) {
	ok := fstest.MapFS{"template/ok.html": dialogPage(`showModalDialog("m", "t", dialogMarkup(["{{ T $.ctx "a" }}"]));`)}
	noBuilder := fstest.MapFS{"template/plain.html": dialogPage(`showModalDialog("m", "t", "{{ T $.ctx "a" }}");`)}

	for name, trees := range map[string][]fs.FS{
		"an empty tree":    {ok, fstest.MapFS{}},
		"no builder call":  {noBuilder},
		"no dialog at all": {fstest.MapFS{"static/other.js": {Data: []byte("const x = 1;\n")}}},
	} {
		t.Run(name, func(t *testing.T) {
			report := guard.Run(func(r guard.Reporter) { assertDialogMessages(r, fixtureMarkup, trees...) })
			assert.True(t, report.Stopped, report.Text())
		})
	}
}
