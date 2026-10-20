package guard

// The rules AssertClassesAreDrawn enforces, over fixture trees walked through the same finder and
// reporting half the two servers' web packages reach: a tree naming classes the stylesheet lacks,
// one naming only classes it draws, the stylesheet's selectors read apart from its declarations, an
// out-of-scope list in both directions, and the walks that reach nothing.

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const drawnCSS = `/*! tailwindcss v4 */ .panel{} .button,.button-danger{} .notice-positive,.notice-danger{}
.theme-swatch-light{} .sm\:flex{} .w-1\/2{} .\32 xl\:flex{} .open{} .text-accent{}
.panel::before{content:".missing"} /* .ghost{} */ @media (width >= 40rem){.tag{}}`

func TestClassesAreDrawn_TheGuardReportsEveryClassWithNoRule(t *testing.T) {
	fsys := fstest.MapFS{
		"template/page.html": {Data: []byte(`<div class="panel pannel">` + "\n" +
			`<a class="button {{ if .danger }}button-dangerous{{ end }}">x</a>` + "\n" +
			`<span class='swatch-{{ .theme }}'></span>` + "\n" +
			`<p class="missing ghost"></p></div>`)},
		"static/page.js": {Data: []byte(`el.className = "panel gone";` + "\n" +
			`el.classList.add("open", "shut");` + "\n" +
			`el["classList"].toggle("hidden-now", on);` + "\n" +
			`notice.className = "notice tone-" + tone;` + "\n" +
			`cell.className = on ? "button" : "missing-branch";` + "\n" +
			`el.classList.remove(on ? "open" : "closed");`)},
	}

	report := Run(func(r Reporter) { assertClassesAreDrawn(r, []byte(drawnCSS), nil, fsys) })

	require.True(t, report.Failed())
	for _, want := range []string{
		`template/page.html: line 1: class "pannel" has no rule in main.css`,
		`template/page.html: line 2: class "button-dangerous" has no rule in main.css`,
		`template/page.html: line 3: no class in main.css begins with "swatch-"`,
		`template/page.html: line 4: class "missing" has no rule in main.css`,
		`template/page.html: line 4: class "ghost" has no rule in main.css`,
		`static/page.js: line 1: class "gone" has no rule in main.css`,
		`static/page.js: line 2: class "shut" has no rule in main.css`,
		`static/page.js: line 3: class "hidden-now" has no rule in main.css`,
		`static/page.js: line 4: class "notice" has no rule in main.css`,
		`static/page.js: line 4: no class in main.css begins with "tone-"`,
		`static/page.js: line 5: class "missing-branch" has no rule in main.css`,
		`static/page.js: line 6: class "closed" has no rule in main.css`,
	} {
		assert.Contains(t, report.Text(), want)
	}
	assert.NotContains(t, report.Text(), `"panel"`)
	assert.NotContains(t, report.Text(), `"open"`)
	assert.NotContains(t, report.Text(), `"button"`)
}

func TestClassesAreDrawn_TheGuardPassesATreeNamingOnlyDrawnClasses(t *testing.T) {
	fsys := fstest.MapFS{
		"template/page.html": {Data: []byte(`<div data-class="nothing" class="panel sm:flex w-1/2 2xl:flex {{- if .x }} button {{- else }} button-danger{{ end }}">` +
			`<a class="button{{ if .danger }}-danger{{ end }}">x</a>` +
			`<span class='theme-swatch-{{ . }} {{ .whole }}'></span>` +
			`<!-- <p class="commented-out"></p> -->{{/* <p class="also-commented"></p> */}}</div>`)},
		"static/page.js": {Data: []byte(`el.className = "button " + extra;` + "\n" +
			`notice.className = "notice-" + tone;` + "\n" +
			`el.classList.toggle("open", items.includes("unrelated"));` + "\n" +
			`el.className = on ? "button" : "button-danger";` + "\n" +
			`const text = "class nothing";`)},
	}

	report := Run(func(r Reporter) { assertClassesAreDrawn(r, []byte(drawnCSS), nil, fsys) })

	assert.False(t, report.Failed(), "a tree naming only drawn classes failed the guard: %s", report.Text())
}

// A class is drawn when a selector names it, its escapes decoded, never when a declaration's value,
// a string or a comment spells it.
func TestClassesAreDrawn_TheStylesheetIsReadFromItsSelectors(t *testing.T) {
	drawn := drawnClasses(drawnCSS)

	for _, name := range []string{"panel", "button-danger", "sm:flex", "w-1/2", "2xl:flex", "tag"} {
		assert.True(t, drawn[name], "%s is drawn", name)
	}
	for _, name := range []string{"missing", "ghost", "tailwindcss", "5"} {
		assert.False(t, drawn[name], "%s is not drawn", name)
	}
}

// The email templates are out of scope: a class there is not read, and an entry naming nothing the
// walk reached is reported, so the list holds only what it exempts.
func TestClassesAreDrawn_TheOutOfScopeListOnlyExempts(t *testing.T) {
	fsys := fstest.MapFS{
		"template/page.html":         {Data: []byte(`<p class="panel"></p>`)},
		"template/emails/hello.html": {Data: []byte(`<p class="email-only"></p>`)},
	}

	report := Run(func(r Reporter) {
		assertClassesAreDrawn(r, []byte(drawnCSS), []string{"template/emails/", "template/gone.html"}, fsys)
	})

	require.True(t, report.Failed())
	assert.Contains(t, report.Text(), "template/gone.html: listed as out of scope, and no file there was reached")
	assert.NotContains(t, report.Text(), "email-only")
	assert.NotContains(t, report.Text(), "template/emails/")
}

func TestClassesAreDrawn_AWalkThatReachesNothingIsFatal(t *testing.T) {
	report := Run(func(r Reporter) { assertClassesAreDrawn(r, []byte(drawnCSS), nil) })
	require.True(t, report.Stopped, "a call naming no tree must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "given no tree of pages and scripts")

	report = Run(func(r Reporter) {
		assertClassesAreDrawn(r, []byte(drawnCSS), nil, fstest.MapFS{"readme.txt": {Data: []byte("no pages")}})
	})
	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "reached no .html or .js file")

	report = Run(func(r Reporter) {
		assertClassesAreDrawn(r, []byte("body{color:red}"), nil, fstest.MapFS{"page.html": {Data: []byte(`<p class="x"></p>`)}})
	})
	require.True(t, report.Stopped, "a stylesheet with no class must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "the stylesheet defines no class")
}
