package guard

// The rules AssertClassesAreDrawn enforces, over fixture trees walked through the same finder and
// reporting half the two servers' web packages reach: a tree naming classes the stylesheet lacks,
// one naming only classes it draws, and the walks that reach nothing.

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const drawnCSS = `/*! tailwindcss */ .panel{} .button,.button-danger{} .notice-positive,.notice-danger{}
.theme-swatch-light{} .sm\:flex{} .w-1\/2{} .open{} .text-accent{}`

func TestClassesAreDrawn_TheGuardReportsEveryClassWithNoRule(t *testing.T) {
	fsys := fstest.MapFS{
		"template/page.html": {Data: []byte(`<div class="panel pannel">` + "\n" +
			`<a class="button {{ if .danger }}button-dangerous{{ end }}">x</a>` + "\n" +
			`<span class="swatch-{{ .theme }}"></span></div>`)},
		"static/page.js": {Data: []byte(`el.className = "panel gone";` + "\n" +
			`el.classList.add("open", "shut");` + "\n" +
			`el["classList"].toggle("hidden-now", on);` + "\n" +
			`notice.className = "notice tone-" + tone;`)},
	}

	report := Run(func(r Reporter) { assertClassesAreDrawn(r, []byte(drawnCSS), fsys) })

	require.True(t, report.Failed())
	for _, want := range []string{
		`template/page.html: line 1: class "pannel" has no rule in main.css`,
		`template/page.html: line 2: class "button-dangerous" has no rule in main.css`,
		`template/page.html: line 3: no class in main.css begins with "swatch-"`,
		`static/page.js: line 1: class "gone" has no rule in main.css`,
		`static/page.js: line 2: class "shut" has no rule in main.css`,
		`static/page.js: line 3: class "hidden-now" has no rule in main.css`,
		`static/page.js: line 4: class "notice" has no rule in main.css`,
		`static/page.js: line 4: no class in main.css begins with "tone-"`,
	} {
		assert.Contains(t, report.Text(), want)
	}
	assert.NotContains(t, report.Text(), `"panel"`)
	assert.NotContains(t, report.Text(), `"open"`)
}

func TestClassesAreDrawn_TheGuardPassesATreeNamingOnlyDrawnClasses(t *testing.T) {
	fsys := fstest.MapFS{
		"template/page.html": {Data: []byte(`<div data-class="nothing" class="panel sm:flex w-1/2 {{- if .x }} button {{- else }} button-danger{{ end }}">` +
			`<span class="theme-swatch-{{ . }} {{ .whole }}"></span></div>`)},
		"static/page.js": {Data: []byte(`el.className = "button " + extra;` + "\n" +
			`notice.className = "notice-" + tone;` + "\n" +
			`el.classList.toggle("open", items.includes("unrelated"));` + "\n" +
			`const text = "class nothing";`)},
	}

	report := Run(func(r Reporter) { assertClassesAreDrawn(r, []byte(drawnCSS), fsys) })

	assert.False(t, report.Failed(), "a tree naming only drawn classes failed the guard: %s", report.Text())
}

func TestClassesAreDrawn_AWalkThatReachesNothingIsFatal(t *testing.T) {
	report := Run(func(r Reporter) {
		assertClassesAreDrawn(r, []byte(drawnCSS), fstest.MapFS{"readme.txt": {Data: []byte("no pages")}})
	})
	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "reached no .html or .js file")

	report = Run(func(r Reporter) {
		assertClassesAreDrawn(r, []byte("body{color:red}"), fstest.MapFS{"page.html": {Data: []byte(`<p class="x"></p>`)}})
	})
	require.True(t, report.Stopped, "a stylesheet with no class must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "the stylesheet defines no class")
}
