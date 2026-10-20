package guard

// The rules AssertClassesAreDrawn enforces, over fixture trees walked through the same finder and
// reporting half the two servers' web packages reach: a page naming classes the stylesheet lacks,
// one naming only classes it draws, the out-of-scope list, and the walks that reach nothing.

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const drawnCSS = `/*! tailwindcss v4 */ .panel{} .button,.button-danger{} .theme-swatch-light{}
.sm\:flex{} .w-1\/2{} .\32 xl\:flex{} .panel::before{content:".missing"} /* .ghost{} */`

func TestClassesAreDrawn_TheGuardReportsEveryClassWithNoRule(t *testing.T) {
	fsys := fstest.MapFS{
		"template/page.html": {Data: []byte(`<div class="panel pannel">` + "\n" +
			`<a class="button {{ if .danger }}button-dangerous{{ end }}">x</a>` + "\n" +
			`<span class="swatch-{{ .theme }}"></span>` + "\n" +
			`<p class="missing ghost"></p></div>`)},
	}

	report := Run(func(r Reporter) { assertClassesAreDrawn(r, []byte(drawnCSS), nil, fsys) })

	require.True(t, report.Failed())
	for _, want := range []string{
		`template/page.html: line 1: class "pannel" has no rule in main.css`,
		`template/page.html: line 2: class "button-dangerous" has no rule in main.css`,
		`template/page.html: line 3: no class in main.css begins with "swatch-"`,
		`template/page.html: line 4: class "missing" has no rule in main.css`,
		`template/page.html: line 4: class "ghost" has no rule in main.css`,
	} {
		assert.Contains(t, report.Text(), want)
	}
	assert.NotContains(t, report.Text(), `"panel"`)
}

func TestClassesAreDrawn_TheGuardPassesAPageNamingOnlyDrawnClasses(t *testing.T) {
	fsys := fstest.MapFS{
		"template/page.html": {Data: []byte(`<div class="panel sm:flex w-1/2 2xl:flex">` +
			`<a class="button{{ if .danger }}-danger{{ end }}">x</a>` +
			`<span class='theme-swatch-{{ . }} {{ .whole }}'></span>` +
			`<!-- <p class="commented-out"></p> --></div>`)},
		"static/page.js": {Data: []byte(`el.className = "not-read";`)},
	}

	report := Run(func(r Reporter) { assertClassesAreDrawn(r, []byte(drawnCSS), nil, fsys) })

	assert.False(t, report.Failed(), "a page naming only drawn classes failed the guard: %s", report.Text())
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
}

func TestClassesAreDrawn_AWalkThatReachesNothingIsFatal(t *testing.T) {
	report := Run(func(r Reporter) { assertClassesAreDrawn(r, []byte(drawnCSS), nil) })
	require.True(t, report.Stopped, "a call naming no tree must be fatal rather than a pass")

	report = Run(func(r Reporter) {
		assertClassesAreDrawn(r, []byte(drawnCSS), nil, fstest.MapFS{"readme.txt": {Data: []byte("no pages")}})
	})
	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "reached no .html file")

	report = Run(func(r Reporter) {
		assertClassesAreDrawn(r, []byte("body{color:red}"), nil, fstest.MapFS{"page.html": {Data: []byte(`<p class="x"></p>`)}})
	})
	require.True(t, report.Stopped, "a stylesheet with no class must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "the stylesheet defines no class")
}
