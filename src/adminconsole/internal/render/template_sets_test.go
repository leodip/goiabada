package render

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/web"
)

// The built-in templates cannot change while the console runs, so a page's template set, its
// layout, its template and the shared partials, is parsed the first time the page is drawn and kept:
// a request only executes it (#819 decisions 5 and 6).

// templateSetFS is a layout, an end-user page that names a data-page, an admin page drawn with the
// admin menu, and a partial both pages call.
func templateSetFS() fstest.MapFS {
	return fstest.MapFS{
		"layouts/menu_layout.html": {Data: []byte(`<body data-page="{{.dataPage}}" data-footer="{{if .brandFooter}}yes{{end}}">{{template "menu" .}}{{template "content" .}}</body>`)},
		"account.html":             {Data: []byte(`{{define "data-page"}}account{{end}}{{define "menu"}}{{end}}{{define "content"}}Account {{.name}} {{template "sign" .}}{{end}}`)},
		"admin.html":               {Data: []byte(`{{define "menu"}}{{template "admin_menu" .}}{{end}}{{define "content"}}Admin {{.name}} {{template "sign" .}}{{end}}`)},
		"partials/admin_menu.html": {Data: []byte(`{{define "admin_menu"}}<nav></nav>{{end}}`)},
		"partials/sign.html":       {Data: []byte(`{{define "sign"}}<em>{{.appName}}</em>{{end}}`)},
	}
}

func drawPage(t *testing.T, renderer *Renderer, layout, page, name string) string {
	t.Helper()
	body, err := renderPage(renderer, newRequest(http.MethodGet, "/", nil), layout, page, map[string]interface{}{"name": name})
	require.NoError(t, err)
	return body
}

func TestRenderTemplate_APageDrawnAgainReadsNoTemplate(t *testing.T) {
	templates := &openCountingFS{FS: templateSetFS()}
	renderer := New(templates, nil)

	first := drawPage(t, renderer, "/layouts/menu_layout.html", "/account.html", "Ana")
	assert.Equal(t, `<body data-page="account" data-footer="">Account Ana <em></em></body>`, first)
	read := templates.opens.Load()
	require.Positive(t, read, "the first draw reads the page's template set")

	again := drawPage(t, renderer, "/layouts/menu_layout.html", "/account.html", "Bo")
	assert.Equal(t, `<body data-page="account" data-footer="">Account Bo <em></em></body>`, again, "a draw executes with its own data")
	assert.Equal(t, read, templates.opens.Load(), "a second draw reads no template")
}

// A page's set is its layout and its template: another page is a set of its own, and draws what it
// names, an admin page with the admin menu and no data-page.
func TestRenderTemplate_EachPageIsASetOfItsOwn(t *testing.T) {
	renderer := New(templateSetFS(), nil)

	assert.Equal(t, `<body data-page="account" data-footer="">Account Ana <em></em></body>`,
		drawPage(t, renderer, "/layouts/menu_layout.html", "/account.html", "Ana"))
	assert.Equal(t, `<body data-page="" data-footer=""><nav></nav>Admin Ana <em></em></body>`,
		drawPage(t, renderer, "/layouts/menu_layout.html", "/admin.html", "Ana"))
	assert.Equal(t, `<body data-page="account" data-footer="">Account Ana <em></em></body>`,
		drawPage(t, renderer, "/layouts/menu_layout.html", "/account.html", "Ana"))
}

// A template that does not parse is an error at each draw, as it was before sets were kept.
func TestRenderTemplate_ATemplateThatDoesNotParseFailsEachDraw(t *testing.T) {
	templates := templateSetFS()
	templates["broken.html"] = &fstest.MapFile{Data: []byte(`{{define "content"}}{{.name}`)}
	renderer := New(templates, nil)

	for range 2 {
		_, err := renderPage(renderer, newRequest(http.MethodGet, "/", nil), "/layouts/menu_layout.html", "/broken.html", nil)
		require.Error(t, err)
	}
}

// A kept set is shared by concurrent requests, the first among them included; the race detector
// runs this under the unit tier.
func TestRenderTemplate_ConcurrentDrawsShareTheSet(t *testing.T) {
	renderer := New(templateSetFS(), nil)
	want := map[string]string{
		"/account.html": `<body data-page="account" data-footer="">Account Ana <em></em></body>`,
		"/admin.html":   `<body data-page="" data-footer=""><nav></nav>Admin Ana <em></em></body>`,
	}

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			page := []string{"/account.html", "/admin.html"}[i%2]
			assert.Equal(t, want[page], drawPage(t, renderer, "/layouts/menu_layout.html", page, "Ana"))
		})
	}
	wg.Wait()
}

// The "settings unavailable" page is parsed once too.
func TestSettingsUnavailable_APageAnsweredAgainReadsNoTemplate(t *testing.T) {
	templates := &openCountingFS{FS: web.TemplateFS()}
	renderer := New(templates, web.StaticFS())

	answer := func() string {
		w := httptest.NewRecorder()
		renderer.SettingsUnavailable(w, httptest.NewRequest(http.MethodGet, "/", nil),
			"adminconsole.error.issuer_missing_title", "adminconsole.error.issuer_missing")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
		return w.Body.String()
	}

	first := answer()
	assert.Contains(t, first, "The auth server didn&#39;t report an issuer.")
	read := templates.opens.Load()
	require.Positive(t, read, "the first answer reads the page")

	assert.Equal(t, first, answer())
	assert.Equal(t, read, templates.opens.Load(), "a second answer reads no template")
}

func TestSettingsUnavailable_ConcurrentAnswersShareThePage(t *testing.T) {
	renderer := New(web.TemplateFS(), web.StaticFS())

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			w := httptest.NewRecorder()
			renderer.SettingsUnavailable(w, httptest.NewRequest(http.MethodGet, "/", nil),
				"adminconsole.error.issuer_missing_title", "adminconsole.error.issuer_missing")
			assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
		})
	}
	wg.Wait()
}
