package render

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
)

// The built-in templates cannot change while the server runs, so a page's template set, its layout,
// its template and the shared partials, is parsed the first time the page is drawn and kept: a
// request only executes it (#819 decisions 5 and 6).

// templateSetFS is a layout, two pages that name a data-page, and a partial both pages call.
func templateSetFS() fstest.MapFS {
	return fstest.MapFS{
		"layouts/no_menu_layout.html": {Data: []byte(`<body data-page="{{.dataPage}}">{{template "content" .}}</body>`)},
		"layouts/menu_layout.html":    {Data: []byte(`<main>{{template "content" .}}</main>`)},
		"first.html":                  {Data: []byte(`{{define "data-page"}}first{{end}}{{define "content"}}First {{.name}} {{template "sign" .}}{{end}}`)},
		"second.html":                 {Data: []byte(`{{define "data-page"}}second{{end}}{{define "content"}}Second {{.name}} {{template "sign" .}}{{end}}`)},
		"partials/sign.html":          {Data: []byte(`{{define "sign"}}<em>{{.appName}}</em>{{end}}`)},
	}
}

func drawPage(t *testing.T, renderer *Renderer, layout, page, name string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Acme"}))
	buf, err := renderer.RenderTemplateToBuffer(req, layout, page, map[string]interface{}{"name": name})
	require.NoError(t, err)
	return buf.String()
}

func TestRenderTemplate_APageDrawnAgainReadsNoTemplate(t *testing.T) {
	templates := &openCountingFS{FS: templateSetFS()}
	renderer := New(templates, nil, nil)

	first := drawPage(t, renderer, "/layouts/no_menu_layout.html", "/first.html", "Ana")
	assert.Equal(t, `<body data-page="first">First Ana <em>Acme</em></body>`, first)
	read := templates.opens.Load()
	require.Positive(t, read, "the first draw reads the page's template set")

	again := drawPage(t, renderer, "/layouts/no_menu_layout.html", "/first.html", "Bo")
	assert.Equal(t, `<body data-page="first">First Bo <em>Acme</em></body>`, again, "a draw executes with its own data")
	assert.Equal(t, read, templates.opens.Load(), "a second draw reads no template")
}

// A page's set is its layout and its template: another page, or the same page in another layout, is
// a set of its own, and draws what it names.
func TestRenderTemplate_EachLayoutAndPageIsASetOfItsOwn(t *testing.T) {
	renderer := New(templateSetFS(), nil, nil)

	assert.Equal(t, `<body data-page="first">First Ana <em>Acme</em></body>`,
		drawPage(t, renderer, "/layouts/no_menu_layout.html", "/first.html", "Ana"))
	assert.Equal(t, `<body data-page="second">Second Ana <em>Acme</em></body>`,
		drawPage(t, renderer, "/layouts/no_menu_layout.html", "/second.html", "Ana"))
	assert.Equal(t, `<main>First Ana <em>Acme</em></main>`,
		drawPage(t, renderer, "/layouts/menu_layout.html", "/first.html", "Ana"))
	assert.Equal(t, `<body data-page="first">First Ana <em>Acme</em></body>`,
		drawPage(t, renderer, "/layouts/no_menu_layout.html", "/first.html", "Ana"))
}

// A template that does not parse is an error at each draw, as it was before sets were kept.
func TestRenderTemplate_ATemplateThatDoesNotParseFailsEachDraw(t *testing.T) {
	templates := templateSetFS()
	templates["broken.html"] = &fstest.MapFile{Data: []byte(`{{define "content"}}{{.name}`)}
	renderer := New(templates, nil, nil)

	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
		_, err := renderer.RenderTemplateToBuffer(req, "/layouts/no_menu_layout.html", "/broken.html", nil)
		require.Error(t, err)
	}
}

// A kept set is shared by concurrent requests, the first among them included; the race detector
// runs this under the unit tier.
func TestRenderTemplate_ConcurrentDrawsShareTheSet(t *testing.T) {
	renderer := New(templateSetFS(), nil, nil)

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			page := []string{"/first.html", "/second.html"}[i%2]
			want := map[string]string{
				"/first.html":  `<body data-page="first">First Ana <em>Acme</em></body>`,
				"/second.html": `<body data-page="second">Second Ana <em>Acme</em></body>`,
			}[page]
			assert.Equal(t, want, drawPage(t, renderer, "/layouts/no_menu_layout.html", page, "Ana"))
		})
	}
	wg.Wait()
}

// The frame drawn around every email is parsed once too; an email's own text is still rendered for
// each email.
func TestRenderEmail_AnEmailSentAgainReadsNoTemplate(t *testing.T) {
	templates := &openCountingFS{FS: web.TemplateFS()}
	renderer := New(templates, web.StaticFS(), nil)

	send := func(name string) emailtemplate.Message {
		ctx := reqctx.WithSettings(t.Context(), &record.Settings{AppName: "Acme Portal"})
		req := httptest.NewRequest(http.MethodPost, "/forgot-password", nil).WithContext(ctx)
		message, err := renderer.RenderEmail(req, emailtemplate.PasswordResetLink,
			emailtemplate.Values{Name: name, Link: "https://auth.example.com/reset-password?code=abc", Expiry: 5 * time.Minute})
		require.NoError(t, err)
		return message
	}

	first := send("Ana")
	assert.Contains(t, first.HTML, "Ana")
	read := templates.opens.Load()
	require.Positive(t, read, "the first email reads its frame")

	again := send("Bruna")
	assert.Contains(t, again.HTML, "Bruna")
	assert.NotContains(t, again.HTML, "Ana")
	assert.Equal(t, first.Subject, again.Subject)
	assert.Equal(t, read, templates.opens.Load(), "a second email reads no template")
}

func TestRenderEmail_ConcurrentEmailsShareTheFrame(t *testing.T) {
	renderer := New(web.TemplateFS(), web.StaticFS(), nil)

	messages := make([]emailtemplate.Message, 8)
	failures := make([]error, len(messages))
	var wg sync.WaitGroup
	for i := range messages {
		wg.Go(func() {
			ctx := reqctx.WithSettings(t.Context(), &record.Settings{AppName: "Acme Portal"})
			req := httptest.NewRequest(http.MethodPost, "/forgot-password", nil).WithContext(ctx)
			messages[i], failures[i] = renderer.RenderEmail(req, emailtemplate.PasswordResetLink,
				emailtemplate.Values{Name: "Ana", Link: "https://auth.example.com/reset-password?code=abc", Expiry: 5 * time.Minute})
		})
	}
	wg.Wait()
	for i, message := range messages {
		require.NoError(t, failures[i])
		assert.Contains(t, message.HTML, "Acme Portal")
	}
}
