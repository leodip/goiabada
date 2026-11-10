package render

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// defaultBrandStub answers one default brand, or one failure, and counts the reads. It answers the
// brand of the clients in clients, nil for any other, or clientErr.
type defaultBrandStub struct {
	brand     *record.Brand
	err       error
	reads     int
	clients   map[string]*record.Brand
	clientErr error
}

func (s *defaultBrandStub) GetDefaultBrand(_ context.Context, _ *sql.Tx) (*record.Brand, error) {
	s.reads++
	return s.brand, s.err
}

func (s *defaultBrandStub) GetClientPageBrand(_ context.Context, _ *sql.Tx, clientIdentifier string) (*record.Brand, error) {
	if s.clientErr != nil {
		return nil, s.clientErr
	}
	return s.clients[clientIdentifier], nil
}

// pageHead is what a page's head says about its look: the html element's data-theme, whether it
// carries one, the color-scheme meta, and the stylesheets in the order the page links them.
type pageHead struct {
	dataTheme    string
	hasDataTheme bool
	colorScheme  string
	stylesheets  []string
}

func readPageHead(t *testing.T, page string) pageHead {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(page))
	require.NoError(t, err)

	var head pageHead
	head.dataTheme, head.hasDataTheme = doc.Find("html").Attr("data-theme")
	head.colorScheme, _ = doc.Find(`meta[name="color-scheme"]`).Attr("content")
	doc.Find(`link[rel="stylesheet"]`).Each(func(_ int, link *goquery.Selection) {
		href, _ := link.Attr("href")
		head.stylesheets = append(head.stylesheets, href)
	})
	return head
}

// brandStylesheetHref is the link a page draws a brand on theme with: the brand's own stylesheet
// route, named by the fingerprint the stylesheet is served as current under.
func brandStylesheetHref(t *testing.T, brandId string, theme string) string {
	t.Helper()
	stylesheet, ok := brandthemes.StylesheetOf(theme)
	require.True(t, ok, theme)
	require.Regexp(t, `^[0-9a-f]{12}$`, stylesheet.Fingerprint)
	return "/brand/" + brandId + "/stylesheet.css?v=" + stylesheet.Fingerprint
}

// Both layouts are drawn in the default brand: the html element carries data-theme for a light or
// dark brand and none for an automatic one, the color-scheme meta follows, and the brand's
// stylesheet is linked after main.css, so its tokens win over main.css's (#810 decision 3).
func TestRender_LayoutsAreDrawnInTheDefaultBrand(t *testing.T) {
	for _, layout := range []struct{ layout, page string }{
		{"/layouts/auth_layout.html", "/logged_out.html"},
		{"/layouts/no_menu_layout.html", "/not_found.html"},
	} {
		for _, tc := range []struct {
			name            string
			brand           *record.Brand
			wantDataTheme   string
			wantColorScheme string
			wantBrandHref   func(t *testing.T) string
		}{
			{
				name:            "a dark brand",
				brand:           &record.Brand{Id: 7, Name: "Night", Appearance: record.BrandAppearanceDark, Theme: "plum"},
				wantDataTheme:   "dark",
				wantColorScheme: "dark",
				wantBrandHref:   func(t *testing.T) string { return brandStylesheetHref(t, "7", "plum") },
			},
			{
				name:            "a light brand",
				brand:           &record.Brand{Id: 12, Name: "Day", Appearance: record.BrandAppearanceLight, Theme: "avocado"},
				wantDataTheme:   "light",
				wantColorScheme: "light",
				wantBrandHref:   func(t *testing.T) string { return brandStylesheetHref(t, "12", "avocado") },
			},
			{
				name:            "an automatic brand on Blueberry",
				brand:           &record.Brand{Id: 1, Name: "Default", Appearance: record.BrandAppearanceAuto, Theme: "blueberry"},
				wantColorScheme: "light dark",
				wantBrandHref:   func(t *testing.T) string { return brandStylesheetHref(t, "1", "blueberry") },
			},
		} {
			t.Run(layout.layout+" "+tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Test"}))
				brands := &defaultBrandStub{brand: tc.brand}

				buf, err := New(web.TemplateFS(), web.StaticFS(), brands).RenderTemplateToBuffer(req, layout.layout, layout.page,
					map[string]interface{}{})

				require.NoError(t, err)
				head := readPageHead(t, buf.String())
				if tc.wantDataTheme == "" {
					assert.False(t, head.hasDataTheme, "an automatic page carries no data-theme, got %q", head.dataTheme)
				} else {
					assert.Equal(t, tc.wantDataTheme, head.dataTheme)
				}
				assert.Equal(t, tc.wantColorScheme, head.colorScheme)
				require.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet")
				assert.Regexp(t, `^/static/main\.css\?v=[0-9a-f]{12}$`, head.stylesheets[0])
				assert.Equal(t, tc.wantBrandHref(t), head.stylesheets[1])
			})
		}
	}
}

// A page whose brand cannot be read is still drawn: automatic, in main.css's colors, with no brand
// stylesheet. That is an empty pointer, a failed read, which is logged, and a stored theme that is
// none of the built-in ones, which names no stylesheet and is logged too.
func TestRender_APageWithNoReadableBrandIsStillDrawn(t *testing.T) {
	for _, layout := range []struct{ layout, page string }{
		{"/layouts/auth_layout.html", "/logged_out.html"},
		{"/layouts/no_menu_layout.html", "/not_found.html"},
	} {
		for _, tc := range []struct {
			name    string
			brands  *defaultBrandStub
			wantLog string
		}{
			{name: "no default brand", brands: &defaultBrandStub{}},
			{name: "a failed read", brands: &defaultBrandStub{err: errs.New("the database went away")},
				wantLog: "unable to read the default brand"},
			{name: "a theme none of the built-in ones",
				brands:  &defaultBrandStub{brand: &record.Brand{Id: 3, Name: "Odd", Appearance: record.BrandAppearanceDark, Theme: "mango"}},
				wantLog: "unable to link the brand's stylesheet"},
		} {
			t.Run(layout.layout+" "+tc.name, func(t *testing.T) {
				logs := logtest.CaptureSlog(t)
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Test"}))

				buf, err := New(web.TemplateFS(), web.StaticFS(), tc.brands).RenderTemplateToBuffer(req, layout.layout, layout.page,
					map[string]interface{}{})

				require.NoError(t, err)
				assert.Equal(t, 1, tc.brands.reads)
				head := readPageHead(t, buf.String())
				assert.False(t, head.hasDataTheme, "got data-theme %q", head.dataTheme)
				assert.Equal(t, "light dark", head.colorScheme)
				require.Len(t, head.stylesheets, 1, "main.css alone")
				assert.Regexp(t, `^/static/main\.css\?v=[0-9a-f]{12}$`, head.stylesheets[0])

				var messages []string
				for _, record := range logs.Records() {
					messages = append(messages, record.Message)
				}
				if tc.wantLog == "" {
					assert.Empty(t, messages)
				} else {
					assert.Equal(t, []string{tc.wantLog}, messages)
				}
			})
		}
	}
}

// An email is not a page: it links no stylesheet, so its render reads no brand (#810 leaves emails
// to #817).
func TestRender_AnEmailReadsNoBrand(t *testing.T) {
	templateFS := fstest.MapFS{
		"layouts/email_layout.html": {Data: []byte(`<html>{{template "content" .}}</html>`)},
		"emails/note.html":          {Data: []byte(`{{define "content"}}note{{end}}`)},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Test"}))
	brands := &defaultBrandStub{brand: &record.Brand{Id: 7, Appearance: record.BrandAppearanceDark, Theme: "plum"}}

	buf, err := New(templateFS, nil, brands).RenderTemplateToBuffer(req, "layouts/email_layout.html", "emails/note.html", nil)

	require.NoError(t, err)
	assert.Equal(t, "<html>note</html>", buf.String())
	assert.Zero(t, brands.reads)
}

// A page whose request names a client is drawn in the brand that client's pages take, which the
// database answers: its own, or the default for a client with none. A client that is not there, or a
// page client named and then forgotten, leaves the page in the default brand. A client brand that
// cannot be read still draws the page, automatic in main.css's colors, and the fault is logged
// (#812, as #810 decided for the default brand).
func TestRender_APageForAClientIsDrawnInTheClientsBrand(t *testing.T) {
	night := &record.Brand{Id: 7, Name: "Night", Appearance: record.BrandAppearanceDark, Theme: "plum"}
	day := &record.Brand{Id: 12, Name: "Day", Appearance: record.BrandAppearanceLight, Theme: "avocado"}

	for _, tc := range []struct {
		name            string
		client          string
		forget          bool
		clientErr       error
		wantDataTheme   string
		wantColorScheme string
		wantBrandHref   func(t *testing.T) string
		wantLog         string
	}{
		{
			name:            "a client given a brand",
			client:          "app-1",
			wantDataTheme:   "light",
			wantColorScheme: "light",
			wantBrandHref:   func(t *testing.T) string { return brandStylesheetHref(t, "12", "avocado") },
		},
		{
			name:            "a client that is not there",
			client:          "no-such-client",
			wantDataTheme:   "dark",
			wantColorScheme: "dark",
			wantBrandHref:   func(t *testing.T) string { return brandStylesheetHref(t, "7", "plum") },
		},
		{
			name:            "a client named and then forgotten",
			client:          "app-1",
			forget:          true,
			wantDataTheme:   "dark",
			wantColorScheme: "dark",
			wantBrandHref:   func(t *testing.T) string { return brandStylesheetHref(t, "7", "plum") },
		},
		{
			name:            "a client whose brand cannot be read",
			client:          "app-1",
			clientErr:       errs.New("the database went away"),
			wantColorScheme: "light dark",
			wantLog:         "unable to read the brand of the client a page is drawn for",
		},
	} {
		for _, layout := range []struct{ layout, page string }{
			{"/layouts/auth_layout.html", "/logged_out.html"},
			{"/layouts/no_menu_layout.html", "/not_found.html"},
		} {
			t.Run(layout.layout+" "+tc.name, func(t *testing.T) {
				logs := logtest.CaptureSlog(t)
				ctx := reqctx.WithSettings(context.Background(), &record.Settings{AppName: "Test"})
				ctx = reqctx.WithPageClient(ctx, &reqctx.PageClient{})
				reqctx.NamePageClient(ctx, tc.client)
				if tc.forget {
					reqctx.ForgetPageClient(ctx)
				}
				req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
				brands := &defaultBrandStub{brand: night, clients: map[string]*record.Brand{"app-1": day}, clientErr: tc.clientErr}

				buf, err := New(web.TemplateFS(), web.StaticFS(), brands).RenderTemplateToBuffer(req, layout.layout, layout.page,
					map[string]interface{}{})

				require.NoError(t, err)
				head := readPageHead(t, buf.String())
				if tc.wantDataTheme == "" {
					assert.False(t, head.hasDataTheme, "got data-theme %q", head.dataTheme)
				} else {
					assert.Equal(t, tc.wantDataTheme, head.dataTheme)
				}
				assert.Equal(t, tc.wantColorScheme, head.colorScheme)
				if tc.wantBrandHref == nil {
					assert.Len(t, head.stylesheets, 1, "main.css alone")
				} else if assert.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet") {
					assert.Equal(t, tc.wantBrandHref(t), head.stylesheets[1])
				}

				var messages []string
				for _, record := range logs.Records() {
					messages = append(messages, record.Message)
				}
				if tc.wantLog == "" {
					assert.Empty(t, messages)
				} else {
					assert.Equal(t, []string{tc.wantLog}, messages)
				}
			})
		}
	}
}
