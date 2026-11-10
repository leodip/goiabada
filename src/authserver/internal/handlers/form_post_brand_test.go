package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// formPostHead is what the form_post page's head says about its look: the html element's
// data-theme, whether it carries one, the color-scheme meta, and the stylesheets in link order.
type formPostHead struct {
	dataTheme    string
	hasDataTheme bool
	colorScheme  string
	stylesheets  []string
}

func readFormPostHead(t *testing.T, page string) formPostHead {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(page))
	require.NoError(t, err)

	var head formPostHead
	head.dataTheme, head.hasDataTheme = doc.Find("html").Attr("data-theme")
	head.colorScheme, _ = doc.Find(`meta[name="color-scheme"]`).Attr("content")
	doc.Find(`link[rel="stylesheet"]`).Each(func(_ int, link *goquery.Selection) {
		href, _ := link.Attr("href")
		head.stylesheets = append(head.stylesheets, href)
	})
	return head
}

// formPostBrandDatabase is the database the route table hands the responder: the callback
// registered, which only an error response reads, and the default brand brand, or the failure err,
// which every form_post page reads once.
func formPostBrandDatabase(t *testing.T, callback string, brand *record.Brand, err error) *datamocks.Database {
	database := datamocks.NewDatabase(t)
	database.On("GetRedirectURIsByClientId", mock.Anything, mock.Anything, mock.Anything).
		Return([]record.RedirectURI{{URI: callback}}, nil).Maybe()
	database.On("GetDefaultBrand", mock.Anything, mock.Anything).Return(brand, err).Once()
	return database
}

// The form_post page is drawn in the default brand as the layouts are, an error and a code alike:
// data-theme and the color-scheme meta from its appearance, and its stylesheet linked after
// main.css. It is parsed alone, so the responder the route table builds reads the brand for it.
func TestFormPost_ThePageIsDrawnInTheDefaultBrand(t *testing.T) {
	const callback = "https://example.com/callback"
	plum, ok := brandthemes.StylesheetOf("plum")
	require.True(t, ok)
	avocado, ok := brandthemes.StylesheetOf("avocado")
	require.True(t, ok)

	for _, tc := range []struct {
		name            string
		brand           *record.Brand
		write           func(responder *ClientErrorResponder, w http.ResponseWriter, r *http.Request) error
		wantDataTheme   string
		wantColorScheme string
		wantBrandHref   string
	}{
		{
			name:  "an error, in a dark brand",
			brand: &record.Brand{Id: 7, Name: "Night", Appearance: record.BrandAppearanceDark, Theme: "plum"},
			write: func(responder *ClientErrorResponder, w http.ResponseWriter, r *http.Request) error {
				return responder.redirToClientWithError(w, r,
					testRedirectError("login_required", "Login required", "form_post", callback, "st", "code"))
			},
			wantDataTheme:   "dark",
			wantColorScheme: "dark",
			wantBrandHref:   "/brand/7/stylesheet.css?v=" + plum.Fingerprint,
		},
		{
			name:  "a code, in a light brand",
			brand: &record.Brand{Id: 12, Name: "Day", Appearance: record.BrandAppearanceLight, Theme: "avocado"},
			write: func(responder *ClientErrorResponder, w http.ResponseWriter, r *http.Request) error {
				return issueAuthCode(w, r, responder.formPost, &record.Code{Code: "c0de", State: "st", RedirectURI: callback}, "form_post")
			},
			wantDataTheme:   "light",
			wantColorScheme: "light",
			wantBrandHref:   "/brand/12/stylesheet.css?v=" + avocado.Fingerprint,
		},
		{
			name:  "an error, in an automatic brand",
			brand: &record.Brand{Id: 7, Name: "Night", Appearance: record.BrandAppearanceAuto, Theme: "plum"},
			write: func(responder *ClientErrorResponder, w http.ResponseWriter, r *http.Request) error {
				return responder.redirToClientWithError(w, r,
					testRedirectError("login_required", "Login required", "form_post", callback, "st", "code"))
			},
			wantColorScheme: "light dark",
			wantBrandHref:   "/brand/7/stylesheet.css?v=" + plum.Fingerprint,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := withSettings(httptest.NewRequest(http.MethodGet, "/auth/issue", nil),
				&record.Settings{Issuer: testResponseIssuer, UITheme: "dark"})
			responder := NewClientErrorResponder(formPostBrandDatabase(t, callback, tc.brand, nil), nil)

			require.NoError(t, tc.write(responder, w, r))

			assert.Equal(t, http.StatusOK, w.Code)
			head := readFormPostHead(t, w.Body.String())
			if tc.wantDataTheme == "" {
				assert.False(t, head.hasDataTheme, "an automatic page carries no data-theme, got %q", head.dataTheme)
			} else {
				assert.Equal(t, tc.wantDataTheme, head.dataTheme)
			}
			assert.Equal(t, tc.wantColorScheme, head.colorScheme)
			require.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet")
			assert.Regexp(t, `^/static/main\.css\?v=[0-9a-f]{12}$`, head.stylesheets[0])
			assert.Equal(t, tc.wantBrandHref, head.stylesheets[1])
		})
	}
}

// A form_post page whose brand cannot be read still carries the response: automatic, in main.css's
// colors, with no brand stylesheet, and the client gets its parameters.
func TestFormPost_APageWithNoReadableBrandStillCarriesTheResponse(t *testing.T) {
	const callback = "https://example.com/callback"

	for _, tc := range []struct {
		name  string
		brand *record.Brand
		err   error
	}{
		{name: "no default brand"},
		{name: "a failed read", err: errs.New("the database went away")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := withSettings(httptest.NewRequest(http.MethodGet, "/auth/authorize", nil),
				&record.Settings{Issuer: testResponseIssuer, UITheme: "dark"})
			responder := NewClientErrorResponder(formPostBrandDatabase(t, callback, tc.brand, tc.err), nil)

			require.NoError(t, responder.redirToClientWithError(w, r,
				testRedirectError("login_required", "Login required", "form_post", callback, "st", "code")))

			assert.Equal(t, http.StatusOK, w.Code)
			head := readFormPostHead(t, w.Body.String())
			assert.False(t, head.hasDataTheme, "got data-theme %q", head.dataTheme)
			assert.Equal(t, "light dark", head.colorScheme)
			require.Len(t, head.stylesheets, 1, "main.css alone")
			assert.Regexp(t, `^/static/main\.css\?v=[0-9a-f]{12}$`, head.stylesheets[0])
			assert.Equal(t, [][2]string{{"error", "login_required"}, {"error_description", "Login required"}, {"state", "st"},
				{"iss", testResponseIssuer}}, formPostFields(w.Body.String()))
		})
	}
}
