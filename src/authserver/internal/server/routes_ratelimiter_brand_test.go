package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/authserver/web"
)

// The rate limiter's refusal of a sign-in step, and of a page the sign-in links to while the
// browser still holds that sign-in, is drawn in the brand of the sign-in's client; the same
// refusal of a page that names no sign-in is drawn in the default brand. Each case spends the
// route's published budget through the real route table, its middleware and the real page
// renderer, beneath the page middleware that gives every page request its client (#812).
func TestInitRoutes_ALimiterRefusalIsDrawnInTheBrandOfTheSignInsClient(t *testing.T) {
	night := &record.Brand{Id: 7, Name: "Night", Appearance: record.BrandAppearanceDark, Theme: "plum"}
	day := &record.Brand{Id: 12, Name: "Day", Appearance: record.BrandAppearanceLight, Theme: "avocado"}

	for _, tc := range []struct {
		name          string
		budget        int
		window        int
		request       func(s *Server) func(attempt int) *http.Request
		wantDataTheme string
		wantBrandHref string
	}{
		{
			name:   "POST /auth/pwd, a step of the sign-in",
			budget: pwdIpBudget, window: pwdIpWindow,
			request:       func(s *Server) func(int) *http.Request { return pwdGuess(t, s) },
			wantDataTheme: "light",
			wantBrandHref: routesTestBrandHref(t, 12, "avocado"),
		},
		{
			name:   "POST /forgot-password naming the sign-in the browser holds",
			budget: forgotPwdIpBudget, window: forgotPwdWindow,
			request: func(s *Server) func(int) *http.Request {
				ceremonyId, cookie := linkedSignInCookie(t, s)
				return func(attempt int) *http.Request {
					r := browserForm(http.MethodPost, "/forgot-password?"+ceremony.QueryParameter+"="+ceremonyId,
						"email=user"+strconv.Itoa(attempt)+"@example.com")
					r.AddCookie(cookie)
					return r
				}
			},
			wantDataTheme: "light",
			wantBrandHref: routesTestBrandHref(t, 12, "avocado"),
		},
		{
			name:   "POST /forgot-password naming no sign-in",
			budget: forgotPwdIpBudget, window: forgotPwdWindow,
			request: func(*Server) func(int) *http.Request {
				return func(attempt int) *http.Request {
					return browserForm(http.MethodPost, "/forgot-password", "email=user"+strconv.Itoa(attempt)+"@example.com")
				}
			},
			wantDataTheme: "dark",
			wantBrandHref: routesTestBrandHref(t, 7, "plum"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newRoutesTestServerDrawnIn(t, nil, newTestSessionStore(), nil, web.TemplateFS(), night)
			database, ok := server.database.(*datamocks.Database)
			require.True(t, ok)
			database.On("GetClientPageBrand", mock.Anything, mock.Anything, routesTestClientId).Return(day, nil).Maybe()
			pages := middleware.PageClient()(server.router)
			request := tc.request(server)

			for i := 0; i < tc.budget; i++ {
				rr := httptest.NewRecorder()
				pages.ServeHTTP(rr, request(i))
				require.NotEqual(t, http.StatusTooManyRequests, rr.Code, "request %d must reach the handler", i+1)
			}
			rr := httptest.NewRecorder()
			pages.ServeHTTP(rr, request(tc.budget))

			assertRefused(t, rr, tc.window, shapeBrowser)
			doc, err := goquery.NewDocumentFromReader(strings.NewReader(rr.Body.String()))
			require.NoError(t, err)
			dataTheme, _ := doc.Find("html").Attr("data-theme")
			colorScheme, _ := doc.Find(`meta[name="color-scheme"]`).Attr("content")
			var stylesheets []string
			doc.Find(`link[rel="stylesheet"]`).Each(func(_ int, link *goquery.Selection) {
				href, _ := link.Attr("href")
				stylesheets = append(stylesheets, href)
			})
			assert.Equal(t, tc.wantDataTheme, dataTheme, "data-theme")
			assert.Equal(t, tc.wantDataTheme, colorScheme, "color-scheme")
			if assert.Len(t, stylesheets, 2, "main.css, then the brand's stylesheet") {
				assert.Equal(t, tc.wantBrandHref, stylesheets[1])
			}
		})
	}
}

// routesTestBrandHref is the link a page draws brand id on theme with: the brand's own stylesheet
// route, named by the fingerprint the built-in theme's stylesheet is served under.
func routesTestBrandHref(t *testing.T, id int64, theme string) string {
	t.Helper()
	stylesheet, ok := brandthemes.StylesheetOf(theme)
	require.True(t, ok, theme)
	return "/brand/" + strconv.FormatInt(id, 10) + "/stylesheet.css?v=" + stylesheet.Fingerprint
}

// linkedSignInCookie mints the session cookie of a browser holding a sign-in to routesTestClientId at
// its password step, under a well-formed ceremony id, which a page the sign-in links to names in its
// URL; routesTestCeremonyId is not one. It answers the id and the cookie.
func linkedSignInCookie(t *testing.T, s *Server) (string, *http.Cookie) {
	t.Helper()
	ceremonyId := ceremony.NewId()
	r := httptest.NewRequest(http.MethodGet, "/auth/pwd", nil)
	recorder := httptest.NewRecorder()
	require.NoError(t, ceremony.NewStore(s.sessionStore, sessionkeys.AuthServerSessionName).AddAuthContext(recorder, r,
		&ceremony.AuthContext{
			AuthState:  ceremony.AuthStateLevel1Password,
			CeremonyId: ceremonyId,
			ClientId:   routesTestClientId,
		}))
	cookies := recorder.Result().Cookies()
	require.Len(t, cookies, 1)
	return ceremonyId, cookies[0]
}
