package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A brand's stylesheet is served as a static file is, to anyone and with no session (#810): its
// answer is public and kept for a year, so a session cookie set on it would be stored and replayed
// by a shared cache to other visitors. The browser here carries the cookie of a browser session
// whose user session has ended, the one case the session middleware reissues the cookie on a read,
// to clear the dangling pointer. The stylesheet must be answered without any cookie, and without
// reading the settings or the session: datamocks.NewDatabase(t) fails the test on any call nobody
// expected, so the brand read is the only one the route may make.
func TestRegisterRoutes_TheBrandStylesheetCarriesNoBrowserSession(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetBrandById", mock.Anything, mock.Anything, int64(7)).
				Return(&record.Brand{Id: 7, Name: "Shop", Appearance: "auto", Theme: "plum"}, nil).Once()
			s := newRoutingTestServer(t, database)

			seed := httptest.NewRequest(http.MethodGet, "/", nil)
			session, err := s.sessionStore.Get(seed, sessionkeys.AuthServerSessionName)
			require.NoError(t, err)
			session.Values[sessionkeys.SessionIdentifier] = "ended-session"
			seeded := httptest.NewRecorder()
			require.NoError(t, s.sessionStore.Save(seed, seeded, session))
			cookies := seeded.Result().Cookies()
			require.Len(t, cookies, 1)

			target, err := brandthemes.StylesheetPath(7, "plum")
			require.NoError(t, err)
			request := httptest.NewRequest(method, target, nil)
			request.AddCookie(cookies[0])
			rr := httptest.NewRecorder()
			s.router.ServeHTTP(rr, request)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, "public, max-age=31536000, immutable", rr.Header().Get("Cache-Control"))
			assert.Equal(t, "text/css; charset=utf-8", rr.Header().Get("Content-Type"))
			assert.Empty(t, rr.Header().Values("Set-Cookie"), "a publicly cacheable stylesheet sets no cookie")
		})
	}
}
