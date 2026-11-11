package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A brand asset is answered as a brand's stylesheet is, to anyone and with no session, on the branch
// without the settings read and the session load (#813 decision 11): its answer is public and kept
// for a year, so a session cookie set on it would be stored and replayed by a shared cache. The
// browser carries the cookie of a browser session whose user session has ended, the one case the
// session middleware reissues the cookie on a read. datamocks.NewDatabase(t) fails the test on any
// call nobody expected, so the asset read is the only one the route may make.
//
// A font's grant names the origin of the configured admin console base URL, as a browser sends it
// in Origin: scheme, host and port, without the path (decision 8).
func TestRegisterRoutes_ABrandAssetCarriesNoBrowserSessionAndGrantsAFontToTheConsole(t *testing.T) {
	font := record.BrandAsset{Id: 31, Kind: record.BrandAssetKindFont, ContentType: "font/woff2",
		Fingerprint: "00112233aabb", Content: []byte("wOF2-bytes")}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("PoolStats").Return(testPoolStats).Maybe()
			database.On("GetBrandAssetById", mock.Anything, mock.Anything, int64(31)).Return(&font, nil).Once()
			cfg := &config.Config{}
			cfg.AuthServer.ProfilePictureMaxSizeBytes = testProfilePictureMaxSizeBytes
			cfg.AdminConsole.BaseURL = "https://Console.Example.com:8443/admin/"
			s := NewServer(routing.New(), database, newTestSessionStore(), nil, nil, cfg, testTokenProofs(t))
			s.registerRoutes()

			seed := httptest.NewRequest(http.MethodGet, "/", nil)
			session, err := s.sessionStore.Get(seed, sessionkeys.AuthServerSessionName)
			require.NoError(t, err)
			session.Values[sessionkeys.SessionIdentifier] = "ended-session"
			seeded := httptest.NewRecorder()
			require.NoError(t, s.sessionStore.Save(seed, seeded, session))
			cookies := seeded.Result().Cookies()
			require.Len(t, cookies, 1)

			request := httptest.NewRequest(method, "/brand-assets/31?v=00112233aabb", nil)
			request.AddCookie(cookies[0])
			rr := httptest.NewRecorder()
			s.router.ServeHTTP(rr, request)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, "public, max-age=31536000, immutable", rr.Header().Get("Cache-Control"))
			assert.Equal(t, "font/woff2", rr.Header().Get("Content-Type"))
			assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, "https://console.example.com:8443", rr.Header().Get("Access-Control-Allow-Origin"))
			assert.Empty(t, rr.Header().Values("Set-Cookie"), "a publicly cacheable asset sets no cookie")
		})
	}
}
