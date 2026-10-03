package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/core/httpmw"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The security-bearing settings the chain reads from the configuration main loaded, each driven
// through the real initMiddleware or initRoutes with a value that is not the zero one, so a chain
// that read the setting from anywhere else, or not at all, fails a row (#434). The upload rows'
// body bound, the fourth such setting, is TestBodyLimitPolicy_EachRowAtItsBoundary's, over
// testProfilePictureMaxSizeBytes.

// newConfigValuesTestServer runs the real initMiddleware over cfg and registers a probe on the
// root, beneath the whole root chain, that answers 200 and records the client address the chain
// resolved. The probe sits on the root rather than the application branch, so no settings read
// or session load is involved: the root chain is where these settings are read.
func newConfigValuesTestServer(t *testing.T, cfg *config.Config, remoteAddr *string) *Server {
	t.Helper()

	trusted, err := httpmw.ParseTrustedProxies([]string{"203.0.113.0/24"})
	require.NoError(t, err)

	s := newStaticBranchTestServer(mocks_data.NewDatabase(t))
	s.cfg = cfg
	s.trustedProxies = trusted
	s.initMiddleware()
	s.router.Get("/probe", func(w http.ResponseWriter, r *http.Request) {
		*remoteAddr = r.RemoteAddr
		w.WriteHeader(http.StatusOK)
	})
	return s
}

// TestInitMiddleware_TrustProxyHeadersFollowsTheConfiguration: the peer is inside the trusted
// ranges in both rows, so the switch alone decides whether its X-Forwarded-For is believed.
func TestInitMiddleware_TrustProxyHeadersFollowsTheConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		trust bool
		want  string
	}{
		{"off, the socket peer", false, "203.0.113.9"},
		{"on, the forwarded client", true, "198.51.100.7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.AuthServer.TrustProxyHeaders = tt.trust
			var remoteAddr string
			s := newConfigValuesTestServer(t, cfg, &remoteAddr)

			req := httptest.NewRequest(http.MethodGet, "/probe", nil)
			req.RemoteAddr = "203.0.113.9:4711"
			req.Header.Set("X-Forwarded-For", "198.51.100.7")
			rr := httptest.NewRecorder()
			s.router.ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, tt.want, remoteAddr)
		})
	}
}

// TestInitMiddleware_StrictTransportSecurityFollowsTheBaseURL: the header is sent when the
// configured base URL is https, and only then, since a browser pinning HTTPS on a plain-http
// development deployment would lock itself out of it.
func TestInitMiddleware_StrictTransportSecurityFollowsTheBaseURL(t *testing.T) {
	tests := []struct {
		baseURL  string
		wantHSTS bool
	}{
		{"https://auth.test", true},
		{"http://auth.test", false},
	}
	for _, tt := range tests {
		t.Run(tt.baseURL, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.AuthServer.BaseURL = tt.baseURL
			var remoteAddr string
			s := newConfigValuesTestServer(t, cfg, &remoteAddr)

			rr := httptest.NewRecorder()
			s.router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/probe", nil))

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, tt.wantHSTS, rr.Header().Get("Strict-Transport-Security") != "",
				"Strict-Transport-Security = %q", rr.Header().Get("Strict-Transport-Security"))
		})
	}
}

// TestInitRoutes_DebugAPIRequestsFollowsTheConfiguration: each API group writes one api exchange
// record per request when the setting is on and none when it is off. The requests carry no token,
// so each group's guard refuses it; the debug middleware is mounted ahead of the guards, so the
// refusal is what it records.
func TestInitRoutes_DebugAPIRequestsFollowsTheConfiguration(t *testing.T) {
	targets := []string{"/api/v1/account/profile", "/api/v1/admin/users"}

	for _, enabled := range []bool{false, true} {
		for _, target := range targets {
			t.Run(fmt.Sprintf("%s, enabled %v", target, enabled), func(t *testing.T) {
				logs := logtest.CaptureSlog(t)
				s := newRoutesTestServerWith(t, func(cfg *config.Config) {
					cfg.AuthServer.DebugAPIRequests = enabled
				})

				rr := httptest.NewRecorder()
				s.router.ServeHTTP(rr, withRoutesTestSettings(httptest.NewRequest(http.MethodGet, target, nil)))

				require.GreaterOrEqual(t, rr.Code, http.StatusBadRequest, "the guard must refuse a request carrying no token")
				exchanges := 0
				for _, record := range logs.Records() {
					if record.Message == "api exchange" {
						exchanges++
					}
				}
				want := 0
				if enabled {
					want = 1
				}
				assert.Equal(t, want, exchanges, "api exchange records with DebugAPIRequests=%v", enabled)
			})
		}
	}
}
