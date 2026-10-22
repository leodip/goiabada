package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/publicsettings"
	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

// #620 through the real route table, the real middleware chain and the real store: an anonymous
// request costs the auth server no browser-session row on any path it can reach. The sign-in it
// starts carries its handshake in a sealed cookie, and a cookieless session-ended visit has
// nothing to end. The middleware and handler tests show each arm alone; this is what holds the
// wiring, which a route mounting the wrong store or a handler that saves would break.

// rowCountingBackend counts the rows the store inserts and the reads that reach it.
type rowCountingBackend struct {
	*sessiontest.MemoryBackend
	creates atomic.Int64
}

func (b *rowCountingBackend) Create(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	b.creates.Add(1)
	return b.MemoryBackend.Create(ctx, id, data, authenticated)
}

func TestInitRoutes_AnAnonymousRequestWritesNoBrowserSessionRow(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/public/settings" {
			_, _ = w.Write([]byte(`{"appName":"Goiabada Test","issuer":"https://issuer.example"}`))
			return
		}
		t.Errorf("an anonymous request asked the auth server for %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(authServer.Close)

	backend := &rowCountingBackend{MemoryBackend: sessiontest.NewMemoryBackend()}
	store := newTestSessionStoreOver(backend)
	cfg := &config.Config{
		AdminConsole: config.AdminConsoleConfig{BaseURL: "https://console.example.test"},
		AuthServer:   config.AuthServerConfig{BaseURL: authServer.URL},
	}
	registry := metrics.NewRegistry()
	upstream := upstreammetrics.Register(registry)
	cache := publicsettings.NewCache(publicsettings.NewClient(authServer.URL, nil, upstream), publicsettings.DefaultTTL, registry)
	s := NewServer(chi.NewRouter(), store, cache, nil, cfg, oauthclient.NewAuthServerHTTPClient(nil), nil, nil, registry, upstream)
	s.registerRoutes()

	staleSession := &http.Cookie{Name: store.CookieName(builtin.AdminConsoleSessionName), Value: "garbage"}
	testCases := []struct {
		name          string
		path          string
		cookies       []*http.Cookie
		wantLocation  string
		wantHandshake bool
	}{
		{"an /admin page", "/admin/clients", nil, authServer.URL + "/auth/authorize?", true},
		{"an /admin path no route answers", "/admin/no-such-page", nil, authServer.URL + "/auth/authorize?", true},
		{"an /account page", "/account/profile", nil, authServer.URL + "/auth/authorize?", true},
		{"an /admin page with a session cookie that names nothing", "/admin/clients",
			[]*http.Cookie{staleSession}, authServer.URL + "/auth/authorize?", true},
		{"a cookieless session-ended", "/auth/session-ended", nil, "/", false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveWithCookies(s, http.MethodGet, tc.path, tc.cookies, map[string]string{"Sec-Fetch-Site": "same-origin"})

			require.Equal(t, http.StatusFound, rec.Code)
			assert.Contains(t, rec.Header().Get("Location"), tc.wantLocation)
			var names []string
			for _, c := range rec.Result().Cookies() {
				if c.MaxAge >= 0 {
					names = append(names, c.Name)
				}
			}
			if tc.wantHandshake {
				assert.Equal(t, []string{store.CookieName(oauthclient.SignInHandshakeCookie)}, names,
					"the handshake's cookie, and no session cookie")
			} else {
				assert.Empty(t, names, "no cookie")
			}
		})
	}
	assert.Zero(t, backend.creates.Load(), "no anonymous request writes a browser-session row (#620)")
}
