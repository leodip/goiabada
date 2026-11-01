package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/publicsettings"
	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/routing"
)

// The admin console's HTTP listener (#715), the auth server's cases for this binary. With an https
// base URL and the proxy headers untrusted, nothing says a proxy ends TLS in front of the listener,
// so it only redirects: a 301 to the base URL's scheme, host and port with the request's own path
// and query, for every method, with the baseline security headers and never
// Strict-Transport-Security (RFC 6797 section 7.2) or a cookie; GET and HEAD /health are still
// answered. Every other configuration serves the router, as before. What is under test is the
// handler Start gives the listener, built by the constructor every listener is built by and served
// on a loopback port, and the records the start writes about the listeners, captured.

// The start's records about the HTTP listener, as an operator reads them.
const (
	plainHTTPWarning = "the admin console is listening on HTTP with no TLS, which is insecure outside development unless a reverse proxy in front of it terminates HTTPS"
	behindAProxyInfo = "the admin console is listening on HTTP behind a reverse proxy that terminates HTTPS"
	redirectsOnly    = "the admin console's HTTP listener only redirects to its https base URL, and its HTTPS listener is off"
	httpBaseURLWarn  = "the admin console's HTTPS listener serves a deployment whose base URL is http, so its cookies aren't Secure and it sends no HSTS"
)

// newHTTPListenerTestServer is the server main builds for a configuration, over an auth server
// that answers the public settings and nothing else, with its routes registered as Start registers
// them, before Start builds its listeners.
func newHTTPListenerTestServer(t *testing.T, configure func(*config.AdminConsoleConfig)) *Server {
	t.Helper()

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/public/settings" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"appName":"Goiabada Test","issuer":"https://auth.example.test","uiTheme":"light","smtpEnabled":false}`))
	}))
	t.Cleanup(authServer.Close)

	cfg := &config.Config{
		AdminConsole: config.AdminConsoleConfig{
			LogHttpRequests: true,
			ListenHostHttp:  "127.0.0.1",
			ListenPortHttp:  9091,
		},
		AuthServer: config.AuthServerConfig{BaseURL: authServer.URL},
	}
	configure(&cfg.AdminConsole)
	registry := metrics.NewRegistry()
	upstream := upstreammetrics.Register(registry)
	cache := publicsettings.NewCache(publicsettings.NewClient(authServer.URL, nil, upstream), publicsettings.DefaultTTL, registry)

	s := NewServer(routing.New(), newTestSessionStore(), cache, nil, cfg, nil, nil, nil, registry, upstream)
	s.registerRoutes()
	return s
}

// redirectingServer is an https deployment reached directly: its HTTP listener only redirects.
func redirectingServer(t *testing.T) *Server {
	t.Helper()
	return newHTTPListenerTestServer(t, func(c *config.AdminConsoleConfig) {
		c.BaseURL = "https://console.example.com:8443"
	})
}

// serveHTTPListener serves the handler Start gives s's HTTP listener on a loopback port, and
// answers its address.
func serveHTTPListener(t *testing.T, s *Server) string {
	t.Helper()
	served := servedOnLoopback(t, s.httpListenerHandler())
	go func() { _ = served.serve() }()
	return served.server.Addr
}

// sendToHTTPListener writes request to addr as it stands, on a connection of its own, so the
// request target and the Host field are exactly what a client chose, and reads the response and its
// whole body.
func sendToHTTPListener(t *testing.T, addr, method, request string) (*http.Response, string) {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = io.WriteString(conn, request)
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, string(body)
}

// assertBaselineHeadersWithoutHSTS checks the four headers every answer of either server carries,
// and that neither Strict-Transport-Security, which RFC 6797 section 7.2 forbids over plain HTTP,
// nor a cookie is among them.
func assertBaselineHeadersWithoutHSTS(t *testing.T, header http.Header) {
	t.Helper()
	assert.Equal(t, []string{"DENY"}, header.Values("X-Frame-Options"))
	assert.Equal(t, []string{"script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"},
		header.Values("Content-Security-Policy"))
	assert.Equal(t, []string{"nosniff"}, header.Values("X-Content-Type-Options"))
	assert.Equal(t, []string{"same-origin"}, header.Values("Referrer-Policy"))
	assert.Empty(t, header.Values("Strict-Transport-Security"))
	assert.Empty(t, header.Values("Set-Cookie"))
}

// Every request but GET and HEAD /health is redirected to the base URL's origin with its own path
// and query, never to the host the client named in Host or in the request target: either would make
// the listener an open redirect (#715 decision 3). The base URL's port is kept.
func TestHTTPListener_RedirectsEveryRequestToTheBaseURL(t *testing.T) {
	addr := serveHTTPListener(t, redirectingServer(t))

	for _, tt := range []struct {
		name     string
		method   string
		request  string
		location string
	}{
		{
			name:     "a Host naming another host",
			method:   http.MethodGet,
			request:  "GET /admin/users?page=2&query=a%20b HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
			location: "https://console.example.com:8443/admin/users?page=2&query=a%20b",
		},
		{
			name:     "an absolute-form target naming another host",
			method:   http.MethodGet,
			request:  "GET http://evil.example/admin/clients?tab=web HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
			location: "https://console.example.com:8443/admin/clients?tab=web",
		},
		{
			name:     "a path beginning with two slashes",
			method:   http.MethodGet,
			request:  "GET //evil.example/x HTTP/1.1\r\nHost: console.example.com\r\nConnection: close\r\n\r\n",
			location: "https://console.example.com:8443//evil.example/x",
		},
		{
			name:     "the root",
			method:   http.MethodGet,
			request:  "GET / HTTP/1.1\r\nHost: console.example.com\r\nConnection: close\r\n\r\n",
			location: "https://console.example.com:8443/",
		},
		{
			name:     "a POST with a body",
			method:   http.MethodPost,
			request:  "POST /auth/callback HTTP/1.1\r\nHost: console.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 12\r\nConnection: close\r\n\r\ncode=abc&s=1",
			location: "https://console.example.com:8443/auth/callback",
		},
		{
			name:     "a POST to /health",
			method:   http.MethodPost,
			request:  "POST /health HTTP/1.1\r\nHost: console.example.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			location: "https://console.example.com:8443/health",
		},
		{
			name:     "a HEAD",
			method:   http.MethodHead,
			request:  "HEAD /static/main.css HTTP/1.1\r\nHost: console.example.com\r\nConnection: close\r\n\r\n",
			location: "https://console.example.com:8443/static/main.css",
		},
		{
			name:   "an OPTIONS request",
			method: http.MethodOptions,
			request: "OPTIONS /admin/clients HTTP/1.1\r\nHost: console.example.com\r\nOrigin: https://other.example\r\n" +
				"Access-Control-Request-Method: POST\r\nConnection: close\r\n\r\n",
			location: "https://console.example.com:8443/admin/clients",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := sendToHTTPListener(t, addr, tt.method, tt.request)

			assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
			assert.Equal(t, []string{tt.location}, resp.Header.Values("Location"))
			assertBaselineHeadersWithoutHSTS(t, resp.Header)
			assert.Empty(t, resp.Header.Values("Access-Control-Allow-Origin"))
			if tt.method == http.MethodGet {
				// net/http's short hypertext note (RFC 9110 section 15.4.2).
				assert.Equal(t, "text/html; charset=utf-8", resp.Header.Get("Content-Type"))
				assert.Contains(t, body, "Moved Permanently")
			} else {
				assert.Empty(t, body)
			}
		})
	}
}

// The base URL's path is not the redirect's: its target is the base URL's origin, then the
// request's path and query, whatever the base URL ends in.
func TestHTTPListener_RedirectsToTheBaseURLsOriginAlone(t *testing.T) {
	for _, baseURL := range []string{"https://console.example.com/", "https://console.example.com/goiabada", "HTTPS://console.example.com"} {
		t.Run(baseURL, func(t *testing.T) {
			s := newHTTPListenerTestServer(t, func(c *config.AdminConsoleConfig) { c.BaseURL = baseURL })
			addr := serveHTTPListener(t, s)

			resp, _ := sendToHTTPListener(t, addr, http.MethodGet, "GET /admin/settings/general?x=1 HTTP/1.1\r\nHost: console.example.com\r\nConnection: close\r\n\r\n")

			assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
			assert.Equal(t, "https://console.example.com/admin/settings/general?x=1", resp.Header.Get("Location"))
		})
	}
}

// GET and HEAD /health are answered on the redirecting listener, so a health check pointed at it
// keeps working, with the baseline headers and without HSTS (#715 decisions 3 and 9).
func TestHTTPListener_AnswersTheHealthCheck(t *testing.T) {
	addr := serveHTTPListener(t, redirectingServer(t))

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			resp, body := sendToHTTPListener(t, addr, method, method+" /health HTTP/1.1\r\nHost: console.example.com\r\nConnection: close\r\n\r\n")

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Empty(t, resp.Header.Values("Location"))
			assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
			assertBaselineHeadersWithoutHSTS(t, resp.Header)
			if method == http.MethodGet {
				assert.Equal(t, "healthy", body)
			} else {
				assert.Empty(t, body)
			}
		})
	}
}

// The redirecting listener logs each redirect under the request id it arrived with, and counts its
// redirects under the route value https_redirect and its health checks under /health, as the
// router counts them (#715 decision 10).
func TestHTTPListener_LogsAndCountsItsAnswers(t *testing.T) {
	s := redirectingServer(t)
	addr := serveHTTPListener(t, s)
	logged := logtest.CaptureSlog(t)

	sendToHTTPListener(t, addr, http.MethodGet, "GET /admin/clients HTTP/1.1\r\nHost: console.example.com\r\nX-Request-Id: the-proxys-id 9\r\nConnection: close\r\n\r\n")
	sendToHTTPListener(t, addr, http.MethodPost, "POST /auth/callback HTTP/1.1\r\nHost: console.example.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	sendToHTTPListener(t, addr, http.MethodGet, "GET /no-such-path HTTP/1.1\r\nHost: console.example.com\r\nConnection: close\r\n\r\n")
	sendToHTTPListener(t, addr, http.MethodGet, "GET /health HTTP/1.1\r\nHost: console.example.com\r\nConnection: close\r\n\r\n")

	// The health check is not logged, as on the router.
	records := httpRequestRecords(logged)
	require.Len(t, records, 3)
	assert.Equal(t, "the-proxys-id 9", records[0].Attrs["request_id"])
	assert.Equal(t, "/admin/clients", records[0].Attrs["target"])
	assert.EqualValues(t, http.StatusMovedPermanently, records[0].Attrs["status"])
	assert.Equal(t, "POST", records[1].Attrs["method"])
	assert.EqualValues(t, http.StatusMovedPermanently, records[1].Attrs["status"])

	exposition := scrape(t, s)
	for _, line := range []string{
		`goiabada_http_requests_total{route="https_redirect",method="GET",status="301"} 2`,
		`goiabada_http_requests_total{route="https_redirect",method="POST",status="301"} 1`,
		`goiabada_http_requests_total{route="/health",method="GET",status="200"} 1`,
		`goiabada_http_request_duration_seconds_count{route="https_redirect",method="GET"} 2`,
		`goiabada_http_request_duration_seconds_count{route="/health",method="GET"} 1`,
	} {
		assert.Contains(t, exposition, line+"\n")
	}
	assert.NotContains(t, exposition, `goiabada_http_requests_total{route="unmatched"`)
}

// The redirecting listener runs the root middleware that applies to it, in the router's order: the
// request id, the security headers, the real IP, the request log, the metrics and the panic
// recovery; not the slash strip, the body limit, the CSRF check, the settings or the session (#715).
func TestHTTPListener_TheRedirectingChainInOrder(t *testing.T) {
	handler := redirectingServer(t).httpListenerHandler()
	redirecting, ok := handler.(*routing.Router)
	require.True(t, ok, "the redirecting listener's handler is a router of its own")

	want := []string{
		"github.com/leodip/goiabada/core/requestid.Middleware",
		"github.com/leodip/goiabada/core/httpmw.SecurityHeaders.func1",
		"github.com/leodip/goiabada/core/httpmw.RealIP.func1",
		"github.com/leodip/goiabada/core/httpmw.RequestLogger.func1",
		"github.com/leodip/goiabada/core/metrics.httpRequests.func2",
		"github.com/leodip/goiabada/core/httpmw.Recoverer",
	}
	walked := 0
	err := redirecting.Walk(func(method string, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		walked++
		var chain []string
		for _, mounted := range middlewares {
			chain = append(chain, runtime.FuncForPC(reflect.ValueOf(mounted).Pointer()).Name())
		}
		assert.Equal(t, want, chain, "%s %s", method, route)
		return nil
	})
	require.NoError(t, err)
	assert.NotZero(t, walked)
}

// Which handler the HTTP listener gets, and which records the start writes about the listeners, for
// every combination of the base URL's scheme, the proxy headers' trust and the HTTPS listener. The
// listener only redirects with an https base URL and trust off; with trust on it serves the router,
// whose answers carry HSTS over an https base URL as before (#715 decisions 2, 4, 5 and 11).
func TestStart_TheHTTPListenerAndItsRecords(t *testing.T) {
	// A record is its level and message, as a reader scanning the start sees them.
	type record = string
	warn := func(message string) record { return "WARN " + message }
	info := func(message string) record { return "INFO " + message }
	for _, tt := range []struct {
		baseURL      string
		trusted      bool
		httpsEnabled bool
		httpEnabled  bool
		mode         string
		records      []record
	}{
		{"http://console.example.com", false, false, true, "serves", []record{warn(plainHTTPWarning)}},
		{"http://console.example.com", true, false, true, "serves", []record{warn(plainHTTPWarning)}},
		{"http://console.example.com", false, true, true, "serves", []record{warn(httpBaseURLWarn)}},
		{"http://console.example.com", true, true, true, "serves", []record{warn(httpBaseURLWarn)}},
		{"https://console.example.com", false, false, true, "redirects", []record{warn(redirectsOnly)}},
		{"https://console.example.com", true, false, true, "serves", []record{info(behindAProxyInfo)}},
		{"https://console.example.com", false, true, true, "redirects", nil},
		{"https://console.example.com", true, true, true, "serves", nil},
		{"http://console.example.com", false, true, false, "", []record{warn(httpBaseURLWarn)}},
		{"https://console.example.com", false, true, false, "", nil},
	} {
		name := fmt.Sprintf("%s trusted %v https %v http %v", tt.baseURL, tt.trusted, tt.httpsEnabled, tt.httpEnabled)
		t.Run(name, func(t *testing.T) {
			s := newHTTPListenerTestServer(t, func(c *config.AdminConsoleConfig) {
				c.BaseURL = tt.baseURL
				c.TrustProxyHeaders = tt.trusted
				if tt.httpsEnabled {
					c.ListenHostHttps, c.ListenPortHttps = "127.0.0.1", 9444
					c.CertFile, c.KeyFile = "/certs/cert.pem", "/certs/key.pem"
				}
				if !tt.httpEnabled {
					c.ListenHostHttp = ""
				}
			})
			logs := logtest.CaptureSlog(t)

			httpsEnabled, httpEnabled := s.logListenerConfiguration(context.Background())

			assert.Equal(t, tt.httpsEnabled, httpsEnabled)
			assert.Equal(t, tt.httpEnabled, httpEnabled)
			records := logs.Records()
			require.GreaterOrEqual(t, len(records), 2)
			assert.Equal(t, "https listener configuration", records[0].Message)
			assert.Equal(t, "http listener configuration", records[1].Message)
			if tt.mode == "" {
				assert.NotContains(t, records[1].Attrs, "mode", "a listener that is off has no mode")
			} else {
				assert.Equal(t, tt.mode, records[1].Attrs["mode"])
			}
			var rest []record
			for _, captured := range records[2:] {
				rest = append(rest, captured.Level.String()+" "+captured.Message)
			}
			assert.Equal(t, tt.records, rest, "one record per condition, and none for a deployment as intended")

			if !tt.httpEnabled {
				return
			}
			addr := serveHTTPListener(t, s)
			page, _ := sendToHTTPListener(t, addr, http.MethodGet, "GET /no-such-path HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
			health, _ := sendToHTTPListener(t, addr, http.MethodGet, "GET /health HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
			require.Equal(t, http.StatusOK, health.StatusCode)
			if tt.mode == "redirects" {
				assert.Equal(t, http.StatusMovedPermanently, page.StatusCode)
				assert.Equal(t, "https://console.example.com/no-such-path", page.Header.Get("Location"))
				assert.Empty(t, health.Header.Values("Strict-Transport-Security"))
				return
			}
			assert.Equal(t, http.StatusNotFound, page.StatusCode, "the router's 404")
			if tt.baseURL == "https://console.example.com" {
				assert.Equal(t, []string{"max-age=31536000; includeSubDomains"}, health.Header.Values("Strict-Transport-Security"),
					"behind a proxy that ends TLS, the browser's side is HTTPS (RFC 6797 section 7.1)")
			} else {
				assert.Empty(t, health.Header.Values("Strict-Transport-Security"))
			}
		})
	}
}

// The redirect-only Warn names both ways out of a redirect loop, each in this server's own terms:
// a copy naming the auth server's variable would send an operator to the wrong service.
func TestLogPlainHTTP_TheRedirectOnlyWarnNamesBothFixes(t *testing.T) {
	logs := logtest.CaptureSlog(t)

	logPlainHTTP("https://console.example.com", false)

	records := logs.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelWarn, records[0].Level)
	assert.Equal(t, redirectsOnly, records[0].Message)
	assert.Equal(t, "configure the HTTPS listener, or, behind a reverse proxy that terminates HTTPS, turn on GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS",
		records[0].Attrs["remedy"])
}
