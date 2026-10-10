package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hostport"
	"github.com/leodip/goiabada/core/sessionstore"

	"log/slog"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/middleware"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/publicsettings"
	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/httpmw"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/metrics"
)

type Server struct {
	router *chi.Mux
	// The concrete store rather than sessionstore.Store: routes.go hands it to the sign-in
	// callback, whose port names Regenerate, which is what proves at compile time that the
	// store this console runs rotates the session identifier at sign-in (#431).
	sessionStore  *sessionstore.ServerSideStore
	settingsCache *publicsettings.Cache

	// Parsed by main, which refuses to start on a malformed entry (#425), so the real-IP
	// middleware takes ranges and has no error path of its own.
	trustedProxies []*net.IPNet

	staticFS   fs.FS
	templateFS fs.FS

	// The configuration main loaded, read here and in the route table, which hands each handler
	// the values it uses as it builds it (#441).
	cfg *config.Config

	// Built once by main, which hands the token client to the session token source as well, so
	// every grant the console makes goes through one client with one token URL; the JWKS fetch
	// shares the HTTP client (#441).
	authServerHTTPClient *http.Client
	tokenClient          *oauthclient.TokenClient

	// The families this console exposes on its metrics listener (#400 decision 6). main creates the
	// registry, because the clients it builds before the server, the session backend's, the token
	// client's and the settings cache's, register and record on it; NewServer adds the build stamp
	// and the runtime gauges, and initMiddleware the HTTP requests. upstream is the recorder main
	// registered, which the route table hands the admin API client and the JWKS fetch.
	metrics  *metrics.Registry
	upstream *upstreammetrics.Recorder
}

func NewServer(router *chi.Mux, sessionStore *sessionstore.ServerSideStore, settingsCache *publicsettings.Cache,
	trustedProxies []*net.IPNet, cfg *config.Config, authServerHTTPClient *http.Client,
	tokenClient *oauthclient.TokenClient, registry *metrics.Registry, upstream *upstreammetrics.Recorder) *Server {

	s := Server{
		router:        router,
		sessionStore:  sessionStore,
		settingsCache: settingsCache,

		trustedProxies: trustedProxies,

		cfg: cfg,

		authServerHTTPClient: authServerHTTPClient,
		tokenClient:          tokenClient,

		metrics:  registry,
		upstream: upstream,
	}
	metrics.RegisterBuildInfo(s.metrics)
	metrics.RegisterRuntime(s.metrics)

	if envVar := cfg.AdminConsole.StaticDir; len(envVar) == 0 {
		s.staticFS = web.StaticFS()
		slog.Info("using the embedded static files")
	} else {
		s.staticFS = os.DirFS(envVar)
		slog.Info("using static files from a directory", "directory", envVar)
	}

	if envVar := cfg.AdminConsole.TemplateDir; len(envVar) == 0 {
		s.templateFS = web.TemplateFS()
		slog.Info("using the embedded template files")
	} else {
		s.templateFS = os.DirFS(envVar)
		slog.Info("using template files from a directory", "directory", envVar)
	}

	return &s
}

// Start brings up the listeners and blocks until ctx is cancelled or a listener fails, and on both
// drains in-flight requests before returning. It returns nil after a cancellation, and otherwise
// the error, unlogged: main writes the one record for it and owns the exit. The client secret is
// main's to check, before anything is built (#426, #390).
func (s *Server) Start(ctx context.Context) error {
	httpsHost := s.cfg.AdminConsole.ListenHostHttps
	httpsPort := s.cfg.AdminConsole.ListenPortHttps
	certFile := s.cfg.AdminConsole.CertFile
	keyFile := s.cfg.AdminConsole.KeyFile
	httpsEnabled := httpsHost != "" && httpsPort > 0 && certFile != "" && keyFile != ""

	// One record per listener where five and three lines used to be. A reader
	// checking why HTTPS is off had to join "https enabled: false" to four
	// separate lines to see which of the four settings was the empty one (#320).
	slog.InfoContext(ctx, "https listener configuration",
		"enabled", httpsEnabled,
		"host", httpsHost,
		"port", httpsPort,
		"cert_file", certFile,
		"key_file", keyFile)

	httpHost := s.cfg.AdminConsole.ListenHostHttp
	httpPort := s.cfg.AdminConsole.ListenPortHttp
	httpEnabled := httpHost != "" && httpPort > 0

	slog.InfoContext(ctx, "http listener configuration",
		"enabled", httpEnabled,
		"host", httpHost,
		"port", httpPort)

	if httpEnabled && !httpsEnabled {
		logPlainHTTP(s.cfg.AdminConsole.BaseURL, s.cfg.AdminConsole.TrustProxyHeaders)
	}

	// The metrics listener is enabled by its own setting rather than by a host and port, since its
	// defaults are both set; it does not count as a listener below, because it answers no client.
	metricsEnabled := s.cfg.AdminConsole.MetricsEnabled
	metricsHost := s.cfg.AdminConsole.ListenHostMetrics
	metricsPort := s.cfg.AdminConsole.ListenPortMetrics

	slog.InfoContext(ctx, "metrics listener configuration",
		"enabled", metricsEnabled,
		"host", metricsHost,
		"port", metricsPort)

	// Refused before anything is built, so a process about to exit builds no routes first.
	if !httpsEnabled && !httpEnabled {
		return errs.New("no listener is enabled, so the admin console cannot start: configure at least one of the http and https listeners")
	}

	s.registerRoutes()

	// The servers are kept rather than left local to the goroutine serving each, which is what lets
	// a cancellation drain them. Before #426 nothing could, and SIGTERM cut off every request in
	// flight.
	var listeners []listener

	if httpsEnabled {
		httpsServer := newHTTPServer(httpsHost, httpsPort, s.router)
		listeners = append(listeners, listener{
			server: httpsServer,
			serve:  func() error { return httpsServer.ListenAndServeTLS(certFile, keyFile) },
		})
		slog.InfoContext(ctx, "starting the https listener", "host", httpsHost, "port", httpsPort)
	}

	if httpEnabled {
		httpServer := newHTTPServer(httpHost, httpPort, s.router)
		listeners = append(listeners, listener{
			server: httpServer,
			serve:  httpServer.ListenAndServe,
		})
		slog.InfoContext(ctx, "starting the http listener", "host", httpHost, "port", httpPort)
	}

	// Built by the same constructor, so it carries the same bounds, and drained with the others, so
	// a scrape in flight at shutdown is answered. A port it cannot bind stops the console as theirs
	// does (#400 decision 3).
	if metricsEnabled {
		metricsServer := newHTTPServer(metricsHost, metricsPort, metricsHandler(s.metrics))
		listeners = append(listeners, listener{
			server: metricsServer,
			serve:  metricsServer.ListenAndServe,
		})
		slog.InfoContext(ctx, "starting the metrics listener", "host", metricsHost, "port", metricsPort)
	}

	return serveAndDrain(ctx, listeners)
}

// metricsHandler is the metrics listener's whole handler, the auth server's copied rather than
// shared because each binary owns its listener: a mux of its own answering GET /metrics with reg's
// exposition and 404 for every other path. It is never Go's default mux, on which the
// net/http/pprof and expvar packages chi's middleware links register /debug/pprof/ and /debug/vars
// (#462), and nothing on it passes through the main router's chain, so a scrape is neither logged
// by the request logger nor counted in the HTTP metrics (#400 decision 3).
func metricsHandler(reg *metrics.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", reg.Handler())
	return mux
}

// listener is one of Start's servers and the call that serves it, which is ListenAndServe or
// ListenAndServeTLS in Start and Serve on an ephemeral listener in a test.
type listener struct {
	server *http.Server
	serve  func() error
}

// getAndHead registers handler for GET and for HEAD on pattern. RFC 9110 section 9.1 has a
// general-purpose server support both, and section 9.3.2 has a HEAD answered as the GET would be,
// with the same header fields and no content, which is what net/http does by itself: its
// ResponseWriter discards what a handler writes for a HEAD request, and http.FileServer and
// http.Redirect answer HEAD on their own. It is for the read-only resources a cache, a monitor or a
// link checker may probe, and only those; every page stays GET-only, so a HEAD there is 405 with
// Allow naming GET. The auth server registers its own the same way.
func getAndHead(r chi.Router, pattern string, handler http.HandlerFunc) {
	r.Get(pattern, handler)
	r.Head(pattern, handler)
}

// registerRoutes mounts everything this server answers on s.router: the root chain, the static
// branch and the application branch, in that order. Both branches are registered on s.router;
// only the second carries the middleware initMiddleware returns, which is what keeps a stylesheet
// from costing a session load, and here that load is an HTTP call to the auth server (see
// initMiddleware).
func (s *Server) registerRoutes() {
	app := s.initMiddleware()

	s.serveStaticFiles()

	// Browsers auto-probe /favicon.ico at the site root regardless of the
	// <link rel="icon"> tags; point it at the real asset under /static.
	getAndHead(s.router, "/favicon.ico", http.RedirectHandler("/static/favicon/favicon.ico", http.StatusMovedPermanently).ServeHTTP)

	// Beside the static branch rather than on the application branch, so the probes' endpoint
	// passes through none of the settings cache and the session load, each a call to the auth server, and answers whenever the process is up
	// (see handlers.HandleHealthCheckGet, #390).
	getAndHead(s.router, "/health", handlers.HandleHealthCheckGet())

	s.initRoutes(app)
}

// serveAndDrain is the auth server's, copied rather than shared because each binary owns its
// listener, and without the afterDrain hook, since the console has no worker to stop. It serves every listener
// until ctx ends or one of them fails, and on both paths drains them all before it returns: a
// listener failing is no reason to cut off the requests the other one is answering.
//
// It returns nil after a cancellation with no failure, and otherwise every failure, joined, each
// naming its address. http.ErrServerClosed is what a drained listener's serve call returns, so it is
// never a failure; the console's loop used to report it as one. It writes no record of the failure:
// main writes the one record for whatever Start returns (#426).
func serveAndDrain(ctx context.Context, listeners []listener) error {
	// Buffered for every listener, so a serve goroutine never blocks on a send nobody receives.
	failures := make(chan error, len(listeners))
	var serving sync.WaitGroup

	for _, l := range listeners {
		serving.Add(1)
		go func() {
			defer serving.Done()
			if err := l.serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				failures <- errs.Wrapf(err, "the listener on %s", l.server.Addr)
			}
		}()
	}

	var failed []error
	select {
	case err := <-failures:
		failed = append(failed, err)
	case <-ctx.Done():
		slog.InfoContext(ctx, "shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer cancel()

	for _, l := range listeners {
		if err := l.server.Shutdown(shutdownCtx); err != nil {
			slog.ErrorContext(ctx, "unable to shut down a listener", "address", l.server.Addr, "error", err)
		}
	}
	slog.InfoContext(ctx, "listeners drained")

	// Every serve call has returned once its server is shut down, so this is short. It is what lets
	// a second listener's failure, arriving while the first was being handled, join the result.
	serving.Wait()
	close(failures)
	for err := range failures {
		failed = append(failed, err)
	}

	slog.InfoContext(ctx, "shutdown complete")

	return errs.Join(failed...)
}

// httpShutdownTimeout bounds how long in-flight requests get to finish. The auth server's value: a
// console request in flight is waiting on auth server calls deadlined at 10s each (apiclient's
// generalAPITimeout), and 15s lets the one under way finish.
const httpShutdownTimeout = 15 * time.Second

// newHTTPServer builds one of Start's listeners, unstarted. The address comes from hostport.Join,
// so an IPv6 host such as `::1` listens, where a Sprintf'd `host:port` stopped the console at
// start with "too many colons in address" (#424). `0.0.0.0`, the default, needs no IPv6 spelling
// to reach IPv6 clients: with network "tcp" Go listens on both families from it. It is the only
// place this binary builds an http.Server, so every listener gets the bounds below (#426).
func newHTTPServer(host string, port int, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              hostport.Join(host, port),
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

// The listener's bounds, copied from the auth server's rather than shared: each binary owns its
// listener. net/http's zero for each is no bound at all (1 MB for the header block), so a client
// that opens a connection and stops sending held it for ever (#426). Each value is a constant
// rather than a setting: every one has wide headroom over what a legitimate request needs.
const (
	// readHeaderTimeout closes a connection that never finishes its header block. Being the smallest
	// non-zero timeout, it is also the TLS handshake's deadline, so a client that never says hello
	// is dropped at the same point.
	readHeaderTimeout = 10 * time.Second

	// readTimeout bounds the whole request, header and body, from its first byte. The console's
	// upload form refuses a source image over 3 MB and sends a 512x512 crop (image-upload.js), so
	// 60s leaves this far above any upload the console's own pages send.
	readTimeout = 60 * time.Second

	// writeTimeout must outlast the body read plus the slowest handler, because a handler that runs
	// past it leaves the client with no response at all, not an error. net/http starts it when the
	// header block has been read. One console page chains several auth server calls, each deadlined
	// at 10s (apiclient's generalAPITimeout), and some of them reach the auth server's
	// mail-sending handlers. It is never shorter than readTimeout, or a body the read deadline
	// admits would lose its response.
	writeTimeout = 60 * time.Second

	// idleTimeout closes a kept-alive connection that sends no next request.
	idleTimeout = 120 * time.Second

	// maxHeaderBytes bounds the request line and header fields. The console's own requests are
	// short: its session cookie is an identifier (#266) and its largest query is a search term.
	// It matches the auth server's 64 KiB. net/http adds 4096 bytes of slack and answers 431
	// itself above that, before any handler runs.
	maxHeaderBytes = 64 << 10
)

// initMiddleware mounts the chain and returns the router the application's own routes
// belong on.
//
// Two branches, and the split is the point (#266). Everything mounted on s.router below
// applies to every request this server answers, a stylesheet included: the request id, the
// security headers, the real client IP, the panic recovery, the request log, the slash
// strip and the CSRF origin check. What the returned router adds is the part a file server
// has no use for and cannot use: the settings cache, the cookie reset, the session load and
// the locale resolution.
//
// The cost that split removes is larger here than on the auth server. An admin console page
// references nine to eleven same-origin assets, and this module's session now lives on the
// far side of an HTTP call to the auth server, so unexempted a single page view would cost
// ten calls across the wire and a database read at the other end of each, on the module that
// was kept database-free precisely so it would stay light.
//
// It is a correctness fix too. httpmw.CookieReset answers a cookie it cannot decode with
// a 302 back to the request target, which is not a sensible answer to a request for a
// stylesheet.
//
// chi refuses Use after a route has been registered on the same router, and With freezes the
// parent's chain, so this is a restructure rather than a reorder: every root Use happens
// here, before the branch, and both branches register their routes afterwards.
func (s *Server) initMiddleware() chi.Router {

	slog.Info("initializing middleware")

	// CORS - Admin console doesn't need dynamic CORS from database
	// The CORS middleware is primarily for the auth server's OAuth endpoints

	// Request ID
	s.router.Use(chimiddleware.RequestID)

	// Security headers (before Recoverer so 500 responses carry them too)
	s.router.Use(httpmw.SecurityHeaders(s.cfg.AdminConsole.IsCookieSecure()))

	// Real IP: resolve the client IP into r.RemoteAddr from the socket peer and
	// (when trusted) the forwarded headers, so all downstream consumers (session/
	// audit IP, request logger) share one trustworthy value.
	s.router.Use(httpmw.RealIP(
		s.cfg.AdminConsole.TrustProxyHeaders,
		s.trustedProxies,
	))

	// HTTP request logging, mounted ABOVE Recoverer. Replaces chi's middleware.Logger, which
	// wrote the raw request target to stdout, query string and all, so any credential a client
	// put in a query string landed in the log in full (#159). The redaction lives in the
	// middleware.
	//
	// Mounted unconditionally: httpmw.RequestLogger returns the next handler untouched
	// when the flag is off, so the chain has one shape either way.
	//
	// It sits above Recoverer rather than below it so that a panicking request is recorded
	// as the 500 the client actually received. Below, the logger's wrapped writer never saw
	// a status, because Recoverer's WriteHeader(500) went to the writer above it, and the
	// record said status=0 for every panic: the one request an operator most needs to find
	// was the one indistinguishable from a handler that wrote nothing. The trade, accepted
	// with #203: a panic inside the logger itself is no longer caught, so it drops the
	// connection instead of answering 500. The logger is bounded formatting over values it
	// has already clipped, and a panic in it would be a bug to fix rather than to absorb.
	//
	// It stays before StripSlashes, which edits r.URL.Path in place, which is why the
	// middleware renders the target before calling the next handler.
	logHttpRequests := s.cfg.AdminConsole.LogHttpRequests
	slog.Info("http request logging configured", "enabled", logHttpRequests)
	s.router.Use(httpmw.RequestLogger(logHttpRequests))

	// HTTP metrics: every request this router answers, by route, method and status. Beside the
	// request logger and for the same reason, above Recoverer, so a panicking request is counted as
	// the 500 its client received (#400). The route label's set is this router's own table, read
	// once at the first request, by which time registerRoutes has registered every route.
	s.router.Use(metrics.HTTPRequests(s.metrics, s.router))

	// Recoverer, beneath the request logger so the 500 it writes reaches that logger's
	// wrapped writer and lands in the record (#203).
	s.router.Use(chimiddleware.Recoverer)

	// Strip slashes
	s.router.Use(chimiddleware.StripSlashes)

	// Request-body limits, one per route from bodyLimitPolicy (#426). After StripSlashes, because
	// the lookup resolves the route by the path StripSlashes normalized, and before anything else
	// at the root, so no body is read without a bound.
	s.router.Use(httpmw.BodyLimit(s.router, bodyLimitPolicy()))

	// CSRF
	// Note: CSRF runs before the locale middleware below, so there is no localizer on the
	// context when a request is rejected. httpmw.CSRF resolves a tentative one of its own
	// through i18n.ResolveRequestLocale, so the rejection is localized without moving the
	// origin check down onto the application branch, where a route registered outside that
	// branch would escape it.
	//
	// httpmw.SkipCSRF marks the endpoints that are cross-origin by protocol, and httpmw.CSRF
	// refuses every other state-changing cross-origin request outright, trusting no origin but this
	// deployment's own (#155). httpmw.CSRF takes no configuration; httpmw.SkipCSRF takes this
	// server's own exemption policy, which until #385 was a table in core naming both binaries'
	// routes, so each exempted the other's.
	s.router.Use(httpmw.SkipCSRF(csrfPolicy()))
	s.router.Use(httpmw.CSRF())

	// Everything below is on the application branch, not the root.

	app := s.router.With(
		// Global locale middleware: resolves a tentative localizer from
		// ?ui_locales, Accept-Language, or English. Adminconsole has no
		// AuthContext concept (identity comes from the JWT later in the chain),
		// so authHelper is nil. Per-route user-locale refinement lives in
		// routes.go inside baseAuth/accountAuth/adminAuth, immediately after
		// JWT validation.
		//
		// It goes first so that everything below it can answer a request in the
		// caller's language. It used to go last, which left both of
		// middleware.SettingsCache's refusals unable to reach a localizer: an
		// administrator whose browser asks for pt-BR was told in English that
		// their auth server needs upgrading. Nothing here depends on that
		// ordering being the other way round: i18n.resolveLocale reads
		// ?ui_locales, an optional UI-locales reader (nil in this module), and
		// Accept-Language, and touches no settings, no session and no database.
		// The authserver's copy of this chain does resolve locale last because
		// its reader needs the session to be decoded first.
		i18n.Locale(nil),

		// Adds settings to the request context (fetched from cache, not database)
		middleware.SettingsCache(s.settingsCache),

		// Clear the session cookie and redirect if unable to decode it, and delete
		// whatever the chunked cookie store left in this browser
		httpmw.CookieReset(s.sessionStore, builtin.AdminConsoleSessionName),
	)

	slog.Info("finished initializing middleware")

	return app
}

// csrfPolicy is the admin console's CSRF exemption policy: the endpoints this binary serves that
// are cross-origin by protocol design, so the origin check cannot apply to them. Everything else it
// mounts is a cookie-authenticated page, which is exactly what CSRF defends, so the list is short.
//
// Two entries where the auth server has seven, because this binary mounts three of the eleven
// routes the shared table in core used to name: /auth/callback, /auth/logout and /static/. The
// other eight were the auth server's, and exempting a route that does not exist here was never
// deliberate (#385).
//
// That narrowing is this change's one observable difference, and it is a narrowing rather than a
// break. For every route this server mounts, nothing changes. For a path it does not mount,
// /auth/token say, a cross-origin unsafe-method request used to pass the origin check on the shared
// exemption and reach chi for a 404 or a 405, and is now refused 403 by the origin check instead.
// Safe methods are untouched, because http.CrossOriginProtection.Check only applies to unsafe ones,
// and a 403 tells a cross-origin prober less about this deployment's route table than the 404 did.
//
// /auth/logout is likewise absent. This server mounts GET /auth/logout only, and GET is a safe
// method the origin check never applies to, so the auth server's conditional entry for it would
// exempt nothing here.
func csrfPolicy() httpmw.CSRFPolicy {
	return httpmw.CSRFPolicy{
		// Matched EXACTLY, so a future sibling route is NOT silently exempted: it keeps full CSRF
		// protection until it is deliberately added here.
		ExactPaths: []string{
			// The admin console's OAuth callback: a cross-site form_post carrying the auth code
			// (POST), protected by the OAuth `state` parameter rather than by the origin check.
			"/auth/callback",
		},

		// Whole subtrees where prefix inheritance is intentional, unlike the exact path above.
		Prefixes: []string{
			// Static assets, served with safe methods (GET/HEAD) only, which the origin check
			// never applies to anyway; listed for clarity.
			"/static/",
		},

		// No conditional entries. This server has no endpoint whose exemption depends on the
		// request rather than only on its path; the auth server's /auth/logout predicate is the
		// only one in the tree.
	}
}

const (
	// defaultBodyLimit bounds every request body the table below does not name: /auth/callback,
	// the one form a caller reaches without a console session, and anything no route matches. The
	// callback's form_post carries a code and a state, a few hundred bytes (#426).
	defaultBodyLimit = 64 << 10

	// pageBodyLimit bounds the signed-in pages under /admin and /account: their forms, and the
	// JSON lists some of them send, which the console forwards to an auth server API that is
	// itself bounded at 1 MiB (#426).
	pageBodyLimit = 1 << 20

	// uploadBodyLimit bounds the three image uploads. The console's upload page refuses a source
	// file over 3 MB and sends a 512x512 crop of it (maxSize in web/static/image-upload.js), and
	// 64 KiB above that covers the multipart framing. It is not the auth server's
	// GOIABADA_PROFILE_PICTURE_MAX_SIZE_BYTES, which this binary does not read: a deployment that
	// raises that setting still uploads through this page, which stops at 3 MB (#426).
	uploadBodyLimit = 3<<20 + 64<<10
)

// bodyLimitPolicy is the admin console's request-body table (#426): how many bytes each route may
// read, looked up by httpmw.BodyLimit at the root. A route missing from it gets
// defaultBodyLimit, the smallest limit here, so an omission is a refused request rather than an
// unbounded read.
func bodyLimitPolicy() httpmw.BodyLimitPolicy {
	return httpmw.BodyLimitPolicy{
		Default: defaultBodyLimit,

		Prefixes: map[string]int64{
			"/admin/":   pageBodyLimit,
			"/account/": pageBodyLimit,
		},

		Routes: map[string]int64{
			"POST /account/picture":               uploadBodyLimit,
			"POST /admin/clients/{clientId}/logo": uploadBodyLimit,
			"POST /admin/users/{userId}/picture":  uploadBodyLimit,
		},
	}
}

// serveStaticFiles serves the embedded static files under /static/ and redirects /static to
// /static/. They are mounted nowhere else, so neither the path nor the file system is a parameter.
func (s *Server) serveStaticFiles() {
	getAndHead(s.router, "/static", http.RedirectHandler("/static/", http.StatusMovedPermanently).ServeHTTP)

	getAndHead(s.router, "/static/*", func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		fsHandler := http.StripPrefix(pathPrefix, http.FileServer(http.FS(s.staticFS)))

		cacheInSeconds := 5 * 60
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%v", cacheInSeconds))
		w.Header().Set("Expires", time.Now().Add(time.Second*time.Duration(cacheInSeconds)).Format(http.TimeFormat))
		w.Header().Set("Vary", "Accept-Encoding")

		fsHandler.ServeHTTP(w, r)
	})
}

// logPlainHTTP reports a deployment listening on HTTP with no HTTPS listener. Behind a proxy
// that says so, an https base URL with the forwarded headers trusted, as every configuration the
// setup wizard writes for a proxy sets, that is the deployment working as intended, and the record
// is Info: as a Warn it greeted every healthy install behind a proxy with a warning (#542).
// Otherwise nothing says a proxy ends TLS in front of the server, and it stays the Warn #320
// decision 6 collapsed from an eleven-line banner. The other server's copy is the same records
// about itself: each names the server it is about, and neither module imports the other.
func logPlainHTTP(baseURL string, trustProxyHeaders bool) {
	if trustProxyHeaders && strings.HasPrefix(strings.ToLower(baseURL), "https://") {
		slog.Info("the admin console is listening on HTTP behind a reverse proxy that terminates HTTPS")
		return
	}
	slog.Warn("the admin console is listening on HTTP with no TLS, which is insecure outside development unless a reverse proxy in front of it terminates HTTPS",
		"remedy", "configure the HTTPS listener, or make sure the reverse proxy handles HTTPS")
}
