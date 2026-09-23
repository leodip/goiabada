package server

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hostport"
	"github.com/leodip/goiabada/core/sessionstore"

	"log/slog"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/adminconsole/internal/cache"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	adminconsole_middleware "github.com/leodip/goiabada/adminconsole/internal/middleware"
	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/i18n"
	custom_middleware "github.com/leodip/goiabada/core/middleware"
)

type Server struct {
	router        *chi.Mux
	sessionStore  sessionstore.Store
	settingsCache *cache.SettingsCache

	staticFS   fs.FS
	templateFS fs.FS
}

func NewServer(router *chi.Mux, sessionStore sessionstore.Store, settingsCache *cache.SettingsCache) *Server {

	s := Server{
		router:        router,
		sessionStore:  sessionStore,
		settingsCache: settingsCache,
	}

	if envVar := config.GetAdminConsole().StaticDir; len(envVar) == 0 {
		s.staticFS = web.StaticFS()
		slog.Info("using the embedded static files")
	} else {
		s.staticFS = os.DirFS(envVar)
		slog.Info("using static files from a directory", "directory", envVar)
	}

	if envVar := config.GetAdminConsole().TemplateDir; len(envVar) == 0 {
		s.templateFS = web.TemplateFS()
		slog.Info("using the embedded template files")
	} else {
		s.templateFS = os.DirFS(envVar)
		slog.Info("using template files from a directory", "directory", envVar)
	}

	return &s
}

func (s *Server) Start() {
	// Validate required confidential client configuration. The client id is not part of it:
	// the admin console always authenticates as the client the seeder provisions, so the
	// secret is the only half of the credential a deployment supplies (#285).
	if strings.TrimSpace(config.GetAdminConsole().OAuthClientSecret) == "" {
		slog.Error("the oauth client secret is not configured, so the admin console cannot start: on a first deployment the auth server logs the generated credentials",
			"required", "GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET")
		os.Exit(1)
	}
	// The static branch and the application branch, in that order. Both are registered
	// on s.router; only the second carries the middleware initMiddleware returns, which
	// is what keeps a stylesheet from costing a session load, and here that load is an
	// HTTP call to the auth server (see initMiddleware).
	app := s.initMiddleware()

	s.serveStaticFiles("/static", http.FS(s.staticFS))

	// Browsers auto-probe /favicon.ico at the site root regardless of the
	// <link rel="icon"> tags; point it at the real asset under /static.
	s.router.Get("/favicon.ico", http.RedirectHandler("/static/favicon/favicon.ico", http.StatusMovedPermanently).ServeHTTP)

	s.initRoutes(app)

	httpsHost := config.GetAdminConsole().ListenHostHttps
	httpsPort := config.GetAdminConsole().ListenPortHttps
	certFile := config.GetAdminConsole().CertFile
	keyFile := config.GetAdminConsole().KeyFile
	httpsEnabled := httpsHost != "" && httpsPort > 0 && certFile != "" && keyFile != ""

	// One record per listener where five and three lines used to be. A reader
	// checking why HTTPS is off had to join "https enabled: false" to four
	// separate lines to see which of the four settings was the empty one (#320).
	slog.Info("https listener configuration",
		"enabled", httpsEnabled,
		"host", httpsHost,
		"port", httpsPort,
		"cert_file", certFile,
		"key_file", keyFile)

	httpHost := config.GetAdminConsole().ListenHostHttp
	httpPort := config.GetAdminConsole().ListenPortHttp
	httpEnabled := httpHost != "" && httpPort > 0

	slog.Info("http listener configuration",
		"enabled", httpEnabled,
		"host", httpHost,
		"port", httpPort)

	if httpEnabled && !httpsEnabled {
		logHttpWithoutTlsWarning()
	}

	errChan := make(chan error, 2) // Buffer for both HTTP and HTTPS errors

	// Start HTTPS server if enabled
	if httpsEnabled {
		go func() {
			httpsServer := newHTTPServer(httpsHost, httpsPort, s.router)
			slog.Info("starting the https listener", "host", httpsHost, "port", httpsPort)
			if err := httpsServer.ListenAndServeTLS(certFile, keyFile); err != nil {
				errChan <- errs.Errorf("HTTPS server error: %v", err)
			}
		}()
	}

	// Start HTTP server if enabled
	if httpEnabled {
		go func() {
			httpServer := newHTTPServer(httpHost, httpPort, s.router)
			slog.Info("starting the http listener", "host", httpHost, "port", httpPort)
			if err := httpServer.ListenAndServe(); err != nil {
				errChan <- errs.Errorf("HTTP server error: %v", err)
			}
		}()
	}

	// Exit if neither server is enabled
	if !httpsEnabled && !httpEnabled {
		slog.Error("no listener is enabled, so the admin console cannot start: configure at least one of the http and https listeners")
		os.Exit(1)
	}

	// Wait for any server errors and exit on first error
	for i := 0; i < cap(errChan); i++ {
		if err := <-errChan; err != nil {
			// The error as a value, not as the message: it arrives from errs.Errorf, so
			// %+v prints the frames the message text threw away (#320).
			slog.Error("a listener failed", "error", err)
			os.Exit(1)
		}
	}
}

// newHTTPServer builds one of Start's listeners, unstarted. The address comes from hostport.Join,
// so an IPv6 host such as `::1` listens, where a Sprintf'd `host:port` stopped the console at
// start with "too many colons in address" (#424). `0.0.0.0`, the default, needs no IPv6 spelling
// to reach IPv6 clients: with network "tcp" Go listens on both families from it.
func newHTTPServer(host string, port int, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:    hostport.Join(host, port),
		Handler: handler,
	}
}

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
// It is a correctness fix too. MiddlewareCookieReset answers a cookie it cannot decode with
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
	s.router.Use(middleware.RequestID)

	// Security headers (before Recoverer so 500 responses carry them too)
	s.router.Use(custom_middleware.MiddlewareSecurityHeaders(config.GetAdminConsole().IsCookieSecure()))

	// Real IP: resolve the client IP into r.RemoteAddr from the socket peer and
	// (when trusted) the forwarded headers, so all downstream consumers (session/
	// audit IP, request logger) share one trustworthy value.
	s.router.Use(custom_middleware.MiddlewareRealIP(
		config.GetAdminConsole().TrustProxyHeaders,
		config.GetAdminConsole().TrustedProxies,
	))

	// HTTP request logging, mounted ABOVE Recoverer. Replaces chi's middleware.Logger, which
	// wrote the raw request target to stdout, query string and all, so any credential a client
	// put in a query string landed in the log in full (#159). The redaction lives in the
	// middleware.
	//
	// Mounted unconditionally: MiddlewareRequestLogger returns the next handler untouched
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
	logHttpRequests := config.GetAdminConsole().LogHttpRequests
	slog.Info("http request logging configured", "enabled", logHttpRequests)
	s.router.Use(custom_middleware.MiddlewareRequestLogger(logHttpRequests))

	// Recoverer, beneath the request logger so the 500 it writes reaches that logger's
	// wrapped writer and lands in the record (#203).
	s.router.Use(middleware.Recoverer)

	// Strip slashes
	s.router.Use(middleware.StripSlashes)

	// CSRF
	// Note: CSRF runs before the locale middleware below, so there is no localizer on the
	// context when a request is rejected. MiddlewareCsrf resolves a tentative one of its own
	// through i18n.ResolveRequestLocale, so the rejection is localized without moving the
	// origin check down onto the application branch, where a route registered outside that
	// branch would escape it.
	//
	// MiddlewareSkipCsrf marks the endpoints that are cross-origin by protocol, and MiddlewareCsrf
	// refuses every other state-changing cross-origin request outright, trusting no origin but this
	// deployment's own (#155). MiddlewareCsrf takes no configuration; MiddlewareSkipCsrf takes this
	// server's own exemption policy, which until #385 was a table in core naming both binaries'
	// routes, so each exempted the other's.
	s.router.Use(custom_middleware.MiddlewareSkipCsrf(csrfPolicy()))
	s.router.Use(custom_middleware.MiddlewareCsrf())

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
		// MiddlewareSettingsCache's refusals unable to reach a localizer: an
		// administrator whose browser asks for pt-BR was told in English that
		// their auth server needs upgrading. Nothing here depends on that
		// ordering being the other way round: i18n.resolveLocale reads
		// ?ui_locales, an optional UI-locales reader (nil in this module), and
		// Accept-Language, and touches no settings, no session and no database.
		// The authserver's copy of this chain does resolve locale last because
		// its reader needs the session to be decoded first.
		i18n.MiddlewareLocale(nil),

		// Adds settings to the request context (fetched from cache, not database)
		adminconsole_middleware.MiddlewareSettingsCache(s.settingsCache),

		// Clear the session cookie and redirect if unable to decode it, and delete
		// whatever the chunked cookie store left in this browser
		custom_middleware.MiddlewareCookieReset(s.sessionStore, constants.AdminConsoleSessionName),
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
func csrfPolicy() custom_middleware.CsrfPolicy {
	return custom_middleware.CsrfPolicy{
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

func (s *Server) serveStaticFiles(path string, root http.FileSystem) {

	if path != "/" && path[len(path)-1] != '/' {
		s.router.Get(path, http.RedirectHandler(path+"/", http.StatusMovedPermanently).ServeHTTP)
		path += "/"
	}
	path += "*"

	s.router.Get(path, func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		fsHandler := http.StripPrefix(pathPrefix, http.FileServer(root))

		cacheInSeconds := 5 * 60
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%v", cacheInSeconds))
		w.Header().Set("Expires", time.Now().Add(time.Second*time.Duration(cacheInSeconds)).Format(http.TimeFormat))
		w.Header().Set("Vary", "Accept-Encoding")

		fsHandler.ServeHTTP(w, r)
	})
}

// logHttpWithoutTlsWarning reports a deployment listening on HTTP with no HTTPS
// listener configured. The auth server's copy is the same record about the other
// server, and the two cannot be shared: each names the server it is about, and
// neither module imports the other (#320 decision 6).
func logHttpWithoutTlsWarning() {
	slog.Warn("the admin console is listening on HTTP with no TLS, which is insecure outside development unless a reverse proxy in front of it terminates HTTPS",
		"remedy", "configure the HTTPS listener, or make sure the reverse proxy handles HTTPS")
}
