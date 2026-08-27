package server

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/sessions"

	"log/slog"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/adminconsole/internal/cache"
	adminconsole_middleware "github.com/leodip/goiabada/adminconsole/internal/middleware"
	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/i18n"
	custom_middleware "github.com/leodip/goiabada/core/middleware"
)

type Server struct {
	router        *chi.Mux
	sessionStore  sessions.Store
	settingsCache *cache.SettingsCache

	staticFS   fs.FS
	templateFS fs.FS
}

func NewServer(router *chi.Mux, sessionStore sessions.Store, settingsCache *cache.SettingsCache) *Server {

	s := Server{
		router:        router,
		sessionStore:  sessionStore,
		settingsCache: settingsCache,
	}

	if envVar := config.GetAdminConsole().StaticDir; len(envVar) == 0 {
		s.staticFS = web.StaticFS()
		slog.Info("using embedded static files directory")
	} else {
		s.staticFS = os.DirFS(envVar)
		slog.Info(fmt.Sprintf("using static files directory %v", envVar))
	}

	if envVar := config.GetAdminConsole().TemplateDir; len(envVar) == 0 {
		s.templateFS = web.TemplateFS()
		slog.Info("using embedded template files directory")
	} else {
		s.templateFS = os.DirFS(envVar)
		slog.Info(fmt.Sprintf("using template files directory %v", envVar))
	}

	return &s
}

func (s *Server) Start() {
	// Validate required confidential client configuration
	if strings.TrimSpace(config.GetAdminConsole().OAuthClientID) == "" || strings.TrimSpace(config.GetAdminConsole().OAuthClientSecret) == "" {
		slog.Error("Missing admin console OAuth client configuration: GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID and GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET must be set. If you're running the admin console for the first time, please look at the auth server logs for the generated credentials.")
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

	slog.Info("listen host https: " + httpsHost)
	slog.Info(fmt.Sprintf("listen port https: %v", httpsPort))
	slog.Info("cert file: " + certFile)
	slog.Info("key file: " + keyFile)
	slog.Info(fmt.Sprintf("https enabled: %v", httpsEnabled))

	httpHost := config.GetAdminConsole().ListenHostHttp
	httpPort := config.GetAdminConsole().ListenPortHttp
	httpEnabled := httpHost != "" && httpPort > 0

	slog.Info("listen host http: " + httpHost)
	slog.Info(fmt.Sprintf("listen port http: %v", httpPort))
	slog.Info(fmt.Sprintf("http enabled: %v", httpEnabled))

	if httpEnabled && !httpsEnabled {
		slog.Warn("=== WARNING ===")
		slog.Warn("You are running the admin console with HTTP (without TLS/HTTPS).")
		slog.Warn("This is HIGHLY INSECURE unless you are:")
		slog.Warn("  1. Only doing development/testing, OR")
		slog.Warn("  2. Running behind a reverse proxy that handles HTTPS")
		slog.Warn("")
		slog.Warn("In production environments, you should either:")
		slog.Warn("  - Enable HTTPS configuration, OR")
		slog.Warn("  - Ensure your reverse proxy handles HTTPS properly")
		slog.Warn("===============")
	}

	errChan := make(chan error, 2) // Buffer for both HTTP and HTTPS errors

	// Start HTTPS server if enabled
	if httpsEnabled {
		go func() {
			httpsServer := &http.Server{
				Addr:    fmt.Sprintf("%s:%d", httpsHost, httpsPort),
				Handler: s.router,
			}
			slog.Info(fmt.Sprintf("starting HTTPS server on %s:%d", httpsHost, httpsPort))
			if err := httpsServer.ListenAndServeTLS(certFile, keyFile); err != nil {
				errChan <- fmt.Errorf("HTTPS server error: %v", err)
			}
		}()
	}

	// Start HTTP server if enabled
	if httpEnabled {
		go func() {
			httpServer := &http.Server{
				Addr:    fmt.Sprintf("%s:%d", httpHost, httpPort),
				Handler: s.router,
			}
			slog.Info(fmt.Sprintf("starting HTTP server on %s:%d", httpHost, httpPort))
			if err := httpServer.ListenAndServe(); err != nil {
				errChan <- fmt.Errorf("HTTP server error: %v", err)
			}
		}()
	}

	// Exit if neither server is enabled
	if !httpsEnabled && !httpEnabled {
		slog.Error("no server configuration enabled - at least one of HTTP or HTTPS must be configured")
		os.Exit(1)
	}

	// Wait for any server errors and exit on first error
	for i := 0; i < cap(errChan); i++ {
		if err := <-errChan; err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
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

	// Recoverer
	s.router.Use(middleware.Recoverer)

	// HTTP request logging. Replaces chi's middleware.Logger, which wrote the raw
	// request target to stdout, query string and all, so any credential a client
	// put in a query string landed in the log in full (#159). The redaction lives
	// in the middleware.
	//
	// Mounted unconditionally: MiddlewareRequestLogger returns the next handler
	// untouched when the flag is off, so the chain has one shape either way. It
	// stays here in the chain, after Recoverer and before StripSlashes, on
	// purpose: earlier would put a component outside the only middleware that
	// catches its panics, and StripSlashes edits r.URL.Path in place, which is
	// why the middleware renders the target before calling the next handler.
	logHttpRequests := config.GetAdminConsole().LogHttpRequests
	if logHttpRequests {
		slog.Info("http request logging enabled")
	} else {
		slog.Info("http request logging disabled")
	}
	s.router.Use(custom_middleware.MiddlewareRequestLogger(logHttpRequests))

	// Strip slashes
	s.router.Use(middleware.StripSlashes)

	// CSRF
	// Note: CSRF runs before the locale middleware below, so no localizer exists yet when a
	// request is rejected. CSRF rejection responses therefore render in English regardless of
	// the user's preferred locale. This is acceptable for an infrequent, transient failure mode
	// (typically a form left open across a deployment change, fixed by a page reload).
	//
	// The pair takes no configuration: MiddlewareSkipCsrf marks the endpoints that are
	// cross-origin by protocol, and MiddlewareCsrf refuses every other state-changing
	// cross-origin request outright, trusting no origin but this deployment's own (#155).
	s.router.Use(custom_middleware.MiddlewareSkipCsrf())
	s.router.Use(custom_middleware.MiddlewareCsrf())

	// Everything below is on the application branch, not the root.

	app := s.router.With(
		// Adds settings to the request context (fetched from cache, not database)
		adminconsole_middleware.MiddlewareSettingsCache(s.settingsCache),

		// Clear the session cookie and redirect if unable to decode it, and delete
		// whatever the chunked cookie store left in this browser
		custom_middleware.MiddlewareCookieReset(s.sessionStore, constants.AdminConsoleSessionName),

		// Global locale middleware: resolves a tentative localizer from
		// ?ui_locales, Accept-Language, or English. Adminconsole has no
		// AuthContext concept (identity comes from the JWT later in the chain),
		// so authHelper is nil. Per-route user-locale refinement lives in
		// routes.go inside baseAuth/accountAuth/adminAuth, immediately after
		// JWT validation.
		i18n.MiddlewareLocale(nil),
	)

	slog.Info("finished initializing middleware")

	return app
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
