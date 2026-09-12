package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/sessionstore"

	"log/slog"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	authserver_middleware "github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/workers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/i18n"
	custom_middleware "github.com/leodip/goiabada/core/middleware"
)

type Server struct {
	router       *chi.Mux
	database     data.Database
	sessionStore sessionstore.Store
	worker       *workers.Worker

	staticFS   fs.FS
	templateFS fs.FS

	// Config fields
	baseURL             string
	adminConsoleBaseURL string
	setCookieSecure     bool
}

func NewServer(router *chi.Mux, database data.Database, sessionStore sessionstore.Store) *Server {

	s := Server{
		router:       router,
		database:     database,
		sessionStore: sessionStore,
		worker:       workers.NewWorker(database),

		// Config fields
		baseURL:             config.GetAuthServer().BaseURL,
		adminConsoleBaseURL: config.GetAdminConsole().BaseURL,
		setCookieSecure:     config.GetAuthServer().IsCookieSecure(),
	}

	if envVar := config.GetAuthServer().StaticDir; len(envVar) == 0 {
		s.staticFS = web.StaticFS()
		slog.Info("using the embedded static files")
	} else {
		s.staticFS = os.DirFS(envVar)
		slog.Info("using static files from a directory", "directory", envVar)
	}

	if envVar := config.GetAuthServer().TemplateDir; len(envVar) == 0 {
		s.templateFS = web.TemplateFS()
		slog.Info("using the embedded template files")
	} else {
		s.templateFS = os.DirFS(envVar)
		slog.Info("using template files from a directory", "directory", envVar)
	}

	return &s
}

// Start brings up the listeners and blocks until ctx is cancelled or a listener
// fails. On cancellation it drains in-flight requests and stops the worker before
// returning, so the process can exit cleanly.
func (s *Server) Start(ctx context.Context) {
	s.worker.Start()

	// The static branch and the application branch, in that order. Both are registered
	// on s.router; only the second carries the middleware initMiddleware returns, which
	// is what keeps a stylesheet from costing a settings read and a session load
	// (see initMiddleware).
	app := s.initMiddleware()

	s.serveStaticFiles("/static", http.FS(s.staticFS))

	// Browsers auto-probe /favicon.ico at the site root regardless of the
	// <link rel="icon"> tags; point it at the real asset under /static.
	s.router.Get("/favicon.ico", http.RedirectHandler("/static/favicon/favicon.ico", http.StatusMovedPermanently).ServeHTTP)

	s.initRoutes(app)

	httpsHost := config.GetAuthServer().ListenHostHttps
	httpsPort := config.GetAuthServer().ListenPortHttps
	certFile := config.GetAuthServer().CertFile
	keyFile := config.GetAuthServer().KeyFile
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

	httpHost := config.GetAuthServer().ListenHostHttp
	httpPort := config.GetAuthServer().ListenPortHttp
	httpEnabled := httpHost != "" && httpPort > 0

	slog.InfoContext(ctx, "http listener configuration",
		"enabled", httpEnabled,
		"host", httpHost,
		"port", httpPort)

	if httpEnabled && !httpsEnabled {
		logHttpWithoutTlsWarning()
	}

	errChan := make(chan error, 2) // Buffer for both HTTP and HTTPS errors

	// The listeners are kept so shutdown can drain them. http.ErrServerClosed is
	// the normal result of Shutdown, so it must not be reported as a failure.
	var httpServers []*http.Server

	// Start HTTPS server if enabled
	if httpsEnabled {
		httpsServer := &http.Server{
			Addr:    fmt.Sprintf("%s:%d", httpsHost, httpsPort),
			Handler: s.router,
		}
		httpServers = append(httpServers, httpsServer)
		go func() {
			slog.InfoContext(ctx, "starting the https listener", "host", httpsHost, "port", httpsPort)
			if err := httpsServer.ListenAndServeTLS(certFile, keyFile); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				errChan <- errs.Errorf("HTTPS server error: %v", err)
			}
		}()
	}

	// Start HTTP server if enabled
	if httpEnabled {
		httpServer := &http.Server{
			Addr:    fmt.Sprintf("%s:%d", httpHost, httpPort),
			Handler: s.router,
		}
		httpServers = append(httpServers, httpServer)
		go func() {
			slog.InfoContext(ctx, "starting the http listener", "host", httpHost, "port", httpPort)
			if err := httpServer.ListenAndServe(); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				errChan <- errs.Errorf("HTTP server error: %v", err)
			}
		}()
	}

	// Exit if neither server is enabled
	if len(httpServers) == 0 {
		slog.ErrorContext(ctx, "no listener is enabled, so the auth server cannot start: configure at least one of the http and https listeners")
		os.Exit(1)
	}

	select {
	case err := <-errChan:
		// A listener failed. Still shut down cleanly so the worker is not left
		// holding a half-finished delete, then exit non-zero.
		// The error as a value, not as the message: it arrives from errs.Errorf, so
		// %+v prints the frames the message text threw away (#320).
		slog.ErrorContext(ctx, "a listener failed", "error", err)
		s.shutdown(httpServers)
		os.Exit(1)
	case <-ctx.Done():
		slog.InfoContext(ctx, "shutdown signal received")
		s.shutdown(httpServers)
	}
}

const (
	// httpShutdownTimeout bounds how long in-flight requests get to finish.
	httpShutdownTimeout = 15 * time.Second

	// workerStopTimeout bounds the wait for the background worker. It cannot be
	// interrupted mid-statement (data.Database takes no context), so this is a
	// ceiling on how long a cleanup delete may hold up shutdown.
	workerStopTimeout = 20 * time.Second
)

// shutdown stops accepting requests first, then the background worker.
//
// The order matters: draining the listeners first means no new request can start
// work that the worker's cleanup might be deleting underneath it.
func (s *Server) shutdown(httpServers []*http.Server) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer cancel()

	for _, httpServer := range httpServers {
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("unable to shut down a listener", "address", httpServer.Addr, "error", err)
		}
	}
	slog.Info("listeners drained")

	s.worker.Stop(workerStopTimeout)
	slog.Info("shutdown complete")
}

// initMiddleware mounts the chain and returns the router the application's own routes
// belong on.
//
// Two branches, and the split is the point (#266). Everything mounted on s.router below
// applies to every request this server answers, a stylesheet included: the CORS answer,
// the request id, the security headers, the real client IP, the panic recovery, the
// request log, the slash strip and the CSRF origin check. What the returned router adds
// is the part a file server has no use for and cannot use: the settings read, the cookie
// reset, the session load and the locale resolution.
//
// The cost that split removes is not hypothetical. An auth page references seven
// same-origin assets, and MiddlewareSettings reads settings from the database uncached on
// every request, so a single page view already cost seven database reads for files that
// could not use the result. Once the session moved out of the cookie and into a row, each
// of those would have cost a session read as well.
//
// It is a correctness fix too. MiddlewareCookieReset answers a cookie it cannot decode
// with a 302 back to the request target, which is not a sensible answer to a request for
// a stylesheet.
//
// chi refuses Use after a route has been registered on the same router, and With freezes
// the parent's chain, so this is a restructure rather than a reorder: every root Use
// happens here, before the branch, and both branches register their routes afterwards.
func (s *Server) initMiddleware() chi.Router {

	slog.Info("initializing middleware")

	// CORS
	s.router.Use(custom_middleware.MiddlewareCors(s.database))

	// Request ID
	s.router.Use(middleware.RequestID)

	// Security headers (before Recoverer so 500 responses carry them too)
	s.router.Use(custom_middleware.MiddlewareSecurityHeaders(s.setCookieSecure))

	// Real IP: resolve the client IP into r.RemoteAddr from the socket peer and
	// (when trusted) the forwarded headers, so all downstream consumers (rate
	// limiter, session/audit IP, request logger) share one trustworthy value.
	s.router.Use(custom_middleware.MiddlewareRealIP(
		config.GetAuthServer().TrustProxyHeaders,
		config.GetAuthServer().TrustedProxies,
	))

	// HTTP request logging, mounted ABOVE Recoverer. Replaces chi's middleware.Logger, which
	// wrote the raw request target to stdout, query string and all, so an id_token_hint JWT
	// landed in the log in full (#159). The redaction lives in the middleware.
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
	logHttpRequests := config.GetAuthServer().LogHttpRequests
	slog.Info("http request logging configured", "enabled", logHttpRequests)
	s.router.Use(custom_middleware.MiddlewareRequestLogger(logHttpRequests))

	// Recoverer, beneath the request logger so the 500 it writes reaches that logger's
	// wrapped writer and lands in the record (#203).
	s.router.Use(middleware.Recoverer)

	// Strip slashes
	s.router.Use(middleware.StripSlashes)

	// CSRF
	// Note: CSRF runs before the locale middleware below, so no localizer exists yet when a
	// request is rejected. CSRF rejection responses therefore render in English regardless of
	// the user's preferred locale. This is acceptable for an infrequent, transient failure mode
	// (typically a form left open across a deployment change, fixed by a page reload) and avoids
	// the locale lookup cost on every rejected request. Localizing it would mean resolving a
	// locale this early for the sake of a response nobody normally sees.
	//
	// The pair takes no configuration: MiddlewareSkipCsrf marks the endpoints that are
	// cross-origin by protocol, and MiddlewareCsrf refuses every other state-changing
	// cross-origin request outright, trusting no origin but this deployment's own (#155).
	s.router.Use(custom_middleware.MiddlewareSkipCsrf())
	s.router.Use(custom_middleware.MiddlewareCsrf())

	// Everything below is on the application branch, not the root.

	// Global locale middleware: resolves a tentative localizer from
	// ?ui_locales, AuthContext.UILocales (in-flight authorize flow),
	// Accept-Language, or English. Must run AFTER MiddlewareSessionIdentifier
	// so the session is decoded — the middleware reads AuthContext via the
	// AuthHelper. User-locale refinement happens per-handler in authserver
	// (RefineLocalizerWithUser), since identity is established at handler
	// scope rather than at middleware scope.
	i18nAuthHelper := handlerhelpers.NewAuthHelper(s.sessionStore, constants.AuthServerSessionName, s.baseURL, s.adminConsoleBaseURL)

	app := s.router.With(
		// Adds settings to the request context
		custom_middleware.MiddlewareSettings(s.database),

		// Clear the session cookie and redirect if unable to decode it, and delete
		// whatever the chunked cookie store left in this browser
		custom_middleware.MiddlewareCookieReset(s.sessionStore, constants.AuthServerSessionName),

		// Adds the session identifier (if available) to the request context
		authserver_middleware.MiddlewareSessionIdentifier(s.sessionStore, s.database),

		i18n.MiddlewareLocale(i18nAuthHelper),
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

// logHttpWithoutTlsWarning reports a deployment listening on HTTP with no HTTPS
// listener configured.
//
// One record where an 11-line banner used to be, which is what makes it greppable
// by message and readable under both log formats: the banner's ruled box and blank
// lines were unparseable noise in a JSON stream, and its nine lines of prose said
// the two things the message and the remedy attribute say (#320 decision 6).
func logHttpWithoutTlsWarning() {
	slog.Warn("the auth server is listening on HTTP with no TLS, which is insecure outside development unless a reverse proxy in front of it terminates HTTPS",
		"remedy", "configure the HTTPS listener, or make sure the reverse proxy handles HTTPS")
}
