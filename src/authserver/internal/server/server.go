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

	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/sessionstore"

	"log/slog"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/data"
	authhandlerhelpers "github.com/leodip/goiabada/authserver/internal/handlerhelpers"
	"github.com/leodip/goiabada/authserver/internal/imaging"
	authserver_middleware "github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/workers"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hostport"
	"github.com/leodip/goiabada/core/i18n"
	custom_middleware "github.com/leodip/goiabada/core/middleware"
)

type Server struct {
	router *chi.Mux
	// The whole interface, and one of the four places that still holds it: routes.go hands this
	// to every constructor and each one narrows it to a port of its own (#386 decision 8).
	database     data.Database
	sessionStore sessionstore.Store
	worker       *workers.Worker

	// Parsed by main, which refuses to start on a malformed entry (#425), so the real-IP
	// middleware takes ranges and has no error path of its own.
	trustedProxies []*net.IPNet

	staticFS   fs.FS
	templateFS fs.FS

	// Config fields
	baseURL         string
	setCookieSecure bool
}

func NewServer(router *chi.Mux, database data.Database, sessionStore sessionstore.Store, trustedProxies []*net.IPNet) *Server {

	s := Server{
		router:       router,
		database:     database,
		sessionStore: sessionStore,
		worker:       workers.NewWorker(database),

		trustedProxies: trustedProxies,

		// Config fields
		baseURL:         config.GetAuthServer().BaseURL,
		setCookieSecure: config.GetAuthServer().IsCookieSecure(),
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

// Start brings up the listeners and blocks until ctx is cancelled or a listener fails. On both it
// drains in-flight requests and then stops the worker before returning. It returns nil after a
// cancellation, and otherwise the error, unlogged: main writes the one record for it and owns the
// exit, so nothing below main decides to end the process (#426, #390).
func (s *Server) Start(ctx context.Context) error {
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

	// Refused before anything starts: the worker would otherwise be left running, and the routes
	// half built, behind a process that is about to exit.
	if !httpsEnabled && !httpEnabled {
		return errs.New("no listener is enabled, so the auth server cannot start: configure at least one of the http and https listeners")
	}

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

	s.worker.Start()

	return serveAndDrain(ctx, listeners, func() { s.worker.Stop(workerStopTimeout) })
}

// listener is one of Start's servers and the call that serves it, which is ListenAndServe or
// ListenAndServeTLS in Start and Serve on an ephemeral listener in a test.
type listener struct {
	server *http.Server
	serve  func() error
}

// serveAndDrain serves every listener until ctx ends or one of them fails, and on both paths drains
// them all before it returns: a listener failing is no reason to cut off the requests the other one
// is answering. afterDrain runs once every listener has stopped, which is where the auth server stops
// its worker.
//
// The order matters: draining the listeners first means no new request can start work that the
// worker's cleanup might be deleting underneath it.
//
// It returns nil after a cancellation with no failure, and otherwise every failure, joined, each
// naming its address. http.ErrServerClosed is what a drained listener's serve call returns, so it is
// never a failure. It writes no record of the failure: main writes the one record for whatever
// Start returns (#426).
func serveAndDrain(ctx context.Context, listeners []listener, afterDrain func()) error {
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

	afterDrain()
	slog.InfoContext(ctx, "shutdown complete")

	return errs.Join(failed...)
}

// newHTTPServer builds one of Start's listeners, unstarted. The address comes from hostport.Join,
// so an IPv6 host such as `::1` listens, where a Sprintf'd `host:port` stopped the server at start
// with "too many colons in address" (#424). `0.0.0.0`, the default, needs no IPv6 spelling to
// reach IPv6 clients: with network "tcp" Go listens on both families from it. It is the only
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

// The listener's bounds. net/http's zero for each is no bound at all (1 MB for the header block),
// so a client that opens a connection and stops sending held it for ever (#426). Each value is a
// constant rather than a setting: every one has wide headroom over what a legitimate request needs.
const (
	// readHeaderTimeout closes a connection that never finishes its header block. Being the smallest
	// non-zero timeout, it is also the TLS handshake's deadline, so a client that never says hello
	// is dropped at the same point.
	readHeaderTimeout = 10 * time.Second

	// readTimeout bounds the whole request, header and body, from its first byte. 60s carries a
	// 3 MiB profile picture or logo upload at about 53 KB/s.
	readTimeout = 60 * time.Second

	// writeTimeout must outlast the body read plus the slowest handler, because a handler that runs
	// past it leaves the client with no response at all, not an error. net/http starts it when the
	// header block has been read, so the body's arrival counts against it. The slowest handlers send
	// mail synchronously, up to 40s of SMTP dial and conversation (emaildelivery), behind a form body
	// under a kilobyte. It is never shorter than readTimeout, or a body the read deadline admits
	// would lose its response.
	writeTimeout = 60 * time.Second

	// idleTimeout closes a kept-alive connection that sends no next request.
	idleTimeout = 120 * time.Second

	// maxHeaderBytes bounds the request line and header fields. The largest legitimate request is an
	// authorize or logout URL carrying an id_token_hint and a client-chosen state, about 10 KB, plus
	// cookies, and this server's own session cookie is an identifier (#266). net/http adds 4096
	// bytes of slack and answers 431 itself above that, before any handler runs.
	maxHeaderBytes = 64 << 10
)

const (
	// httpShutdownTimeout bounds how long in-flight requests get to finish.
	httpShutdownTimeout = 15 * time.Second

	// workerStopTimeout bounds the wait for the background worker. Cancelling now reaches
	// the statement, since every data.Database call takes the worker's context (#386), so
	// this is no longer the only thing bounding a cleanup delete -- it is the ceiling for
	// the case where the driver does something else with the cancellation than stop.
	workerStopTimeout = 20 * time.Second
)

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
	s.router.Use(authserver_middleware.MiddlewareCors(s.database))

	// Request ID
	s.router.Use(middleware.RequestID)

	// Security headers (before Recoverer so 500 responses carry them too)
	s.router.Use(custom_middleware.MiddlewareSecurityHeaders(s.setCookieSecure))

	// Real IP: resolve the client IP into r.RemoteAddr from the socket peer and
	// (when trusted) the forwarded headers, so all downstream consumers (rate
	// limiter, session/audit IP, request logger) share one trustworthy value.
	s.router.Use(custom_middleware.MiddlewareRealIP(
		config.GetAuthServer().TrustProxyHeaders,
		s.trustedProxies,
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

	// Request-body limits, one per route from bodyLimitPolicy (#426). After StripSlashes, because
	// the lookup resolves the route by the path StripSlashes normalized; before MiddlewareSkipCsrf,
	// because the /auth/logout exemption predicate parses the form body right there at the root,
	// and a body read before this mount would be read without a bound.
	s.router.Use(custom_middleware.MiddlewareBodyLimit(s.router,
		bodyLimitPolicy(config.GetAuthServer().ProfilePictureMaxSizeBytes)))

	// CSRF
	// Note: CSRF runs before the locale middleware below, so there is no localizer on the context
	// when a request is rejected. MiddlewareCsrf resolves a tentative one of its own through
	// i18n.ResolveRequestLocale, so the rejection is localized without moving the origin check
	// down onto the application branch, where a route registered outside that branch would
	// escape it.
	//
	// MiddlewareSkipCsrf marks the endpoints that are cross-origin by protocol, and MiddlewareCsrf
	// refuses every other state-changing cross-origin request outright, trusting no origin but this
	// deployment's own (#155). MiddlewareCsrf takes no configuration; MiddlewareSkipCsrf takes this
	// server's own exemption policy, which until #385 was a table in core naming both binaries'
	// routes, so each exempted the other's.
	s.router.Use(custom_middleware.MiddlewareSkipCsrf(csrfPolicy()))
	s.router.Use(custom_middleware.MiddlewareCsrf())

	// Everything below is on the application branch, not the root.

	// Global locale middleware: resolves a tentative localizer from
	// ?ui_locales, UI locales from an in-flight authorize flow,
	// Accept-Language, or English. Must run AFTER MiddlewareSessionIdentifier
	// so the session is decoded — the reader gets UI locales from session-backed
	// authorize state. User-locale refinement happens per-handler in authserver
	// (an i18n.WithLocale call once a password has been checked), since
	// identity is established at handler scope rather than at middleware
	// scope.
	i18nAuthHelper := authhandlerhelpers.NewAuthHelper(s.sessionStore, constants.AuthServerSessionName)

	app := s.router.With(
		// Adds settings to the request context
		authserver_middleware.MiddlewareSettings(s.database),

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

// csrfPolicy is the auth server's CSRF exemption policy: the endpoints this binary serves that are
// cross-origin by protocol design, so the origin check cannot apply to them.
//
// There is no single property these share, and in particular they do NOT all authenticate the
// caller, so each carries its own rationale rather than leaning on a shared one (#155). What core
// owns is the matching and the three-way distinction between the shapes; what this server owns is
// which of its own routes go in which shape (#385). A route absent from all three keeps full CSRF
// protection.
//
// /auth/callback is deliberately not here. It is the admin console's OAuth callback and this binary
// does not mount it; it was in the shared table this replaces, which is the kind of entry a
// per-application policy exists to stop.
func csrfPolicy() custom_middleware.CsrfPolicy {
	return custom_middleware.CsrfPolicy{
		// Matched EXACTLY, so a future sibling route (e.g. /auth/token-introspect or
		// /userinfo-export) is NOT silently exempted: it keeps full CSRF protection until it is
		// deliberately added here.
		ExactPaths: []string{
			// OAuth2 authorization endpoint (GET/POST). OIDC Core 3.1.2.1 requires both methods.
			// It does consult the session cookie for SSO, so the exemption rests instead on a
			// cross-site POST here reaching nothing a plain link would not: it starts a ceremony,
			// and every state-changing step it leads to (password, OTP, consent) is itself
			// origin-checked (#67).
			"/auth/authorize",

			// OAuth2 token endpoint (POST). A confidential client authenticates with its secret; a
			// public client instead redeems a one-time code bound to its registered redirect URI
			// and, when PKCE was used, to a code verifier. No session cookie is read either way.
			"/auth/token",

			// OIDC userinfo; bearer-token authenticated (GET/POST).
			"/userinfo",

			// Dynamic Client Registration (POST). Deliberately unauthenticated when enabled: it
			// creates a client rather than acting on a signed-in user, so there is no user state
			// for CSRF to reach. Disabled by default, rate limited.
			"/connect/register",
		},

		// Whole subtrees where prefix inheritance is intentional, unlike the exact paths above.
		Prefixes: []string{
			// Bearer-token REST API surface. Every route authenticates via the Authorization
			// header, never the session cookie, so new endpoints added under this prefix SHOULD
			// inherit the exemption. Cookie-authenticated routes must never be mounted here.
			"/api/",

			// Static assets, served with safe methods (GET/HEAD) only, which the origin check
			// never applies to anyway; listed for clarity.
			"/static/",
		},

		// Endpoints whose exemption depends on the request rather than only on its path.
		//
		// This shape exists because an unconditional entry for /auth/logout would be a hole: any
		// site could then POST to it with no hint and no token, and the handler treats a hintless
		// POST as the confirmation of its consent page, so the End-User would be signed out
		// without ever being asked.
		Conditional: map[string]func(*http.Request) bool{
			// RP-initiated logout, exempt only for a POST carrying an id_token_hint. See
			// middleware.LogoutIdTokenHintPresent for why presence is the test and why it is read
			// through the same function the logout handler classifies the parameter with (#109).
			"/auth/logout": authserver_middleware.LogoutIdTokenHintPresent,
		},
	}
}

const (
	// defaultBodyLimit bounds every request body the table below does not name: every browser
	// form, every /auth endpoint, /connect/register, /userinfo and anything no route matches, all
	// reachable by anyone. The largest of those a legitimate caller sends is a registration
	// request, whose metadata RFC 7591 section 2 says to ignore rather than refuse when this
	// server does not understand it, so it is 64 KiB rather than a form's few hundred bytes: room
	// for an inline jwks or a software_statement this server never reads (#426).
	defaultBodyLimit = 64 << 10

	// apiBodyLimit bounds the admin and account APIs. The caller is signed in, but /api/v1/account
	// is open to any user holding manage-account, so signed in is not trusted; the largest
	// legitimate body is a permission, group or redirect-URI list of tens of KB (#426).
	apiBodyLimit = 1 << 20

	// uploadMultipartAllowance is what an upload row allows above the image itself, for the
	// multipart boundaries and part headers around it. The upload handlers bound their own bodies
	// at the image size plus 1 KiB and answer FILE_TOO_LARGE past it; this is wider, so the
	// handler's bound is always the one that answers (#426).
	uploadMultipartAllowance = 64 << 10
)

// bodyLimitPolicy is the auth server's request-body table (#426): how many bytes each route may
// read, looked up by MiddlewareBodyLimit at the root. A route missing from it gets
// defaultBodyLimit, the smallest limit here, so an omission is a refused request rather than an
// unbounded read.
//
// Every limit is at least the bound of the handler inside it, so a handler that bounds its own
// body keeps answering for it: the uploads, the session endpoints and the account OTP PUT.
//
// profilePictureMaxSizeBytes is GOIABADA_PROFILE_PICTURE_MAX_SIZE_BYTES, read once at startup, so
// raising it raises the upload rows with it.
func bodyLimitPolicy(profilePictureMaxSizeBytes int64) custom_middleware.BodyLimitPolicy {
	uploadLimit := imaging.MaxFileSize(profilePictureMaxSizeBytes) + uploadMultipartAllowance

	return custom_middleware.BodyLimitPolicy{
		Default: defaultBodyLimit,

		Prefixes: map[string]int64{
			"/api/v1/admin/":   apiBodyLimit,
			"/api/v1/account/": apiBodyLimit,

			// The admin console's session transport. Its handlers bound their bodies at the
			// store's own wire ceiling, deliberately, so a session the store accepts is a request
			// they read; the row names the same constant, so the two cannot drift apart and the
			// handler's bound stays the one that answers.
			"/api/v1/sessions/": sessionstore.MaxSessionWireBytes,
		},

		Routes: map[string]int64{
			"POST /api/v1/admin/users/{id}/profile-picture": uploadLimit,
			"POST /api/v1/admin/clients/{id}/logo":          uploadLimit,
			"POST /api/v1/account/profile-picture":          uploadLimit,
		},
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
