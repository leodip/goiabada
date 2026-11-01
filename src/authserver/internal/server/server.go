package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/sessionstore"

	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/cleanup"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/introspectionmetrics"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/poolmetrics"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/revocationmetrics"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/authserver/internal/tokenmetrics"
	"github.com/leodip/goiabada/authserver/internal/turnstile"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hostport"
	"github.com/leodip/goiabada/core/httpmw"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/requestid"
	"github.com/leodip/goiabada/core/routing"
)

type Server struct {
	router *routing.Router
	// The whole interface, and one of the four places that still holds it: routes.go hands this
	// to every constructor and each one narrows it to a port of its own (#386 decision 8).
	database data.Database
	// The concrete store rather than sessionstore.Store: routes.go hands it to the two
	// constructors whose ports name a rotation, which is what proves at compile time that the
	// store this server runs rotates the session identifier at sign-in (#431). A
	// ConditionalStore, because that rotation is its conditional one, as are the ceremony's
	// saves and clears (#579).
	sessionStore *sessionstore.ConditionalStore
	// Built by main from the configured data key and handed to every consumer routes.go
	// constructs, so no service reads a process-wide key (#434).
	dataCipher *encryption.DataCipher
	worker     *cleanup.Worker
	// The work handlers hand off to run after their responses, waited for on shutdown once the
	// listeners have drained (#404 decision 8).
	jobs *afterresponse.Jobs

	// Parsed by main, which refuses to start on a malformed entry (#425), so the real-IP
	// middleware takes ranges and has no error path of its own.
	trustedProxies []*net.IPNet

	staticFS   fs.FS
	templateFS fs.FS

	// Loaded once by main and read here and in routes.go wherever a listener, a middleware or a
	// handler needs a setting, so nothing below main reads a process-wide configuration (#434).
	cfg *config.Config

	// The families this server exposes on its metrics listener, registered at startup: the build
	// stamp, the runtime gauges and the database pool here, the HTTP requests where initMiddleware mounts their
	// middleware (#400).
	metrics *metrics.Registry

	// The HTTP metrics' middleware initMiddleware mounts on the router, kept so the redirect-only HTTP
	// listener counts into the same two families rather than registering them again (#715).
	httpMetrics func(http.Handler) http.Handler

	// The tokens this server issues and the token requests it refuses, counted on the metrics
	// listener. Registered here rather than in initRoutes because the token endpoint's branch, which
	// initMiddleware builds, counts the refusals its faults answer too (#400 decision 5).
	tokenMetrics *tokenmetrics.Recorder

	// The requests the revocation endpoint answers, by outcome (#676 decision 11). Registered here
	// for the reason tokenMetrics is: the endpoint's branch counts the faults it answers too.
	revocationMetrics *revocationmetrics.Recorder

	// The requests the introspection endpoint answers, by outcome (#676 decision 11), registered here
	// for the same reason.
	introspectionMetrics *introspectionmetrics.Recorder

	// The Turnstile challenge's check, through which the forms that carry it verify a submission's
	// token with Cloudflare, counting each check on the metrics listener (#642 decisions 3 and 4).
	// Built here, beside the other counters, over the data cipher its secret key is sealed under.
	challengeVerifier handlers.ChallengeVerifier

	// The same verifier's check of a secret key, which the admin API's Turnstile save asks before it
	// puts a secret key in use (#642 decision 11).
	secretKeyChecker *turnstile.Verifier
}

func NewServer(router *routing.Router, database data.Database, sessionStore *sessionstore.ConditionalStore,
	dataCipher *encryption.DataCipher, trustedProxies []*net.IPNet, cfg *config.Config) *Server {

	registry := metrics.NewRegistry()
	challengeVerifier := turnstile.NewVerifier(registry, dataCipher, cfg.AuthServer.BaseURL, turnstile.SiteverifyURL)
	s := Server{
		router:       router,
		database:     database,
		sessionStore: sessionStore,
		dataCipher:   dataCipher,
		worker:       cleanup.New(database, registry),
		jobs:         afterresponse.New(registry),

		trustedProxies: trustedProxies,

		cfg: cfg,

		metrics: registry,

		tokenMetrics:         tokenmetrics.Register(registry),
		revocationMetrics:    revocationmetrics.Register(registry),
		introspectionMetrics: introspectionmetrics.Register(registry),

		challengeVerifier: challengeVerifier,
		secretKeyChecker:  challengeVerifier,
	}
	metrics.RegisterBuildInfo(s.metrics)
	metrics.RegisterRuntime(s.metrics)
	poolmetrics.Register(s.metrics, database)

	if envVar := cfg.AuthServer.StaticDir; len(envVar) == 0 {
		s.staticFS = web.StaticFS()
		slog.Info("using the embedded static files")
	} else {
		s.staticFS = os.DirFS(envVar)
		slog.Info("using static files from a directory", "directory", envVar)
	}

	if envVar := cfg.AuthServer.TemplateDir; len(envVar) == 0 {
		s.templateFS = web.TemplateFS()
		slog.Info("using the embedded template files")
	} else {
		s.templateFS = os.DirFS(envVar)
		slog.Info("using template files from a directory", "directory", envVar)
	}

	return &s
}

// Start brings up the listeners and blocks until ctx is cancelled or a listener fails. On both it
// drains in-flight requests, waits for the work they handed off, and then stops the worker before
// returning. It returns nil after a
// cancellation, and otherwise the error, unlogged: main writes the one record for it and owns the
// exit, so nothing below main decides to end the process (#426, #390).
//
// drained reports whether nothing that uses the database is still running when it returns: every
// request finished within the shutdown timeout, and so did the handed-off work and the worker. main
// closes the database only then. A refusal before anything started has started nothing, so it is
// drained too.
func (s *Server) Start(ctx context.Context) (drained bool, err error) {
	httpsHost := s.cfg.AuthServer.ListenHostHttps
	httpsPort := s.cfg.AuthServer.ListenPortHttps
	certFile := s.cfg.AuthServer.CertFile
	keyFile := s.cfg.AuthServer.KeyFile
	httpHost := s.cfg.AuthServer.ListenHostHttp
	httpPort := s.cfg.AuthServer.ListenPortHttp
	httpsEnabled, httpEnabled := s.logListenerConfiguration(ctx)

	// The metrics listener is enabled by its own setting rather than by a host and port, since its
	// defaults are both set; it does not count as a listener below, because it answers no client.
	metricsEnabled := s.cfg.AuthServer.MetricsEnabled
	metricsHost := s.cfg.AuthServer.ListenHostMetrics
	metricsPort := s.cfg.AuthServer.ListenPortMetrics

	slog.InfoContext(ctx, "metrics listener configuration",
		"enabled", metricsEnabled,
		"host", metricsHost,
		"port", metricsPort)

	// Refused before anything starts: the worker would otherwise be left running, and the routes
	// half built, behind a process that is about to exit.
	if !httpsEnabled && !httpEnabled {
		return true, errs.New("no listener is enabled, so the auth server cannot start: configure at least one of the http and https listeners")
	}

	s.registerRoutes()

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
		httpServer := newHTTPServer(httpHost, httpPort, s.httpListenerHandler())
		listeners = append(listeners, listener{
			server: httpServer,
			serve:  httpServer.ListenAndServe,
		})
		slog.InfoContext(ctx, "starting the http listener", "host", httpHost, "port", httpPort)
	}

	// Built by the same constructor, so it carries the same bounds, and drained with the others, so
	// a scrape in flight at shutdown is answered. A port it cannot bind stops the server as theirs
	// does (#400 decision 3).
	if metricsEnabled {
		metricsServer := newHTTPServer(metricsHost, metricsPort, metricsHandler(s.metrics))
		listeners = append(listeners, listener{
			server: metricsServer,
			serve:  metricsServer.ListenAndServe,
		})
		slog.InfoContext(ctx, "starting the metrics listener", "host", metricsHost, "port", metricsPort)
	}

	s.worker.Start()

	return serveAndDrain(ctx, listeners, httpShutdownTimeout, s.stopBackgroundWork)
}

// logListenerConfiguration writes the start's records about the HTTPS and HTTP listeners, and
// reports which of the two the configuration enables.
func (s *Server) logListenerConfiguration(ctx context.Context) (httpsEnabled, httpEnabled bool) {
	httpsHost := s.cfg.AuthServer.ListenHostHttps
	httpsPort := s.cfg.AuthServer.ListenPortHttps
	certFile := s.cfg.AuthServer.CertFile
	keyFile := s.cfg.AuthServer.KeyFile
	httpsEnabled = httpsHost != "" && httpsPort > 0 && certFile != "" && keyFile != ""

	// One record per listener where five and three lines used to be. A reader
	// checking why HTTPS is off had to join "https enabled: false" to four
	// separate lines to see which of the four settings was the empty one (#320).
	slog.InfoContext(ctx, "https listener configuration",
		"enabled", httpsEnabled,
		"host", httpsHost,
		"port", httpsPort,
		"cert_file", certFile,
		"key_file", keyFile)

	httpHost := s.cfg.AuthServer.ListenHostHttp
	httpPort := s.cfg.AuthServer.ListenPortHttp
	httpEnabled = httpHost != "" && httpPort > 0

	if httpEnabled {
		// What the listener does, while it is on: an operator reading a redirect loop at start finds
		// it here (#715 decision 11).
		mode := "serves"
		if s.httpListenerRedirects() {
			mode = "redirects"
		}
		slog.InfoContext(ctx, "http listener configuration",
			"enabled", httpEnabled,
			"host", httpHost,
			"port", httpPort,
			"mode", mode)
	} else {
		slog.InfoContext(ctx, "http listener configuration",
			"enabled", httpEnabled,
			"host", httpHost,
			"port", httpPort)
	}

	if httpEnabled && !httpsEnabled {
		logPlainHTTP(s.cfg.AuthServer.BaseURL, s.cfg.AuthServer.TrustProxyHeaders)
	}

	// The HTTPS listener on, under a base URL whose scheme says otherwise, is a deployment whose
	// cookies are not Secure and which sends no HSTS, whichever listener a browser reaches (#715
	// decision 5).
	if httpsEnabled && !s.cfg.AuthServer.IsCookieSecure() {
		slog.WarnContext(ctx, "the auth server's HTTPS listener serves a deployment whose base URL is http, so its cookies aren't Secure and it sends no HSTS")
	}

	return httpsEnabled, httpEnabled
}

// httpListenerRedirects reports whether the HTTP listener only redirects: the base URL is https and
// the proxy headers are untrusted, so nothing says a proxy that ends TLS stands in front of the
// listener, and a client reaching it reaches it directly over plain HTTP (#715 decisions 1 and 2).
// With trust on, the browser's side of the connection is the proxy's HTTPS, and the listener serves.
func (s *Server) httpListenerRedirects() bool {
	return s.cfg.AuthServer.IsCookieSecure() && !s.cfg.AuthServer.TrustProxyHeaders
}

// httpListenerHandler is the handler Start gives the HTTP listener: the router, unless the listener
// only redirects. Call it after registerRoutes, whose root chain the redirecting handler shares the
// HTTP metrics of.
func (s *Server) httpListenerHandler() http.Handler {
	if !s.httpListenerRedirects() {
		return s.router
	}
	return s.redirectingRouter()
}

// redirectingRouter is the redirect-only HTTP listener's handler. GET and HEAD /health are answered
// as the router answers them, so a health check pointed at the listener keeps working; every other
// request, of any method and on any path, is a 301 to the base URL's origin with the request's own
// path and query (#715 decision 3, RFC 6797 section 7.2).
//
// It runs the router's root middleware that applies to an answer that is never a page: the request
// id, the security headers with HSTS off (RFC 6797 section 7.2 forbids it over plain HTTP, and
// decision 9 keeps the baseline headers on every answer), the real IP with the proxy headers
// untrusted, as they are in this mode, the request log, the HTTP metrics and the panic recovery. No
// CORS, slash strip, body limit or CSRF check: nothing here reads a body, a session or a path
// beyond the one it copies, and nothing sets a cookie.
func (s *Server) redirectingRouter() *routing.Router {
	redirect := httpsRedirect(s.cfg.AuthServer.BaseURL)

	r := routing.New()
	r.Use(requestid.Middleware)
	r.Use(httpmw.SecurityHeaders(false))
	r.Use(httpmw.RealIP(false, s.trustedProxies))
	r.Use(httpmw.RequestLogger(s.cfg.AuthServer.LogHttpRequests))
	r.Use(s.httpMetrics)
	r.Use(httpmw.Recoverer)

	// Counted under /health, as the router counts it, through the route of the same name.
	getAndHead(r, "/health", handlers.HandleHealthCheckGet())
	// Every other method of /health, which the router would answer 405, and every path no route
	// matches, the non-canonical ones such as "//host/x" included.
	r.Handle("/health", redirect)
	r.NotFound(redirect.ServeHTTP)
	return r
}

// httpsRedirect answers every request with a 301 to baseURL's scheme, host and port followed by the
// request's path and query, counted under the route value https_redirect. The origin comes from the
// base URL alone, never from the Host field or the request target's authority, which the client
// chooses: either would make the listener an open redirect (#715 decision 3). The base URL's own
// path is not added. The answer is net/http's: Location, and for GET and HEAD its short hypertext
// note (RFC 9110 section 15.4.2).
func httpsRedirect(baseURL string) http.Handler {
	origin := httpsOrigin(baseURL)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metrics.NameRoute(r, metrics.RouteHTTPSRedirect)
		target := r.URL.EscapedPath()
		if target == "" {
			target = "/"
		}
		if r.URL.ForceQuery || r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		//nolint:gosec // G710: the configured base URL's origin, never the Host or the target's authority, then the request's own path and query
		http.Redirect(w, r, origin+target, http.StatusMovedPermanently)
	})
}

// httpsOrigin is an https base URL's origin: https://, then its host and port as configured, with
// no path, query or fragment.
func httpsOrigin(baseURL string) string {
	authority := strings.TrimSpace(baseURL)[len("https://"):]
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	// Userinfo has no place in a redirect target; it is dropped as url.URL.Host drops it.
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}
	return "https://" + authority
}

// metricsHandler is the metrics listener's whole handler: a mux of its own answering GET /metrics
// with reg's exposition and 404 for every other path. It is never Go's default mux, on which the
// net/http/pprof and expvar packages would register /debug/pprof/ and /debug/vars, were either
// linked (rule 9 refuses both in every shipped binary, #462), and nothing on it passes through the
// main router's chain, so a scrape is neither logged by the request logger nor counted in the HTTP
// metrics (#400 decision 3).
func metricsHandler(reg *metrics.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", reg.Handler())
	return mux
}

// getAndHead registers handler for GET and for HEAD on pattern. RFC 9110 section 9.1 has a
// general-purpose server support both, and section 9.3.2 has a HEAD answered as the GET would be,
// with the same header fields and no content, which is what net/http does by itself: its
// ResponseWriter discards what a handler writes for a HEAD request, and http.FileServer and
// http.Redirect answer HEAD on their own. It is for the read-only resources a cache, a monitor or a
// link checker may probe, and only those: an endpoint whose GET starts or changes something, such
// as /auth/authorize, stays GET-only, so a HEAD there is 405 with Allow naming GET.
func getAndHead(r *routing.Router, pattern string, handler http.HandlerFunc) {
	r.Get(pattern, handler)
	r.Head(pattern, handler)
}

// registerRoutes mounts everything this server answers on s.router: the root chain, the static
// branch and the application branches, in that order. All are registered on s.router; only the
// application branches carry the middleware initMiddleware returns, which is what keeps a
// stylesheet from costing a settings read and a session load (see initMiddleware).
func (s *Server) registerRoutes() {
	branches := s.initMiddleware()

	s.serveStaticFiles()

	// Browsers auto-probe /favicon.ico at the site root regardless of the
	// <link rel="icon"> tags; point it at the real asset under /static.
	getAndHead(s.router, "/favicon.ico", http.RedirectHandler("/static/favicon/favicon.ico", http.StatusMovedPermanently).ServeHTTP)

	// Beside the static branch rather than on the application branch, so the probes' endpoint
	// passes through none of the settings read and the session load, and answers whenever the process is up
	// (see handlers.HandleHealthCheckGet, #390).
	getAndHead(s.router, "/health", handlers.HandleHealthCheckGet())

	s.initRoutes(branches)
}

// stopBackgroundWork is what Start does once every listener has drained: it waits for the jobs the
// handlers handed off to run after their responses, then stops the cleanup worker.
//
// The jobs come first because nothing can start another once the listeners are down, and each one
// is a request's unfinished business, a forgot-password request's code, record and mail, which a
// graceful stop should not lose. They are given the shutdown timeout the requests themselves were
// given, and one still running after it is left to the process's exit (#404 decision 8).
//
// It reports whether both finished: false means a job or a sweep may still be using the database.
func (s *Server) stopBackgroundWork() bool {
	jobsDone := s.jobs.Wait(httpShutdownTimeout)
	if !jobsDone {
		slog.Warn("the work handed off after responses did not finish within the timeout, continuing shutdown",
			"timeout", httpShutdownTimeout)
	}
	workerDone := s.worker.Stop(workerStopTimeout)
	return jobsDone && workerDone
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
//
// drained reports whether everything stopped: every listener shut down within shutdownTimeout, so
// no handler is still running, and afterDrain reported its own work done. Shutdown returns at its
// deadline with handlers still running, so a false here means something may still be using the
// database, and main leaves it open for the process exit rather than close it under them.
func serveAndDrain(ctx context.Context, listeners []listener, shutdownTimeout time.Duration,
	afterDrain func() bool) (drained bool, err error) {
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

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	drained = true
	for _, l := range listeners {
		if shutdownErr := l.server.Shutdown(shutdownCtx); shutdownErr != nil {
			drained = false
			slog.ErrorContext(ctx, "unable to shut down a listener", "address", l.server.Addr, "error", shutdownErr)
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

	if !afterDrain() {
		drained = false
	}
	slog.InfoContext(ctx, "shutdown complete")

	return drained, errs.Join(failed...)
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

	// readTimeout bounds the whole request, header and body. net/http starts it as it begins reading
	// the request: on a new connection once any TLS handshake is done, on a kept-alive one once the
	// next request's first bytes have arrived. 60s carries a 3 MiB profile picture or logo upload at
	// about 53 KB/s.
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
	// httpShutdownTimeout bounds how long in-flight requests get to finish, and then, separately,
	// how long the work they handed off to run after their responses gets.
	httpShutdownTimeout = 15 * time.Second

	// workerStopTimeout bounds the wait for the background worker. Cancelling now reaches
	// the statement, since every data.Database call takes the worker's context (#386), so
	// this is no longer the only thing bounding a cleanup delete -- it is the ceiling for
	// the case where the driver does something else with the cancellation than stop.
	workerStopTimeout = 20 * time.Second
)

// initMiddleware mounts the chain and returns the branches the application's own routes
// belong on.
//
// Two branches, and the split is the point (#266). Everything mounted on s.router below
// applies to every request this server answers, a stylesheet included: the CORS answer,
// the request id, the security headers, the real client IP, the panic recovery, the
// request log, the slash strip and the CSRF origin check. What the returned branches add
// is the part a file server has no use for and cannot use: the settings read, the cookie
// reset, the session load and the locale resolution. There are three of them, one per
// format a route answers a fault in (see appBranches, #435).
//
// The cost that split removes is not hypothetical. An auth page references seven
// same-origin assets, and middleware.Settings reads settings from the database uncached on
// every request, so a single page view already cost seven database reads for files that
// could not use the result. Once the session moved out of the cookie and into a row, each
// of those would have cost a session read as well.
//
// It is a correctness fix too. httpmw.CookieReset answers a cookie it cannot decode
// with a 302 back to the request target, which is not a sensible answer to a request for
// a stylesheet.
//
// The router refuses Use after a route has been registered on the same router, and With
// freezes the parent's chain, so this is a restructure rather than a reorder: every root Use
// happens here, before the branches, and every branch registers its routes afterwards.
func (s *Server) initMiddleware() appBranches {

	slog.Info("initializing middleware")

	// Request ID: the X-Request-Id the request arrived with, or one minted as chi minted them
	// (#462 decision 6), on the context of every record, audit event and error page below.
	s.router.Use(requestid.Middleware)

	// Security headers (before Recoverer so 500 responses carry them too)
	s.router.Use(httpmw.SecurityHeaders(s.cfg.AuthServer.IsCookieSecure()))

	// Real IP: resolve the client IP into r.RemoteAddr from the socket peer and
	// (when trusted) the forwarded headers, so all downstream consumers (rate
	// limiter, session/audit IP, request logger) share one trustworthy value.
	s.router.Use(httpmw.RealIP(
		s.cfg.AuthServer.TrustProxyHeaders,
		s.trustedProxies,
	))

	// HTTP request logging, mounted ABOVE Recoverer. Replaces chi's middleware.Logger, which
	// wrote the raw request target to stdout, query string and all, so an id_token_hint JWT
	// landed in the log in full (#159). The redaction lives in the middleware.
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
	// It stays above StripTrailingSlash, which edits r.URL.Path in place, and renders the target
	// before calling the next handler, so its record carries the path the client sent.
	logHttpRequests := s.cfg.AuthServer.LogHttpRequests
	slog.Info("http request logging configured", "enabled", logHttpRequests)
	s.router.Use(httpmw.RequestLogger(logHttpRequests))

	// HTTP metrics: every request this router answers, by route, method and status. Beside the
	// request logger and for the same reason, above Recoverer, so a panicking request is counted as
	// the 500 its client received (#400). The route label's set is this router's own table, read
	// once at the first request, by which time registerRoutes has registered every route.
	s.httpMetrics = metrics.HTTPRequests(s.metrics, s.router)
	s.router.Use(s.httpMetrics)

	// Recoverer, beneath the request logger so the 500 it writes reaches that logger's
	// wrapped writer and lands in the record (#203). It writes the panic's one ERROR record, with
	// the request id and the stack, through the process's log handler (#462).
	s.router.Use(httpmw.Recoverer)

	// CORS, beneath everything above so a preflight, which it answers before any route, carries the
	// security headers, Strict-Transport-Security over HTTPS included, and its request id, leaves a
	// request-log record and a metrics sample under the route value preflight, and is answered 500
	// when its origin lookup panics (#715 decision 6). Above StripTrailingSlash: it normalizes the
	// trailing slash of the paths it covers itself.
	s.router.Use(middleware.CORS(s.database))

	// One trailing slash stripped before routing, from r.URL.Path itself, so the router, the
	// lookups below and the handlers all read the stripped path (#462).
	s.router.Use(httpmw.StripTrailingSlash)

	// Request-body limits, one per route from bodyLimitPolicy (#426). After StripTrailingSlash,
	// because the lookup resolves the route by the path it stripped; before httpmw.SkipCSRF,
	// because the /auth/logout exemption predicate parses the form body right there at the root,
	// and a body read before this mount would be read without a bound.
	s.router.Use(httpmw.BodyLimit(s.router,
		bodyLimitPolicy(s.cfg.AuthServer.ProfilePictureMaxSizeBytes)))

	// CSRF
	// Note: CSRF runs before the locale middleware below, so there is no localizer on the context
	// when a request is rejected. httpmw.CSRF resolves a tentative one of its own through
	// i18n.ResolveRequestLocale, so the rejection is localized without moving the origin check
	// down onto the application branch, where a route registered outside that branch would
	// escape it.
	//
	// httpmw.SkipCSRF marks the endpoints that are cross-origin by protocol, and httpmw.CSRF
	// refuses every other state-changing cross-origin request outright, trusting no origin but this
	// deployment's own (#155). httpmw.CSRF takes no configuration; httpmw.SkipCSRF takes this
	// server's own exemption policy, which until #385 was a table in core naming both binaries'
	// routes, so each exempted the other's.
	s.router.Use(httpmw.SkipCSRF(csrfPolicy()))
	s.router.Use(httpmw.CSRF())

	// Everything below is on the application branch, not the root.

	branches := appBranches{
		pages:      s.router.With(s.pageChain()...),
		files:      s.router.With(s.applicationChain(middleware.PageFaults())...),
		protocol:   s.router.With(s.applicationChain(middleware.ProtocolFaults(render.New(s.templateFS, s.staticFS)))...),
		token:      s.router.With(s.applicationChain(middleware.ProtocolFaults(s.tokenMetrics.Refusals(render.New(s.templateFS, s.staticFS))))...),
		revoke:     s.router.With(s.applicationChain(middleware.ProtocolFaults(handlers.RevocationFaults(render.New(s.templateFS, s.staticFS), s.revocationMetrics)))...),
		introspect: s.router.With(s.applicationChain(middleware.ProtocolFaults(handlers.IntrospectionFaults(render.New(s.templateFS, s.staticFS), s.introspectionMetrics)))...),
		api:        s.router.With(s.applicationChain(middleware.APIFaults())...),
	}

	slog.Info("finished initializing middleware")

	return branches
}

// applicationChain is the application branch's own middleware, beneath the root's, answering what
// stops a request before its handler through faults. The branches initMiddleware builds run this
// same middleware in the same order and differ only in faults: the settings or the session could not
// be read, or something panicked. The static branch puts the page branch's in front of the 404 page
// it answers a directory with, the one request there that needs it.
func (s *Server) applicationChain(faults middleware.ServerFaults) []func(http.Handler) http.Handler {
	// Global locale middleware: resolves a tentative localizer from
	// ?ui_locales, UI locales from an in-flight authorize flow,
	// Accept-Language, or English. Must run AFTER middleware.SessionIdentifier
	// so the session is decoded — the reader gets UI locales from session-backed
	// authorize state. A known user's page language goes over it on the page
	// branch alone (pageChain).
	i18nCeremonyStore := ceremony.NewStore(s.sessionStore, sessionkeys.AuthServerSessionName)

	return []func(http.Handler) http.Handler{
		// Answers a panic on the branch in the branch's format; on the page branch it is a
		// pass-through and the root Recoverer answers
		faults.Recoverer,

		// Adds settings to the request context
		middleware.Settings(s.database, faults),

		// Clear the session cookie and redirect if unable to decode it, and delete
		// whatever the chunked cookie store left in this browser
		httpmw.CookieReset(s.sessionStore, sessionkeys.AuthServerSessionName),

		// Adds the session identifier (if available) to the request context
		middleware.SessionIdentifier(s.sessionStore, s.database, faults),

		i18n.Locale(i18nCeremonyStore),
	}
}

// pageChain is the page branch's middleware: the application chain, then the page language of the
// user a page is drawn for, over what the locale middleware resolved (#631 decision 5). The other
// branches answer protocol clients and the APIs, whose refusals keep the language the request asks
// for.
func (s *Server) pageChain() []func(http.Handler) http.Handler {
	return append(s.applicationChain(middleware.PageFaults()),
		middleware.PageLanguage(ceremony.NewStore(s.sessionStore, sessionkeys.AuthServerSessionName), s.database))
}

// appBranches is the application branch in its answering formats, and on pages with and without
// the page language, which initMiddleware returns and initRoutes registers every application route
// on. A route goes on the branch of the format its
// handler answers every other fault in, so a client parsing a protocol endpoint or an API as JSON is
// not handed text/plain when the settings or the session cannot be read, or an empty body when
// something panics. The format is chosen by where routes.go registers a route and never read off the
// request path, as the bearer guards' refusals are (#435).
type appBranches struct {
	// pages carries everything that answers a page, text or a redirect, and answers such a fault in
	// text/plain, as every route did before #435.
	pages *routing.Router
	// files carries the images and the OpenAPI document. It answers a fault as pages does, and leaves
	// out the page language, which only a drawn page uses, so an image costs no read of its user
	// (#631).
	files *routing.Router
	// protocol carries the endpoints that answer RFC 6749 section 5.2's {error, error_description}:
	// token, userinfo, JWKS, discovery and dynamic client registration.
	protocol *routing.Router
	// api carries the admin, account and session APIs and the public settings, which answer the
	// {error_code, error_description} envelope.
	api *routing.Router
	// token carries the token endpoint alone. It answers as protocol does, and counts each fault it
	// answers as a token request refused, which the protocol branch cannot, since its faults are
	// every protocol endpoint's (#400 decision 5).
	token *routing.Router
	// revoke carries the revocation endpoint alone. It answers a fault as its handler answers its
	// own, 503, on which the client treats the token as still live (RFC 7009 section 2.2.1), and
	// counts it as an error, which the protocol branch's 500 would not say (#676 decision 12).
	revoke *routing.Router
	// introspect carries the introspection endpoint alone. It answers a fault as protocol does, 500
	// and never {"active": false}, and counts it as an error, which the protocol branch cannot (#676
	// decisions 11 and 13).
	introspect *routing.Router
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
func csrfPolicy() httpmw.CSRFPolicy {
	return httpmw.CSRFPolicy{
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

			// OAuth2 token revocation (POST, RFC 7009). The client authenticates as at the token
			// endpoint, or a public client names itself, and sends a token it holds; no session
			// cookie is read, and a cross-site POST can only end a grant whose token it already
			// has. A browser app revokes at sign-out from its own origin (#676).
			"/auth/revoke",

			// OAuth2 token introspection (POST, RFC 7662). An API's confidential client
			// authenticates with its secret and sends a token; no session cookie is read, and the
			// caller cannot authenticate without the secret a cross-site page does not have (#676).
			"/auth/introspect",

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
			"/auth/logout": middleware.LogoutIdTokenHintPresent,
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
// read, looked up by httpmw.BodyLimit at the root. A route missing from it gets
// defaultBodyLimit, the smallest limit here, so an omission is a refused request rather than an
// unbounded read.
//
// Every limit is at least the bound of the handler inside it, so a handler that bounds its own
// body keeps answering for it: the uploads, the session endpoints and the account OTP PUT.
//
// profilePictureMaxSizeBytes is GOIABADA_PROFILE_PICTURE_MAX_SIZE_BYTES, read once at startup, so
// raising it raises the upload rows with it. config.Load holds it positive and at most
// config.MaxProfilePictureMaxSizeBytes, which is what keeps the sum below from wrapping (#435).
func bodyLimitPolicy(profilePictureMaxSizeBytes int64) httpmw.BodyLimitPolicy {
	uploadLimit := profilePictureMaxSizeBytes + uploadMultipartAllowance

	return httpmw.BodyLimitPolicy{
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

// staticPrefix is where the static files are served, and what is stripped from a request's path to
// name the file.
const staticPrefix = "/static"

// serveStaticFiles serves the embedded static files under /static/. They are mounted nowhere else,
// so neither the path nor the file system is a parameter.
//
// A directory is the 404 page, /static/ itself included, where Go's file server answered one with
// a listing of its files (#462 decision 7). /static has no route, so it is the router's 404 page
// too: it redirected to /static/, which looped for ever once its trailing slash was stripped back to
// /static. The 404 page is drawn behind the page branch's chain, which it reads its settings and
// language from, so a directory costs what an unmatched path costs; a file still costs neither.
func (s *Server) serveStaticFiles() {
	files := http.StripPrefix(staticPrefix, http.FileServer(http.FS(s.staticFS)))
	notFound := handlers.HandleNotFoundGet(render.New(s.templateFS, s.staticFS))
	directory := http.Handler(notFound)
	chain := s.pageChain()
	for i := len(chain) - 1; i >= 0; i-- {
		directory = chain[i](directory)
	}

	getAndHead(s.router, staticPrefix+"/*", func(w http.ResponseWriter, r *http.Request) {
		if s.isStaticDirectory(r.URL.Path) {
			directory.ServeHTTP(w, r)
			return
		}

		cacheInSeconds := 5 * 60
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%v", cacheInSeconds))
		w.Header().Set("Expires", time.Now().UTC().Add(time.Second*time.Duration(cacheInSeconds)).Format(http.TimeFormat))
		w.Header().Set("Vary", "Accept-Encoding")

		files.ServeHTTP(w, r)
	})
}

// isStaticDirectory reports whether urlPath, under /static, names a directory of the static files,
// the root among them. The name is read as http.FileServer reads it, so the two agree on what is
// opened; a name that is not there is no directory, and the file server answers its 404.
func (s *Server) isStaticDirectory(urlPath string) bool {
	name := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(urlPath, staticPrefix)), "/")
	if name == "" {
		return true
	}
	info, err := fs.Stat(s.staticFS, name)
	return err == nil && info.IsDir()
}

// logPlainHTTP reports a deployment listening on HTTP with no HTTPS listener. Behind a proxy
// that says so, an https base URL with the forwarded headers trusted, as every configuration the
// setup wizard writes for a proxy sets, that is the deployment working as intended, and the record
// is Info: as a Warn it greeted every healthy install behind a proxy with a warning (#542).
// With an https base URL and trust off, the listener only redirects, so the server serves nothing
// at all; the Warn names both ways out, the second being what a proxy that ends TLS and left trust
// off, looping on the redirect, needs (#715 decision 11). Otherwise nothing says a proxy ends TLS
// in front of the server, and it stays the Warn #320 decision 6 collapsed from an eleven-line
// banner. The other server's copy is the same records about itself: each names the server it is
// about, and neither module imports the other.
func logPlainHTTP(baseURL string, trustProxyHeaders bool) {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(baseURL)), "https://") {
		if trustProxyHeaders {
			slog.Info("the auth server is listening on HTTP behind a reverse proxy that terminates HTTPS")
			return
		}
		slog.Warn("the auth server's HTTP listener only redirects to its https base URL, and its HTTPS listener is off",
			"remedy", "configure the HTTPS listener, or, behind a reverse proxy that terminates HTTPS, turn on GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS")
		return
	}
	slog.Warn("the auth server is listening on HTTP with no TLS, which is insecure outside development unless a reverse proxy in front of it terminates HTTPS",
		"remedy", "configure the HTTPS listener, or make sure the reverse proxy handles HTTPS")
}
