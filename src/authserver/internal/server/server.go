package server

import (
    "fmt"
    "io/fs"
    "net/http"
    "os"
    "strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/authserver/web"

	"log/slog"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	authserver_middleware "github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/workers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
    custom_middleware "github.com/leodip/goiabada/core/middleware"
    "github.com/leodip/goiabada/core/models"
)

type Server struct {
    router       *chi.Mux
    database     data.Database
    sessionStore sessions.Store
    worker       *workers.Worker

	staticFS   fs.FS
	templateFS fs.FS

	// Config fields
	baseURL             string
	adminConsoleBaseURL string
	auditLogsInConsole  bool
	setCookieSecure     bool
}

func NewServer(router *chi.Mux, database data.Database, sessionStore sessions.Store) *Server {

    s := Server{
        router:       router,
        database:     database,
        sessionStore: sessionStore,
        worker:       workers.NewWorker(database),

		// Config fields
        baseURL:             config.GetAuthServer().BaseURL,
        adminConsoleBaseURL: config.GetAdminConsole().BaseURL,
		auditLogsInConsole:  config.GetAuthServer().AuditLogsInConsole,
		setCookieSecure:     config.GetAuthServer().SetCookieSecure,
	}

	if envVar := config.GetAuthServer().StaticDir; len(envVar) == 0 {
		s.staticFS = web.StaticFS()
		slog.Info("using embedded static files directory")
	} else {
		s.staticFS = os.DirFS(envVar)
		slog.Info(fmt.Sprintf("using static files directory %v", envVar))
	}

	if envVar := config.GetAuthServer().TemplateDir; len(envVar) == 0 {
		s.templateFS = web.TemplateFS()
		slog.Info("using embedded template files directory")
	} else {
		s.templateFS = os.DirFS(envVar)
		slog.Info(fmt.Sprintf("using template files directory %v", envVar))
	}

	return &s
}

func (s *Server) Start(settings *models.Settings) {
	s.worker.Start()

	s.initMiddleware(settings)

	s.serveStaticFiles("/static", http.FS(s.staticFS))

	s.initRoutes()

	httpsHost := config.GetAuthServer().ListenHostHttps
	httpsPort := config.GetAuthServer().ListenPortHttps
	certFile := config.GetAuthServer().CertFile
	keyFile := config.GetAuthServer().KeyFile
	httpsEnabled := httpsHost != "" && httpsPort > 0 && certFile != "" && keyFile != ""

	slog.Info("listen host https: " + httpsHost)
	slog.Info(fmt.Sprintf("listen port https: %v", httpsPort))
	slog.Info("cert file: " + certFile)
	slog.Info("key file: " + keyFile)
	slog.Info(fmt.Sprintf("https enabled: %v", httpsEnabled))

	httpHost := config.GetAuthServer().ListenHostHttp
	httpPort := config.GetAuthServer().ListenPortHttp
	httpEnabled := httpHost != "" && httpPort > 0

	slog.Info("listen host http: " + httpHost)
	slog.Info(fmt.Sprintf("listen port http: %v", httpPort))
	slog.Info(fmt.Sprintf("http enabled: %v", httpEnabled))

	if httpEnabled && !httpsEnabled {
		slog.Warn("=== WARNING ===")
		slog.Warn("You are running the auth server with HTTP (without TLS/HTTPS).")
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

func (s *Server) initMiddleware(settings *models.Settings) {

	slog.Info("initializing middleware")

	// CORS
	s.router.Use(custom_middleware.MiddlewareCors(s.database))

	// Request ID
	s.router.Use(middleware.RequestID)

	// Real IP
	if config.GetAuthServer().TrustProxyHeaders {
		slog.Info("adding real ip middleware")
		s.router.Use(middleware.RealIP)
	} else {
		slog.Info("not adding real ip middleware")
	}

	// Recoverer
	s.router.Use(middleware.Recoverer)

	// HTTP request logging
	if config.GetAuthServer().LogHttpRequests {
		slog.Info("http request logging enabled")
		s.router.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Skip logging for health check, static files, and favicon
				if r.URL.Path == "/health" ||
					strings.HasPrefix(r.URL.Path, "/static/") ||
					r.URL.Path == "/favicon.ico" {
					next.ServeHTTP(w, r)
					return
				}
				// Use the standard Chi logger for all other routes
				middleware.Logger(next).ServeHTTP(w, r)
			})
		})
	} else {
		slog.Info("http request logging disabled")
	}

	// Strip slashes
	s.router.Use(middleware.StripSlashes)

	// CSRF
	s.router.Use(custom_middleware.MiddlewareSkipCsrf())
	s.router.Use(custom_middleware.MiddlewareCsrf(settings, s.baseURL, s.adminConsoleBaseURL, s.setCookieSecure))

	// Adds settings to the request context
	s.router.Use(custom_middleware.MiddlewareSettings(s.database))

	// Clear the session cookie and redirect if unable to decode it
	s.router.Use(custom_middleware.MiddlewareCookieReset(s.sessionStore, constants.AuthServerSessionName))

	// Adds the session identifier (if available) to the request context
	s.router.Use(authserver_middleware.MiddlewareSessionIdentifier(s.sessionStore, s.database))

	slog.Info("finished initializing middleware")
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
