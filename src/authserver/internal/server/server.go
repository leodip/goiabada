package server

import (
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/authserver/web"

	"log/slog"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/data"
	custom_middleware "github.com/leodip/goiabada/core/middleware"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
)

type Server struct {
	router       *chi.Mux
	database     data.Database
	sessionStore sessions.Store
	tokenParser  *oauth.TokenParser

	staticFS   fs.FS
	templateFS fs.FS
}

func NewServer(router *chi.Mux, database data.Database, sessionStore sessions.Store) *Server {

	s := Server{
		router:       router,
		database:     database,
		sessionStore: sessionStore,
		tokenParser:  oauth.NewTokenParser(database),
	}

	if envVar := config.Get().StaticDir; len(envVar) == 0 {
		s.staticFS = web.StaticFS()
		slog.Info("using embedded static files directory")
	} else {
		s.staticFS = os.DirFS(envVar)
		slog.Info(fmt.Sprintf("using static files directory %v", envVar))
	}

	if envVar := config.Get().TemplateDir; len(envVar) == 0 {
		s.templateFS = web.TemplateFS()
		slog.Info("using embedded template files directory")
	} else {
		s.templateFS = os.DirFS(envVar)
		slog.Info(fmt.Sprintf("using template files directory %v", envVar))
	}

	return &s
}

func (s *Server) Start(settings *models.Settings) {
	s.initMiddleware(settings)

	s.serveStaticFiles("/static", http.FS(s.staticFS))

	s.initRoutes()

	if len(config.Get().CertFile) == 0 {
		slog.Info("TLS cert file not set")
	} else {
		slog.Info(fmt.Sprintf("cert file: %v", config.Get().CertFile))
	}

	if len(config.Get().KeyFile) == 0 {
		slog.Info("TLS key file not set")
	} else {
		slog.Info(fmt.Sprintf("key file: %v", config.Get().KeyFile))
	}

	slog.Info(fmt.Sprintf("audit logs in console enabled: %v", config.Get().AuditLogsInConsole))

	host := strings.TrimSpace(config.Get().Host)
	port := strings.TrimSpace(config.Get().Port)
	slog.Info("host: " + host)
	slog.Info("port: " + port)
	slog.Info("base url: " + config.Get().BaseURL)

	if config.Get().IsHttpsEnabled() {
		if !strings.HasPrefix(config.Get().BaseURL, "https://") {
			slog.Warn(fmt.Sprintf("https is enabled but the base url '%v' is not using https. Please review your configuration.", config.Get().BaseURL))
		}
		slog.Info(fmt.Sprintf("listening on host:port %v:%v (https)", host, port))
		log.Fatal(http.ListenAndServeTLS(fmt.Sprintf("%v:%v", host, port), config.Get().CertFile, config.Get().KeyFile, s.router))
	} else {
		// non-TLS mode
		if !strings.HasPrefix(config.Get().BaseURL, "http://") {
			slog.Warn(fmt.Sprintf("https is disabled but the base url '%v' is using https. Please review your configuration.", config.Get().BaseURL))
		}
		slog.Warn("WARNING: the application is running in an insecure mode (without TLS).")
		slog.Warn("Do not use this mode in production!")
		slog.Info(fmt.Sprintf("listening on host:port %v:%v (http)", host, port))
		log.Fatal(http.ListenAndServe(fmt.Sprintf("%v:%v", host, port), s.router))
	}
}

func (s *Server) initMiddleware(settings *models.Settings) {

	slog.Info("initializing middleware")

	// CORS
	s.router.Use(custom_middleware.MiddlewareCors(s.database))

	// Request ID
	s.router.Use(middleware.RequestID)

	// Real IP
	if config.Get().IsBehindAReverseProxy {
		slog.Info("adding real ip middleware")
		s.router.Use(middleware.RealIP)
	} else {
		slog.Info("not adding real ip middleware")
	}

	// Recoverer
	s.router.Use(middleware.Recoverer)

	// HTTP request logging
	if config.Get().LogHttpRequests {
		slog.Info("http request logging enabled")
		s.router.Use(middleware.Logger)
	} else {
		slog.Info("http request logging disabled")
	}

	// Strip slashes
	s.router.Use(middleware.StripSlashes)

	// CSRF
	s.router.Use(custom_middleware.MiddlewareSkipCsrf())
	s.router.Use(custom_middleware.MiddlewareCsrf(settings))

	// Adds settings to the request context
	s.router.Use(custom_middleware.MiddlewareSettings(s.database))

	// Clear the session cookie and redirect if unable to decode it
	s.router.Use(custom_middleware.MiddlewareCookieReset(s.sessionStore))

	// Adds the session identifier (if available) to the request context
	s.router.Use(custom_middleware.MiddlewareSessionIdentifier(s.sessionStore, s.database))

	// Rate limiter
	if config.Get().RateLimiter.Enabled {
		maxRequests := config.Get().RateLimiter.MaxRequests
		windowSizeInSeconds := config.Get().RateLimiter.WindowSizeInSeconds
		slog.Info(fmt.Sprintf("http rate limiter enabled. max requests: %v, window size in seconds: %v", maxRequests, windowSizeInSeconds))
		s.router.Use(custom_middleware.MiddlewareRateLimiter(s.sessionStore, maxRequests, windowSizeInSeconds))
	} else {
		slog.Info("http rate limiter disabled")
	}

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
