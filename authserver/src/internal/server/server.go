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
	"github.com/leodip/goiabada/web"

	"log/slog"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/leodip/goiabada/internal/security"

	"github.com/spf13/viper"
)

type Server struct {
	router       *chi.Mux
	database     data.Database
	sessionStore sessions.Store
	tokenParser  *security.TokenParser

	staticFS   fs.FS
	templateFS fs.FS
}

func NewServer(router *chi.Mux, database data.Database, sessionStore sessions.Store) *Server {

	s := Server{
		router:       router,
		database:     database,
		sessionStore: sessionStore,
		tokenParser:  security.NewTokenParser(database),
	}

	if envVar := viper.GetString("StaticDir"); len(envVar) == 0 {
		s.staticFS = web.StaticFS()
		slog.Info("using embedded static files directory")
	} else {
		s.staticFS = os.DirFS(envVar)
		slog.Info(fmt.Sprintf("using static files directory %v", envVar))
	}

	if envVar := viper.GetString("TemplateDir"); len(envVar) == 0 {
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
	certFile := viper.GetString("CertFile")
	keyFile := viper.GetString("KeyFile")

	if len(certFile) == 0 {
		slog.Info("TLS cert file not set")
	} else {
		slog.Info(fmt.Sprintf("cert file: %v", certFile))
	}

	if len(keyFile) == 0 {
		slog.Info("TLS key file not set")
	} else {
		slog.Info(fmt.Sprintf("key file: %v", keyFile))
	}

	consoleLogEnabled := viper.GetBool("Auditing.ConsoleLog.Enabled")
	slog.Info(fmt.Sprintf("auditing console log enabled: %v", consoleLogEnabled))

	host := strings.TrimSpace(viper.GetString("Host"))
	port := strings.TrimSpace(viper.GetString("Port"))
	slog.Info("base url: " + lib.GetBaseUrl())

	if lib.IsHttpsEnabled() {
		if !strings.HasPrefix(settings.Issuer, "https://") {
			slog.Warn(fmt.Sprintf("https is enabled but the issuer '%v' is not using https. Please review your configuration.", settings.Issuer))
		}
		if !strings.HasPrefix(lib.GetBaseUrl(), "https://") {
			slog.Warn(fmt.Sprintf("https is enabled but the base url '%v' is not using https. Please review your configuration.", lib.GetBaseUrl()))
		}
		slog.Info(fmt.Sprintf("listening on host:port %v:%v (https)", host, port))
		log.Fatal(http.ListenAndServeTLS(fmt.Sprintf("%v:%v", host, port), certFile, keyFile, s.router))
	} else {
		// non-TLS mode
		if !strings.HasPrefix(settings.Issuer, "http://") {
			slog.Warn(fmt.Sprintf("https is disabled but the issuer '%v' is using https. Please review your configuration.", settings.Issuer))
		}
		if !strings.HasPrefix(lib.GetBaseUrl(), "http://") {
			slog.Warn(fmt.Sprintf("https is disabled but the base url '%v' is using https. Please review your configuration.", lib.GetBaseUrl()))
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
	s.router.Use(MiddlewareCors(s.database))

	// Request ID
	s.router.Use(middleware.RequestID)

	// Real IP
	if viper.GetBool("IsBehindAReverseProxy") {
		slog.Info("adding real ip middleware")
		s.router.Use(middleware.RealIP)
	} else {
		slog.Info("not adding real ip middleware")
	}

	// Recoverer
	s.router.Use(middleware.Recoverer)

	// HTTP request logging
	httpRequestLoggingEnabled := viper.GetBool("Logger.Router.HttpRequests.Enabled")
	if httpRequestLoggingEnabled {
		slog.Info("http request logging enabled")
		s.router.Use(middleware.Logger)
	} else {
		slog.Info("http request logging disabled")
	}

	// Strip slashes
	s.router.Use(middleware.StripSlashes)

	// CSRF
	s.router.Use(MiddlewareSkipCsrf())
	s.router.Use(MiddlewareCsrf(settings))

	// Adds settings to the request context
	s.router.Use(MiddlewareSettings(s.database))

	// Clear the session cookie and redirect if unable to decode it
	s.router.Use(MiddlewareCookieReset(s.sessionStore))

	// Adds the session identifier (if available) to the request context
	s.router.Use(MiddlewareSessionIdentifier(s.sessionStore, s.database))

	// Rate limiter
	rateLimiterEnabled := viper.GetBool("RateLimiter.Enabled")
	if rateLimiterEnabled {
		maxRequests := viper.GetInt("RateLimiter.MaxRequests")
		windowSizeInSeconds := viper.GetInt("RateLimiter.WindowSizeInSeconds")
		slog.Info(fmt.Sprintf("http rate limiter enabled. max requests: %v, window size in seconds: %v", maxRequests, windowSizeInSeconds))
		s.router.Use(MiddlewareRateLimiter(s.sessionStore, maxRequests, windowSizeInSeconds))
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
