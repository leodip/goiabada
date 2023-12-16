package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"log/slog"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/gorilla/csrf"
	"github.com/gorilla/securecookie"
	"github.com/leodip/goiabada/internal/common"
	core_token "github.com/leodip/goiabada/internal/core/token"
	"github.com/leodip/goiabada/internal/lib"

	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/sessionstore"
	"github.com/spf13/viper"
)

type Server struct {
	router       *chi.Mux
	database     *data.Database
	sessionStore *sessionstore.MySQLStore
	tokenParser  *core_token.TokenParser
}

func NewServer(router *chi.Mux, database *data.Database, sessionStore *sessionstore.MySQLStore) *Server {

	return &Server{
		router:       router,
		database:     database,
		sessionStore: sessionStore,
		tokenParser:  core_token.NewTokenParser(database),
	}
}

func (s *Server) Start(settings *entities.Settings) {
	s.initMiddleware(settings)

	staticDir := viper.GetString("StaticDir")
	slog.Info(fmt.Sprintf("using static files directory %v", staticDir))
	s.serveStaticFiles("/static", http.Dir(staticDir))

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

func (s *Server) initMiddleware(settings *entities.Settings) {

	slog.Info("initializing middleware")

	// configures CORS
	s.router.Use(cors.Handler(cors.Options{
		AllowOriginFunc: func(r *http.Request, origin string) bool {
			if r.URL.Path == "/.well-known/openid-configuration" || r.URL.Path == "/certs" {
				// always allow the discovery URL
				return true
			} else if r.URL.Path == "/auth/token" || r.URL.Path == "/auth/logout" || r.URL.Path == "/userinfo" {
				// allow when the web origin of the request matches a web origin in the database
				webOrigins, err := s.database.GetAllWebOrigins()
				if err != nil {
					slog.Error(err.Error())
					return false
				}
				for _, or := range webOrigins {
					if or.Origin == origin {
						return true
					}
				}
			}
			return false
		},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
	}))

	s.router.Use(middleware.RequestID)
	if viper.GetBool("IsBehindAReverseProxy") {
		slog.Info("adding real ip middleware")
		s.router.Use(middleware.RealIP)
	} else {
		slog.Info("not adding real ip middleware")
	}

	httpRequestLoggingEnabled := viper.GetBool("Logger.Router.HttpRequests.Enabled")
	if httpRequestLoggingEnabled {
		slog.Info("http request logging enabled")
		s.router.Use(middleware.Logger)
	} else {
		slog.Info("http request logging disabled")
	}
	s.router.Use(middleware.StripSlashes)
	s.router.Use(middleware.Timeout(60 * time.Second))

	// skips csrf for certain routes
	s.router.Use(func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			skip := false
			if strings.HasPrefix(r.URL.Path, "/static") ||
				strings.HasPrefix(r.URL.Path, "/userinfo") ||
				strings.HasPrefix(r.URL.Path, "/auth/token") ||
				strings.HasPrefix(r.URL.Path, "/auth/callback") {
				skip = true
			}
			if skip {
				r = csrf.UnsafeSkipCheck(r)
			}
			next.ServeHTTP(w, r.WithContext(r.Context()))
		}
		return http.HandlerFunc(fn)
	})

	s.router.Use(csrf.Protect(settings.SessionAuthenticationKey, csrf.Secure(lib.IsHttpsEnabled())))

	// injects the application settings in the request context
	s.router.Use(func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			settings, err := s.database.GetSettings()
			if err != nil {
				slog.Error(strings.TrimSpace(err.Error()), "request-id", middleware.GetReqID(r.Context()))
				http.Error(w, fmt.Sprintf("fatal failure in GetSettings() middleware. For additional information, refer to the server logs. Request Id: %v", middleware.GetReqID(r.Context())), http.StatusInternalServerError)
			} else {
				ctx = context.WithValue(ctx, common.ContextKeySettings, settings)
				next.ServeHTTP(w, r.WithContext(ctx))
			}
		}
		return http.HandlerFunc(fn)
	})

	// clear the session cookie and redirect if unable to decode it
	s.router.Use(func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			_, err := s.sessionStore.Get(r, common.SessionName)
			if err != nil {
				multiErr, ok := err.(securecookie.MultiError)
				if ok && multiErr.IsDecode() {
					cookie := http.Cookie{
						Name:    common.SessionName,
						Expires: time.Now().AddDate(0, 0, -1),
						MaxAge:  -1,
						Path:    "/",
					}
					http.SetCookie(w, &cookie)
					http.Redirect(w, r, r.RequestURI, http.StatusFound)
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	})

	// adds the session identifier (if available) to the request context
	s.router.Use(func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			requestId := middleware.GetReqID(ctx)

			errorMsg := fmt.Sprintf("fatal failure in session middleware. For additional information, refer to the server logs. Request Id: %v", requestId)

			sess, err := s.sessionStore.Get(r, common.SessionName)
			if err != nil {
				slog.Error(fmt.Sprintf("unable to get the session store: %v", err.Error()), "request-id", requestId)
				http.Error(w, errorMsg, http.StatusInternalServerError)
				return
			}

			if sess.Values[common.SessionKeySessionIdentifier] != nil {
				sessionIdentifier := sess.Values[common.SessionKeySessionIdentifier].(string)

				userSession, err := s.database.GetUserSessionBySessionIdentifier(sessionIdentifier)
				if err != nil {
					slog.Error(fmt.Sprintf("unable to get the user session: %v", err.Error()), "request-id", requestId)
					http.Error(w, errorMsg, http.StatusInternalServerError)
					return
				}
				if userSession == nil {
					// session has been deleted, will clear the session state
					sess.Values = make(map[interface{}]interface{})
					err = sess.Save(r, w)
					if err != nil {
						slog.Error(fmt.Sprintf("unable to save the session: %v", err.Error()), "request-id", requestId)
						http.Error(w, errorMsg, http.StatusInternalServerError)
						return
					}
				} else {
					ctx = context.WithValue(ctx, common.ContextKeySessionIdentifier, sessionIdentifier)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	})

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
		fs := http.StripPrefix(pathPrefix, http.FileServer(root))

		cacheInSeconds := 5 * 60
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%v", cacheInSeconds))
		w.Header().Set("Expires", time.Now().Add(time.Second*time.Duration(cacheInSeconds)).Format(http.TimeFormat))
		w.Header().Set("Vary", "Accept-Encoding")

		fs.ServeHTTP(w, r)
	})
}
