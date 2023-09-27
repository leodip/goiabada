package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	core_token "github.com/leodip/goiabada/internal/core/token"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/sessionstore"
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
)

type Server struct {
	router         *chi.Mux
	database       *data.Database
	sessionStore   *sessionstore.MySQLStore
	tokenValidator tokenValidator
}

func NewServer(router *chi.Mux, database *data.Database, sessionStore *sessionstore.MySQLStore) *Server {
	return &Server{
		router:         router,
		database:       database,
		sessionStore:   sessionStore,
		tokenValidator: core_token.NewTokenValidator(database),
	}
}

func (s *Server) Start(settings *entities.Settings) {
	s.initMiddleware(settings)

	staticDir := viper.GetString("StaticDir")
	slog.Info(fmt.Sprintf("using static files directory %v", staticDir))
	s.serveStaticFiles("/static", http.Dir(staticDir))

	s.initRoutes()
	//log.Fatal(http.ListenAndServe(fmt.Sprintf("%v:%v", viper.GetString("Host"), viper.GetString("Port")), s.router))
	log.Fatal(http.ListenAndServeTLS(fmt.Sprintf("%v:%v", viper.GetString("Host"), viper.GetString("Port")), "/home/leodip/code/cert/localhost.crt", "/home/leodip/code/cert/localhost.key", s.router))
}

func (s *Server) initMiddleware(settings *entities.Settings) {
	s.router.Use(middleware.RequestID)
	s.router.Use(middleware.RealIP)
	s.router.Use(middleware.Logger)
	s.router.Use(middleware.StripSlashes)
	s.router.Use(middleware.Timeout(60 * time.Second))

	s.router.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"https://*", "http://*"},
	}))

	s.router.Use(func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/auth/token") {
				r = csrf.UnsafeSkipCheck(r)
			}
			next.ServeHTTP(w, r.WithContext(r.Context()))
		}
		return http.HandlerFunc(fn)
	})

	s.router.Use(func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", "default-src 'self' https://cdn.jsdelivr.net/ http://goiabada.local:3000/; script-src 'unsafe-inline' http://goiabada.local:3000/; img-src 'self' data:;")
			next.ServeHTTP(w, r.WithContext(r.Context()))
		}
		return http.HandlerFunc(fn)
	})

	mode := viper.GetString("Mode")
	if mode == "dev" {
		// allow non-secure cookies
		s.router.Use(csrf.Protect(settings.SessionAuthenticationKey, csrf.Secure(false)))
	} else {
		s.router.Use(csrf.Protect(settings.SessionAuthenticationKey))
	}

	// this will inject the application settings in the request context
	s.router.Use(func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			settings, err := s.database.GetSettings()
			if err != nil {
				slog.Error(strings.TrimSpace(err.Error()), "request-id", middleware.GetReqID(r.Context()))
				http.Error(w, fmt.Sprintf("failure in GetSettings() middleware. For additional information, refer to the server logs. Request Id: %v", middleware.GetReqID(r.Context())), http.StatusInternalServerError)
			} else {
				ctx = context.WithValue(ctx, common.ContextKeySettings, settings)
				next.ServeHTTP(w, r.WithContext(ctx))
			}
		}
		return http.HandlerFunc(fn)
	})
}

func (s *Server) serveStaticFiles(path string, root http.FileSystem) {

	if strings.ContainsAny(path, "{}*") {
		panic("FileServer does not permit any URL parameters.")
	}

	if path != "/" && path[len(path)-1] != '/' {
		s.router.Get(path, http.RedirectHandler(path+"/", http.StatusMovedPermanently).ServeHTTP)
		path += "/"
	}
	path += "*"

	s.router.Get(path, func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		fs := http.StripPrefix(pathPrefix, http.FileServer(root))
		fs.ServeHTTP(w, r)
	})
}

func (s *Server) handleIndexGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Welcome to goiabada!"))
	}
}
