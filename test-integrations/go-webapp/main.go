// main.go
package main

import (
	"context"
	"encoding/gob"
	"fmt"
	"go-webapp/auth"
	"go-webapp/config"
	"go-webapp/handlers"
	"log/slog"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
)

func main() {
	slog.Info("Welcome to the Go web app")
	appConfig := config.GetAppConfig()

	// Log configuration
	slog.Info((fmt.Sprintf("WebAppPort: %s", config.WebAppPort)))
	slog.Info((fmt.Sprintf("ClientID: %s", appConfig.ClientID)))
	slog.Info((fmt.Sprintf("ClientSecret: %s", appConfig.ClientSecret)))
	slog.Info((fmt.Sprintf("IssuerURL: %s", appConfig.IssuerURL)))
	slog.Info((fmt.Sprintf("AuthURL: %s", appConfig.AuthURL)))
	slog.Info((fmt.Sprintf("TokenURL: %s", appConfig.TokenURL)))
	slog.Info((fmt.Sprintf("UserInfoURL: %s", appConfig.UserInfoURL)))
	slog.Info((fmt.Sprintf("JWKSURL: %s", appConfig.JWKSURL)))
	slog.Info((fmt.Sprintf("EndSessionEndpoint: %s", appConfig.EndSessionEndpoint)))
	slog.Info((fmt.Sprintf("RedirectURL: %s", appConfig.RedirectURL)))
	slog.Info((fmt.Sprintf("PostLogoutRedirectURL: %s", appConfig.PostLogoutRedirectURL)))

	// Initialize session store
	tempDir := os.TempDir()
	fsStore := sessions.NewFilesystemStore(tempDir, []byte(config.SessionAuthKey), []byte(config.SessionEncryptionKey))
	fsStore.MaxLength(1024 * 1024) // 1 MB in bytes

	// required to serialize claims to the session store
	gob.Register(map[string]interface{}{})

	// Initialize auth
	ctx := context.Background()
	err := auth.InitAuth(ctx, appConfig, fsStore)
	if err != nil {
		slog.Error("Failed to initialize auth", "error", err)
		panic(err)
	}
	oauth2Config := auth.GetOAuth2Config()

	// Routes
	// Public routes with optional claims extraction
	http.HandleFunc("/", handlers.ExtractClaims(handlers.IndexHandler(), fsStore))
	http.HandleFunc("/forbidden", handlers.ForbiddenHandler(fsStore))

	// Login routes (no middleware needed)
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			handlers.LoginGetHandler().ServeHTTP(w, r)
		case "POST":
			handlers.LoginPostHandler(oauth2Config, fsStore).ServeHTTP(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Callback route (no middleware needed)
	http.HandleFunc("/callback", handlers.CallbackHandler(oauth2Config, fsStore))

	// Protected routes requiring authentication
	http.HandleFunc("/protected-authenticated",
		handlers.ExtractClaims(
			handlers.RequiresAuthentication(
				handlers.ProtectedAuthenticatedHandler(),
				fsStore,
			),
			fsStore,
		),
	)

	// Protected routes requiring authentication and scope
	http.HandleFunc("/protected-authenticated-plus-scope",
		handlers.ExtractClaims(
			handlers.RequiresAuthentication(
				handlers.RequiresScope(
					handlers.ProtectedAuthenticatedPlusScopeHandler(),
					fsStore,
					"testserver:read", // required scope
				),
				fsStore,
			),
			fsStore,
		),
	)

	http.HandleFunc("/refresh-token",
		handlers.ExtractClaims(
			handlers.RefreshTokenHandler(oauth2Config, fsStore),
			fsStore,
		),
	)

	http.HandleFunc("/userinfo",
		handlers.ExtractClaims(
			handlers.UserInfoHandler(fsStore),
			fsStore,
		),
	)

	http.HandleFunc("/logout", handlers.LogoutHandler(fsStore))
	http.HandleFunc("/clear-session", handlers.ClearSessionHandler(fsStore))

	// Start the server
	slog.Info("Starting server on port " + config.WebAppPort)
	if err := http.ListenAndServe(":"+config.WebAppPort, nil); err != nil {
		slog.Error("Server failed to start", "error", err)
		panic(err)
	}
}
