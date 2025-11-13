package main

import (
	"encoding/gob"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/server"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/timezones"
)

func main() {
	slog.Info("admin console started")
	slog.Info("goiabada version: " + constants.Version)
	slog.Info("build date: " + constants.BuildDate)
	slog.Info("git commit: " + constants.GitCommit)

	config.Init("AdminConsole")
	slog.Info("config loaded")

	slog.Info("auth server base URL: " + config.GetAuthServer().BaseURL)
	slog.Info("auth server internal base URL: " + config.GetAuthServer().InternalBaseURL)
	slog.Info("admin console base URL: " + config.GetAdminConsole().BaseURL)
	slog.Info("admin console internal base URL: " + config.GetAdminConsole().InternalBaseURL)

	dir, err := os.Getwd()
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
	slog.Info("current working directory: " + dir)

	// trigger the load of timezones from OS (they will be cached)
	_ = timezones.Get()
	slog.Info("timezones loaded")

	// gob registration
	gob.Register(oauth.TokenResponse{})

	slog.Info("current time zone is: " + time.Now().Location().String())
	slog.Info("current local time is: " + time.Now().String())
	slog.Info("current UTC time is: " + time.Now().UTC().String())

	database, err := data.NewDatabase(config.GetDatabase(), config.GetAdminConsole().LogSQL)
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
	slog.Info("created database connection")

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
	if settings == nil {
		slog.Error("Settings not found in database. The database is likely not seeded yet.")
		slog.Error("Start the auth server first to seed the database and generate Admin Console OAuth credentials.")
		os.Exit(1)
	}

	slog.Info("set cookie secure: " + fmt.Sprintf("%t", config.GetAdminConsole().SetCookieSecure))

	// Use ChunkedCookieStore to support large sessions with custom JWT claims
	chunkedStore := sessionstore.NewChunkedCookieStore(
		[]byte(settings.SessionAuthenticationKey),
		[]byte(settings.SessionEncryptionKey))
	chunkedStore.Options.Path = "/"
	chunkedStore.Options.MaxAge = 86400 * 365 * 2 // 2 years
	chunkedStore.Options.HttpOnly = true
	chunkedStore.Options.Secure = config.GetAdminConsole().SetCookieSecure
	chunkedStore.Options.SameSite = http.SameSiteLaxMode

	slog.Info("initialized chunked cookie session store")

	r := chi.NewRouter()
	s := server.NewServer(r, database, chunkedStore)

	s.Start(settings)
}
