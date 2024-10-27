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

	database, err := data.NewDatabase()
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

	slog.Info("set cookie secure: " + fmt.Sprintf("%t", config.Get().SetCookieSecure))

	sqlStore := sessionstore.NewSQLStore(
		database,
		"/",
		86400*365*2,                  // max age
		true,                         // http only
		config.Get().SetCookieSecure, // secure
		http.SameSiteLaxMode,         // same site
		settings.SessionAuthenticationKey,
		settings.SessionEncryptionKey)

	sqlStore.Cleanup(time.Minute * 10)
	slog.Info("initialized session store")

	r := chi.NewRouter()
	s := server.NewServer(r, database, sqlStore)

	s.Start(settings)
}
