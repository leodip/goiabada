package main

import (
	"encoding/gob"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"

	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/server"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/timezones"
)

func main() {

	slog.Info("auth server started")
	slog.Info("goiabada version: " + constants.Version)
	slog.Info("build date: " + constants.BuildDate)
	slog.Info("git commit: " + constants.GitCommit)

	config.Init("AuthServer")
	slog.Info("config loaded")

	slog.Info("auth server base URL: " + config.GetAuthServer().BaseURL)
	slog.Info("auth server internal base URL: " + config.GetAuthServer().InternalBaseURL)
	slog.Info("admin console base URL: " + config.GetAdminConsole().BaseURL)
	slog.Info("admin console internal base URL: " + config.GetAdminConsole().InternalBaseURL)
	slog.Info("debug API requests: " + fmt.Sprintf("%t", config.GetAuthServer().DebugAPIRequests))

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

	database, err := data.NewDatabase(config.GetDatabase(), config.GetAuthServer().LogSQL)
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
	slog.Info("created database connection")

	isEmpty, err := database.IsEmpty()
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}

	if isEmpty {
		slog.Info("database is empty, seeding")
		databaseSeeder := data.NewDatabaseSeeder(database, config.GetAdminEmail(), config.GetAdminPassword(), config.GetAppName(), config.GetAuthServer().BaseURL, config.GetAdminConsole().BaseURL)
		err = databaseSeeder.Seed()
		if err != nil {
			slog.Error(fmt.Sprintf("%+v", err))
			os.Exit(1)
		}
	} else {
		slog.Info("database does not need seeding")
	}

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}

	slog.Info("set cookie secure: " + fmt.Sprintf("%t", config.GetAuthServer().SetCookieSecure))

	sqlStore := sessionstore.NewSQLStore(
		database,
		"/",
		86400*365*2,                  // max age
		true,                         // http only
		config.GetAuthServer().SetCookieSecure, // secure
		http.SameSiteLaxMode,         // same site
		settings.SessionAuthenticationKey,
		settings.SessionEncryptionKey)

	sqlStore.Cleanup(time.Minute * 10)
	slog.Info("initialized session store")

	r := chi.NewRouter()
	s := server.NewServer(r, database, sqlStore)

	s.Start(settings)
}
