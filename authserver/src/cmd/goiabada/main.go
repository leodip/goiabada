package main

import (
	"encoding/gob"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"

	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/oauth"
	"github.com/leodip/goiabada/authserver/internal/server"
	"github.com/leodip/goiabada/authserver/internal/sessionstore"
	"github.com/leodip/goiabada/authserver/internal/timezones"
)

func main() {

	slog.Info("auth server started")
	slog.Info("goiabada version: " + constants.Version)
	slog.Info("build date: " + constants.BuildDate)
	slog.Info("git commit: " + constants.GitCommit)

	config.Init()
	slog.Info("config loaded")

	slog.Info("auth server base URL: " + config.AuthServerBaseUrl)
	slog.Info("admin console base URL: " + config.AdminConsoleBaseUrl)

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

	isEmpty, err := database.IsEmpty()
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}

	if isEmpty {
		slog.Info("database is empty, seeding")
		err = database.Seed()
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

	sqlStore := sessionstore.NewSQLStore(
		database,
		"/",
		86400*365*2,             // max age
		true,                    // http only
		config.IsHttpsEnabled(), // secure
		http.SameSiteLaxMode,    // same site
		settings.SessionAuthenticationKey,
		settings.SessionEncryptionKey)

	sqlStore.Cleanup(time.Minute * 10)
	slog.Info("initialized session store")

	r := chi.NewRouter()
	s := server.NewServer(r, database, sqlStore)

	s.Start(settings)
}
