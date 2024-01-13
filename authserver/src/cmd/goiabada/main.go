package main

import (
	"encoding/gob"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"

	"log/slog"

	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/initialization"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/server"
	"github.com/leodip/goiabada/internal/sessionstore"
)

func main() {

	configureSlog()

	slog.Info("application starting")

	dir, err := os.Getwd()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	slog.Info("current directory: " + dir)

	slog.Info("goiabada version: " + constants.Version)
	slog.Info("build date: " + constants.BuildDate)
	slog.Info("git commit: " + constants.GitCommit)

	initialization.InitViper()
	initialization.InitTimeZones()

	// gob registration
	gob.Register(dtos.TokenResponse{})

	database, err := data.NewDatabase()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	slog.Info("created database connection")

	settings, err := database.GetSettings()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	_, err = database.DB.DB()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	mysqlStore, err := sessionstore.NewGORMStoreFromConnection(
		database.DB,
		"/",
		86400*365*2,          // max age
		true,                 // http only
		lib.IsHttpsEnabled(), // secure
		http.SameSiteLaxMode, // same site
		settings.SessionAuthenticationKey,
		settings.SessionEncryptionKey)

	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	mysqlStore.Cleanup(time.Minute * 10)
	slog.Info("initialized session store")

	r := chi.NewRouter()
	s := server.NewServer(r, database, mysqlStore)

	s.Start(settings)
}

func configureSlog() {

	w := os.Stderr

	logLevel := slog.LevelInfo

	// set global logger with custom options
	slog.SetDefault(slog.New(
		tint.NewHandler(w, &tint.Options{
			Level:      logLevel,
			TimeFormat: "2006-01-02 15:04:05.000",
			NoColor:    !isatty.IsTerminal(w.Fd()),
		}),
	))
}
