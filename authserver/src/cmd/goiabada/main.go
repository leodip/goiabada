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

	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/initialization"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/server"
	"github.com/leodip/goiabada/internal/sessionstore"
)

func main() {

	configureSlog()

	slog.Info("application starting")
	initialization.Viper()

	// trigger the load of timezones from OS (they will be cached)
	_ = lib.GetTimeZones()

	slog.Info("timezones loaded")
	slog.Info("current time zone is:" + time.Now().Location().String())
	slog.Info("current local time is:" + time.Now().String())
	slog.Info("current UTC time is:" + time.Now().UTC().String())

	// we'll need to marshal/unmarshal these types
	gob.Register([]enums.AuthMethod{})
	gob.Register(dtos.TokenResponse{})

	database, err := data.NewDatabase()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	settings, err := database.GetSettings()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	db, err := database.DB.DB()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	mysqlStore, err := sessionstore.NewMySQLStoreFromConnection(
		db,
		"session_state",
		"/",
		86400*365*2,          // max age
		true,                 // http only
		true,                 // secure
		http.SameSiteLaxMode, // same site
		settings.SessionAuthenticationKey,
		settings.SessionEncryptionKey)

	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	mysqlStore.Cleanup(time.Minute * 10)

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
