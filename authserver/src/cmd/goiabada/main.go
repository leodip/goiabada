package main

import (
	"encoding/gob"
	"os"
	"time"

	"github.com/go-chi/chi/v5"

	"golang.org/x/exp/slog"

	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/initialization"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/server"
	"github.com/leodip/goiabada/internal/sessionstore"
)

func main() {
	slog.Info("starting")
	initialization.Viper()

	// trigger the load of timezones from OS (they will be cached)
	_ = lib.GetTimeZones()

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
	mysqlStore, err := sessionstore.NewMySQLStoreFromConnection(db, "session_state", "/", 86400*30, settings.SessionAuthenticationKey, settings.SessionEncryptionKey)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	mysqlStore.Cleanup(time.Minute * 10)

	r := chi.NewRouter()
	s := server.NewServer(r, database, mysqlStore)
	s.Start(settings)
}
