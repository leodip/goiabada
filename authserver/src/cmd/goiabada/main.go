package main

import (
	"encoding/gob"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pkg/errors"

	"golang.org/x/exp/slog"

	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/server"
	"github.com/leodip/goiabada/internal/sessionstore"

	"github.com/spf13/viper"
)

func main() {
	slog.Info("starting")
	initViper()

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

	// client, _ := database.GetClientByClientIdentifier("test-client-1")
	// clientSecret, _ := lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
	// slog.Info(fmt.Sprintf("(DEBUG) client secret of %v: %v", client.ClientIdentifier, clientSecret))

	// client, _ = database.GetClientByClientIdentifier("admin-client")
	// clientSecret, _ = lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
	// slog.Info(fmt.Sprintf("(DEBUG) client secret of %v: %v", client.ClientIdentifier, clientSecret))

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

func initViper() {
	viper.SetConfigName("config")
	viper.SetConfigType("json")

	// possible locations for config file
	viper.AddConfigPath(".")
	viper.AddConfigPath("./configs")

	viper.SetEnvPrefix("GOIABADA")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	err := viper.ReadInConfig()
	if err != nil {
		slog.Error(errors.Wrap(err, "unable to initialize configuration - make sure a config.json file exists and has content").Error())
		os.Exit(1)
	}
	slog.Info(fmt.Sprintf("viper configuration initialized. Config file used: %v", viper.ConfigFileUsed()))
}
