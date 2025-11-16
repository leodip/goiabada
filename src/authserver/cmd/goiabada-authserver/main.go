package main

import (
	"encoding/gob"
	"encoding/hex"
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

	config.Init()
	slog.Info("config loaded")

	// Validate session keys EARLY - fail fast if missing or invalid
	if err := config.ValidateAuthServerSessionKeys(); err != nil {
		slog.Error("session key validation failed: " + err.Error())
		slog.Error("Please set GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY and GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY")
		slog.Error("Generate keys with: openssl rand -hex 64 (for authentication key) and openssl rand -hex 32 (for encryption key)")
		os.Exit(1)
	}
	slog.Info("session keys validated")

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
		databaseSeeder := data.NewDatabaseSeeder(
			database,
			config.GetAdminEmail(),
			config.GetAdminPassword(),
			config.GetAppName(),
			config.GetAuthServer().BaseURL,
			config.GetAdminConsole().BaseURL,
		).WithBootstrapEnvOutFile(config.GetAuthServer().BootstrapEnvOutFile)
		err = databaseSeeder.Seed()
		if err != nil {
			slog.Error(fmt.Sprintf("%+v", err))
			os.Exit(1)
		}
	} else {
		slog.Info("database does not need seeding")
	}

	slog.Info("set cookie secure: " + fmt.Sprintf("%t", config.GetAuthServer().SetCookieSecure))

	// Decode session keys from config (already validated at startup)
	authKey, _ := hex.DecodeString(config.GetAuthServer().SessionAuthenticationKey)
	encKey, _ := hex.DecodeString(config.GetAuthServer().SessionEncryptionKey)

	// Use ChunkedCookieStore to support large sessions with custom JWT claims
	chunkedStore := sessionstore.NewChunkedCookieStore(authKey, encKey)
	chunkedStore.Options.Path = "/"
	chunkedStore.Options.MaxAge = 86400 * 365 * 2 // 2 years
	chunkedStore.Options.HttpOnly = true
	chunkedStore.Options.Secure = config.GetAuthServer().SetCookieSecure
	chunkedStore.Options.SameSite = http.SameSiteLaxMode

	slog.Info("initialized chunked cookie session store")

	r := chi.NewRouter()
	s := server.NewServer(r, database, chunkedStore)

	s.Start()
}
