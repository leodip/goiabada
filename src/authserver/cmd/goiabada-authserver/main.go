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

	slog.Info("auth server base URL: " + config.GetAuthServer().BaseURL)
	slog.Info("auth server internal base URL: " + config.GetAuthServer().InternalBaseURL)
	slog.Info("admin console base URL: " + config.GetAdminConsole().BaseURL)
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
		slog.Info("database is empty, performing initial bootstrap")

		// Check if OAuth client secret is provided (new single-step setup via goiabada-setup)
		providedOAuthSecret := config.GetAdminConsole().OAuthClientSecret
		bootstrapFile := config.GetAuthServer().BootstrapEnvOutFile

		// Determine which bootstrap mode to use
		if providedOAuthSecret != "" {
			// New flow: OAuth client secret provided via goiabada-setup
			// Session keys should also be configured - seed and continue running
			slog.Info("OAuth client secret provided - using single-step setup mode")

			databaseSeeder := data.NewDatabaseSeeder(
				database,
				config.GetAdminEmail(),
				config.GetAdminPassword(),
				config.GetAppName(),
				config.GetAuthServer().BaseURL,
				config.GetAdminConsole().BaseURL,
			).WithOAuthClientSecret(providedOAuthSecret)

			err = databaseSeeder.Seed()
			if err != nil {
				slog.Error(fmt.Sprintf("%+v", err))
				os.Exit(1)
			}

			slog.Info("================================================================================")
			slog.Info("DATABASE SEEDED SUCCESSFULLY")
			slog.Info("================================================================================")
			slog.Info("Continuing with normal startup...")
			// Don't exit - continue to normal operation
		} else if bootstrapFile != "" {
			// Legacy flow: No OAuth secret, but bootstrap file configured
			// Generate credentials, write to file, and exit
			slog.Info("using legacy two-step bootstrap mode")

			databaseSeeder := data.NewDatabaseSeeder(
				database,
				config.GetAdminEmail(),
				config.GetAdminPassword(),
				config.GetAppName(),
				config.GetAuthServer().BaseURL,
				config.GetAdminConsole().BaseURL,
			).WithBootstrapEnvOutFile(bootstrapFile)

			err = databaseSeeder.Seed()
			if err != nil {
				slog.Error(fmt.Sprintf("%+v", err))
				os.Exit(1)
			}

			slog.Info("================================================================================")
			slog.Info("BOOTSTRAP COMPLETE - AUTH SERVER EXITING")
			slog.Info("================================================================================")
			slog.Info("")
			slog.Info("The bootstrap credentials have been written to: " + bootstrapFile)
			slog.Info("")
			slog.Info("NEXT STEPS:")
			slog.Info("1. Copy the credentials from the bootstrap file")
			slog.Info("2. Add them as environment variables in your docker-compose.yml or deployment config")
			slog.Info("3. Restart the services")
			slog.Info("")
			slog.Info("For Docker Compose, add these to the admin console service:")
			slog.Info("  environment:")
			slog.Info("    - GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID=<from bootstrap file>")
			slog.Info("    - GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=<from bootstrap file>")
			slog.Info("    - GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY=<from bootstrap file>")
			slog.Info("    - GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY=<from bootstrap file>")
			slog.Info("")
			slog.Info("And add these to the auth server service:")
			slog.Info("  environment:")
			slog.Info("    - GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY=<from bootstrap file>")
			slog.Info("    - GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY=<from bootstrap file>")
			slog.Info("================================================================================")

			os.Exit(0)
		} else {
			// No OAuth secret and no bootstrap file - show helpful error
			slog.Error("================================================================================")
			slog.Error("INITIAL SETUP REQUIRED")
			slog.Error("================================================================================")
			slog.Error("")
			slog.Error("The database is empty and needs to be seeded. Choose one of these options:")
			slog.Error("")
			slog.Error("OPTION 1 - Recommended: Use goiabada-setup (single-step)")
			slog.Error("  Run: goiabada-setup")
			slog.Error("  This generates a ready-to-use docker-compose.yml with all credentials")
			slog.Error("")
			slog.Error("OPTION 2 - Legacy: Two-step bootstrap")
			slog.Error("  Set GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE=/bootstrap/bootstrap.env")
			slog.Error("  Run the auth server, copy credentials from the file, then restart")
			slog.Error("================================================================================")
			os.Exit(1)
		}
	} else {
		slog.Info("database already initialized, proceeding with normal startup")
	}

	// Validate session keys for normal operation (after bootstrap check)
	if err := config.ValidateAuthServerSessionKeys(); err != nil {
		slog.Error("================================================================================")
		slog.Error("BOOTSTRAP CREDENTIALS NOT CONFIGURED - AUTH SERVER CANNOT START")
		slog.Error("================================================================================")
		slog.Error("session key validation failed: " + err.Error())
		slog.Error("")
		slog.Error("ACTION REQUIRED:")
		slog.Error("1. Open the bootstrap file: ./bootstrap/bootstrap.env")
		slog.Error("2. Copy ALL credentials from the file")
		slog.Error("")
		slog.Error("   For AUTH SERVER (add to goiabada-authserver service):")
		slog.Error("   - GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY")
		slog.Error("   - GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY")
		slog.Error("")
		slog.Error("   For ADMIN CONSOLE (add to goiabada-adminconsole service):")
		slog.Error("   - GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID")
		slog.Error("   - GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET")
		slog.Error("   - GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY")
		slog.Error("   - GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY")
		slog.Error("")
		slog.Error("3. Add them to your docker-compose.yml (uncomment the credential lines)")
		slog.Error("4. Restart both services")
		slog.Error("================================================================================")
		os.Exit(1)
	}
	slog.Info("session keys validated")

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
