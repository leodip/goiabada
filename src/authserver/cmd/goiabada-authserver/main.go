package main

import (
	"context"
	"encoding/gob"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/go-chi/chi/v5"

	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/server"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/timezones"
)

func main() {

	// The configuration and the log handler come before the first record. The
	// level and the format are per-server settings, so anything written ahead of
	// the install goes out in a shape the deployment did not choose, and a value
	// the handler cannot read has to stop the server rather than be silently
	// replaced by a default (#320).
	config.Init()
	if err := logging.Install(config.GetAuthServer().LogLevel, config.GetAuthServer().LogFormat); err != nil {
		slog.Error("unable to install the log handler", "error", err)
		os.Exit(1)
	}

	slog.Info("auth server started")
	slog.Info("build information",
		"version", constants.Version,
		"build_date", constants.BuildDate,
		"git_commit", constants.GitCommit)
	slog.Info("config loaded")

	// The `migrate` subcommand is dispatched here: after the configuration is loaded, because it
	// needs GOIABADA_DB_*, and before the data-encryption key is validated, because a schema
	// migration touches no encrypted value and the key would otherwise be a precondition for
	// repairing a database on a deployment that has not set one (#268).
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		os.Exit(migrateCommand(os.Args[2:]))
	}

	// Validate the data-encryption key EARLY and initialize the process cipher
	// before the database is opened: NewDatabase runs the at-rest re-encryption
	// migration, which needs the key. The key is supplied from the environment
	// and never co-located with the ciphertext (issue #83).
	if err := config.ValidateAESEncryptionKey(); err != nil {
		// One record where three used to be, for the same reason decision 6 collapses the
		// banners: the two lines after the failure were prose an operator had to read as a
		// unit, and a JSON deployment received them as three unrelated records with the
		// remedy in a message field nothing could query (#320).
		slog.Error("the data encryption key is missing or malformed, so the auth server cannot start: set GOIABADA_AES_ENCRYPTION_KEY, and back it up separately from the database because every encrypted secret and signing key is unrecoverable without it",
			"error", err,
			"generate_with", "openssl rand -hex 32")
		os.Exit(1)
	}
	if err := encryption.InitDataCipher(config.GetAESEncryptionKey()); err != nil {
		slog.Error("unable to initialize the data cipher", "error", err)
		os.Exit(1)
	}
	slog.Info("data encryption key validated")

	slog.Info("using configuration",
		"auth_server_base_url", config.GetAuthServer().BaseURL,
		"auth_server_internal_base_url", config.GetAuthServer().InternalBaseURL,
		"admin_console_base_url", config.GetAdminConsole().BaseURL,
		"debug_api_requests", config.GetAuthServer().DebugAPIRequests)

	dir, err := os.Getwd()
	if err != nil {
		slog.Error("unable to determine the working directory", "error", err)
		os.Exit(1)
	}
	slog.Info("current working directory", "directory", dir)

	// trigger the load of timezones from OS (they will be cached)
	_ = timezones.Get()
	slog.Info("timezones loaded")

	// Load i18n message catalogs (and merge GOIABADA_I18N_OVERRIDES_DIR if set).
	// Fail-fast: a malformed catalog or missing override dir is a config bug.
	if _, err := i18n.LoadBundle(); err != nil {
		slog.Error("unable to load the i18n message catalogs", "error", err)
		os.Exit(1)
	}
	slog.Info("i18n catalogs loaded")

	// gob registration
	gob.Register(oauth.TokenResponse{})

	now := time.Now()
	slog.Info("process clock",
		"time_zone", now.Location().String(),
		"local_time", now,
		"utc_time", now.UTC())

	database, err := data.NewDatabase(config.GetDatabase(), config.GetAuthServer().LogSQL)
	if err != nil {
		slog.Error("unable to create the database connection", "error", err)
		os.Exit(1)
	}
	slog.Info("created database connection")

	isEmpty, err := database.IsEmpty()
	if err != nil {
		slog.Error("unable to check whether the database is empty", "error", err)
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
			slog.Info("using single-step setup mode, because an oauth client secret is configured")

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
				slog.Error("unable to seed the database", "error", err)
				os.Exit(1)
			}

			slog.Info("database seeded, continuing with normal startup")
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
				slog.Error("unable to seed the database", "error", err)
				os.Exit(1)
			}

			logBootstrapComplete(bootstrapFile)

			os.Exit(0)
		} else {
			// No OAuth secret and no bootstrap file - show helpful error
			logInitialSetupRequired()
			os.Exit(1)
		}
	} else {
		slog.Info("database already initialized, proceeding with normal startup")
	}

	// Validate session keys for normal operation (after bootstrap check)
	if err := config.ValidateAuthServerSessionKeys(); err != nil {
		logBootstrapCredentialsNotConfigured(err, config.GetAuthServer().BootstrapEnvOutFile)
		os.Exit(1)
	}
	slog.Info("session keys validated")

	slog.Info("cookie security derived from the base URL",
		"cookie_secure", config.GetAuthServer().IsCookieSecure())

	// Decode the session keys from config, which validated them at startup. The decode
	// errors are still checked: what they would otherwise become is a store keyed with two
	// empty byte slices, which is a key anyone can recompute rather than a failure (#269).
	currentKeys, err := sessionstore.DecodeKeyPair(
		config.GetAuthServer().SessionAuthenticationKey,
		config.GetAuthServer().SessionEncryptionKey)
	if err != nil {
		slog.Error("unable to decode the session keys", "error", err)
		os.Exit(1)
	}

	// The previous pair, nil unless an operator is rotating the session keys. The store
	// seals with the current pair and opens with the current pair and then this one, so a
	// rotation signs nobody out; the operator removes the two _PREVIOUS variables once the
	// maximum session lifetime has passed (#269, #270).
	previousKeys, err := sessionstore.DecodePreviousKeyPair(
		config.GetAuthServer().SessionAuthenticationKeyPrevious,
		config.GetAuthServer().SessionEncryptionKeyPrevious)
	if err != nil {
		slog.Error("unable to decode the previous session keys", "error", err)
		os.Exit(1)
	}
	if previousKeys != nil {
		slog.Info("previous session keys configured: a session sealed under them still opens")
	}

	// The session lives in the database and the browser carries nothing but a sealed,
	// opaque identifier, about 140 characters in one cookie whatever a deployment
	// configures and whatever claims it mints: one version byte, a 24 byte nonce, 64
	// characters of identifier and a 16 byte tag, base64 encoded once. What it replaces
	// put the whole session in the cookie and split the ciphertext across up to fifty of
	// them, which is why this deployment's documentation had to tell operators to enlarge
	// their proxy buffers (#266, #270).
	//
	// The backend is scoped to this application's own rows at construction, so no code
	// path here can name an admin console session however it is composed.
	sessionStore, err := sessionstore.NewServerSideStore(
		sessionstore.NewDatabaseBackend(database, constants.AuthServerSessionName),
		constants.SessionKeySessionIdentifier,
		config.GetAuthServer().IsCookieSecure(),
		currentKeys,
		previousKeys,
	)
	if err != nil {
		slog.Error("unable to initialize the session store", "error", err)
		os.Exit(1)
	}

	// The end user's cookie keeps an expiry, so single sign-on survives a browser
	// restart. It is set per save from the row's own expires_at, which the operator's
	// session settings decide, so one knob governs both halves and the browser never
	// holds a handle that outlives what it names. The admin console does the opposite
	// for the opposite reason, and the trade is argued in full in the issue (#266).
	sessionStore.PersistentCookie = true

	slog.Info("initialized server-side session store")

	r := chi.NewRouter()
	s := server.NewServer(r, database, sessionStore)

	// The process owns the signals; the server just gets told when to stop. On
	// SIGTERM (what a container runtime sends) or SIGINT, ctx is cancelled and
	// Start drains the listeners and stops the background worker before returning.
	ctx, stopListeningForSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopListeningForSignals()

	s.Start(ctx)

	slog.Info("auth server stopped")
}

// bootstrapCredentialVars are the five values a deployment has to carry over from
// the bootstrap file, three for the admin console and two for the auth server.
//
// One list rather than one per record. Two of this file's records name these
// variables, and before this they were two hand-typed lists in two banners: a
// credential added to the bootstrap file and to one of them would leave an
// operator following the other one short, with a startup failure naming a variable
// they had never been told to set (#320).
var bootstrapCredentialVars = []string{
	"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET",
	"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY",
	"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY",
	"GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY",
	"GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY",
}

// logBootstrapComplete reports the end of the legacy two-step bootstrap.
//
// One record where a 22-line banner used to be. The prose it replaced walked
// through the docker-compose.yml edit twice, once per service; what an operator
// needs from it is the file and the names, and those are the two attributes (#320
// decision 6).
func logBootstrapComplete(bootstrapFile string) {
	slog.Info("bootstrap complete, so the auth server is exiting: copy every credential from the bootstrap file into the two services' configuration, then restart them",
		"bootstrap_file", bootstrapFile,
		"required", bootstrapCredentialVars)
}

// logInitialSetupRequired reports an empty database with neither bootstrap mode
// configured, which is the one startup failure an operator hits before they have
// any credentials at all.
func logInitialSetupRequired() {
	slog.Error("initial setup is required, because the database is empty and neither bootstrap mode is configured",
		"options", []string{
			"run goiabada-setup, which writes a ready-to-use docker-compose.yml carrying every credential",
			"or set GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE and restart, then copy the credentials out of the file it writes",
		})
}

// logBootstrapCredentialsNotConfigured reports session keys that are missing or
// malformed on a database that is already seeded.
//
// bootstrap_file is read from the configuration. The banner this replaced printed
// "./bootstrap/bootstrap.env", which is the path the shipped compose files happen
// to use rather than this deployment's, so an operator who mounted the file
// somewhere else was sent to look at a path that did not exist (#320).
func logBootstrapCredentialsNotConfigured(err error, bootstrapFile string) {
	slog.Error("bootstrap credentials are not configured, so the auth server cannot start: copy every credential from the bootstrap file into the two services' configuration, then restart them",
		"error", err,
		"bootstrap_file", bootstrapFile,
		"required", bootstrapCredentialVars)
}
