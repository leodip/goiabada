// Command goiabada-authserver is the Goiabada auth server, and the tool that steps its schema.
//
//	goiabada-authserver [flags]                                     serve
//	goiabada-authserver [flags] migrate [--db-* flags] version      report the schema version
//	goiabada-authserver [flags] migrate [--db-* flags] to <version> step the schema to <version>
//
// Flags before `migrate` are the server's, and only the --db-* ones among them reach `migrate`;
// after it, only the --db-* flags are accepted, and one given there overrides the same flag given
// before. Any other first argument is refused.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/go-chi/chi/v5"

	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/bootstrap"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/datafactory"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/server"
	"github.com/leodip/goiabada/authserver/internal/sessionbackend"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging"
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

	// The command is chosen from what the flag parse left, not from os.Args: the parse stops at
	// the first argument that is not a flag, so reading os.Args[1] took `-db-type=mysql migrate
	// to 44` for a server start and migrated a database up that the operator asked to step down
	// (#424). A refusal is the operator's typo rather than a server event, so it goes to stderr
	// as one line and nothing is opened.
	migrateArgs, isMigrate, err := dispatch(config.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(migrateExitUsage)
	}

	slog.Info("auth server started")
	slog.Info("build information",
		"version", coreconstants.Version,
		"build_date", coreconstants.BuildDate,
		"git_commit", coreconstants.GitCommit)
	slog.Info("config loaded")

	// The `migrate` subcommand runs here: after the configuration is loaded, because it needs
	// GOIABADA_DB_* and the --db-* flags given before it, and before the data-encryption key is
	// validated, because a schema migration touches no encrypted value and the key would
	// otherwise be a precondition for repairing a database on a deployment that has not set one
	// (#268). Its arguments are the ones dispatch left after the word `migrate`, and the database
	// configuration is handed over by value, so the --db-* flags it parses among them override a
	// copy and the loaded configuration stays what the process was started with (#424).
	if isMigrate {
		os.Exit(migrateCommand(migrateArgs, *config.GetDatabase(), os.Stdout, os.Stderr))
	}

	// A trusted-proxy entry that is neither an IP nor a CIDR stops the server whatever
	// TRUST_PROXY_HEADERS says. Skipping it would leave a list of typos empty, which the real-IP
	// middleware reads as trusting any single hop, and a typo in a list trust is off for today
	// would otherwise surface only on the day trust is switched on (#425). It is checked after
	// `migrate` for the reason the encryption key is: that command serves no request, and a
	// setting only the server reads is no precondition for repairing a schema.
	trustedProxies, proxyErr := config.GetAuthServer().TrustedProxyRanges()
	if proxyErr != nil {
		slog.Error("the trusted proxy list is malformed, so the auth server cannot start", "error", proxyErr)
		os.Exit(1)
	}

	// Validate the data-encryption key EARLY and initialize the process cipher
	// before the database is opened: NewDatabase runs the at-rest re-encryption
	// migration, which needs the key. The key is supplied from the environment
	// and never co-located with the ciphertext (issue #83).
	if aesKeyErr := config.ValidateAESEncryptionKey(); aesKeyErr != nil {
		// One record where three used to be, for the same reason decision 6 collapses the
		// banners: the two lines after the failure were prose an operator had to read as a
		// unit, and a JSON deployment received them as three unrelated records with the
		// remedy in a message field nothing could query (#320).
		slog.Error("the data encryption key is missing or malformed, so the auth server cannot start: set GOIABADA_AES_ENCRYPTION_KEY, and back it up separately from the database because every encrypted secret and signing key is unrecoverable without it",
			"error", aesKeyErr,
			"generate_with", "openssl rand -hex 32")
		os.Exit(1)
	}
	if initDataCipherErr := encryption.InitDataCipher(config.GetAESEncryptionKey()); initDataCipherErr != nil {
		slog.Error("unable to initialize the data cipher", "error", initDataCipherErr)
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
	if _, loadBundleErr := i18n.LoadBundle(); loadBundleErr != nil {
		slog.Error("unable to load the i18n message catalogs", "error", loadBundleErr)
		os.Exit(1)
	}
	slog.Info("i18n catalogs loaded")

	now := time.Now()
	slog.Info("process clock",
		"time_zone", now.Location().String(),
		"local_time", now,
		"utc_time", now.UTC())

	// main owns this root: the startup sequence below is what the process exists to complete,
	// and there is no request and no operator above it to cancel. Everything it reaches takes a
	// context rather than opening one where it lands (#386).
	startupCtx := context.Background()

	database, err := datafactory.NewDatabase(startupCtx, config.GetDatabase(),
		config.GetAESEncryptionKey(), config.GetAESEncryptionKeyPrevious(),
		config.GetAuthServer().LogSQL)
	if err != nil {
		slog.Error("unable to create the database connection", "error", err)
		os.Exit(1)
	}
	slog.Info("created database connection")

	// An empty database is seeded here, in the mode the configuration selects, before the server
	// listens and before the signal context exists: nothing cancels the seed, since it commits
	// whole or not at all and the next start retries it (#386, #424). bootstrap owns the choice
	// and the records; main owns only what the process does next.
	outcome, err := bootstrap.Run(startupCtx, database, bootstrap.Config{
		AdminEmail:          config.GetAdminEmail(),
		AdminPassword:       config.GetAdminPassword(),
		AppName:             config.GetAppName(),
		AuthServerBaseURL:   config.GetAuthServer().BaseURL,
		AdminConsoleBaseURL: config.GetAdminConsole().BaseURL,
		OAuthClientSecret:   config.GetAdminConsole().OAuthClientSecret,
		BootstrapEnvOutFile: config.GetAuthServer().BootstrapEnvOutFile,
	})
	if err != nil {
		slog.Error("unable to bootstrap the database", "error", err)
		os.Exit(1)
	}
	switch outcome {
	case bootstrap.Exit:
		os.Exit(0)
	case bootstrap.Refused:
		os.Exit(1)
	}

	// Validate session keys for normal operation (after bootstrap check)
	if sessionKeysErr := config.ValidateAuthServerSessionKeys(); sessionKeysErr != nil {
		bootstrap.LogCredentialsNotConfigured(startupCtx, sessionKeysErr, config.GetAuthServer().BootstrapEnvOutFile)
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
		sessionbackend.NewAuthServerBackend(database),
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
	s := server.NewServer(r, database, sessionStore, trustedProxies)

	// The process owns the signals; the server just gets told when to stop. On
	// SIGTERM (what a container runtime sends) or SIGINT, ctx is cancelled and
	// Start drains the listeners and stops the background worker before returning.
	ctx, stopListeningForSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopListeningForSignals()

	s.Start(ctx)

	slog.Info("auth server stopped")
}

// dispatch chooses the command from the positional arguments the flag parse left: none serves,
// a first `migrate` hands the rest to the subcommand, and anything else is refused, before a
// database is opened. A typo such as `migrat to 44` used to start the server and migrate the
// database up, the opposite of what was asked (#424).
func dispatch(args []string) (migrateArgs []string, isMigrate bool, err error) {
	if len(args) == 0 {
		return nil, false, nil
	}
	if args[0] == "migrate" {
		return args[1:], true, nil
	}
	return nil, false, errs.Errorf("unknown command %q: run goiabada-authserver [flags] with no "+
		"command to start the server, or goiabada-authserver [flags] migrate version, or "+
		"goiabada-authserver [flags] migrate to <version>, to manage the schema; the server's "+
		"flags go before the command", args[0])
}
