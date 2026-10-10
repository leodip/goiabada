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
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata" // embeds the zone database localzone.Install resolves TZ against (#49, #331, #432)

	"github.com/go-chi/chi/v5"

	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/bootstrap"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data/datafactory"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/server"
	"github.com/leodip/goiabada/authserver/internal/sessionbackend"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/buildinfo"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/localzone"
	"github.com/leodip/goiabada/core/logging"
	"github.com/leodip/goiabada/core/sessionstore"
)

func main() {
	os.Exit(run())
}

// run is the process from its start to its stop, and answers the code main exits with, so what it
// defers is done on every path out of it.
func run() int {
	// TZ is resolved again before anything else, so the first record is already in the zone the
	// deployment chose. The zone database this binary embeds is reachable only from here: a
	// dependency fixes the local zone during package initialization, before it registers, so on a
	// host with no zone database TZ was ignored. A TZ that names no zone, or a zone file that does
	// not load, takes a malformed variable's channel and code, one line on stderr and exit 2 (#331).
	if err := localzone.Install(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return migrateExitUsage
	}

	// The configuration and the log handler come before the first record. The
	// level and the format are per-server settings, so anything written ahead of
	// the install goes out in a shape the deployment did not choose, and a value
	// the handler cannot read has to stop the server rather than be silently
	// replaced by a default (#320).
	//
	// A variable that does not parse stops the process here, before `migrate` is dispatched as
	// well: the variable is its flag's default, and a malformed flag already exits 2 at this very
	// parse. So the refusal takes the flag's channel and code, one line on stderr, since no log
	// handler exists yet, and exit 2 (#434).
	cfg, loadErr := config.Load(flag.CommandLine, os.Args[1:])
	if loadErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", loadErr)
		return migrateExitUsage
	}
	if err := logging.Install(cfg.AuthServer.LogLevel, cfg.AuthServer.LogFormat); err != nil {
		slog.Error("unable to install the log handler", "error", err)
		return 1
	}

	// The command is chosen from what the flag parse left, not from os.Args: the parse stops at
	// the first argument that is not a flag, so reading os.Args[1] took `-db-type=mysql migrate
	// to 44` for a server start and migrated a database up that the operator asked to step down
	// (#424). A refusal is the operator's typo rather than a server event, so it goes to stderr
	// as one line and nothing is opened.
	migrateArgs, isMigrate, err := dispatch(cfg.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return migrateExitUsage
	}

	slog.Info("auth server started")
	slog.Info("build information",
		"version", buildinfo.Version,
		"build_date", buildinfo.BuildDate,
		"git_commit", buildinfo.GitCommit)
	slog.Info("config loaded")

	// The `migrate` subcommand runs here: after the configuration is loaded, because it needs
	// GOIABADA_DB_* and the --db-* flags given before it, and before the data-encryption key is
	// validated, because a schema migration touches no encrypted value and the key would
	// otherwise be a precondition for repairing a database on a deployment that has not set one
	// (#268). Its arguments are the ones dispatch left after the word `migrate`, and the database
	// configuration is handed over by value, so the --db-* flags it parses among them override a
	// copy and the loaded configuration stays what the process was started with (#424).
	if isMigrate {
		return migrateCommand(migrateArgs, cfg.Database, os.Stdout, os.Stderr)
	}

	// The process owns the signals, from here to its exit, so a stop arriving while the server is
	// still starting is handled rather than ending the process mid-step (#390 decisions 8 and 9).
	// On SIGTERM, what a container runtime sends, or SIGINT, signalled is cancelled: during startup
	// the running step finishes and no new one starts, and once the server runs, Start drains the
	// listeners and stops the background worker before returning. Installed after `migrate` is
	// dispatched, which is no server start.
	signalled, stopListeningForSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopListeningForSignals()
	startupCtx, finishStartup := watchStartup(signalled)

	// A trusted-proxy entry that is neither an IP nor a CIDR stops the server whatever
	// TRUST_PROXY_HEADERS says. Skipping it would leave a list of typos empty, which the real-IP
	// middleware reads as trusting any single hop, and a typo in a list trust is off for today
	// would otherwise surface only on the day trust is switched on (#425). It is checked after
	// `migrate` for the reason the encryption key is: that command serves no request, and a
	// setting only the server reads is no precondition for repairing a schema.
	trustedProxies, proxyErr := cfg.AuthServer.TrustedProxyRanges()
	if proxyErr != nil {
		slog.Error("the trusted proxy list is malformed, so the auth server cannot start", "error", proxyErr)
		return 1
	}

	// Validate the data-encryption key EARLY and build the data cipher from it
	// before the database is opened: NewDatabase runs the at-rest re-encryption
	// migration, which needs the key. The key is supplied from the environment
	// and never co-located with the ciphertext (issue #83).
	currentDataKey, previousDataKey, aesKeyErr := cfg.DataKeys()
	if aesKeyErr != nil {
		// One record where three used to be, for the same reason decision 6 collapses the
		// banners: the two lines after the failure were prose an operator had to read as a
		// unit, and a JSON deployment received them as three unrelated records with the
		// remedy in a message field nothing could query (#320).
		slog.Error("the data encryption key is missing or malformed, so the auth server cannot start: set GOIABADA_AES_ENCRYPTION_KEY, and back it up separately from the database because every encrypted secret and signing key is unrecoverable without it",
			"error", aesKeyErr,
			"generate_with", "openssl rand -hex 32")
		return 1
	}
	// One cipher for the process, built here and handed to every consumer rather than set as a
	// package-wide key each of them reads (#434).
	dataCipher, dataCipherErr := encryption.NewDataCipher(currentDataKey)
	if dataCipherErr != nil {
		slog.Error("unable to initialize the data cipher", "error", dataCipherErr)
		return 1
	}
	slog.Info("data encryption key validated")

	slog.Info("using configuration",
		"auth_server_base_url", cfg.AuthServer.BaseURL,
		"auth_server_internal_base_url", cfg.AuthServer.InternalBaseURL,
		"admin_console_base_url", cfg.AdminConsole.BaseURL,
		"debug_api_requests", cfg.AuthServer.DebugAPIRequests)

	dir, err := os.Getwd()
	if err != nil {
		slog.Error("unable to determine the working directory", "error", err)
		return 1
	}
	slog.Info("current working directory", "directory", dir)

	// Merge the overrides directory the configuration read from GOIABADA_I18N_OVERRIDES_DIR over
	// the embedded message catalogs. Fail-fast: a malformed catalog is a config bug.
	if loadBundleErr := i18n.LoadBundle(cfg.AuthServer.I18nOverridesDir); loadBundleErr != nil {
		slog.Error("unable to load the i18n message catalogs", "error", loadBundleErr)
		return 1
	}
	slog.Info("i18n catalogs loaded")

	now := time.Now()
	slog.Info("process clock",
		"time_zone", now.Location().String(),
		"local_time", now,
		"utc_time", now.UTC())

	// startupCtx is the root of the startup sequence below, and a shutdown signal is what ends it.
	// Everything it reaches takes a context rather than opening one where it lands (#386), and
	// reads its end as a stop rather than a failure: a wait (connecting, creating the database,
	// the migration lock) is cancelled at once; a migration file already running runs to its end
	// and the next does not start, leaving the schema clean at the version it reached; the
	// data-key rotation and the seed, each one transaction, complete if they are under way and do
	// not start otherwise (#390 decision 9). A step stopped that way answers an error matching
	// context.Canceled, and the start then exits 0, as it does after a drain.
	database, err := datafactory.NewDatabase(startupCtx, &cfg.Database,
		currentDataKey, previousDataKey, cfg.AuthServer.LogSQL)
	if err != nil {
		if stoppedDuringStartup(startupCtx, err) {
			return stopCleanly()
		}
		if errors.Is(err, datafactory.ErrDataKeyMismatch) {
			slog.Error("the data encryption key does not decrypt the stored data, so the auth server cannot start",
				"error", err,
				"remedy", "set GOIABADA_AES_ENCRYPTION_KEY to the last key the stored data was encrypted under, from your backup of it: "+
					"the key the database was set up with, or after a rotation the key it was rotated to")
			return 1
		}
		slog.Error("unable to create the database connection", "error", err)
		return 1
	}
	slog.Info("created database connection")
	// Closed on every return from here once nothing uses it: on a startup path nothing has, and
	// after the server only when Start reports its requests, its handed-off work and its cleanup
	// worker all finished. On SQLite the close is what checkpoints the WAL into goiabada.db, so a
	// stopped server leaves the database in one file (#542). A stop whose work outlived its
	// timeouts leaves the database to the process exit instead: closing the pool under that work
	// would only turn its next query into an error a moment before the exit ends it, and SQLite
	// replays the WAL at the next start.
	closeOnReturn := true
	defer func() {
		if closeOnReturn {
			closeDatabase(database)
		}
	}()

	// An empty database is seeded here, in the mode the configuration selects, before the server
	// listens. A seed commits whole or not at all and the next start retries it (#386, #424), so a
	// signal keeps one from beginning and lets one under way commit. bootstrap owns the choice and
	// the records; main owns only what the process does next.
	outcome, err := bootstrap.Run(startupCtx, database, dataCipher, bootstrap.Config{
		AdminEmail:          cfg.AdminEmail,
		AdminPassword:       cfg.AdminPassword,
		AppName:             cfg.AppName,
		AuthServerBaseURL:   cfg.AuthServer.BaseURL,
		AdminConsoleBaseURL: cfg.AdminConsole.BaseURL,
		OAuthClientSecret:   cfg.AdminConsole.OAuthClientSecret,
		BootstrapEnvOutFile: cfg.AuthServer.BootstrapEnvOutFile,
	})
	if err != nil {
		if stoppedDuringStartup(startupCtx, err) {
			return stopCleanly()
		}
		slog.Error("unable to bootstrap the database", "error", err)
		return 1
	}
	switch outcome {
	case bootstrap.Exit:
		// The legacy two-step seed ends the process whatever happens next, but a signal that
		// arrived while it ran is still a stop during startup, said as every other one is.
		if finishStartup() {
			return stopCleanly()
		}
		return 0
	case bootstrap.Refused:
		return 1
	}

	// Validate and decode the session keys for normal operation, after the bootstrap check,
	// which mints them on a fresh install. previousKeys is nil unless an operator is rotating
	// the session keys: the store seals with the current pair and opens with the current pair
	// and then this one, so a rotation signs nobody out; the operator removes the two _PREVIOUS
	// variables once the maximum session lifetime has passed (#269, #270, #434).
	currentKeys, previousKeys, sessionKeysErr := cfg.AuthServer.SessionKeys()
	if sessionKeysErr != nil {
		logSessionKeysRefused(startupCtx, sessionKeysErr, cfg.AuthServer.BootstrapEnvOutFile)
		return 1
	}
	slog.Info("session keys validated")

	slog.Info("cookie security derived from the base URL",
		"cookie_secure", cfg.AuthServer.IsCookieSecure())

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
	sessionStore, err := newSessionStore(
		sessionbackend.NewAuthServerBackend(database),
		cfg.AuthServer.IsCookieSecure(),
		currentKeys,
		previousKeys,
	)
	if err != nil {
		slog.Error("unable to initialize the session store", "error", err)
		return 1
	}

	slog.Info("initialized server-side session store")

	r := chi.NewRouter()
	s := server.NewServer(r, database, sessionStore, dataCipher, trustedProxies, cfg)

	// A signal that arrived during the steps above that read no context, the session keys and the
	// store, is still a stop during startup: the server does not start. From here on a signal is
	// the running server's to say and to act on.
	if finishStartup() {
		return stopCleanly()
	}

	// The server just gets told when to stop. Start has drained whatever it started by the time it
	// returns, says whether all of it finished in time, and logs no error: this is the one record,
	// and the one exit, for all of them (#426).
	drained, err := s.Start(signalled)
	if !drained {
		closeOnReturn = false
		slog.Warn("work using the database outlived the shutdown, so the database is left to the process exit")
	}
	if err != nil {
		slog.Error("the auth server stopped on an error", "error", err)
		return 1
	}

	slog.Info("auth server stopped")
	return 0
}

// closeDatabase closes the database once the process is done with it. A close that fails stops
// nothing, since the process is ending; on SQLite it leaves the WAL beside the database, which the
// next start reads, so it is a warning.
func closeDatabase(database io.Closer) {
	if err := database.Close(); err != nil {
		slog.Warn("unable to close the database", "error", err)
	}
}

// watchStartup answers the context the startup steps run under, which ends when signalled does,
// and finish, which hands the signal over to the running server.
//
// The record saying the signal arrived is written when it arrives, with the running server's own
// message so both phases read alike in an aggregator, and the startup context ends only after it,
// so whatever a step says about its stop, such as where a migration stopped, follows it. finish
// reports whether the signal arrived during startup; when it did, the record has been written,
// and when it did not, nothing here will write it, so the running server's drain says it once.
func watchStartup(signalled context.Context) (startup context.Context, finish func() (stopped bool)) {
	startup, endStartup := context.WithCancel(context.Background())
	stopWatching := context.AfterFunc(signalled, func() {
		slog.InfoContext(signalled, "shutdown signal received")
		endStartup()
	})
	return startup, func() bool {
		if stopWatching() {
			endStartup()
			return false
		}
		<-startup.Done()
		return true
	}
}

// stoppedDuringStartup reports whether err is a startup step's answer to the shutdown signal
// rather than a failure: the signal arrived, and the step answered with the cancellation it
// caused. A step that failed for its own reason while the signal arrived is still a failure.
func stoppedDuringStartup(startup context.Context, err error) bool {
	return startup.Err() != nil && errors.Is(err, context.Canceled)
}

// stopCleanly ends a start the shutdown signal stopped: the running step finished and nothing new
// started, so the platform's request was carried out cleanly, and it answers exit code 0, as a
// drain does. Kubernetes restarts the container whatever the code, and Compose does not restart
// one it was told to stop (#390 decision 9).
func stopCleanly() int {
	slog.Info("auth server stopped")
	return 0
}

// sessionKeysPrevious and sessionKeysRequired are the auth server's two session-key pairs, by the
// variables a deployment sets them in.
var (
	sessionKeysPrevious = []string{
		"GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY_PREVIOUS",
		"GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY_PREVIOUS",
	}
	sessionKeysRequired = []string{
		"GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY",
		"GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY",
	}
)

// logSessionKeysRefused reports the session keys the auth server stops on, by what is wrong with
// them, since the remedy differs. Every refusal went to the bootstrap record, which told an operator
// who had added one half of a previous pair, or who had never had a bootstrap file, to copy every
// credential out of one. The error names the variable in all three cases:
//   - a previous pair set in part or malformed is a rotation mistake, and the record says to set
//     both halves or neither;
//   - a current key, where the legacy two-step bootstrap wrote a file, is a credential not yet
//     carried over from it, and the bootstrap record says so;
//   - a current key anywhere else, the single-step mode the setup wizard configures, has no file
//     to copy from, and the record names the two variables and how to generate them.
func logSessionKeysRefused(ctx context.Context, err error, bootstrapFile string) {
	var previousErr *sessionstore.PreviousKeysError
	switch {
	case errors.As(err, &previousErr):
		slog.ErrorContext(ctx, "the previous session key pair is incomplete or malformed, so the auth server cannot start: set both of its variables, or neither once the rotation is done",
			"error", err,
			"previous", sessionKeysPrevious)
	case bootstrapFile != "":
		bootstrap.LogCredentialsNotConfigured(ctx, err, bootstrapFile)
	default:
		slog.ErrorContext(ctx, "the auth server session keys are missing or malformed, so the auth server cannot start",
			"error", err,
			"required", sessionKeysRequired,
			"generate_with", "openssl rand -hex 64 (authentication key), openssl rand -hex 32 (encryption key)")
	}
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

// newSessionStore builds the auth server's browser session store over backend.
//
// The end user's cookie keeps an expiry, so single sign-on survives a browser restart. It is
// set per save from the row's own expires_at, which the operator's session settings decide,
// so one knob governs both halves and the browser never holds a handle that outlives what it
// names. The admin console does the opposite for the opposite reason, and the trade is argued
// in full in #266. A function of its own so the choice is pinned where it is made: the store's
// tests pin what each lifetime writes, and this package's pin which one this binary passes
// (#431).
func newSessionStore(backend sessionstore.Backend, secure bool,
	current sessionstore.KeyPair, previous *sessionstore.KeyPair) (*sessionstore.ServerSideStore, error) {
	return sessionstore.NewServerSideStore(backend, sessionkeys.SessionIdentifier, secure,
		sessionstore.PersistentCookie, current, previous)
}
