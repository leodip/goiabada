package main

import (
	"encoding/gob"
	"log/slog"
	"os"
	"time"
	_ "time/tzdata"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/cache"
	"github.com/leodip/goiabada/adminconsole/internal/server"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
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
	if err := logging.Install(config.GetAdminConsole().LogLevel, config.GetAdminConsole().LogFormat); err != nil {
		slog.Error("unable to install the log handler", "error", err)
		os.Exit(1)
	}

	slog.Info("admin console started")
	slog.Info("build information",
		"version", constants.Version,
		"build_date", constants.BuildDate,
		"git_commit", constants.GitCommit)
	slog.Info("config loaded")

	// Refuse a configuration carried over from a release where the client id and the issuer
	// were settings here. Both now come from the auth server that owns them, so a value left
	// behind is either ignored or points this module at a client the auth server never
	// provisioned (#285).
	if err := config.ValidateRemovedAdminConsoleVars(); err != nil {
		slog.Error("the configuration sets variables that were removed, so the admin console cannot start",
			"error", err)
		os.Exit(1)
	}

	// Validate session keys EARLY - fail fast if missing or invalid
	if err := config.ValidateAdminConsoleSessionKeys(); err != nil {
		logSessionKeysNotConfigured(err)
		os.Exit(1)
	}
	slog.Info("session keys validated")

	// Validate OAuth credentials EARLY - fail fast if missing
	adminConsoleConfig := config.GetAdminConsole()
	// One block, keyed on the secret: the client id is no longer configuration, so the only
	// half of the credential a deployment supplies is the secret (#285).
	if adminConsoleConfig.OAuthClientSecret == "" {
		logBootstrapCredentialsNotConfigured()
		os.Exit(1)
	}
	slog.Info("oauth credentials validated")

	slog.Info("using configuration",
		"auth_server_base_url", config.GetAuthServer().BaseURL,
		"auth_server_internal_base_url", config.GetAuthServer().InternalBaseURL,
		"admin_console_base_url", config.GetAdminConsole().BaseURL)

	dir, err := os.Getwd()
	if err != nil {
		slog.Error("unable to determine the current working directory", "error", err)
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

	slog.Info("cookie security derived from the base URL",
		"cookie_secure", config.GetAdminConsole().IsCookieSecure())

	// Decode the session keys from config, which validated them at startup. The decode
	// errors are still checked: what they would otherwise become is a store keyed with two
	// empty byte slices, which is a key anyone can recompute rather than a failure (#269).
	currentKeys, err := sessionstore.DecodeKeyPair(
		config.GetAdminConsole().SessionAuthenticationKey,
		config.GetAdminConsole().SessionEncryptionKey)
	if err != nil {
		slog.Error("unable to decode the session keys", "error", err)
		os.Exit(1)
	}

	// The previous pair, nil unless an operator is rotating the session keys. The store
	// seals with the current pair and opens with the current pair and then this one, so a
	// rotation signs nobody out; the operator removes the two _PREVIOUS variables once the
	// maximum session lifetime has passed (#269, #270).
	previousKeys, err := sessionstore.DecodePreviousKeyPair(
		config.GetAdminConsole().SessionAuthenticationKeyPrevious,
		config.GetAdminConsole().SessionEncryptionKeyPrevious)
	if err != nil {
		slog.Error("unable to decode the previous session keys", "error", err)
		os.Exit(1)
	}
	if previousKeys != nil {
		slog.Info("previous session keys configured: a session sealed under them still opens")
	}

	// The session lives in a row on the auth server's side of the wire and the browser
	// carries nothing but a signed, opaque identifier. This module keeps no database
	// connection of its own, deliberately, so it reaches that row through the auth
	// server's session endpoint with a client_credentials token carrying one narrow
	// permission.
	//
	// What crosses the wire is ciphertext encrypted with this module's own session keys,
	// so the auth server stores bytes it holds no key for: administrator tokens are the
	// highest value tokens in the deployment, and a dump of the auth server's database
	// yields none of them, which is the invariant it has today and this must not spend.
	//
	// What it replaces put the whole session, an entire token set included, in the cookie
	// and split the ciphertext across up to fifty of them (#266).
	tokenSource := apiclient.NewSessionTokenSource(
		config.GetAuthServer().GetEffectiveBaseURL(),
		constants.AdminConsoleClientIdentifier,
		adminConsoleConfig.OAuthClientSecret,
	)

	sessionStore, err := sessionstore.NewServerSideStore(
		sessionstore.NewHTTPBackend(config.GetAuthServer().GetEffectiveBaseURL(), tokenSource),
		constants.SessionKeyJwt,
		config.GetAdminConsole().IsCookieSecure(),
		currentKeys,
		previousKeys,
	)
	if err != nil {
		slog.Error("unable to initialize the session store", "error", err)
		os.Exit(1)
	}

	// PersistentCookie is left false, which is the half of the split the auth server does
	// not take: its cookie carries an expiry so single sign-on survives a browser restart,
	// and this one carries none so the browser drops it when it closes. An administrator
	// pays one extra sign-in after a browser restart, and in exchange the handle to the
	// deployment's most privileged session is not left sitting on the disk of a machine
	// that can be stolen. Browser session restore can still bring such a cookie back, so
	// this is real protection rather than a guarantee (#266).
	//
	// It also retires a defect: the store this replaces set a one year cookie expiry with
	// no resolver, so a machine held a handle for a year for contents that stopped working
	// in minutes.

	slog.Info("initialized server-side session store")

	// Initialize settings cache (fetches from authserver public API)
	// Prefer internal base URL for server-to-server communication
	settingsCache := cache.NewSettingsCache(config.GetAuthServer().GetEffectiveBaseURL())
	slog.Info("initialized settings cache with 30s TTL")

	r := chi.NewRouter()
	s := server.NewServer(r, sessionStore, settingsCache)

	s.Start()
}

// logBootstrapCredentialsNotConfigured reports a deployment with no OAuth client
// secret, which is the credential the admin console authenticates to the auth
// server with and the one half of it a deployment supplies (#285).
//
// One record where a 13-line banner used to be. The names are listed rather than
// described, because the operator's next action is to set them (#320 decision 6).
// logSessionKeysNotConfigured reports session keys the console cannot use, which
// it needs before it can seal a cookie and therefore before it can serve anything.
//
// One record where three used to be, for the reason decision 6 collapses the
// banners: the failure, the two variables to set and the command that generates
// them are one instruction, and as three records a JSON deployment received them
// unrelated, with the remedy in a message field nothing could query. It is a
// function rather than three lines inside main so that the record has a seam to be
// asserted at (#320).
func logSessionKeysNotConfigured(err error) {
	slog.Error("the admin console session keys are missing or malformed, so the admin console cannot start",
		"error", err,
		"required", []string{
			"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY",
			"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY",
		},
		"generate_with", "openssl rand -hex 64 (authentication key), openssl rand -hex 32 (encryption key)")
}

func logBootstrapCredentialsNotConfigured() {
	slog.Error("bootstrap credentials are not configured, so the admin console cannot start: on a first deployment start the auth server first, which writes the bootstrap file and exits, then copy every credential into the two services' configuration and restart them",
		"required", []string{
			"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET",
			"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY",
			"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY",
		})
}
