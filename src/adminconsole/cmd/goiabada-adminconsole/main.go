package main

import (
	"encoding/gob"
	"encoding/hex"
	"fmt"
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
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/timezones"
)

func main() {
	slog.Info("admin console started")
	slog.Info("goiabada version: " + constants.Version)
	slog.Info("build date: " + constants.BuildDate)
	slog.Info("git commit: " + constants.GitCommit)

	config.Init()
	slog.Info("config loaded")

	// Refuse a configuration carried over from a release where the client id and the issuer
	// were settings here. Both now come from the auth server that owns them, so a value left
	// behind is either ignored or points this module at a client the auth server never
	// provisioned (#285).
	if err := config.ValidateRemovedAdminConsoleVars(); err != nil {
		slog.Error("configuration validation failed: " + err.Error())
		os.Exit(1)
	}

	// Validate session keys EARLY - fail fast if missing or invalid
	if err := config.ValidateAdminConsoleSessionKeys(); err != nil {
		slog.Error("session key validation failed: " + err.Error())
		slog.Error("Please set GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY and GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY")
		slog.Error("Generate keys with: openssl rand -hex 64 (for authentication key) and openssl rand -hex 32 (for encryption key)")
		os.Exit(1)
	}
	slog.Info("session keys validated")

	// Validate OAuth credentials EARLY - fail fast if missing
	adminConsoleConfig := config.GetAdminConsole()
	// One block, keyed on the secret: the client id is no longer configuration, so the only
	// half of the credential a deployment supplies is the secret (#285).
	if adminConsoleConfig.OAuthClientSecret == "" {
		slog.Error("================================================================================")
		slog.Error("BOOTSTRAP CREDENTIALS NOT CONFIGURED")
		slog.Error("================================================================================")
		slog.Error("The admin console requires OAuth credentials to authenticate with the auth server.")
		slog.Error("")
		slog.Error("If this is your first deployment:")
		slog.Error("1. Start the auth server first - it will generate bootstrap credentials and exit")
		slog.Error("2. Copy credentials from the bootstrap file to your deployment configuration")
		slog.Error("3. Restart both auth server and admin console with the credentials set")
		slog.Error("")
		slog.Error("Required environment variables:")
		slog.Error("  - GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET")
		slog.Error("  - GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY")
		slog.Error("  - GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY")
		slog.Error("================================================================================")
		os.Exit(1)
	}
	slog.Info("OAuth credentials validated")

	slog.Info("auth server base URL: " + config.GetAuthServer().BaseURL)
	slog.Info("auth server internal base URL: " + config.GetAuthServer().InternalBaseURL)
	slog.Info("admin console base URL: " + config.GetAdminConsole().BaseURL)

	dir, err := os.Getwd()
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
	slog.Info("current working directory: " + dir)

	// trigger the load of timezones from OS (they will be cached)
	_ = timezones.Get()
	slog.Info("timezones loaded")

	// Load i18n message catalogs (and merge GOIABADA_I18N_OVERRIDES_DIR if set).
	// Fail-fast: a malformed catalog or missing override dir is a config bug.
	if _, err := i18n.LoadBundle(); err != nil {
		slog.Error(fmt.Sprintf("i18n LoadBundle failed: %+v", err))
		os.Exit(1)
	}
	slog.Info("i18n catalogs loaded")

	// gob registration
	gob.Register(oauth.TokenResponse{})

	slog.Info("current time zone is: " + time.Now().Location().String())
	slog.Info("current local time is: " + time.Now().String())
	slog.Info("current UTC time is: " + time.Now().UTC().String())

	slog.Info("cookie secure (derived from base URL): " + fmt.Sprintf("%t", config.GetAdminConsole().IsCookieSecure()))

	// Decode session keys from config (already validated at startup)
	authKey, _ := hex.DecodeString(config.GetAdminConsole().SessionAuthenticationKey)
	encKey, _ := hex.DecodeString(config.GetAdminConsole().SessionEncryptionKey)

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

	sessionStore := sessionstore.NewServerSideStore(
		sessionstore.NewHTTPBackend(config.GetAuthServer().GetEffectiveBaseURL(), tokenSource),
		constants.SessionKeyJwt,
		config.GetAdminConsole().IsCookieSecure(),
		authKey, encKey,
	)

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
