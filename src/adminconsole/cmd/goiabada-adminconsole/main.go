package main

import (
	"context"
	"encoding/gob"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // embeds the zone database localzone.Install resolves TZ against (#49, #331, #432)

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/publicsettings"
	"github.com/leodip/goiabada/adminconsole/internal/server"
	"github.com/leodip/goiabada/adminconsole/internal/sessionbackend"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/localzone"
	"github.com/leodip/goiabada/core/logging"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
)

func main() {
	// TZ is resolved again before anything else, so the first record is already in the zone the
	// deployment chose. The zone database this binary embeds is reachable only from here: a
	// dependency fixes the local zone during package initialization, before it registers, so on a
	// host with no zone database TZ was ignored. A TZ that names no zone, or a zone file that does
	// not load, takes a malformed variable's channel and code, one line on stderr and exit 2 (#331).
	if err := localzone.Install(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}

	// The configuration and the log handler come before the first record. The
	// level and the format are per-server settings, so anything written ahead of
	// the install goes out in a shape the deployment did not choose, and a value
	// the handler cannot read has to stop the server rather than be silently
	// replaced by a default (#320).
	//
	// A numeric or boolean variable that does not parse stops the server here, all of them named
	// at once. It goes to stderr as one line and exits 2, which is what a bad flag already gets
	// from flag.CommandLine, because no log handler exists yet to write it through (#434).
	//
	// It is loaded once, here, and handed on: the server and every handler receive the values
	// they use when they are built (#441).
	cfg, loadErr := config.Load(flag.CommandLine, os.Args[1:])
	if loadErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", loadErr)
		os.Exit(2)
	}
	if err := logging.Install(cfg.AdminConsole.LogLevel, cfg.AdminConsole.LogFormat); err != nil {
		slog.Error("unable to install the log handler", "error", err)
		os.Exit(1)
	}

	// A trusted-proxy entry that is neither an IP nor a CIDR stops the server whatever
	// TRUST_PROXY_HEADERS says. Skipping it would leave a list of typos empty, which the real-IP
	// middleware reads as trusting any single hop, and a typo in a list trust is off for today
	// would otherwise surface only on the day trust is switched on (#425).
	trustedProxies, proxyErr := cfg.AdminConsole.TrustedProxyRanges()
	if proxyErr != nil {
		slog.Error("the trusted proxy list is malformed, so the admin console cannot start", "error", proxyErr)
		os.Exit(1)
	}

	slog.Info("admin console started")
	slog.Info("build information",
		"version", coreconstants.Version,
		"build_date", coreconstants.BuildDate,
		"git_commit", coreconstants.GitCommit)
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

	// Validate and decode the session keys EARLY - fail fast if missing or invalid.
	// previousKeys is nil unless an operator is rotating the session keys: the store seals
	// with the current pair and opens with the current pair and then this one, so a rotation
	// signs nobody out; the operator removes the two _PREVIOUS variables once the maximum
	// session lifetime has passed (#269, #270, #434).
	currentKeys, previousKeys, err := cfg.AdminConsole.SessionKeys()
	if err != nil {
		logSessionKeysNotConfigured(err)
		os.Exit(1)
	}
	slog.Info("session keys validated")

	// Validate OAuth credentials EARLY - fail fast if missing
	// One block, keyed on the secret: the client id is no longer configuration, so the only
	// half of the credential a deployment supplies is the secret (#285). The only check, too:
	// Start used to repeat it with TrimSpace, so a secret of blanks passed here and stopped the
	// console there (#426).
	if strings.TrimSpace(cfg.AdminConsole.OAuthClientSecret) == "" {
		logBootstrapCredentialsNotConfigured()
		os.Exit(1)
	}
	slog.Info("oauth credentials validated")

	slog.Info("using configuration",
		"auth_server_base_url", cfg.AuthServer.BaseURL,
		"auth_server_internal_base_url", cfg.AuthServer.InternalBaseURL,
		"admin_console_base_url", cfg.AdminConsole.BaseURL)

	dir, err := os.Getwd()
	if err != nil {
		slog.Error("unable to determine the current working directory", "error", err)
		os.Exit(1)
	}
	slog.Info("current working directory", "directory", dir)

	// Merge the overrides directory the configuration read from GOIABADA_I18N_OVERRIDES_DIR over
	// the embedded message catalogs. Fail-fast: a malformed catalog is a config bug.
	if loadBundleErr := i18n.LoadBundle(cfg.AdminConsole.I18nOverridesDir); loadBundleErr != nil {
		slog.Error("unable to load the i18n message catalogs", "error", loadBundleErr)
		os.Exit(1)
	}
	slog.Info("i18n catalogs loaded")

	// The admin console keeps the token response in its session, and session.Values is a
	// map[interface{}]interface{}, so gob has to be told the concrete type before it can
	// decode one back. This registration is live: handler_auth_callback.go writes the value
	// and internal/middleware reads it. The auth server had the same two lines and encoded no
	// such value, so they went with #338; the name this call registers is pinned by
	// TestTokenResponse_GobSessionIdentity in core/oauth, because it is written into every
	// session in flight and an administrator whose session cannot be decoded is signed out.
	gob.Register(oauth.TokenResponse{})

	now := time.Now()
	slog.Info("process clock",
		"time_zone", now.Location().String(),
		"local_time", now,
		"utc_time", now.UTC())

	slog.Info("cookie security derived from the base URL",
		"cookie_secure", cfg.AdminConsole.IsCookieSecure())

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
	//
	// The bearer is a client_credentials token from the one token client, cached by
	// SessionTokenSource; the backend asks it for one and knows nothing of the grant. The same
	// token client and HTTP client go to the server, for the sign-in's exchange, the refresh and
	// the JWKS fetch, so no second construction can drift from this one (#441).
	authServerBaseURL := cfg.AuthServer.GetEffectiveBaseURL()
	authServerHTTPClient := oauthclient.NewAuthServerHTTPClient()
	tokenClient := newTokenClient(cfg, authServerHTTPClient)
	tokenSource := oauthclient.NewSessionTokenSource(tokenClient)

	sessionStore, err := newSessionStore(
		sessionbackend.New(authServerBaseURL, tokenSource),
		cfg.AdminConsole.IsCookieSecure(),
		currentKeys,
		previousKeys,
	)
	if err != nil {
		slog.Error("unable to initialize the session store", "error", err)
		os.Exit(1)
	}

	slog.Info("initialized server-side session store")

	// Initialize settings cache (fetches from authserver public API)
	// Prefer internal base URL for server-to-server communication
	settingsCache := publicsettings.NewCache(
		publicsettings.NewClient(cfg.AuthServer.GetEffectiveBaseURL()), publicsettings.DefaultTTL)
	slog.Info("initialized settings cache with 30s TTL")

	r := chi.NewRouter()
	s := server.NewServer(r, sessionStore, settingsCache, trustedProxies, cfg, authServerHTTPClient, tokenClient)

	// The process owns the signals, as the auth server's does; the console just gets told when to
	// stop. On SIGTERM (what a container runtime sends) or SIGINT, ctx is cancelled and Start
	// drains the listeners before returning. Before #426 nothing listened, and SIGTERM cut off
	// every request in flight.
	ctx, stopListeningForSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopListeningForSignals()

	// Start logs none of its errors: this is the one record, and the one exit, for all of them. The
	// deferred stop does not run under os.Exit, hence the explicit call.
	if err := s.Start(ctx); err != nil {
		slog.Error("the admin console stopped on an error", "error", err)
		stopListeningForSignals()
		os.Exit(1)
	}

	slog.Info("admin console stopped")
}

// newTokenClient builds the console's one token client, which makes all three of its grants. The
// token URL is the effective auth server base URL joined through TokenEndpointURL, so a configured
// base URL ending in a slash still reaches /auth/token. The admin console is always the client the
// seeder provisions, so the identifier is the constant and only the secret is per deployment
// (#285, #441).
func newTokenClient(cfg *config.Config, httpClient *http.Client) *oauthclient.TokenClient {
	return oauthclient.NewTokenClient(
		oauthclient.TokenEndpointURL(cfg.AuthServer.GetEffectiveBaseURL()),
		coreconstants.AdminConsoleClientIdentifier,
		cfg.AdminConsole.OAuthClientSecret,
		httpClient,
	)
}

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

// logBootstrapCredentialsNotConfigured reports a deployment with no OAuth client
// secret, which is the credential the admin console authenticates to the auth
// server with and the one half of it a deployment supplies (#285).
//
// One record where a 13-line banner used to be. The names are listed rather than
// described, because the operator's next action is to set them (#320 decision 6).
func logBootstrapCredentialsNotConfigured() {
	slog.Error("bootstrap credentials are not configured, so the admin console cannot start: on a first deployment start the auth server first, which writes the bootstrap file and exits, then copy every credential into the two services' configuration and restart them",
		"required", []string{
			"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET",
			"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY",
			"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY",
		})
}

// newSessionStore builds the admin console's browser session store over backend.
//
// Its cookie carries no expiry, which is the half of the split the auth server does not take:
// that cookie carries one so single sign-on survives a browser restart, and this one carries
// none so the browser drops it when it closes. An administrator pays one extra sign-in after a
// browser restart, and in exchange the handle to the deployment's most privileged session is
// not left sitting on the disk of a machine that can be stolen. Browser session restore can
// still bring such a cookie back, so this is real protection rather than a guarantee (#266).
// It also retired a defect: the store this replaced set a one year cookie expiry with no
// resolver, so a machine held a handle for a year for contents that stopped working in
// minutes.
//
// A function of its own so the choice is pinned where it is made: the store's tests pin what
// each lifetime writes, and this package's pin which one this binary passes (#431).
func newSessionStore(backend sessionstore.Backend, secure bool,
	current sessionstore.KeyPair, previous *sessionstore.KeyPair) (*sessionstore.ServerSideStore, error) {
	return sessionstore.NewServerSideStore(backend, sessionkeys.SessionKeyJwt, secure,
		sessionstore.BrowserSessionCookie, current, previous)
}
