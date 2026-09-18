// Package config loads and holds the admin console's configuration.
//
// It carries only what this process reads: its own settings, and the two auth server endpoints it
// talks to. The auth server's listener, logging, database, initial-admin and data-encryption
// settings are not this binary's to load, and it no longer registers flags for them (#351).
package config

import (
	"encoding/hex"
	"flag"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
)

type AdminConsoleConfig struct {
	BaseURL                  string
	ListenHostHttps          string
	ListenPortHttps          int
	ListenHostHttp           string
	ListenPortHttp           int
	TrustProxyHeaders        bool
	TrustedProxies           []string
	LogHttpRequests          bool
	LogLevel                 string
	LogFormat                string
	CertFile                 string
	KeyFile                  string
	StaticDir                string
	TemplateDir              string
	OAuthClientSecret        string
	SessionAuthenticationKey string
	SessionEncryptionKey     string
	// The previous pair is set only while an operator is rotating the session keys. Both
	// or neither: the store needs both halves to open anything sealed under the old pair.
	SessionAuthenticationKeyPrevious string
	SessionEncryptionKeyPrevious     string
}

// IsCookieSecure reports whether cookies should carry the Secure flag. It is
// derived from the public BaseURL: https deployments get Secure cookies
// automatically, while plain-http (dev) deployments stay non-secure so login
// works over http://localhost. There is intentionally no separate override
// setting; the base URL scheme is the single source of truth.
func (c *AdminConsoleConfig) IsCookieSecure() bool {
	return isHTTPSURL(c.BaseURL)
}

// isHTTPSURL reports whether a URL uses the https scheme (case-insensitive).
func isHTTPSURL(u string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(u)), "https://")
}

// AuthServerConfig is the peer's configuration as far as the admin console is concerned, which is
// two endpoints rather than the whole of it. Both are peer endpoints: the admin console redirects
// the browser to BaseURL to authenticate, and calls the admin API at InternalBaseURL when one is
// set. Neither is the peer's own listener, logging, database or session configuration, which this
// process has no business loading (#351).
//
// There is deliberately no IsCookieSecure here, unlike on AdminConsoleConfig: whether the auth
// server's cookies carry the Secure flag is decided in the auth server, by the auth server.
type AuthServerConfig struct {
	BaseURL         string
	InternalBaseURL string
}

// GetEffectiveBaseURL returns the InternalBaseURL if set, otherwise returns BaseURL.
// Use InternalBaseURL for server-to-server communication to prefer internal network routes.
func (c *AuthServerConfig) GetEffectiveBaseURL() string {
	if ib := strings.TrimSpace(c.InternalBaseURL); ib != "" {
		return ib
	}
	return c.BaseURL
}

type Config struct {
	AdminConsole AdminConsoleConfig
	AuthServer   AuthServerConfig
}

var (
	cfg  Config
	once sync.Once
)

// Init initializes the configuration
func Init() {
	once.Do(load)
}

func load() {
	loadFrom(flag.CommandLine, os.Args[1:])
}

// loadFrom is load with the flag set and the arguments supplied.
//
// The seam exists because these flags live on the process-global
// flag.CommandLine, which panics on the second registration of any name: load()
// can therefore run exactly once per process, and no test could call it twice to
// observe what a flag or a variable lands on the config (#320).
func loadFrom(fs *flag.FlagSet, args []string) {
	cfg = Config{
		AdminConsole: AdminConsoleConfig{
			BaseURL:                          getEnv("GOIABADA_ADMINCONSOLE_BASEURL", "http://localhost:9091"),
			ListenHostHttps:                  getEnv("GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTPS", "0.0.0.0"),
			ListenPortHttps:                  getEnvAsInt("GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS", 9444),
			ListenHostHttp:                   getEnv("GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP", "0.0.0.0"),
			ListenPortHttp:                   getEnvAsInt("GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP", 9091),
			TrustProxyHeaders:                getEnvAsBool("GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS"),
			TrustedProxies:                   getEnvAsStringSlice("GOIABADA_ADMINCONSOLE_TRUSTED_PROXIES"),
			LogHttpRequests:                  getEnvAsBool("GOIABADA_ADMINCONSOLE_LOG_HTTP_REQUESTS"),
			LogLevel:                         getEnv("GOIABADA_ADMINCONSOLE_LOG_LEVEL", "info"),
			LogFormat:                        getEnv("GOIABADA_ADMINCONSOLE_LOG_FORMAT", "text"),
			CertFile:                         getEnv("GOIABADA_ADMINCONSOLE_CERTFILE", ""),
			KeyFile:                          getEnv("GOIABADA_ADMINCONSOLE_KEYFILE", ""),
			StaticDir:                        getEnv("GOIABADA_ADMINCONSOLE_STATICDIR", ""),
			TemplateDir:                      getEnv("GOIABADA_ADMINCONSOLE_TEMPLATEDIR", ""),
			OAuthClientSecret:                getEnv("GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET", ""),
			SessionAuthenticationKey:         getEnv("GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY", ""),
			SessionEncryptionKey:             getEnv("GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY", ""),
			SessionAuthenticationKeyPrevious: getEnv("GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY_PREVIOUS", ""),
			SessionEncryptionKeyPrevious:     getEnv("GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS", ""),
		},
		AuthServer: AuthServerConfig{
			BaseURL:         getEnv("GOIABADA_AUTHSERVER_BASEURL", "http://localhost:9090"),
			InternalBaseURL: getEnv("GOIABADA_AUTHSERVER_INTERNALBASEURL", ""),
		},
	}

	// Admin console
	fs.StringVar(&cfg.AdminConsole.BaseURL, "adminconsole-baseurl", cfg.AdminConsole.BaseURL, "Goiabada admin console base URL")
	fs.StringVar(&cfg.AdminConsole.ListenHostHttps, "adminconsole-listen-host-https", cfg.AdminConsole.ListenHostHttps, "Admin console https host")
	fs.IntVar(&cfg.AdminConsole.ListenPortHttps, "adminconsole-listen-port-https", cfg.AdminConsole.ListenPortHttps, "Admin console https port")
	fs.StringVar(&cfg.AdminConsole.ListenHostHttp, "adminconsole-listen-host-http", cfg.AdminConsole.ListenHostHttp, "Admin console http host")
	fs.IntVar(&cfg.AdminConsole.ListenPortHttp, "adminconsole-listen-port-http", cfg.AdminConsole.ListenPortHttp, "Admin console http port")
	fs.BoolVar(&cfg.AdminConsole.TrustProxyHeaders, "adminconsole-trust-proxy-headers", cfg.AdminConsole.TrustProxyHeaders, "Trust HTTP headers from reverse proxy in Admin console? (True-Client-IP, X-Real-IP or the X-Forwarded-For headers)")
	adminConsoleTrustedProxies := strings.Join(cfg.AdminConsole.TrustedProxies, ",")
	fs.StringVar(&adminConsoleTrustedProxies, "adminconsole-trusted-proxies", adminConsoleTrustedProxies, "Comma-separated list of trusted reverse-proxy IPs/CIDRs used to resolve the real client IP from X-Forwarded-For (admin console)")
	fs.BoolVar(&cfg.AdminConsole.LogHttpRequests, "adminconsole-log-http-requests", cfg.AdminConsole.LogHttpRequests, "Log HTTP requests for admin console")
	fs.StringVar(&cfg.AdminConsole.LogLevel, "adminconsole-log-level", cfg.AdminConsole.LogLevel, "Lowest level of log record the admin console writes. Options: debug, info, warn, error")
	fs.StringVar(&cfg.AdminConsole.LogFormat, "adminconsole-log-format", cfg.AdminConsole.LogFormat, "Format the admin console writes log records in. Options: text, json")
	fs.StringVar(&cfg.AdminConsole.CertFile, "adminconsole-certfile", cfg.AdminConsole.CertFile, "Certificate file for HTTPS (admin console)")
	fs.StringVar(&cfg.AdminConsole.KeyFile, "adminconsole-keyfile", cfg.AdminConsole.KeyFile, "Key file for HTTPS (admin console)")
	fs.StringVar(&cfg.AdminConsole.StaticDir, "adminconsole-staticdir", cfg.AdminConsole.StaticDir, "Static files directory for admin console")
	fs.StringVar(&cfg.AdminConsole.TemplateDir, "adminconsole-templatedir", cfg.AdminConsole.TemplateDir, "Template files directory for admin console")
	fs.StringVar(&cfg.AdminConsole.OAuthClientSecret, "adminconsole-oauth-client-secret", cfg.AdminConsole.OAuthClientSecret, "OAuth client_secret used by admin console (confidential client)")

	// Auth server: the two endpoints this process talks to, and nothing else. A flag the binary
	// cannot act on is a trap rather than a courtesy, because it reads as having configured
	// something -- so -db-type, -admin-email and the twenty-six others beside them are not
	// registered here, and this binary now refuses them instead of ignoring them (#351).
	fs.StringVar(&cfg.AuthServer.BaseURL, "authserver-baseurl", cfg.AuthServer.BaseURL, "Goiabada auth server base URL")
	fs.StringVar(&cfg.AuthServer.InternalBaseURL, "authserver-internalbaseurl", cfg.AuthServer.InternalBaseURL, "Goiabada auth server internal base URL")

	// The error is discarded rather than returned: flag.CommandLine is built with
	// ExitOnError, so a server given a bad flag has already exited by here, and a
	// test supplying its own set asserts on the config rather than on the parse.
	_ = fs.Parse(args)

	// Re-derive slice-valued config after flag parsing so a command-line flag
	// (comma-separated) overrides the environment value.
	cfg.AdminConsole.TrustedProxies = splitCSV(adminConsoleTrustedProxies)

	// Warn about removed settings still present in the environment so a
	// deployment relying on them notices they are now ignored. The Secure cookie
	// flag is derived from an https base URL (see IsCookieSecure).
	//
	// Only this process's own removed setting is named. GOIABADA_AUTHSERVER_SET_COOKIE_SECURE
	// is warned about by the auth server, whose cookies it was meant to affect, so an operator
	// hears about a setting from the binary it was for and this log stops carrying a line about
	// one it never honoured. Each binary warning about both would mean each carrying the other's
	// list of removed names, which is the coupling this split exists to remove (#351).
	for _, k := range deprecatedEnvVarsPresent("GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE") {
		// This is the one record in the tree the installed handler never sees: config.Init runs
		// before logging.Install, because the level and format it installs are read from this
		// very config. So it prints under Go's built-in handler, at its shape (#320).
		slog.Warn("a removed setting is present in the environment and is ignored, because the secure cookie flag is now derived from an https base url",
			"setting", k)
	}
}

func GetAdminConsole() *AdminConsoleConfig {
	return &cfg.AdminConsole
}

func GetAuthServer() *AuthServerConfig {
	return &cfg.AuthServer
}

func getEnv(key string, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(defaultVal)
}

func getEnvAsInt(key string, defaultVal int) int {
	valueStr := getEnv(key, "")
	if value, err := strconv.Atoi(strings.TrimSpace(valueStr)); err == nil {
		return value
	}
	return defaultVal
}

func getEnvAsBool(key string) bool {
	valueStr := getEnv(key, "")
	if value, err := strconv.ParseBool(strings.TrimSpace(valueStr)); err == nil {
		return value
	}
	return false
}

func getEnvAsStringSlice(key string) []string {
	return splitCSV(getEnv(key, ""))
}

// deprecatedEnvVarsPresent returns the subset of the given env var names that
// are set in the environment. Used to warn operators about removed settings.
func deprecatedEnvVarsPresent(keys ...string) []string {
	var present []string
	for _, k := range keys {
		if _, ok := os.LookupEnv(k); ok {
			present = append(present, k)
		}
	}
	return present
}

// splitCSV splits a comma-separated string into trimmed, non-empty items.
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// The two admin console settings that stopped being configuration: the client id the admin
// console authenticates as, which is the constant the seeder writes and the migrations grant
// against, and the issuer, which the auth server stamps into the tokens the admin console
// validates (#285).
const (
	removedClientIDVar = "GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID"
	removedIssuerVar   = "GOIABADA_ADMINCONSOLE_ISSUER"
)

// ValidateRemovedAdminConsoleVars refuses startup when a deployment still carries either
// removed variable at a value the admin console can no longer honour (#285). It reads the
// raw environment because neither value is held in config any more.
//
// It refuses rather than warning, which is the deliberate difference from the removed-setting
// loop in Init: an operator can miss a log line in a running deployment, and what they would
// otherwise meet is a token failure naming a client they never configured. The client id is
// checked first, so an operator carrying both wrong values is told about the client id first.
//
// A client id present and equal to the constant starts silently, because that is what every
// deployment the setup wizard has ever produced sets. The issuer refuses whenever it is
// present at all: nothing in the tree ever sets it, so any value is a hand-written line.
func ValidateRemovedAdminConsoleVars() error {
	for _, k := range deprecatedEnvVarsPresent(removedClientIDVar, removedIssuerVar) {
		value := os.Getenv(k)
		switch k {
		case removedClientIDVar:
			if strings.TrimSpace(value) == constants.AdminConsoleClientIdentifier {
				continue
			}
			return errs.Errorf("%s is set to %q but is no longer configuration: the admin console always authenticates as %q, the client the auth server seeds. Remove %s from the deployment's configuration",
				removedClientIDVar, value, constants.AdminConsoleClientIdentifier, removedClientIDVar)
		case removedIssuerVar:
			return errs.Errorf("%s is set to %q but is no longer configuration: the admin console takes the issuer from the auth server that stamps it into tokens, so this value is never read. Remove %s from the deployment's configuration",
				removedIssuerVar, value, removedIssuerVar)
		}
	}
	return nil
}

// ValidateAdminConsoleSessionKeys validates that admin console session keys are present
// and correct length, and that the optional previous pair, when a rotation is in progress,
// is set in full and to the same lengths.
func ValidateAdminConsoleSessionKeys() error {
	authKey := cfg.AdminConsole.SessionAuthenticationKey
	encKey := cfg.AdminConsole.SessionEncryptionKey

	if authKey == "" {
		return errs.Errorf("GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY is required")
	}
	if encKey == "" {
		return errs.Errorf("GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY is required")
	}

	// Validate hex encoding and length
	authKeyBytes, err := hex.DecodeString(authKey)
	if err != nil {
		return errs.Errorf("GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY must be hex-encoded (error: %w). Generate with: openssl rand -hex 64", err)
	}
	if len(authKeyBytes) != 64 {
		return errs.Errorf("GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY must be 64 bytes (128 hex chars), got %d bytes. Generate with: openssl rand -hex 64", len(authKeyBytes))
	}

	encKeyBytes, err := hex.DecodeString(encKey)
	if err != nil {
		return errs.Errorf("GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY must be hex-encoded (error: %w). Generate with: openssl rand -hex 32", err)
	}
	if len(encKeyBytes) != 32 {
		return errs.Errorf("GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY must be 32 bytes (64 hex chars), got %d bytes. Generate with: openssl rand -hex 32", len(encKeyBytes))
	}
	// The previous pair is optional and set only while the session keys are being rotated,
	// but it is accepted as a pair rather than as two variables: one half alone opens
	// nothing, so a deployment that sets one and not the other has a rotation it believes
	// is in place and is not, and everybody it was meant to keep signed in signs in again
	// (decision 10).
	prevAuthKey := strings.TrimSpace(cfg.AdminConsole.SessionAuthenticationKeyPrevious)
	prevEncKey := strings.TrimSpace(cfg.AdminConsole.SessionEncryptionKeyPrevious)

	if prevAuthKey != "" || prevEncKey != "" {
		if prevAuthKey == "" {
			return errs.Errorf("GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY_PREVIOUS is required when GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS is set: both halves of the previous pair are needed to open a session sealed under it")
		}
		if prevEncKey == "" {
			return errs.Errorf("GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS is required when GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY_PREVIOUS is set: both halves of the previous pair are needed to open a session sealed under it")
		}

		prevAuthKeyBytes, err := hex.DecodeString(prevAuthKey)
		if err != nil {
			return errs.Errorf("GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY_PREVIOUS must be hex-encoded (error: %w)", err)
		}
		if len(prevAuthKeyBytes) != 64 {
			return errs.Errorf("GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY_PREVIOUS must be 64 bytes (128 hex chars), got %d bytes", len(prevAuthKeyBytes))
		}

		prevEncKeyBytes, err := hex.DecodeString(prevEncKey)
		if err != nil {
			return errs.Errorf("GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS must be hex-encoded (error: %w)", err)
		}
		if len(prevEncKeyBytes) != 32 {
			return errs.Errorf("GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS must be 32 bytes (64 hex chars), got %d bytes", len(prevEncKeyBytes))
		}
	}

	return nil
}
