// Package config loads and holds the admin console's configuration.
//
// It carries only what this process reads: its own settings, and the two auth server endpoints it
// talks to. The auth server's listener, logging, database, initial-admin and data-encryption
// settings are not this binary's to load, and it no longer registers flags for them (#351).
package config

import (
	"flag"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/middleware"
	"github.com/leodip/goiabada/core/sessionstore"
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
	// I18nOverridesDir is the directory whose catalogs/ main merges over the embedded message
	// catalogs, or empty for none. It has no flag, like the auth server's, so the one variable
	// configures both servers the same way (#431).
	I18nOverridesDir string
}

// IsCookieSecure reports whether cookies should carry the Secure flag. It is
// derived from the public BaseURL: https deployments get Secure cookies
// automatically, while plain-http (dev) deployments stay non-secure so login
// works over http://localhost. There is intentionally no separate override
// setting; the base URL scheme is the single source of truth.
func (c *AdminConsoleConfig) IsCookieSecure() bool {
	return isHTTPSURL(c.BaseURL)
}

// TrustedProxyRanges parses TrustedProxies into the ranges the real-IP
// middleware walks. main refuses to start on the error, whatever
// TrustProxyHeaders says, because an entry that is neither an IP nor a CIDR is
// a restriction the operator asked for and cannot get (#425). The value can come
// from the variable or the flag, so the error names both.
func (c *AdminConsoleConfig) TrustedProxyRanges() ([]*net.IPNet, error) {
	ranges, err := middleware.ParseTrustedProxies(c.TrustedProxies)
	if err != nil {
		return nil, errs.Wrap(err, "GOIABADA_ADMINCONSOLE_TRUSTED_PROXIES (--adminconsole-trusted-proxies)")
	}
	return ranges, nil
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
	cfg     Config
	once    sync.Once
	loadErr error
)

// Init initializes the configuration and answers the load's refusal, a malformed numeric or
// boolean variable. The once keeps the error as well as the load, so every call answers it and a
// caller cannot read a refused configuration by calling twice (#434).
func Init() error {
	once.Do(func() { loadErr = load() })
	return loadErr
}

func load() error {
	return loadFrom(flag.CommandLine, os.Args[1:])
}

// loadFrom is load with the flag set and the arguments supplied.
//
// The seam exists because these flags live on the process-global
// flag.CommandLine, which panics on the second registration of any name: load()
// can therefore run exactly once per process, and no test could call it twice to
// observe what a flag or a variable lands on the config (#320).
//
// It answers every numeric or boolean variable that is set and does not parse, in one error, and
// fills cfg either way. A flag given for the same setting does not rescue the variable: the value
// the operator wrote is wrong whichever of the two wins (#434).
func loadFrom(fs *flag.FlagSet, args []string) error {
	var malformed malformedValues
	cfg = Config{
		AdminConsole: AdminConsoleConfig{
			BaseURL:                          getEnv("GOIABADA_ADMINCONSOLE_BASEURL", "http://localhost:9091"),
			ListenHostHttps:                  getEnv("GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTPS", "0.0.0.0"),
			ListenPortHttps:                  getEnvAsInt("GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS", 9444, &malformed),
			ListenHostHttp:                   getEnv("GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP", "0.0.0.0"),
			ListenPortHttp:                   getEnvAsInt("GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP", 9091, &malformed),
			TrustProxyHeaders:                getEnvAsBool("GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS", &malformed),
			TrustedProxies:                   getEnvAsStringSlice("GOIABADA_ADMINCONSOLE_TRUSTED_PROXIES"),
			LogHttpRequests:                  getEnvAsBool("GOIABADA_ADMINCONSOLE_LOG_HTTP_REQUESTS", &malformed),
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
			I18nOverridesDir:                 getEnv("GOIABADA_I18N_OVERRIDES_DIR", ""),
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

	return malformed.err()
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

// malformedValues collects every numeric or boolean variable loadFrom could not parse, so one
// refusal names them all rather than costing the operator a restart per typo (#434).
type malformedValues []string

func (m *malformedValues) add(key, value, want string) {
	*m = append(*m, key+" is "+strconv.Quote(value)+", not "+want)
}

// err is the refusal: one line, whatever the values hold, because main writes it to stderr
// before any log handler exists and an operator reads it as the one reason the server stopped.
// The values are quoted, so not even a value carrying a newline can break it.
func (m malformedValues) err() error {
	if len(m) == 0 {
		return nil
	}
	return errs.Errorf("malformed configuration: %s", strings.Join(m, "; "))
}

// getEnvAsInt answers the default when the variable is unset or empty after the trim, and the
// number when it parses. Anything else is recorded as malformed rather than read as the default:
// a mistyped port used to leave the server on the port it shipped with and say nothing (#434).
// Empty stays the default because every shipped compose file and the setup wizard write
// GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS= to mean no https listener.
func getEnvAsInt(key string, defaultVal int, malformed *malformedValues) int {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultVal
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		malformed.add(key, valueStr, "an integer")
		return defaultVal
	}
	return value
}

// getEnvAsBool is getEnvAsInt's rule for a setting whose default is false: an operator writing
// yes used to get the setting off, silently (#434).
func getEnvAsBool(key string, malformed *malformedValues) bool {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return false
	}
	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		malformed.add(key, valueStr, "a boolean (true or false)")
		return false
	}
	return value
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

// SessionKeys decodes the admin console's session keys through the one rule both
// applications share, sessionstore.ParseKeys, under this binary's variable names: the
// current pair, required, and the previous pair, nil unless a rotation is in progress.
func (c *AdminConsoleConfig) SessionKeys() (sessionstore.KeyPair, *sessionstore.KeyPair, error) {
	return sessionstore.ParseKeys(sessionstore.ConfiguredKeys{
		Authentication: sessionstore.ConfiguredKey{
			Name:  "GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY",
			Value: c.SessionAuthenticationKey,
		},
		Encryption: sessionstore.ConfiguredKey{
			Name:  "GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY",
			Value: c.SessionEncryptionKey,
		},
		PreviousAuthentication: sessionstore.ConfiguredKey{
			Name:  "GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY_PREVIOUS",
			Value: c.SessionAuthenticationKeyPrevious,
		},
		PreviousEncryption: sessionstore.ConfiguredKey{
			Name:  "GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS",
			Value: c.SessionEncryptionKeyPrevious,
		},
	})
}
