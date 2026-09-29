// Package config loads and holds the auth server's configuration.
//
// It carries only what this process reads: its own settings, the database, the initial-admin and
// app-name values, the two data-encryption keys, and the two admin console values the auth server
// genuinely needs. The admin console's listener, logging, directory and session settings are not
// this binary's to load, and it no longer registers flags for them (#351).
package config

import (
	"encoding/hex"
	"flag"
	"log/slog"
	"math"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/middleware"
	"github.com/leodip/goiabada/core/sessionstore"
)

type AuthServerConfig struct {
	BaseURL                  string
	InternalBaseURL          string
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
	LogSQL                   bool
	StaticDir                string
	TemplateDir              string
	DebugAPIRequests         bool
	BootstrapEnvOutFile      string
	SessionAuthenticationKey string
	SessionEncryptionKey     string
	// The previous pair is set only while an operator is rotating the session keys. Both
	// or neither: the store needs both halves to open anything sealed under the old pair.
	SessionAuthenticationKeyPrevious string
	SessionEncryptionKeyPrevious     string
	RateLimiterEnabled               bool
	ProfilePictureMaxSizeBytes       int64
	// I18nOverridesDir is the directory whose catalogs/ main merges over the embedded message
	// catalogs, or empty for none. It has no flag, like the admin console's, so the one variable
	// configures both servers the same way (#431).
	I18nOverridesDir string
}

// IsCookieSecure reports whether cookies should carry the Secure flag. It is
// derived from the public BaseURL: https deployments get Secure cookies
// automatically, while plain-http (dev) deployments stay non-secure so login
// works over http://localhost. There is intentionally no separate override
// setting; the base URL scheme is the single source of truth.
func (c *AuthServerConfig) IsCookieSecure() bool {
	return isHTTPSURL(c.BaseURL)
}

// TrustedProxyRanges parses TrustedProxies into the ranges the real-IP
// middleware walks. main refuses to start on the error, whatever
// TrustProxyHeaders says, because an entry that is neither an IP nor a CIDR is
// a restriction the operator asked for and cannot get (#425). The value can come
// from the variable or the flag, so the error names both.
func (c *AuthServerConfig) TrustedProxyRanges() ([]*net.IPNet, error) {
	ranges, err := middleware.ParseTrustedProxies(c.TrustedProxies)
	if err != nil {
		return nil, errs.Wrap(err, "GOIABADA_AUTHSERVER_TRUSTED_PROXIES (--authserver-trusted-proxies)")
	}
	return ranges, nil
}

// isHTTPSURL reports whether a URL uses the https scheme (case-insensitive).
func isHTTPSURL(u string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(u)), "https://")
}

// AdminConsoleConfig is the peer's configuration as far as the auth server is concerned, which is
// two values rather than the whole of it. BaseURL is a peer endpoint: the auth server puts it in
// the links it mails and redirects `/` to it. OAuthClientSecret is the one shared bootstrap
// secret -- goiabada-setup writes GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET into both services'
// environment blocks, the auth server seeds the admin console's client row with it, and the admin
// console authenticates with it. Neither is the peer's own listener, logging or session
// configuration, which this process has no business loading (#351).
//
// There is deliberately no IsCookieSecure here, unlike on AuthServerConfig: whether the admin
// console's cookies carry the Secure flag is decided in the admin console, by the admin console.
type AdminConsoleConfig struct {
	BaseURL           string
	OAuthClientSecret string
}

type DatabaseConfig struct {
	Type     string
	Username string
	Password string
	Host     string
	Port     int
	Name     string
	DSN      string
	Create   bool
}

type Config struct {
	AuthServer    AuthServerConfig
	AdminConsole  AdminConsoleConfig
	Database      DatabaseConfig
	AdminEmail    string
	AdminPassword string
	AppName       string
	// AESEncryptionKey is the hex-encoded (32-byte) key used to encrypt secrets
	// at rest in the database (client secrets, SMTP/SMS credentials, verification
	// codes, OTP seeds, RSA signing keys). Only the auth server uses it (the admin
	// console has no database access). Supplied via GOIABADA_AES_ENCRYPTION_KEY.
	AESEncryptionKey string
	// AESEncryptionKeyPrevious is the OPTIONAL previous data key, set only while
	// rotating GOIABADA_AES_ENCRYPTION_KEY. When present, the auth server detects
	// data still encrypted under it at startup and re-encrypts everything to the
	// current key. It is safe to leave set across restarts (the re-encryption is
	// idempotent) and should be removed once rotation is confirmed. Supplied via
	// GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS.
	AESEncryptionKeyPrevious string

	// Args is what the flag parse left, in order. The parse stops at the first argument that is
	// not a flag, so the first of these selects the command and the rest belong to it; none means
	// the server runs (#424).
	Args []string
}

// Load reads the configuration from the environment, registers a flag over each value that has
// one on fs, and parses args. Each caller passes its own set: main flag.CommandLine, whose
// ExitOnError keeps the usage text and exit 2 for a bad flag, and a test a ContinueOnError set of
// its own, which is also what lets it load twice in one process (#320).
//
// It answers a whole configuration or an error: the parse's, or one naming every numeric or
// boolean variable that is set and does not parse. A flag given for the same setting does not
// rescue the variable, because the value the operator wrote is wrong whichever of the two wins,
// and a setting only the server reads is refused before `migrate` as well, as its flag already
// is (#434).
func Load(fs *flag.FlagSet, args []string) (*Config, error) {
	var malformed malformedValues
	authServerBaseURL := getEnv("GOIABADA_AUTHSERVER_BASEURL", "http://localhost:9090")

	c := &Config{
		AuthServer: AuthServerConfig{
			BaseURL:                          authServerBaseURL,
			InternalBaseURL:                  getEnv("GOIABADA_AUTHSERVER_INTERNALBASEURL", ""),
			ListenHostHttps:                  getEnv("GOIABADA_AUTHSERVER_LISTEN_HOST_HTTPS", "0.0.0.0"),
			ListenPortHttps:                  getEnvAsInt("GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS", 9443, &malformed),
			ListenHostHttp:                   getEnv("GOIABADA_AUTHSERVER_LISTEN_HOST_HTTP", "0.0.0.0"),
			ListenPortHttp:                   getEnvAsInt("GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP", 9090, &malformed),
			TrustProxyHeaders:                getEnvAsBool("GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS", &malformed),
			TrustedProxies:                   getEnvAsStringSlice("GOIABADA_AUTHSERVER_TRUSTED_PROXIES"),
			LogHttpRequests:                  getEnvAsBool("GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS", &malformed),
			LogLevel:                         getEnv("GOIABADA_AUTHSERVER_LOG_LEVEL", "info"),
			LogFormat:                        getEnv("GOIABADA_AUTHSERVER_LOG_FORMAT", "text"),
			CertFile:                         getEnv("GOIABADA_AUTHSERVER_CERTFILE", ""),
			KeyFile:                          getEnv("GOIABADA_AUTHSERVER_KEYFILE", ""),
			LogSQL:                           getEnvAsBool("GOIABADA_AUTHSERVER_LOG_SQL", &malformed),
			StaticDir:                        getEnv("GOIABADA_AUTHSERVER_STATICDIR", ""),
			TemplateDir:                      getEnv("GOIABADA_AUTHSERVER_TEMPLATEDIR", ""),
			DebugAPIRequests:                 getEnvAsBool("GOIABADA_AUTHSERVER_DEBUG_API_REQUESTS", &malformed),
			BootstrapEnvOutFile:              getEnv("GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE", ""),
			SessionAuthenticationKey:         getEnv("GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY", ""),
			SessionEncryptionKey:             getEnv("GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY", ""),
			SessionAuthenticationKeyPrevious: getEnv("GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY_PREVIOUS", ""),
			SessionEncryptionKeyPrevious:     getEnv("GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY_PREVIOUS", ""),
			RateLimiterEnabled:               getEnvAsBool("GOIABADA_AUTHSERVER_RATELIMITER_ENABLED", &malformed),
			ProfilePictureMaxSizeBytes:       getEnvAsUploadSize("GOIABADA_PROFILE_PICTURE_MAX_SIZE_BYTES", defaultProfilePictureMaxSizeBytes, &malformed),
			I18nOverridesDir:                 getEnv("GOIABADA_I18N_OVERRIDES_DIR", ""),
		},
		AdminConsole: AdminConsoleConfig{
			BaseURL:           getEnv("GOIABADA_ADMINCONSOLE_BASEURL", "http://localhost:9091"),
			OAuthClientSecret: getEnv("GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET", ""),
		},
		Database: DatabaseConfig{
			Type:     getEnv("GOIABADA_DB_TYPE", "sqlite"),
			Username: getEnv("GOIABADA_DB_USERNAME", "root"),
			Password: getEnv("GOIABADA_DB_PASSWORD", ""),
			Host:     getEnv("GOIABADA_DB_HOST", "localhost"),
			Port:     getEnvAsInt("GOIABADA_DB_PORT", 3306, &malformed),
			Name:     getEnv("GOIABADA_DB_NAME", "goiabada"),
			DSN:      getEnv("GOIABADA_DB_DSN", "file::memory:?cache=shared"),
			Create:   getEnvAsBoolDefault("GOIABADA_DB_CREATE", true, &malformed),
		},
		AdminEmail:               getEnv("GOIABADA_ADMIN_EMAIL", "admin"),
		AdminPassword:            getEnv("GOIABADA_ADMIN_PASSWORD", "changeme"),
		AppName:                  getEnv("GOIABADA_APPNAME", "Goiabada"),
		AESEncryptionKey:         getEnv("GOIABADA_AES_ENCRYPTION_KEY", ""),
		AESEncryptionKeyPrevious: getEnv("GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS", ""),
	}

	// Auth server
	fs.StringVar(&c.AuthServer.BaseURL, "authserver-baseurl", c.AuthServer.BaseURL, "Goiabada auth server base URL")
	fs.StringVar(&c.AuthServer.InternalBaseURL, "authserver-internalbaseurl", c.AuthServer.InternalBaseURL, "Goiabada auth server internal base URL")
	fs.StringVar(&c.AuthServer.ListenHostHttps, "authserver-listen-host-https", c.AuthServer.ListenHostHttps, "Auth server https host")
	fs.IntVar(&c.AuthServer.ListenPortHttps, "authserver-listen-port-https", c.AuthServer.ListenPortHttps, "Auth server https port")
	fs.StringVar(&c.AuthServer.ListenHostHttp, "authserver-listen-host-http", c.AuthServer.ListenHostHttp, "Auth server http host")
	fs.IntVar(&c.AuthServer.ListenPortHttp, "authserver-listen-port-http", c.AuthServer.ListenPortHttp, "Auth server http port")
	fs.BoolVar(&c.AuthServer.TrustProxyHeaders, "authserver-trust-proxy-headers", c.AuthServer.TrustProxyHeaders, "Trust HTTP headers from reverse proxy in Auth server? (True-Client-IP, X-Real-IP or the X-Forwarded-For headers)")
	authServerTrustedProxies := strings.Join(c.AuthServer.TrustedProxies, ",")
	fs.StringVar(&authServerTrustedProxies, "authserver-trusted-proxies", authServerTrustedProxies, "Comma-separated list of trusted reverse-proxy IPs/CIDRs used to resolve the real client IP from X-Forwarded-For (auth server)")
	fs.BoolVar(&c.AuthServer.LogHttpRequests, "authserver-log-http-requests", c.AuthServer.LogHttpRequests, "Log HTTP requests for auth server")
	fs.StringVar(&c.AuthServer.LogLevel, "authserver-log-level", c.AuthServer.LogLevel, "Lowest level of log record the auth server writes. Options: debug, info, warn, error")
	fs.StringVar(&c.AuthServer.LogFormat, "authserver-log-format", c.AuthServer.LogFormat, "Format the auth server writes log records in. Options: text, json")
	fs.StringVar(&c.AuthServer.CertFile, "authserver-certfile", c.AuthServer.CertFile, "Certificate file for HTTPS (auth server)")
	fs.StringVar(&c.AuthServer.KeyFile, "authserver-keyfile", c.AuthServer.KeyFile, "Key file for HTTPS (auth server)")
	fs.BoolVar(&c.AuthServer.LogSQL, "authserver-log-sql", c.AuthServer.LogSQL, "Log SQL queries for auth server")
	fs.StringVar(&c.AuthServer.StaticDir, "authserver-staticdir", c.AuthServer.StaticDir, "Static files directory for auth server")
	fs.StringVar(&c.AuthServer.TemplateDir, "authserver-templatedir", c.AuthServer.TemplateDir, "Template files directory for auth server")
	fs.BoolVar(&c.AuthServer.DebugAPIRequests, "authserver-debug-api-requests", c.AuthServer.DebugAPIRequests, "Enable debug logging for API requests on auth server")
	fs.StringVar(&c.AuthServer.BootstrapEnvOutFile, "authserver-bootstrap-env-outfile", c.AuthServer.BootstrapEnvOutFile, "If set, write initial admin console OAuth credentials to this file (0600) during DB seed")
	fs.BoolVar(&c.AuthServer.RateLimiterEnabled, "authserver-ratelimiter-enabled", c.AuthServer.RateLimiterEnabled, "Enable rate limiting for security-sensitive endpoints on auth server")

	// Admin console: the two values this process reads, and nothing else. A flag the binary
	// cannot act on is a trap rather than a courtesy, because it reads as having configured
	// something -- so -adminconsole-log-level and the twelve others beside it are not
	// registered here, and this binary now refuses them instead of ignoring them (#351).
	fs.StringVar(&c.AdminConsole.BaseURL, "adminconsole-baseurl", c.AdminConsole.BaseURL, "Goiabada admin console base URL")
	fs.StringVar(&c.AdminConsole.OAuthClientSecret, "adminconsole-oauth-client-secret", c.AdminConsole.OAuthClientSecret, "OAuth client_secret used by admin console (confidential client)")

	// Database
	RegisterDatabaseFlags(fs, &c.Database)

	// Initial setup
	fs.StringVar(&c.AdminEmail, "admin-email", c.AdminEmail, "Default admin email")
	fs.StringVar(&c.AdminPassword, "admin-password", c.AdminPassword, "Default admin password")
	fs.StringVar(&c.AppName, "appname", c.AppName, "Default app name")

	// Under flag.CommandLine, built with ExitOnError, a bad flag has already exited by here; a set
	// built with ContinueOnError answers it, flag.ErrHelp for -h included.
	if err := fs.Parse(args); err != nil {
		return nil, errs.WithStack(err)
	}
	c.Args = fs.Args()

	// Re-derive slice-valued config after flag parsing so a command-line flag
	// (comma-separated) overrides the environment value.
	c.AuthServer.TrustedProxies = splitCSV(authServerTrustedProxies)

	// Warn about removed settings still present in the environment so a
	// deployment relying on them notices they are now ignored. The Secure cookie
	// flag is derived from an https base URL (see IsCookieSecure).
	//
	// Only this process's own removed setting is named. GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE
	// is warned about by the admin console, whose cookies it was meant to affect, so an operator
	// hears about a setting from the binary it was for and this log stops carrying a line about
	// one it never honoured. Each binary warning about both would mean each carrying the other's
	// list of removed names, which is the coupling this split exists to remove (#351).
	for _, k := range deprecatedEnvVarsPresent("GOIABADA_AUTHSERVER_SET_COOKIE_SECURE") {
		// This is the one record in the tree the installed handler never sees: config.Load runs
		// before logging.Install, because the level and format it installs are read from this
		// very config. So it prints under Go's built-in handler, at its shape (#320).
		slog.Warn("a removed setting is present in the environment and is ignored, because the secure cookie flag is now derived from an https base url",
			"setting", k)
	}

	if err := malformed.err(); err != nil {
		return nil, err
	}
	return c, nil
}

// RegisterDatabaseFlags registers the eight --db-* flags on fs, each writing into c and
// defaulting to the value c already holds.
//
// It is the one registration of those names. The server's parse registers them over the loaded
// configuration, and the `migrate` subcommand registers them again on a set of its own over a copy
// of it, so that the same flags given after `migrate` override the ones given before; a second
// hand-written list would let the two command lines drift apart (#424).
func RegisterDatabaseFlags(fs *flag.FlagSet, c *DatabaseConfig) {
	fs.StringVar(&c.Type, "db-type", c.Type, "Database type. Options: sqlite, mysql, postgres, mssql")
	fs.StringVar(&c.Username, "db-username", c.Username, "Database username")
	fs.StringVar(&c.Password, "db-password", c.Password, "Database password")
	fs.StringVar(&c.Host, "db-host", c.Host, "Database host")
	fs.IntVar(&c.Port, "db-port", c.Port, "Database port")
	fs.StringVar(&c.Name, "db-name", c.Name, "Database name")
	fs.StringVar(&c.DSN, "db-dsn", c.DSN, "Database DSN (only for sqlite)")
	fs.BoolVar(&c.Create, "db-create", c.Create, "Create the database if it does not exist (only for mysql, postgres, mssql)")
}

// DataKeys decodes the data-encryption keys: the current one, which must be present,
// hex-encoded and exactly 32 bytes, and the previous one, nil unless a rotation is in progress
// and held to the same rule when it is. The key is supplied from the environment rather than
// co-located with the ciphertext it protects (#83). On a refusal both keys are nil, so no caller
// can go on with half a validated pair.
func (c *Config) DataKeys() (current, previous []byte, err error) {
	key := strings.TrimSpace(c.AESEncryptionKey)
	if key == "" {
		return nil, nil, errs.Errorf("GOIABADA_AES_ENCRYPTION_KEY is required. Generate with: openssl rand -hex 32")
	}
	current, err = hex.DecodeString(key)
	if err != nil {
		return nil, nil, errs.Errorf("GOIABADA_AES_ENCRYPTION_KEY must be hex-encoded (error: %w). Generate with: openssl rand -hex 32", err)
	}
	if len(current) != 32 {
		return nil, nil, errs.Errorf("GOIABADA_AES_ENCRYPTION_KEY must be 32 bytes (64 hex chars), got %d bytes. Generate with: openssl rand -hex 32", len(current))
	}

	// The previous key is optional (rotation only), but if present it must be a
	// valid 32-byte hex key too.
	if prev := strings.TrimSpace(c.AESEncryptionKeyPrevious); prev != "" {
		previous, err = hex.DecodeString(prev)
		if err != nil {
			return nil, nil, errs.Errorf("GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS must be hex-encoded (error: %w)", err)
		}
		if len(previous) != 32 {
			return nil, nil, errs.Errorf("GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS must be 32 bytes (64 hex chars), got %d bytes", len(previous))
		}
	}

	return current, previous, nil
}

func getEnv(key string, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(defaultVal)
}

// malformedValues collects every numeric or boolean variable Load could not parse, so one refusal
// names them all rather than costing the operator a restart per typo (#434).
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
// GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS= to mean no https listener, and run-tests.sh exports
// GOIABADA_DB_PORT empty.
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

// getEnvAsInt64 is getEnvAsInt for a 64-bit setting.
func getEnvAsInt64(key string, defaultVal int64, malformed *malformedValues) int64 {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultVal
	}
	value, err := strconv.ParseInt(valueStr, 10, 64)
	if err != nil {
		malformed.add(key, valueStr, "an integer")
		return defaultVal
	}
	return value
}

const (
	// defaultProfilePictureMaxSizeBytes is GOIABADA_PROFILE_PICTURE_MAX_SIZE_BYTES unset: 3 MiB.
	// It is written here and nowhere else; the upload handlers and the request-body table use
	// the loaded value as it is (#435).
	defaultProfilePictureMaxSizeBytes = 3 * 1024 * 1024

	// MaxProfilePictureMaxSizeBytes is the largest GOIABADA_PROFILE_PICTURE_MAX_SIZE_BYTES Load
	// accepts. The server's request-body table adds a 64 KiB multipart allowance to the value,
	// and anything above this wrapped that sum negative, which the body limiter refuses with a
	// panic at startup rather than a sentence naming the variable. The server's tests hold its
	// allowance within the gap this leaves (#435).
	MaxProfilePictureMaxSizeBytes = math.MaxInt64 - 64<<10
)

// getEnvAsUploadSize is getEnvAsInt64 for the upload size, which must be positive and at most
// MaxProfilePictureMaxSizeBytes. A value outside that is recorded as malformed: a zero or negative
// size used to be read as the 3 MiB default with no message, so an operator who wrote 0 got 3 MiB
// (#435).
func getEnvAsUploadSize(key string, defaultVal int64, malformed *malformedValues) int64 {
	before := len(*malformed)
	value := getEnvAsInt64(key, defaultVal, malformed)
	if len(*malformed) > before {
		return value
	}
	switch {
	case value <= 0:
		malformed.add(key, getEnv(key, ""), "a positive integer")
	case value > MaxProfilePictureMaxSizeBytes:
		malformed.add(key, getEnv(key, ""), "at most "+strconv.FormatInt(MaxProfilePictureMaxSizeBytes, 10))
	}
	return value
}

// getEnvAsBool is getEnvAsBoolDefault for a setting whose default is false.
func getEnvAsBool(key string, malformed *malformedValues) bool {
	return getEnvAsBoolDefault(key, false, malformed)
}

// getEnvAsBoolDefault is getEnvAsInt's rule for a boolean with a caller-supplied default, for a
// setting whose default is true (#293): an operator writing yes used to get the default, silently
// (#434).
func getEnvAsBoolDefault(key string, defaultVal bool, malformed *malformedValues) bool {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultVal
	}
	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		malformed.add(key, valueStr, "a boolean (true or false)")
		return defaultVal
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

// SessionKeys decodes the auth server's session keys through the one rule both
// applications share, sessionstore.ParseKeys, under this binary's variable names: the
// current pair, required, and the previous pair, nil unless a rotation is in progress.
func (c *AuthServerConfig) SessionKeys() (sessionstore.KeyPair, *sessionstore.KeyPair, error) {
	return sessionstore.ParseKeys(sessionstore.ConfiguredKeys{
		Authentication: sessionstore.ConfiguredKey{
			Name:  "GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY",
			Value: c.SessionAuthenticationKey,
		},
		Encryption: sessionstore.ConfiguredKey{
			Name:  "GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY",
			Value: c.SessionEncryptionKey,
		},
		PreviousAuthentication: sessionstore.ConfiguredKey{
			Name:  "GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY_PREVIOUS",
			Value: c.SessionAuthenticationKeyPrevious,
		},
		PreviousEncryption: sessionstore.ConfiguredKey{
			Name:  "GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY_PREVIOUS",
			Value: c.SessionEncryptionKeyPrevious,
		},
	})
}
