package config

import (
	"errors"
	"flag"
	"io"
	"log/slog"
	"maps"
	"os"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/logging/logtest"
)

// -----------------------------------------------------------------------------
// Seam 1: every live GOIABADA_* variable, its default, its environment value and
// the flag that beats it.
// -----------------------------------------------------------------------------
//
// This is stage 1's matrix, written against core/config's loadFrom and carried here unchanged
// except for its roster: 40 variables and 32 flags, the auth server's own 25, the 8 database, the
// 3 top-level, the 2 data-encryption keys and the 2 admin console values this process reads. The
// same assertions passing on both sides of the move is what makes it a lock on the behaviour
// rather than a description of it (#351).

// configVar is one live GOIABADA_* setting: its flag if it has one, what Load lands
// when nothing is set, and what it lands from the environment and from the command line.
//
// read takes the landed value off the configuration Load returned, which is what main hands to
// everything it builds: a matrix reading anything else would keep passing with that value broken
// (#351, #434).
type configVar struct {
	env  string // the GOIABADA_* name
	flag string // the flag name, or "" when the variable has none
	def  any    // what Load lands with nothing set

	// envValue differs from the default, so no environment case can pass by the default
	// happening to agree. flagValue differs from envValue, so no flag case can pass by the
	// flag being ignored. A setting with only two values (every bool, and the log format)
	// therefore has flagValue equal to its default, and the case still discriminates,
	// because it is the environment that supplied the other value.
	envValue  string
	envWant   any
	flagValue string // ignored when flag is ""
	flagWant  any

	// with is set beside envValue in the environment and the flag cases, for a setting another
	// one has to allow: a CA file loads only beside a mode that checks the certificate (#502).
	with map[string]string

	read func(*Config) any
}

// envWith is the environment of v's environment and flag cases: its own value, and what it needs
// beside it.
func (v configVar) envWith() map[string]string {
	env := map[string]string{v.env: v.envValue}
	maps.Copy(env, v.with)
	return env
}

// strVar is a row whose landed value is the string as supplied.
func strVar(name, flagName, def, fromEnv, fromFlag string, read func(*Config) any) configVar {
	return configVar{
		env: name, flag: flagName, def: def,
		envValue: fromEnv, envWant: fromEnv,
		flagValue: fromFlag, flagWant: fromFlag,
		read: read,
	}
}

// strVarNoFlag is strVar for a variable with no flag of its own.
func strVarNoFlag(name, def, fromEnv string, read func(*Config) any) configVar {
	return configVar{env: name, def: def, envValue: fromEnv, envWant: fromEnv, read: read}
}

func intVar(name, flagName string, def, fromEnv, fromFlag int, read func(*Config) any) configVar {
	return configVar{
		env: name, flag: flagName, def: def,
		envValue: strconv.Itoa(fromEnv), envWant: fromEnv,
		flagValue: strconv.Itoa(fromFlag), flagWant: fromFlag,
		read: read,
	}
}

// int64VarNoFlag is the int64 row for a variable with no flag of its own.
func int64VarNoFlag(name string, def, fromEnv int64, read func(*Config) any) configVar {
	return configVar{
		env: name, def: def,
		envValue: strconv.FormatInt(fromEnv, 10), envWant: fromEnv,
		read: read,
	}
}

func boolVar(name, flagName string, def, fromEnv, fromFlag bool, read func(*Config) any) configVar {
	return configVar{
		env: name, flag: flagName, def: def,
		envValue: strconv.FormatBool(fromEnv), envWant: fromEnv,
		flagValue: strconv.FormatBool(fromFlag), flagWant: fromFlag,
		read: read,
	}
}

// durationVar is a row in Go's duration syntax, which is what the standard flag package reads and
// what the environment variable is held to as well (#394 decision 5).
func durationVar(name, flagName string, def time.Duration, fromEnv string, wantEnv time.Duration, fromFlag string, wantFlag time.Duration, read func(*Config) any) configVar {
	return configVar{
		env: name, flag: flagName, def: def,
		envValue: fromEnv, envWant: wantEnv,
		flagValue: fromFlag, flagWant: wantFlag,
		read: read,
	}
}

// csvVar is a comma-separated row. Its default is a nil []string rather than an empty one,
// which is what splitCSV answers for an absent value and which reflect.DeepEqual tells apart.
func csvVar(name, flagName, fromEnv string, wantEnv []string, fromFlag string, wantFlag []string, read func(*Config) any) configVar {
	return configVar{
		env: name, flag: flagName, def: []string(nil),
		envValue: fromEnv, envWant: wantEnv,
		flagValue: fromFlag, flagWant: wantFlag,
		read: read,
	}
}

// configVariables is every live GOIABADA_* variable this process loads: 28 auth server, the 2
// admin console values it reads, 14 database and 5 top-level, of which 41 have a flag. The one
// name Load mentions that is not live configuration is in nonLiveEnvVars.
var configVariables = []configVar{
	// Auth server
	strVar("GOIABADA_AUTHSERVER_BASEURL", "authserver-baseurl", "http://localhost:9090",
		"https://auth.env.example.com", "https://auth.flag.example.com",
		func(c *Config) any { return c.AuthServer.BaseURL }),
	strVar("GOIABADA_AUTHSERVER_INTERNALBASEURL", "authserver-internalbaseurl", "",
		"http://auth-env.internal:9090", "http://auth-flag.internal:9090",
		func(c *Config) any { return c.AuthServer.InternalBaseURL }),
	strVar("GOIABADA_AUTHSERVER_LISTEN_HOST_HTTPS", "authserver-listen-host-https", "0.0.0.0",
		"10.0.0.1", "10.0.0.2",
		func(c *Config) any { return c.AuthServer.ListenHostHttps }),
	intVar("GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS", "authserver-listen-port-https", 9443,
		19443, 29443,
		func(c *Config) any { return c.AuthServer.ListenPortHttps }),
	strVar("GOIABADA_AUTHSERVER_LISTEN_HOST_HTTP", "authserver-listen-host-http", "0.0.0.0",
		"10.0.1.1", "10.0.1.2",
		func(c *Config) any { return c.AuthServer.ListenHostHttp }),
	intVar("GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP", "authserver-listen-port-http", 9090,
		19090, 29090,
		func(c *Config) any { return c.AuthServer.ListenPortHttp }),
	boolVar("GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS", "authserver-trust-proxy-headers", false,
		true, false,
		func(c *Config) any { return c.AuthServer.TrustProxyHeaders }),
	csvVar("GOIABADA_AUTHSERVER_TRUSTED_PROXIES", "authserver-trusted-proxies",
		" 10.0.0.0/8 , 172.16.0.0/12 ", []string{"10.0.0.0/8", "172.16.0.0/12"},
		"192.168.0.1,, ,203.0.113.0/24", []string{"192.168.0.1", "203.0.113.0/24"},
		func(c *Config) any { return c.AuthServer.TrustedProxies }),
	boolVar("GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS", "authserver-log-http-requests", false,
		true, false,
		func(c *Config) any { return c.AuthServer.LogHttpRequests }),
	strVar("GOIABADA_AUTHSERVER_LOG_LEVEL", "authserver-log-level", "info",
		"debug", "warn",
		func(c *Config) any { return c.AuthServer.LogLevel }),
	strVar("GOIABADA_AUTHSERVER_LOG_FORMAT", "authserver-log-format", "text",
		"json", "text",
		func(c *Config) any { return c.AuthServer.LogFormat }),
	strVar("GOIABADA_AUTHSERVER_CERTFILE", "authserver-certfile", "",
		"/env/auth-cert.pem", "/flag/auth-cert.pem",
		func(c *Config) any { return c.AuthServer.CertFile }),
	strVar("GOIABADA_AUTHSERVER_KEYFILE", "authserver-keyfile", "",
		"/env/auth-key.pem", "/flag/auth-key.pem",
		func(c *Config) any { return c.AuthServer.KeyFile }),
	boolVar("GOIABADA_AUTHSERVER_LOG_SQL", "authserver-log-sql", false,
		true, false,
		func(c *Config) any { return c.AuthServer.LogSQL }),
	strVar("GOIABADA_AUTHSERVER_STATICDIR", "authserver-staticdir", "",
		"/env/auth-static", "/flag/auth-static",
		func(c *Config) any { return c.AuthServer.StaticDir }),
	strVar("GOIABADA_AUTHSERVER_TEMPLATEDIR", "authserver-templatedir", "",
		"/env/auth-templates", "/flag/auth-templates",
		func(c *Config) any { return c.AuthServer.TemplateDir }),
	boolVar("GOIABADA_AUTHSERVER_DEBUG_API_REQUESTS", "authserver-debug-api-requests", false,
		true, false,
		func(c *Config) any { return c.AuthServer.DebugAPIRequests }),
	strVar("GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE", "authserver-bootstrap-env-outfile", "",
		"/env/bootstrap.env", "/flag/bootstrap.env",
		func(c *Config) any { return c.AuthServer.BootstrapEnvOutFile }),
	strVarNoFlag("GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY", "", strings.Repeat("a1", 64),
		func(c *Config) any { return c.AuthServer.SessionAuthenticationKey }),
	strVarNoFlag("GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY", "", strings.Repeat("a2", 32),
		func(c *Config) any { return c.AuthServer.SessionEncryptionKey }),
	strVarNoFlag("GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY_PREVIOUS", "", strings.Repeat("a3", 64),
		func(c *Config) any { return c.AuthServer.SessionAuthenticationKeyPrevious }),
	strVarNoFlag("GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY_PREVIOUS", "", strings.Repeat("a4", 32),
		func(c *Config) any { return c.AuthServer.SessionEncryptionKeyPrevious }),
	boolVar("GOIABADA_AUTHSERVER_RATELIMITER_ENABLED", "authserver-ratelimiter-enabled", false,
		true, false,
		func(c *Config) any { return c.AuthServer.RateLimiterEnabled }),
	// The metrics listener, off unless enabled, on the host the other listeners default to and a
	// port of its own (#400 decision 3).
	boolVar("GOIABADA_AUTHSERVER_METRICS_ENABLED", "authserver-metrics-enabled", false,
		true, false,
		func(c *Config) any { return c.AuthServer.MetricsEnabled }),
	strVar("GOIABADA_AUTHSERVER_LISTEN_HOST_METRICS", "authserver-listen-host-metrics", "0.0.0.0",
		"10.0.2.1", "10.0.2.2",
		func(c *Config) any { return c.AuthServer.ListenHostMetrics }),
	intVar("GOIABADA_AUTHSERVER_LISTEN_PORT_METRICS", "authserver-listen-port-metrics", 9190,
		19190, 29190,
		func(c *Config) any { return c.AuthServer.ListenPortMetrics }),
	int64VarNoFlag("GOIABADA_PROFILE_PICTURE_MAX_SIZE_BYTES", 3*1024*1024, 5*1024*1024,
		func(c *Config) any { return c.AuthServer.ProfilePictureMaxSizeBytes }),
	// No flag, and trimmed, which is what core/i18n did when it read the variable itself: the row
	// is what pins both now that the configuration reads it instead (#431).
	{
		env: "GOIABADA_I18N_OVERRIDES_DIR", def: "",
		envValue: " /env/i18n-overrides ", envWant: "/env/i18n-overrides",
		read: func(c *Config) any { return c.AuthServer.I18nOverridesDir },
	},

	// Admin console: the two values this process reads. The other 17 GOIABADA_ADMINCONSOLE_*
	// variables are the peer's own and are not loaded here, so they have no row -- and the drift
	// guard below checks that in both directions, against config.go.
	strVar("GOIABADA_ADMINCONSOLE_BASEURL", "adminconsole-baseurl", "http://localhost:9091",
		"https://admin.env.example.com", "https://admin.flag.example.com",
		func(c *Config) any { return c.AdminConsole.BaseURL }),
	strVar("GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET", "adminconsole-oauth-client-secret", "",
		"env-client-secret", "flag-client-secret",
		func(c *Config) any { return c.AdminConsole.OAuthClientSecret }),

	// Database
	strVar("GOIABADA_DB_TYPE", "db-type", "sqlite",
		"mysql", "postgres",
		func(c *Config) any { return c.Database.Type }),
	strVar("GOIABADA_DB_USERNAME", "db-username", "root",
		"env-user", "flag-user",
		func(c *Config) any { return c.Database.Username }),
	strVar("GOIABADA_DB_PASSWORD", "db-password", "",
		"env-db-password", "flag-db-password",
		func(c *Config) any { return c.Database.Password }),
	strVar("GOIABADA_DB_HOST", "db-host", "localhost",
		"env.db.example.com", "flag.db.example.com",
		func(c *Config) any { return c.Database.Host }),
	intVar("GOIABADA_DB_PORT", "db-port", 3306,
		13306, 23306,
		func(c *Config) any { return c.Database.Port }),
	strVar("GOIABADA_DB_NAME", "db-name", "goiabada",
		"env_goiabada", "flag_goiabada",
		func(c *Config) any { return c.Database.Name }),
	strVar("GOIABADA_DB_DSN", "db-dsn", "file::memory:?cache=shared",
		"file:env.db?cache=shared", "file:flag.db?cache=shared",
		func(c *Config) any { return c.Database.DSN }),
	// The one setting whose default is true, which is why it goes through
	// getEnvAsBoolDefault rather than getEnvAsBool (#293).
	boolVar("GOIABADA_DB_CREATE", "db-create", true,
		false, true,
		func(c *Config) any { return c.Database.Create }),
	// The pool of the three server engines (#394 decisions 5 and 6). The idle row reads the value
	// the engines are given, which follows the open cap while neither the variable nor the flag
	// sets it: its default is the open cap's default, 20.
	intVar("GOIABADA_DB_MAX_OPEN_CONNS", "db-max-open-conns", 20,
		35, 45,
		func(c *Config) any { return c.Database.MaxOpenConns }),
	intVar("GOIABADA_DB_MAX_IDLE_CONNS", "db-max-idle-conns", 20,
		7, 3,
		func(c *Config) any { return c.Database.EffectiveMaxIdleConns() }),
	durationVar("GOIABADA_DB_CONN_MAX_LIFETIME", "db-conn-max-lifetime", 30*time.Minute,
		"1h", time.Hour, "90s", 90*time.Second,
		func(c *Config) any { return c.Database.ConnMaxLifetime }),
	// The flag writes 0, no limit, which is a legitimate choice behind a pooler such as PgBouncer.
	durationVar("GOIABADA_DB_CONN_MAX_IDLE_TIME", "db-conn-max-idle-time", 5*time.Minute,
		"10m", 10*time.Minute, "0", 0,
		func(c *Config) any { return c.Database.ConnMaxIdleTime }),
	// The connection's protection, read as the mode the engines are given: prefer while neither
	// the variable nor the flag sets it (#502).
	strVar("GOIABADA_DB_TLS_MODE", "db-tls-mode", "prefer",
		"verify-full", "disable",
		func(c *Config) any { return string(c.Database.EffectiveTLSMode()) }),
	// A CA file loads only beside a mode that checks the certificate, on an engine with a
	// connection to check, so its cases set both; the two files are certificates and nothing else.
	{
		env: "GOIABADA_DB_TLS_CA_FILE", flag: "db-tls-ca-file", def: "",
		envValue: "testdata/db-tls-ca-env.pem", envWant: "testdata/db-tls-ca-env.pem",
		flagValue: "testdata/db-tls-ca-flag.pem", flagWant: "testdata/db-tls-ca-flag.pem",
		with: map[string]string{"GOIABADA_DB_TYPE": "postgres", "GOIABADA_DB_TLS_MODE": "verify-ca"},
		read: func(c *Config) any { return c.Database.TLSCAFile },
	},

	// Initial setup and the data-encryption keys
	// One default for unset and empty alike, the address the seed falls back to for an empty
	// one: unset used to give "admin", which is not an address (#500 decision 5).
	strVar("GOIABADA_ADMIN_EMAIL", "admin-email", "admin@example.com",
		"env-admin@example.com", "flag-admin@example.com",
		func(c *Config) any { return c.AdminEmail }),
	// No default: the published changeme it had seeded an administrator anyone could sign in
	// as, and the seed now refuses an empty password (#500 decision 1).
	strVar("GOIABADA_ADMIN_PASSWORD", "admin-password", "",
		"env-admin-password", "flag-admin-password",
		func(c *Config) any { return c.AdminPassword }),
	strVar("GOIABADA_APPNAME", "appname", "Goiabada",
		"Env Goiabada", "Flag Goiabada",
		func(c *Config) any { return c.AppName }),
	// The hex text as supplied: DataKeys decodes it, and TestDataKeys owns what it answers.
	strVarNoFlag("GOIABADA_AES_ENCRYPTION_KEY", "", strings.Repeat("ab", 32),
		func(c *Config) any { return c.AESEncryptionKey }),
	strVarNoFlag("GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS", "", strings.Repeat("cd", 32),
		func(c *Config) any { return c.AESEncryptionKeyPrevious }),
}

// nonLiveEnvVars are the GOIABADA_* names Load mentions that are not live configuration. For
// this binary that is one name: the removed cookie setting it warns about, because the Secure flag
// is derived from an https base URL (#293). It lands on no field, so it has no row, and the drift
// guard carries it as a named exception rather than as silence.
//
// GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE is listed for a different reason: this binary stopped
// warning about it (#351), and the only place config.go still spells it is the comment saying so.
// The drift guard reads names wherever they appear in the source, so a name in prose needs an
// entry here just as one in a warning list does. What holds the warning itself to naming only the
// auth server's is TestLoad_WarnsAboutThisProcessesRemovedSettingOnly, not this list. The two
// removed variables the admin console refuses outright (#285) were never this binary's at all.
var nonLiveEnvVars = []string{
	"GOIABADA_AUTHSERVER_SET_COOKIE_SECURE",
	"GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE",
}

// loadMatrix drives Load with its own flag set and returns the set and the configuration, so a
// case can assert on what was registered as well as on what was landed. Every name in the roster
// is cleared first, so a developer's own environment cannot decide what a default case observes.
//
// A load error fails the case, so every row of the matrix also shows that the values it sets
// load without a refusal (#434).
func loadMatrix(t *testing.T, env map[string]string, args []string) (*flag.FlagSet, *Config) {
	t.Helper()

	fs, c, err := loadMatrixRefusing(t, env, args)
	if err != nil {
		t.Fatalf("Load() = %v, want no error", err)
	}
	if c == nil {
		t.Fatal("Load() answered neither a configuration nor an error")
	}
	return fs, c
}

// loadMatrixRefusing is loadMatrix answering the load's error rather than failing on it.
func loadMatrixRefusing(t *testing.T, env map[string]string, args []string) (*flag.FlagSet, *Config, error) {
	t.Helper()

	for _, v := range configVariables {
		unsetEnv(t, v.env)
	}
	for _, name := range nonLiveEnvVars {
		unsetEnv(t, name)
	}
	for key, value := range env {
		t.Setenv(key, value)
	}

	fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	c, err := Load(fs, args)
	return fs, c, err
}

// malformedVariableRows is one refusal per numeric or boolean variable: a value that does not
// parse, the valid flag for the same setting where the variable has one, and the one problem the
// refusal names.
var malformedVariableRows = []struct {
	env, value, flag, want string
}{
	{"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS", "9443a", "-authserver-listen-port-https=9443",
		`GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS is "9443a", not an integer`},
	{"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP", "9090.0", "-authserver-listen-port-http=9090",
		`GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP is "9090.0", not an integer`},
	{"GOIABADA_DB_PORT", "0x10", "-db-port=3306",
		`GOIABADA_DB_PORT is "0x10", not an integer`},
	{"GOIABADA_PROFILE_PICTURE_MAX_SIZE_BYTES", "3MB", "",
		`GOIABADA_PROFILE_PICTURE_MAX_SIZE_BYTES is "3MB", not an integer`},
	{"GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS", "yes", "-authserver-trust-proxy-headers=true",
		`GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS is "yes", not a boolean (true or false)`},
	{"GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS", "on", "-authserver-log-http-requests=true",
		`GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS is "on", not a boolean (true or false)`},
	{"GOIABADA_AUTHSERVER_LOG_SQL", "enabled", "-authserver-log-sql=false",
		`GOIABADA_AUTHSERVER_LOG_SQL is "enabled", not a boolean (true or false)`},
	{"GOIABADA_AUTHSERVER_DEBUG_API_REQUESTS", "Y", "-authserver-debug-api-requests=true",
		`GOIABADA_AUTHSERVER_DEBUG_API_REQUESTS is "Y", not a boolean (true or false)`},
	{"GOIABADA_AUTHSERVER_RATELIMITER_ENABLED", "no", "-authserver-ratelimiter-enabled=false",
		`GOIABADA_AUTHSERVER_RATELIMITER_ENABLED is "no", not a boolean (true or false)`},
	{"GOIABADA_AUTHSERVER_METRICS_ENABLED", "1x", "-authserver-metrics-enabled=true",
		`GOIABADA_AUTHSERVER_METRICS_ENABLED is "1x", not a boolean (true or false)`},
	{"GOIABADA_AUTHSERVER_LISTEN_PORT_METRICS", "9190/tcp", "-authserver-listen-port-metrics=9190",
		`GOIABADA_AUTHSERVER_LISTEN_PORT_METRICS is "9190/tcp", not an integer`},
	{"GOIABADA_DB_CREATE", "yes", "-db-create=true",
		`GOIABADA_DB_CREATE is "yes", not a boolean (true or false)`},
	{"GOIABADA_DB_MAX_OPEN_CONNS", "twenty", "-db-max-open-conns=20",
		`GOIABADA_DB_MAX_OPEN_CONNS is "twenty", not an integer`},
	{"GOIABADA_DB_MAX_IDLE_CONNS", "5.5", "-db-max-idle-conns=5",
		`GOIABADA_DB_MAX_IDLE_CONNS is "5.5", not an integer`},
	// A bare number is seconds to an operator and nothing to Go's duration syntax, which needs a
	// unit, so it is refused rather than guessed at (#394 decision 5).
	{"GOIABADA_DB_CONN_MAX_LIFETIME", "1800", "-db-conn-max-lifetime=30m",
		`GOIABADA_DB_CONN_MAX_LIFETIME is "1800", not a duration such as 30m, 1h or 90s`},
	{"GOIABADA_DB_CONN_MAX_IDLE_TIME", "5 minutes", "-db-conn-max-idle-time=5m",
		`GOIABADA_DB_CONN_MAX_IDLE_TIME is "5 minutes", not a duration such as 30m, 1h or 90s`},
}

// TestLoad_RefusesAMalformedVariable is decisions 6 and 10 of #434 over the ten numeric and
// boolean variables this binary loads, each through Load rather than the helper alone, so a row
// fails if Load reads the variable any other way. Each case also gives a valid flag for the same
// setting where the variable has one, which must not rescue it: the value the operator wrote is
// wrong whichever of the two wins. The refusal answers no configuration, so nothing can start
// from a half-read one.
func TestLoad_RefusesAMalformedVariable(t *testing.T) {
	for _, tt := range malformedVariableRows {
		t.Run(tt.env, func(t *testing.T) {
			var args []string
			if tt.flag != "" {
				args = []string{tt.flag}
			}
			_, c, err := loadMatrixRefusing(t, map[string]string{tt.env: tt.value}, args)

			want := "malformed configuration: " + tt.want
			if err == nil || err.Error() != want {
				t.Errorf("Load() with %s=%q and %v = %v, want %q", tt.env, tt.value, args, err, want)
			}
			if c != nil {
				t.Errorf("Load() refused and still answered a configuration: %#v", c)
			}
		})
	}
}

// TestLoad_EveryNumericAndBooleanVariableHasARefusalRow holds the table above to the ten: a
// numeric or boolean row in the matrix with no refusal row is a variable whose malformed value
// nothing shows is refused.
func TestLoad_EveryNumericAndBooleanVariableHasARefusalRow(t *testing.T) {
	refused := map[string]bool{}
	for _, row := range malformedVariableRows {
		refused[row.env] = true
	}
	for _, v := range configVariables {
		switch v.def.(type) {
		case int, int64, bool, time.Duration:
			if !refused[v.env] {
				t.Errorf("%s is numeric or boolean and TestLoad_RefusesAMalformedVariable has no row for it", v.env)
			}
			delete(refused, v.env)
		}
	}
	for _, name := range sortedKeys(refused) {
		t.Errorf("%s has a refusal row but no numeric or boolean row in configVariables", name)
	}
}

// TestLoad_TheUploadSizeMustBePositive is decision 13 of #435: a zero or negative size used to be
// read as 3 MiB with no message, and a size near MaxInt64 wrapped the request-body table's upload
// rows negative, which panicked at startup without naming the variable. Both are refused with the
// variable named, and the bounds either side of each refusal are accepted as written.
func TestLoad_TheUploadSizeMustBePositive(t *testing.T) {
	const key = "GOIABADA_PROFILE_PICTURE_MAX_SIZE_BYTES"
	tests := []struct {
		name    string
		env     map[string]string
		want    int64
		refusal string
	}{
		{name: "unset is 3 MiB", want: 3 << 20},
		{name: "one byte", env: map[string]string{key: "1"}, want: 1},
		{name: "a raised size", env: map[string]string{key: "10485760"}, want: 10 << 20},
		{name: "the largest accepted size", env: map[string]string{key: "9223372036854710271"}, want: MaxProfilePictureMaxSizeBytes},
		{name: "zero", env: map[string]string{key: "0"},
			refusal: key + ` is "0", not a positive integer`},
		{name: "a negative size", env: map[string]string{key: " -1 "},
			refusal: key + ` is "-1", not a positive integer`},
		{name: "one byte over the largest accepted size", env: map[string]string{key: "9223372036854710272"},
			refusal: key + ` is "9223372036854710272", not at most 9223372036854710271`},
		{name: "MaxInt64", env: map[string]string{key: "9223372036854775807"},
			refusal: key + ` is "9223372036854775807", not at most 9223372036854710271`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c, err := loadMatrixRefusing(t, tt.env, nil)

			if tt.refusal != "" {
				want := "malformed configuration: " + tt.refusal
				if err == nil || err.Error() != want {
					t.Errorf("Load() = %v, want %q", err, want)
				}
				if c != nil {
					t.Errorf("Load() refused and still answered a configuration: %#v", c)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() = %v", err)
			}
			if c.AuthServer.ProfilePictureMaxSizeBytes != tt.want {
				t.Errorf("ProfilePictureMaxSizeBytes = %d, want %d", c.AuthServer.ProfilePictureMaxSizeBytes, tt.want)
			}
		})
	}
}

// TestLoad_ThePoolSettingsAreHeldToTheirRanges is #394 decision 5's refusals and decision 6's
// defaults, through Load: the open cap is at least 1, since 0 is database/sql's unlimited; the idle
// cap is 0 or more and never above the open cap, which follows the open cap unless it is set; the
// two durations are 0 or more, 0 meaning no limit. A refusal names the variable or the flag that
// supplied the value, a flag given for a refused variable does not rescue it, and every value is
// checked on SQLite too, which is the default engine every row here loads under: the value the
// operator wrote is wrong whichever engine reads it (#434).
func TestLoad_ThePoolSettingsAreHeldToTheirRanges(t *testing.T) {
	type pool struct {
		open, idle         int
		lifetime, idleTime time.Duration
	}
	tests := []struct {
		name    string
		env     map[string]string
		args    []string
		want    pool
		refusal string
	}{
		{name: "nothing set is 20, 20, 30m and 5m",
			want: pool{20, 20, 30 * time.Minute, 5 * time.Minute}},
		{name: "the smallest open cap, with idle following it", env: map[string]string{"GOIABADA_DB_MAX_OPEN_CONNS": "1"},
			want: pool{1, 1, 30 * time.Minute, 5 * time.Minute}},
		{name: "idle follows a lowered open cap rather than being refused above it",
			env:  map[string]string{"GOIABADA_DB_MAX_OPEN_CONNS": "10"},
			want: pool{10, 10, 30 * time.Minute, 5 * time.Minute}},
		{name: "idle follows the open cap's flag, which beat its variable",
			env:  map[string]string{"GOIABADA_DB_MAX_OPEN_CONNS": "5"},
			args: []string{"-db-max-open-conns=30"},
			want: pool{30, 30, 30 * time.Minute, 5 * time.Minute}},
		{name: "idle set to 0 keeps none idle", env: map[string]string{"GOIABADA_DB_MAX_IDLE_CONNS": "0"},
			want: pool{20, 0, 30 * time.Minute, 5 * time.Minute}},
		{name: "idle equal to the open cap", env: map[string]string{"GOIABADA_DB_MAX_OPEN_CONNS": "8", "GOIABADA_DB_MAX_IDLE_CONNS": "8"},
			want: pool{8, 8, 30 * time.Minute, 5 * time.Minute}},
		{name: "a set idle cap stays when the open cap is raised", args: []string{"-db-max-idle-conns=4", "-db-max-open-conns=50"},
			want: pool{50, 4, 30 * time.Minute, 5 * time.Minute}},
		{name: "both durations 0, no limit", env: map[string]string{"GOIABADA_DB_CONN_MAX_LIFETIME": "0", "GOIABADA_DB_CONN_MAX_IDLE_TIME": "0s"},
			want: pool{20, 20, 0, 0}},

		{name: "an open cap of 0, which database/sql reads as unlimited",
			env:     map[string]string{"GOIABADA_DB_MAX_OPEN_CONNS": "0"},
			refusal: `GOIABADA_DB_MAX_OPEN_CONNS is "0", not at least 1`},
		{name: "a negative open cap", env: map[string]string{"GOIABADA_DB_MAX_OPEN_CONNS": " -3 "},
			refusal: `GOIABADA_DB_MAX_OPEN_CONNS is "-3", not at least 1`},
		{name: "a refused open cap is not rescued by its flag",
			env:     map[string]string{"GOIABADA_DB_MAX_OPEN_CONNS": "0"},
			args:    []string{"-db-max-open-conns=10"},
			refusal: `GOIABADA_DB_MAX_OPEN_CONNS is "0", not at least 1`},
		{name: "an open cap of 0 from the flag", args: []string{"-db-max-open-conns=0"},
			refusal: `--db-max-open-conns is "0", not at least 1`},
		{name: "a negative idle cap", env: map[string]string{"GOIABADA_DB_MAX_IDLE_CONNS": "-1"},
			refusal: `GOIABADA_DB_MAX_IDLE_CONNS is "-1", not at least 0`},
		{name: "a negative idle cap from the flag", args: []string{"-db-max-idle-conns=-1"},
			refusal: `--db-max-idle-conns is "-1", not at least 0`},
		{name: "an idle cap above the default open cap is refused, not lowered",
			env:     map[string]string{"GOIABADA_DB_MAX_IDLE_CONNS": "21"},
			refusal: `GOIABADA_DB_MAX_IDLE_CONNS (--db-max-idle-conns) is "21", not at most GOIABADA_DB_MAX_OPEN_CONNS (--db-max-open-conns), which is 20`},
		{name: "an idle cap above an open cap the flags set",
			args:    []string{"-db-max-open-conns=25", "-db-max-idle-conns=30"},
			refusal: `GOIABADA_DB_MAX_IDLE_CONNS (--db-max-idle-conns) is "30", not at most GOIABADA_DB_MAX_OPEN_CONNS (--db-max-open-conns), which is 25`},
		{name: "a negative lifetime", env: map[string]string{"GOIABADA_DB_CONN_MAX_LIFETIME": "-1m"},
			refusal: `GOIABADA_DB_CONN_MAX_LIFETIME is "-1m", not at least 0`},
		{name: "a negative lifetime from the flag", args: []string{"-db-conn-max-lifetime=-1s"},
			refusal: `--db-conn-max-lifetime is "-1s", not at least 0`},
		{name: "a bare number of seconds from the flag", args: []string{"-db-conn-max-lifetime=1800"},
			refusal: `invalid value "1800" for flag -db-conn-max-lifetime: parse error`},
		{name: "a negative idle time", env: map[string]string{"GOIABADA_DB_CONN_MAX_IDLE_TIME": "-5s"},
			refusal: `GOIABADA_DB_CONN_MAX_IDLE_TIME is "-5s", not at least 0`},
		{name: "a negative idle time from the flag", args: []string{"-db-conn-max-idle-time=-2h"},
			refusal: `--db-conn-max-idle-time is "-2h0m0s", not at least 0`},
		{name: "every bad value at once, from the variables and the flags",
			env: map[string]string{
				"GOIABADA_DB_MAX_OPEN_CONNS":    "0",
				"GOIABADA_DB_CONN_MAX_LIFETIME": "1800",
			},
			args: []string{"-db-max-idle-conns=-2", "-db-conn-max-idle-time=-1s"},
			refusal: `GOIABADA_DB_MAX_OPEN_CONNS is "0", not at least 1; ` +
				`GOIABADA_DB_CONN_MAX_LIFETIME is "1800", not a duration such as 30m, 1h or 90s; ` +
				`--db-max-idle-conns is "-2", not at least 0; ` +
				`--db-conn-max-idle-time is "-1s", not at least 0`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c, err := loadMatrixRefusing(t, tt.env, tt.args)

			if tt.refusal != "" {
				want := tt.refusal
				if !strings.HasPrefix(want, "invalid value") {
					want = "malformed configuration: " + want
				}
				if err == nil || err.Error() != want {
					t.Errorf("Load() = %v, want %q", err, want)
				}
				if c != nil {
					t.Errorf("Load() refused and still answered a configuration: %#v", c)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() = %v", err)
			}
			if c.Database.Type != "sqlite" {
				t.Fatalf("the row loaded under %q, want the default sqlite this test is about", c.Database.Type)
			}
			got := pool{c.Database.MaxOpenConns, c.Database.EffectiveMaxIdleConns(), c.Database.ConnMaxLifetime, c.Database.ConnMaxIdleTime}
			if got.open != tt.want.open || got.idle != tt.want.idle ||
				got.lifetime != tt.want.lifetime || got.idleTime != tt.want.idleTime {
				t.Errorf("pool = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestLoad_NamesEveryMalformedVariableInOneError is the row that pins "all at once". Keep it: a
// Load stopping at the first malformed variable passes every other case, and costs the operator
// one restart per typo. The error is one line, because main writes it to stderr as the one line
// an operator reads (#434).
func TestLoad_NamesEveryMalformedVariableInOneError(t *testing.T) {
	_, _, err := loadMatrixRefusing(t, map[string]string{
		"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP": "90 90",
		"GOIABADA_DB_CREATE":                   "yes",
	}, nil)

	want := `malformed configuration: GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP is "90 90", not an integer; ` +
		`GOIABADA_DB_CREATE is "yes", not a boolean (true or false)`
	if err == nil || err.Error() != want {
		t.Errorf("Load() = %v, want %q", err, want)
	}
}

// TestLoad_ReturnsTheParseError: under a ContinueOnError set the parse's refusal is answered, and
// -h keeps flag.ErrHelp, so a caller can tell a request for the usage text from a mistake.
func TestLoad_ReturnsTheParseError(t *testing.T) {
	t.Run("an undefined flag", func(t *testing.T) {
		_, c, err := loadMatrixRefusing(t, nil, []string{"-no-such-flag"})
		if err == nil || !strings.Contains(err.Error(), "flag provided but not defined: -no-such-flag") {
			t.Errorf("Load() = %v, want the parse's refusal of -no-such-flag", err)
		}
		if c != nil {
			t.Errorf("Load() refused and still answered a configuration: %#v", c)
		}
	})
	t.Run("-h", func(t *testing.T) {
		_, _, err := loadMatrixRefusing(t, nil, []string{"-h"})
		if !errors.Is(err, flag.ErrHelp) {
			t.Errorf("Load() = %v, want flag.ErrHelp", err)
		}
	})
}

func TestLoad_Defaults(t *testing.T) {
	for _, v := range configVariables {
		t.Run(v.env, func(t *testing.T) {
			_, c := loadMatrix(t, nil, nil)

			if got := v.read(c); !reflect.DeepEqual(got, v.def) {
				t.Errorf("%s unset: got %#v, want the default %#v", v.env, got, v.def)
			}
		})
	}
}

func TestLoad_FromTheEnvironment(t *testing.T) {
	for _, v := range configVariables {
		t.Run(v.env, func(t *testing.T) {
			_, c := loadMatrix(t, v.envWith(), nil)

			if got := v.read(c); !reflect.DeepEqual(got, v.envWant) {
				t.Errorf("%s=%q: got %#v, want %#v", v.env, v.envValue, got, v.envWant)
			}
		})
	}
}

func TestLoad_FlagBeatsTheEnvironment(t *testing.T) {
	for _, v := range configVariables {
		if v.flag == "" {
			continue
		}
		t.Run(v.flag, func(t *testing.T) {
			// The variable is set to a value the flag does not use, so a pass cannot come
			// from the environment having supplied the same answer.
			args := []string{"-" + v.flag + "=" + v.flagValue}
			_, c := loadMatrix(t, v.envWith(), args)

			if got := v.read(c); !reflect.DeepEqual(got, v.flagWant) {
				t.Errorf("%s=%q with %s: got %#v, want the flag's %#v",
					v.env, v.envValue, args[0], got, v.flagWant)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Seam 2: the registered flag set of this binary
// -----------------------------------------------------------------------------

// authServerFlags is the 41 flags the auth server registers: its own 22, the 14 database flags,
// the 3 initial-setup flags, and the two admin console values it reads. 32 were what the split
// left (#351); the four pool flags came after it (#394), the three metrics listener flags
// after those (#400), and the two of the connection's TLS after those (#502).
//
// It is written out rather than derived from configVariables, and that is the whole point. A
// derived expectation cannot fail when a flag is dropped from the table and from config.go
// together, which is exactly what an import change or a careless narrowing does. This list and
// refusedFlags are the only two places in the tree that say what each binary's command line is,
// and the narrowing is the one observable behaviour change this issue makes.
var authServerFlags = []string{
	"admin-email",
	"admin-password",
	"adminconsole-baseurl",
	"adminconsole-oauth-client-secret",
	"appname",
	"authserver-baseurl",
	"authserver-bootstrap-env-outfile",
	"authserver-certfile",
	"authserver-debug-api-requests",
	"authserver-internalbaseurl",
	"authserver-keyfile",
	"authserver-listen-host-http",
	"authserver-listen-host-https",
	"authserver-listen-host-metrics",
	"authserver-listen-port-http",
	"authserver-listen-port-https",
	"authserver-listen-port-metrics",
	"authserver-log-format",
	"authserver-log-http-requests",
	"authserver-log-level",
	"authserver-log-sql",
	"authserver-metrics-enabled",
	"authserver-ratelimiter-enabled",
	"authserver-staticdir",
	"authserver-templatedir",
	"authserver-trust-proxy-headers",
	"authserver-trusted-proxies",
	"db-conn-max-idle-time",
	"db-conn-max-lifetime",
	"db-create",
	"db-dsn",
	"db-host",
	"db-max-idle-conns",
	"db-max-open-conns",
	"db-name",
	"db-password",
	"db-port",
	"db-tls-ca-file",
	"db-tls-mode",
	"db-type",
	"db-username",
}

// flagsAddedAfterTheSplit are the auth server's flags that no binary registered before #351, so
// they are outside the partition TestFlagLists_AgreeWithTheTable counts.
var flagsAddedAfterTheSplit = []string{
	"authserver-listen-host-metrics",
	"authserver-listen-port-metrics",
	"authserver-metrics-enabled",
	"db-conn-max-idle-time",
	"db-conn-max-lifetime",
	"db-max-idle-conns",
	"db-max-open-conns",
	"db-tls-ca-file",
	"db-tls-mode",
}

// refusedFlags is the other half of the narrowing, named rather than merely absent: the 13 admin
// console settings this binary used to accept and ignore. flag.CommandLine is built with
// ExitOnError, so `goiabada-authserver -adminconsole-log-level=debug` now prints "flag provided
// but not defined" and exits 2 where it used to parse and change nothing.
//
// Asserting these by name is what makes the case fail for its stated reason. "Not in the expected
// set" would also pass if Load registered nothing at all.
var refusedFlags = []string{
	"adminconsole-certfile",
	"adminconsole-keyfile",
	"adminconsole-listen-host-http",
	"adminconsole-listen-host-https",
	"adminconsole-listen-port-http",
	"adminconsole-listen-port-https",
	"adminconsole-log-format",
	"adminconsole-log-http-requests",
	"adminconsole-log-level",
	"adminconsole-staticdir",
	"adminconsole-templatedir",
	"adminconsole-trust-proxy-headers",
	"adminconsole-trusted-proxies",
}

// TestLoad_RegistersExactlyTheAuthServerFlags holds what this binary's command line is, in
// both directions: a flag in the list that Load does not register, and a flag it registers
// that the list does not claim.
func TestLoad_RegistersExactlyTheAuthServerFlags(t *testing.T) {
	fs, _ := loadMatrix(t, nil, nil)

	registered := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) { registered[f.Name] = true })

	if len(registered) == 0 {
		t.Fatal("Load registered no flags at all, so this case checked nothing")
	}

	expected := map[string]bool{}
	for _, name := range authServerFlags {
		expected[name] = true
	}

	for _, name := range authServerFlags {
		if !registered[name] {
			t.Errorf("the auth server is meant to register %q and Load does not", name)
		}
	}
	for _, name := range sortedKeys(registered) {
		if !expected[name] {
			t.Errorf("Load registers %q, which is not one of the auth server's flags", name)
		}
	}
}

// TestLoad_RefusesTheAdminConsolesOwnFlags is decision 3's narrowing asserted as a refusal.
// Registering the peer's listener, logging and directory flags is loading the peer's
// configuration, and a flag this binary cannot act on reads to an operator as having configured
// something.
func TestLoad_RefusesTheAdminConsolesOwnFlags(t *testing.T) {
	fs, _ := loadMatrix(t, nil, nil)

	registered := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) { registered[f.Name] = true })

	for _, name := range refusedFlags {
		if registered[name] {
			t.Errorf("the auth server registers %q, which belongs to the admin console and which this binary cannot act on", name)
		}
	}
}

// TestFlagLists_AgreeWithTheTable holds the two literals and configVariables to each other, so
// neither can be edited alone. Without it the lists are a second roster nothing checks, and the
// drift guard below only ever sees the table.
func TestFlagLists_AgreeWithTheTable(t *testing.T) {
	inTable := map[string]bool{}
	for _, v := range configVariables {
		if v.flag != "" {
			inTable[v.flag] = true
		}
	}

	expected := map[string]bool{}
	for _, name := range authServerFlags {
		if expected[name] {
			t.Errorf("authServerFlags names %q twice", name)
		}
		expected[name] = true
		if !inTable[name] {
			t.Errorf("authServerFlags names %q, which no row in configVariables claims", name)
		}
	}
	for _, name := range sortedKeys(inTable) {
		if !expected[name] {
			t.Errorf("a row in configVariables claims the flag %q, which authServerFlags does not list", name)
		}
	}

	for _, name := range refusedFlags {
		if expected[name] {
			t.Errorf("%q is in both authServerFlags and refusedFlags", name)
		}
	}

	// 45 flags were registered by both binaries before the split, and the auth server keeps 32
	// of them. The two lists partition that surface, so a flag that quietly left both is a
	// flag nobody decided about. The flags added since are named, not merely counted.
	for _, name := range flagsAddedAfterTheSplit {
		if !expected[name] {
			t.Errorf("flagsAddedAfterTheSplit names %q, which authServerFlags does not list", name)
		}
	}
	if got := len(authServerFlags) - len(flagsAddedAfterTheSplit) + len(refusedFlags); got != 45 {
		t.Errorf("the two lists cover %d of the flags both binaries registered before the split, want 45", got)
	}
}

// TestLoad_ArgsAreWhatTheParseLeft is the half of #424's dispatch that config owns: Config.Args
// holds the positional arguments in order, and the server's parse stops at the first one, so a
// flag written after `migrate` is left for the subcommand's own parse rather than landing here.
func TestLoad_ArgsAreWhatTheParseLeft(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantArgs []string
		wantType string
	}{
		{"no arguments", nil, nil, "sqlite"},
		{"a flag and nothing else", []string{"-db-type=mysql"}, nil, "mysql"},
		{"flags before migrate", []string{"-db-type=mysql", "migrate", "to", "44"}, []string{"migrate", "to", "44"}, "mysql"},
		{"a separate value, two dashes", []string{"--db-type", "mysql", "migrate", "version"}, []string{"migrate", "version"}, "mysql"},
		{"a flag after migrate stays migrate's", []string{"migrate", "to", "44", "-db-type=mysql"}, []string{"migrate", "to", "44", "-db-type=mysql"}, "sqlite"},
		{"a double dash ends the flags", []string{"-db-type=mysql", "--", "migrate", "version"}, []string{"migrate", "version"}, "mysql"},
		{"a typo is left for dispatch to refuse", []string{"migrat", "to", "44"}, []string{"migrat", "to", "44"}, "sqlite"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, c := loadMatrix(t, nil, tc.args)

			if got := c.Args; !slices.Equal(got, tc.wantArgs) {
				t.Errorf("Args = %#v, want %#v", got, tc.wantArgs)
			}
			if got := c.Database.Type; got != tc.wantType {
				t.Errorf("db-type landed as %q, want %q", got, tc.wantType)
			}
		})
	}
}

// TestRegisterDatabaseFlags_RegistersTheDatabaseFlagsOnTheConfigGiven holds the one registration
// both parses share: exactly the db- names of authServerFlags, defaulting to and writing into the
// struct it was handed.
func TestRegisterDatabaseFlags_RegistersTheDatabaseFlagsOnTheConfigGiven(t *testing.T) {
	local := DatabaseConfig{
		Type:     "postgres",
		Username: "u1",
		Password: "p1",
		Host:     "h1",
		Port:     15432,
		Name:     "n1",
		DSN:      "d1",
		Create:   false,

		MaxOpenConns:    11,
		MaxIdleConns:    intPtr(6),
		ConnMaxLifetime: 2 * time.Hour,
		ConnMaxIdleTime: 3 * time.Minute,

		TLSMode:   "require",
		TLSCAFile: "/c1.pem",
	}
	fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	RegisterDatabaseFlags(fs, &local)

	want := map[string]bool{}
	for _, name := range authServerFlags {
		if strings.HasPrefix(name, "db-") {
			want[name] = true
		}
	}
	if len(want) != 14 {
		t.Fatalf("authServerFlags names %d db- flags, want 14, so this case would check the wrong set", len(want))
	}

	registered := map[string]string{}
	fs.VisitAll(func(f *flag.Flag) { registered[f.Name] = f.DefValue })
	for name := range want {
		if _, ok := registered[name]; !ok {
			t.Errorf("RegisterDatabaseFlags does not register %q", name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(registered)) {
		if !want[name] {
			t.Errorf("RegisterDatabaseFlags registers %q, which is not a database flag", name)
		}
	}

	wantDefaults := map[string]string{
		"db-type":     "postgres",
		"db-username": "u1",
		"db-password": "p1",
		"db-host":     "h1",
		"db-port":     "15432",
		"db-name":     "n1",
		"db-dsn":      "d1",
		"db-create":   "false",

		"db-max-open-conns":     "11",
		"db-max-idle-conns":     "6",
		"db-conn-max-lifetime":  "2h0m0s",
		"db-conn-max-idle-time": "3m0s",

		"db-tls-mode":    "require",
		"db-tls-ca-file": "/c1.pem",
	}
	for name, def := range wantDefaults {
		if got := registered[name]; got != def {
			t.Errorf("%s defaults to %q, want the struct's own %q", name, got, def)
		}
	}

	if err := fs.Set("db-port", "1433"); err != nil {
		t.Fatalf("setting db-port: %v", err)
	}
	if local.Port != 1433 {
		t.Errorf("db-port set to 1433 left the struct at %d", local.Port)
	}
	if err := fs.Set("db-max-idle-conns", "9"); err != nil {
		t.Fatalf("setting db-max-idle-conns: %v", err)
	}
	if local.MaxIdleConns == nil || *local.MaxIdleConns != 9 {
		t.Errorf("db-max-idle-conns set to 9 left the struct at %v", local.MaxIdleConns)
	}
}

// TestRegisterDatabaseFlags_AnUnsetIdleCapFollowsTheOpenCap: the idle cap follows the open cap
// until something sets it, so its flag defaults to nothing rather than to a number, and setting
// the open cap alone moves the idle cap the engines are given with it (#394 decision 6).
func TestRegisterDatabaseFlags_AnUnsetIdleCapFollowsTheOpenCap(t *testing.T) {
	local := DatabaseConfig{MaxOpenConns: 20}
	fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	RegisterDatabaseFlags(fs, &local)

	if got := fs.Lookup("db-max-idle-conns").DefValue; got != "" {
		t.Errorf("db-max-idle-conns defaults to %q, want nothing: it follows the open cap", got)
	}
	if err := fs.Parse([]string{"-db-max-open-conns=7"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if local.MaxIdleConns != nil {
		t.Errorf("the idle cap was set to %d by a flag for the open cap", *local.MaxIdleConns)
	}
	if got := local.EffectiveMaxIdleConns(); got != 7 {
		t.Errorf("EffectiveMaxIdleConns() = %d, want the open cap, 7", got)
	}
}

// TestCheckDatabaseFlags_RefusesWhatTheFlagsGivenLeaveOutOfRange is the check the `migrate`
// subcommand runs after its own parse of the --db-* flags, so a pool flag given after `migrate` is
// held to decision 5 as one given before it is: a flag not given is not checked, since what it
// would report came from Load, which checked it already (#394).
func TestCheckDatabaseFlags_RefusesWhatTheFlagsGivenLeaveOutOfRange(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "no flags", want: ""},
		{name: "every flag in range", args: []string{"-db-max-open-conns=3", "-db-max-idle-conns=3", "-db-conn-max-lifetime=0", "-db-conn-max-idle-time=1s"}},
		{name: "every flag out of range",
			args: []string{"-db-max-open-conns=0", "-db-max-idle-conns=-1", "-db-conn-max-lifetime=-1s", "-db-conn-max-idle-time=-1s"},
			want: `malformed configuration: --db-max-open-conns is "0", not at least 1; ` +
				`--db-max-idle-conns is "-1", not at least 0; ` +
				`--db-conn-max-lifetime is "-1s", not at least 0; ` +
				`--db-conn-max-idle-time is "-1s", not at least 0`},
		{name: "an idle cap above the open cap the configuration holds", args: []string{"-db-max-idle-conns=21"},
			want: `malformed configuration: GOIABADA_DB_MAX_IDLE_CONNS (--db-max-idle-conns) is "21", not at most GOIABADA_DB_MAX_OPEN_CONNS (--db-max-open-conns), which is 20`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			local := DatabaseConfig{MaxOpenConns: 20}
			fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			RegisterDatabaseFlags(fs, &local)
			if err := fs.Parse(tt.args); err != nil {
				t.Fatalf("parse: %v", err)
			}

			err := CheckDatabaseFlags(fs, &local)
			if tt.want == "" {
				if err != nil {
					t.Errorf("CheckDatabaseFlags() = %v, want nothing refused", err)
				}
				return
			}
			if err == nil || err.Error() != tt.want {
				t.Errorf("CheckDatabaseFlags() = %v, want %q", err, tt.want)
			}
		})
	}
}

func intPtr(n int) *int { return &n }

// TestRegisterDatabaseFlags_DbTypeHelpNamesEveryEngine: the help text named two of the four
// engines this binary supports.
func TestRegisterDatabaseFlags_DbTypeHelpNamesEveryEngine(t *testing.T) {
	var local DatabaseConfig
	fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	RegisterDatabaseFlags(fs, &local)

	f := fs.Lookup("db-type")
	if f == nil {
		t.Fatal("db-type is not registered")
	}
	for _, engine := range []string{"sqlite", "mysql", "postgres", "mssql"} {
		if !strings.Contains(f.Usage, engine) {
			t.Errorf("db-type's help %q does not name %s", f.Usage, engine)
		}
	}
}

// TestConfigVariables_EveryRowCanFail holds the table to the discipline its own cases depend
// on: a row whose environment value is its default, or whose flag value is its environment
// value, has a case that passes whatever Load does with it.
func TestConfigVariables_EveryRowCanFail(t *testing.T) {
	seenEnv := map[string]bool{}
	seenFlag := map[string]bool{}

	for _, v := range configVariables {
		t.Run(v.env, func(t *testing.T) {
			if seenEnv[v.env] {
				t.Errorf("%s has two rows", v.env)
			}
			seenEnv[v.env] = true

			if reflect.DeepEqual(v.envWant, v.def) {
				t.Errorf("%s: the environment value lands on the default %#v, so the environment case cannot fail",
					v.env, v.def)
			}
			if v.flag == "" {
				return
			}
			if seenFlag[v.flag] {
				t.Errorf("the flag %q has two rows", v.flag)
			}
			seenFlag[v.flag] = true

			if reflect.DeepEqual(v.flagWant, v.envWant) {
				t.Errorf("%s: the flag lands what the environment lands, %#v, so the flag case cannot fail",
					v.env, v.envWant)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// The drift guard: the table is exhaustive rather than plausible
// -----------------------------------------------------------------------------

var (
	envNameInSource  = regexp.MustCompile(`GOIABADA_[A-Z0-9_]+`)
	flagNameInSource = regexp.MustCompile(`fs\.[A-Za-z0-9]*Var\([^,]+, *"([^"]+)"`)
)

// TestConfigSource_EveryVariableAndFlagHasARow reads config.go and compares what Load
// actually names against the table, in both directions. A variable or a flag added with no
// row fails, and so does a row for one that is gone: without it the matrix locks whatever it
// happened to be written against, and a setting added later is simply not covered.
//
// It is a plain test reading one file in its own package rather than a guard in core/guard,
// which is the shape for a walk over the whole tree; this one never leaves the directory.
func TestConfigSource_EveryVariableAndFlagHasARow(t *testing.T) {
	source, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatalf("reading config.go: %v", err)
	}

	t.Run("every GOIABADA_ name", func(t *testing.T) {
		roster := map[string]bool{}
		for _, v := range configVariables {
			roster[v.env] = true
		}
		for _, name := range nonLiveEnvVars {
			roster[name] = true
		}

		inSource := map[string]bool{}
		for _, name := range envNameInSource.FindAllString(string(source), -1) {
			inSource[name] = true
		}
		if len(inSource) == 0 {
			t.Fatal("found no GOIABADA_ names in config.go at all, so this guard checked nothing")
		}

		for _, name := range sortedKeys(inSource) {
			if !roster[name] {
				t.Errorf("config.go names %s, which has no row in configVariables and is not in nonLiveEnvVars", name)
			}
		}
		for _, name := range sortedKeys(roster) {
			if !inSource[name] {
				t.Errorf("%s has a row but config.go no longer names it", name)
			}
		}
	})

	t.Run("every flag", func(t *testing.T) {
		expected := map[string]bool{}
		for _, v := range configVariables {
			if v.flag != "" {
				expected[v.flag] = true
			}
		}

		inSource := map[string]bool{}
		for _, match := range flagNameInSource.FindAllStringSubmatch(string(source), -1) {
			inSource[match[1]] = true
		}
		if len(inSource) == 0 {
			t.Fatal("found no flag registrations in config.go at all, so this guard checked nothing")
		}

		for _, name := range sortedKeys(inSource) {
			if !expected[name] {
				t.Errorf("config.go registers the flag %q, which no row in configVariables claims", name)
			}
		}
		for _, name := range sortedKeys(expected) {
			if !inSource[name] {
				t.Errorf("a row claims the flag %q, which config.go no longer registers", name)
			}
		}
	})
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestLoad_WarnsAboutThisProcessesRemovedSettingOnly is decision 4 of #351: each process warns
// about its own removed settings. Both binaries used to warn about both removed cookie variables,
// so the auth server's log carried a line about a setting whose cookies it never wrote.
//
// Both variables are set, so the case cannot pass by the admin console's simply being absent, and
// the record naming it would be a failure rather than a silence.
func TestLoad_WarnsAboutThisProcessesRemovedSettingOnly(t *testing.T) {
	capture := logtest.CaptureSlog(t)

	_, _ = loadMatrix(t, map[string]string{
		"GOIABADA_AUTHSERVER_SET_COOKIE_SECURE":   "true",
		"GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE": "true",
	}, nil)

	records := capture.Records()
	if len(records) != 1 {
		t.Fatalf("got %d records, want exactly one: %v", len(records), capture.Text())
	}
	if records[0].Level != slog.LevelWarn {
		t.Errorf("the record is at %v, want warn: a removed setting an operator still sets is a handled configuration problem", records[0].Level)
	}
	if got := records[0].Attrs["setting"]; got != "GOIABADA_AUTHSERVER_SET_COOKIE_SECURE" {
		t.Errorf(`setting = %v, want "GOIABADA_AUTHSERVER_SET_COOKIE_SECURE"`, got)
	}
	if strings.Contains(capture.Text(), "GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE") {
		t.Errorf("the auth server named the admin console's removed setting, which is the admin console's to warn about: %s", capture.Text())
	}
}

// TestLoad_SaysNothingWhenNoRemovedSettingIsSet is the quiet half. Without it the case above
// passes for a Load that warns unconditionally.
func TestLoad_SaysNothingWhenNoRemovedSettingIsSet(t *testing.T) {
	capture := logtest.CaptureSlog(t)

	_, _ = loadMatrix(t, nil, nil)

	if records := capture.Records(); len(records) != 0 {
		t.Errorf("got %d records loading a clean environment, want none: %v", len(records), capture.Text())
	}
}
