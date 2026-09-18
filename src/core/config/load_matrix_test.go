package config

import (
	"bytes"
	"flag"
	"io"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// Seam 1: every live GOIABADA_* variable, its default, its environment value and
// the flag that beats it.
// -----------------------------------------------------------------------------
//
// This file is deliberately self-contained apart from unsetEnv: it is copied into each
// process's own config package and narrowed to the half that process owns when core/config
// is split (#351), and the same assertions passing on both sides of that move is the whole
// point of writing them here first.

// configVar is one live GOIABADA_* setting: its flag if it has one, what loadFrom lands
// when nothing is set, and what it lands from the environment and from the command line.
//
// read takes the landed value through the exported accessor rather than off the package-global
// cfg. The accessors are what every call site in the tree uses, so a matrix reading cfg
// directly would keep passing with all of them broken, and would lock nothing a move of this
// package could break (#351).
type configVar struct {
	env  string // the GOIABADA_* name
	flag string // the flag name, or "" when the variable has none
	def  any    // what loadFrom lands with nothing set

	// envValue differs from the default, so no environment case can pass by the default
	// happening to agree. flagValue differs from envValue, so no flag case can pass by the
	// flag being ignored. A setting with only two values (every bool, and the log format)
	// therefore has flagValue equal to its default, and the case still discriminates,
	// because it is the environment that supplied the other value.
	envValue  string
	envWant   any
	flagValue string // ignored when flag is ""
	flagWant  any

	read func() any
}

// strVar is a row whose landed value is the string as supplied.
func strVar(name, flagName, def, fromEnv, fromFlag string, read func() any) configVar {
	return configVar{
		env: name, flag: flagName, def: def,
		envValue: fromEnv, envWant: fromEnv,
		flagValue: fromFlag, flagWant: fromFlag,
		read: read,
	}
}

// strVarNoFlag is strVar for a variable with no flag of its own.
func strVarNoFlag(name, def, fromEnv string, read func() any) configVar {
	return configVar{env: name, def: def, envValue: fromEnv, envWant: fromEnv, read: read}
}

func intVar(name, flagName string, def, fromEnv, fromFlag int, read func() any) configVar {
	return configVar{
		env: name, flag: flagName, def: def,
		envValue: strconv.Itoa(fromEnv), envWant: fromEnv,
		flagValue: strconv.Itoa(fromFlag), flagWant: fromFlag,
		read: read,
	}
}

// int64VarNoFlag is the int64 row for a variable with no flag of its own.
func int64VarNoFlag(name string, def, fromEnv int64, read func() any) configVar {
	return configVar{
		env: name, def: def,
		envValue: strconv.FormatInt(fromEnv, 10), envWant: fromEnv,
		read: read,
	}
}

func boolVar(name, flagName string, def, fromEnv, fromFlag bool, read func() any) configVar {
	return configVar{
		env: name, flag: flagName, def: def,
		envValue: strconv.FormatBool(fromEnv), envWant: fromEnv,
		flagValue: strconv.FormatBool(fromFlag), flagWant: fromFlag,
		read: read,
	}
}

// csvVar is a comma-separated row. Its default is a nil []string rather than an empty one,
// which is what splitCSV answers for an absent value and which reflect.DeepEqual tells apart.
func csvVar(name, flagName, fromEnv string, wantEnv []string, fromFlag string, wantFlag []string, read func() any) configVar {
	return configVar{
		env: name, flag: flagName, def: []string(nil),
		envValue: fromEnv, envWant: wantEnv,
		flagValue: fromFlag, flagWant: wantFlag,
		read: read,
	}
}

// hexKeyVar is a data-encryption key row. Neither key has a flag, and both are read through
// the decoding accessor, so the row asserts the decoded bytes rather than the hex text.
func hexKeyVar(name string, def []byte, fromEnv string, wantEnv []byte, read func() any) configVar {
	return configVar{env: name, def: def, envValue: fromEnv, envWant: wantEnv, read: read}
}

// configVariables is every live GOIABADA_* variable: 24 auth server, 19 admin console,
// 8 database and 5 top-level, of which 45 have a flag. The four names loadFrom mentions
// that are not live configuration are in nonLiveEnvVars.
var configVariables = []configVar{
	// Auth server
	strVar("GOIABADA_AUTHSERVER_BASEURL", "authserver-baseurl", "http://localhost:9090",
		"https://auth.env.example.com", "https://auth.flag.example.com",
		func() any { return GetAuthServer().BaseURL }),
	strVar("GOIABADA_AUTHSERVER_INTERNALBASEURL", "authserver-internalbaseurl", "",
		"http://auth-env.internal:9090", "http://auth-flag.internal:9090",
		func() any { return GetAuthServer().InternalBaseURL }),
	strVar("GOIABADA_AUTHSERVER_LISTEN_HOST_HTTPS", "authserver-listen-host-https", "0.0.0.0",
		"10.0.0.1", "10.0.0.2",
		func() any { return GetAuthServer().ListenHostHttps }),
	intVar("GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS", "authserver-listen-port-https", 9443,
		19443, 29443,
		func() any { return GetAuthServer().ListenPortHttps }),
	strVar("GOIABADA_AUTHSERVER_LISTEN_HOST_HTTP", "authserver-listen-host-http", "0.0.0.0",
		"10.0.1.1", "10.0.1.2",
		func() any { return GetAuthServer().ListenHostHttp }),
	intVar("GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP", "authserver-listen-port-http", 9090,
		19090, 29090,
		func() any { return GetAuthServer().ListenPortHttp }),
	boolVar("GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS", "authserver-trust-proxy-headers", false,
		true, false,
		func() any { return GetAuthServer().TrustProxyHeaders }),
	csvVar("GOIABADA_AUTHSERVER_TRUSTED_PROXIES", "authserver-trusted-proxies",
		" 10.0.0.0/8 , 172.16.0.0/12 ", []string{"10.0.0.0/8", "172.16.0.0/12"},
		"192.168.0.1,, ,203.0.113.0/24", []string{"192.168.0.1", "203.0.113.0/24"},
		func() any { return GetAuthServer().TrustedProxies }),
	boolVar("GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS", "authserver-log-http-requests", false,
		true, false,
		func() any { return GetAuthServer().LogHttpRequests }),
	strVar("GOIABADA_AUTHSERVER_LOG_LEVEL", "authserver-log-level", "info",
		"debug", "warn",
		func() any { return GetAuthServer().LogLevel }),
	strVar("GOIABADA_AUTHSERVER_LOG_FORMAT", "authserver-log-format", "text",
		"json", "text",
		func() any { return GetAuthServer().LogFormat }),
	strVar("GOIABADA_AUTHSERVER_CERTFILE", "authserver-certfile", "",
		"/env/auth-cert.pem", "/flag/auth-cert.pem",
		func() any { return GetAuthServer().CertFile }),
	strVar("GOIABADA_AUTHSERVER_KEYFILE", "authserver-keyfile", "",
		"/env/auth-key.pem", "/flag/auth-key.pem",
		func() any { return GetAuthServer().KeyFile }),
	boolVar("GOIABADA_AUTHSERVER_LOG_SQL", "authserver-log-sql", false,
		true, false,
		func() any { return GetAuthServer().LogSQL }),
	strVar("GOIABADA_AUTHSERVER_STATICDIR", "authserver-staticdir", "",
		"/env/auth-static", "/flag/auth-static",
		func() any { return GetAuthServer().StaticDir }),
	strVar("GOIABADA_AUTHSERVER_TEMPLATEDIR", "authserver-templatedir", "",
		"/env/auth-templates", "/flag/auth-templates",
		func() any { return GetAuthServer().TemplateDir }),
	boolVar("GOIABADA_AUTHSERVER_DEBUG_API_REQUESTS", "authserver-debug-api-requests", false,
		true, false,
		func() any { return GetAuthServer().DebugAPIRequests }),
	strVar("GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE", "authserver-bootstrap-env-outfile", "",
		"/env/bootstrap.env", "/flag/bootstrap.env",
		func() any { return GetAuthServer().BootstrapEnvOutFile }),
	strVarNoFlag("GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY", "", strings.Repeat("a1", 64),
		func() any { return GetAuthServer().SessionAuthenticationKey }),
	strVarNoFlag("GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY", "", strings.Repeat("a2", 32),
		func() any { return GetAuthServer().SessionEncryptionKey }),
	strVarNoFlag("GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY_PREVIOUS", "", strings.Repeat("a3", 64),
		func() any { return GetAuthServer().SessionAuthenticationKeyPrevious }),
	strVarNoFlag("GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY_PREVIOUS", "", strings.Repeat("a4", 32),
		func() any { return GetAuthServer().SessionEncryptionKeyPrevious }),
	boolVar("GOIABADA_AUTHSERVER_RATELIMITER_ENABLED", "authserver-ratelimiter-enabled", false,
		true, false,
		func() any { return GetAuthServer().RateLimiterEnabled }),
	int64VarNoFlag("GOIABADA_PROFILE_PICTURE_MAX_SIZE_BYTES", 3*1024*1024, 5*1024*1024,
		func() any { return GetAuthServer().ProfilePictureMaxSizeBytes }),

	// Admin console
	strVar("GOIABADA_ADMINCONSOLE_BASEURL", "adminconsole-baseurl", "http://localhost:9091",
		"https://admin.env.example.com", "https://admin.flag.example.com",
		func() any { return GetAdminConsole().BaseURL }),
	strVar("GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTPS", "adminconsole-listen-host-https", "0.0.0.0",
		"10.1.0.1", "10.1.0.2",
		func() any { return GetAdminConsole().ListenHostHttps }),
	intVar("GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS", "adminconsole-listen-port-https", 9444,
		19444, 29444,
		func() any { return GetAdminConsole().ListenPortHttps }),
	strVar("GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP", "adminconsole-listen-host-http", "0.0.0.0",
		"10.1.1.1", "10.1.1.2",
		func() any { return GetAdminConsole().ListenHostHttp }),
	intVar("GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP", "adminconsole-listen-port-http", 9091,
		19091, 29091,
		func() any { return GetAdminConsole().ListenPortHttp }),
	boolVar("GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS", "adminconsole-trust-proxy-headers", false,
		true, false,
		func() any { return GetAdminConsole().TrustProxyHeaders }),
	csvVar("GOIABADA_ADMINCONSOLE_TRUSTED_PROXIES", "adminconsole-trusted-proxies",
		" 10.1.0.0/8 , 172.17.0.0/12 ", []string{"10.1.0.0/8", "172.17.0.0/12"},
		"192.168.1.1, ,203.0.113.1", []string{"192.168.1.1", "203.0.113.1"},
		func() any { return GetAdminConsole().TrustedProxies }),
	boolVar("GOIABADA_ADMINCONSOLE_LOG_HTTP_REQUESTS", "adminconsole-log-http-requests", false,
		true, false,
		func() any { return GetAdminConsole().LogHttpRequests }),
	strVar("GOIABADA_ADMINCONSOLE_LOG_LEVEL", "adminconsole-log-level", "info",
		"error", "warn",
		func() any { return GetAdminConsole().LogLevel }),
	strVar("GOIABADA_ADMINCONSOLE_LOG_FORMAT", "adminconsole-log-format", "text",
		"json", "text",
		func() any { return GetAdminConsole().LogFormat }),
	strVar("GOIABADA_ADMINCONSOLE_CERTFILE", "adminconsole-certfile", "",
		"/env/admin-cert.pem", "/flag/admin-cert.pem",
		func() any { return GetAdminConsole().CertFile }),
	strVar("GOIABADA_ADMINCONSOLE_KEYFILE", "adminconsole-keyfile", "",
		"/env/admin-key.pem", "/flag/admin-key.pem",
		func() any { return GetAdminConsole().KeyFile }),
	strVar("GOIABADA_ADMINCONSOLE_STATICDIR", "adminconsole-staticdir", "",
		"/env/admin-static", "/flag/admin-static",
		func() any { return GetAdminConsole().StaticDir }),
	strVar("GOIABADA_ADMINCONSOLE_TEMPLATEDIR", "adminconsole-templatedir", "",
		"/env/admin-templates", "/flag/admin-templates",
		func() any { return GetAdminConsole().TemplateDir }),
	strVar("GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET", "adminconsole-oauth-client-secret", "",
		"env-client-secret", "flag-client-secret",
		func() any { return GetAdminConsole().OAuthClientSecret }),
	strVarNoFlag("GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY", "", strings.Repeat("b1", 64),
		func() any { return GetAdminConsole().SessionAuthenticationKey }),
	strVarNoFlag("GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY", "", strings.Repeat("b2", 32),
		func() any { return GetAdminConsole().SessionEncryptionKey }),
	strVarNoFlag("GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY_PREVIOUS", "", strings.Repeat("b3", 64),
		func() any { return GetAdminConsole().SessionAuthenticationKeyPrevious }),
	strVarNoFlag("GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS", "", strings.Repeat("b4", 32),
		func() any { return GetAdminConsole().SessionEncryptionKeyPrevious }),

	// Database
	strVar("GOIABADA_DB_TYPE", "db-type", "sqlite",
		"mysql", "postgres",
		func() any { return GetDatabase().Type }),
	strVar("GOIABADA_DB_USERNAME", "db-username", "root",
		"env-user", "flag-user",
		func() any { return GetDatabase().Username }),
	strVar("GOIABADA_DB_PASSWORD", "db-password", "",
		"env-db-password", "flag-db-password",
		func() any { return GetDatabase().Password }),
	strVar("GOIABADA_DB_HOST", "db-host", "localhost",
		"env.db.example.com", "flag.db.example.com",
		func() any { return GetDatabase().Host }),
	intVar("GOIABADA_DB_PORT", "db-port", 3306,
		13306, 23306,
		func() any { return GetDatabase().Port }),
	strVar("GOIABADA_DB_NAME", "db-name", "goiabada",
		"env_goiabada", "flag_goiabada",
		func() any { return GetDatabase().Name }),
	strVar("GOIABADA_DB_DSN", "db-dsn", "file::memory:?cache=shared",
		"file:env.db?cache=shared", "file:flag.db?cache=shared",
		func() any { return GetDatabase().DSN }),
	// The one setting whose default is true, which is why it goes through
	// getEnvAsBoolDefault rather than getEnvAsBool (#293).
	boolVar("GOIABADA_DB_CREATE", "db-create", true,
		false, true,
		func() any { return GetDatabase().Create }),

	// Initial setup and the data-encryption keys
	strVar("GOIABADA_ADMIN_EMAIL", "admin-email", "admin",
		"env-admin@example.com", "flag-admin@example.com",
		func() any { return GetAdminEmail() }),
	strVar("GOIABADA_ADMIN_PASSWORD", "admin-password", "changeme",
		"env-admin-password", "flag-admin-password",
		func() any { return GetAdminPassword() }),
	strVar("GOIABADA_APPNAME", "appname", "Goiabada",
		"Env Goiabada", "Flag Goiabada",
		func() any { return GetAppName() }),
	// hex.DecodeString("") answers an empty non-nil slice, so the current key's default is
	// an empty slice where the previous key's, which short-circuits on the empty string, is
	// nil. reflect.DeepEqual tells the two apart, which is why the rows record them apart.
	hexKeyVar("GOIABADA_AES_ENCRYPTION_KEY", []byte{},
		strings.Repeat("ab", 32), bytes.Repeat([]byte{0xab}, 32),
		func() any { return GetAESEncryptionKey() }),
	hexKeyVar("GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS", []byte(nil),
		strings.Repeat("cd", 32), bytes.Repeat([]byte{0xcd}, 32),
		func() any { return GetAESEncryptionKeyPrevious() }),
}

// nonLiveEnvVars are the GOIABADA_* names loadFrom mentions that are not live configuration:
// the two removed cookie settings it warns about, because the Secure flag is derived from an
// https base URL (#293), and the two removed admin console settings
// ValidateRemovedAdminConsoleVars refuses outright (#285). They land on no field, so they have
// no row, and the drift guard carries them as a named exception rather than as silence.
var nonLiveEnvVars = []string{
	"GOIABADA_AUTHSERVER_SET_COOKIE_SECURE",
	"GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE",
	"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID",
	"GOIABADA_ADMINCONSOLE_ISSUER",
}

// loadMatrix drives loadFrom with its own flag set and returns it, so a case can assert on
// what was registered as well as on what was landed. Every name in the roster is cleared
// first, so a developer's own environment cannot decide what a default case observes.
func loadMatrix(t *testing.T, env map[string]string, args []string) *flag.FlagSet {
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

	saved := cfg
	t.Cleanup(func() { cfg = saved })

	fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	loadFrom(fs, args)

	return fs
}

func TestLoadFrom_Defaults(t *testing.T) {
	for _, v := range configVariables {
		t.Run(v.env, func(t *testing.T) {
			loadMatrix(t, nil, nil)

			if got := v.read(); !reflect.DeepEqual(got, v.def) {
				t.Errorf("%s unset: got %#v, want the default %#v", v.env, got, v.def)
			}
		})
	}
}

func TestLoadFrom_FromTheEnvironment(t *testing.T) {
	for _, v := range configVariables {
		t.Run(v.env, func(t *testing.T) {
			loadMatrix(t, map[string]string{v.env: v.envValue}, nil)

			if got := v.read(); !reflect.DeepEqual(got, v.envWant) {
				t.Errorf("%s=%q: got %#v, want %#v", v.env, v.envValue, got, v.envWant)
			}
		})
	}
}

func TestLoadFrom_FlagBeatsTheEnvironment(t *testing.T) {
	for _, v := range configVariables {
		if v.flag == "" {
			continue
		}
		t.Run(v.flag, func(t *testing.T) {
			// The variable is set to a value the flag does not use, so a pass cannot come
			// from the environment having supplied the same answer.
			args := []string{"-" + v.flag + "=" + v.flagValue}
			loadMatrix(t, map[string]string{v.env: v.envValue}, args)

			if got := v.read(); !reflect.DeepEqual(got, v.flagWant) {
				t.Errorf("%s=%q with %s: got %#v, want the flag's %#v",
					v.env, v.envValue, args[0], got, v.flagWant)
			}
		})
	}
}

// TestLoadFrom_RegistersEveryFlag is the "before" half of the flag narrowing (#351 decision 3):
// both binaries register the identical 45 flags today, because loadFrom registers every one of
// them on whatever set it is handed. Each process's own config package carries this test
// narrowed to its own flags once the split lands.
func TestLoadFrom_RegistersEveryFlag(t *testing.T) {
	fs := loadMatrix(t, nil, nil)

	registered := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) { registered[f.Name] = true })

	expected := map[string]bool{}
	for _, v := range configVariables {
		if v.flag != "" {
			expected[v.flag] = true
		}
	}

	for name := range expected {
		if !registered[name] {
			t.Errorf("the table has a flag %q that loadFrom does not register", name)
		}
	}
	for name := range registered {
		if !expected[name] {
			t.Errorf("loadFrom registers a flag %q that no row in the table claims", name)
		}
	}
}

// TestAESKeyAccessors_AnswerNilOnAMalformedKey covers the arms the table cannot reach: both
// accessors decode, and both answer nil rather than an error when the value is not hex.
// ValidateAESEncryptionKey is what refuses such a value at startup, so the accessors are only
// reached once it has passed; a nil here is the accessor declining to guess. The previous
// key's unset-means-nil arm is the row's default case.
func TestAESKeyAccessors_AnswerNilOnAMalformedKey(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		read func() any
	}{
		{
			name: "the current key",
			env:  map[string]string{"GOIABADA_AES_ENCRYPTION_KEY": "zz"},
			read: func() any { return GetAESEncryptionKey() },
		},
		{
			name: "the previous key",
			env:  map[string]string{"GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS": "zz"},
			read: func() any { return GetAESEncryptionKeyPrevious() },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loadMatrix(t, test.env, nil)

			if got := test.read(); got != nil && !reflect.DeepEqual(got, []byte(nil)) {
				t.Errorf("a malformed key decoded to %#v, want nil", got)
			}
		})
	}
}

// TestConfigVariables_EveryRowCanFail holds the table to the discipline its own cases depend
// on: a row whose environment value is its default, or whose flag value is its environment
// value, has a case that passes whatever loadFrom does with it.
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
	flagNameInSource = regexp.MustCompile(`fs\.[A-Za-z0-9]+Var\([^,]+, *"([^"]+)"`)
)

// TestConfigSource_EveryVariableAndFlagHasARow reads config.go and compares what loadFrom
// actually names against the table, in both directions. A variable or a flag added with no
// row fails, and so does a row for one that is gone: without it the matrix locks whatever it
// happened to be written against, and a setting added later is simply not covered.
//
// It is a plain test reading one file in its own package rather than a core/testutil guard,
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
