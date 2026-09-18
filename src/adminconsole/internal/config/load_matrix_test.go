package config

import (
	"flag"
	"io"
	"log/slog"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// -----------------------------------------------------------------------------
// Seam 1: every live GOIABADA_* variable, its default, its environment value and
// the flag that beats it.
// -----------------------------------------------------------------------------
//
// This is stage 1's matrix, written against core/config's loadFrom and carried here unchanged
// except for its roster: 21 variables and 17 flags, the admin console's own 19 and the 2 auth
// server endpoints it talks to. The same assertions passing on both sides of the move is what
// makes it a lock on the behaviour rather than a description of it (#351).

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

// configVariables is every live GOIABADA_* variable this process loads: the admin console's own
// 19 and the 2 auth server endpoints it talks to, of which 17 have a flag. The names loadFrom
// mentions that are not live configuration are in nonLiveEnvVars.
var configVariables = []configVar{
	// Admin console
	strVar("GOIABADA_ADMINCONSOLE_BASEURL", "adminconsole-baseurl", "http://localhost:9091",
		"https://admin.env.example.com", "https://admin.flag.example.com",
		func() any { return GetAdminConsole().BaseURL }),
	strVar("GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTPS", "adminconsole-listen-host-https", "0.0.0.0",
		"10.0.0.1", "10.0.0.2",
		func() any { return GetAdminConsole().ListenHostHttps }),
	intVar("GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS", "adminconsole-listen-port-https", 9444,
		19444, 29444,
		func() any { return GetAdminConsole().ListenPortHttps }),
	strVar("GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP", "adminconsole-listen-host-http", "0.0.0.0",
		"10.0.1.1", "10.0.1.2",
		func() any { return GetAdminConsole().ListenHostHttp }),
	intVar("GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP", "adminconsole-listen-port-http", 9091,
		19091, 29091,
		func() any { return GetAdminConsole().ListenPortHttp }),
	boolVar("GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS", "adminconsole-trust-proxy-headers", false,
		true, false,
		func() any { return GetAdminConsole().TrustProxyHeaders }),
	csvVar("GOIABADA_ADMINCONSOLE_TRUSTED_PROXIES", "adminconsole-trusted-proxies",
		" 10.0.0.0/8 , 172.16.0.0/12 ", []string{"10.0.0.0/8", "172.16.0.0/12"},
		"192.168.0.1,, ,203.0.113.0/24", []string{"192.168.0.1", "203.0.113.0/24"},
		func() any { return GetAdminConsole().TrustedProxies }),
	boolVar("GOIABADA_ADMINCONSOLE_LOG_HTTP_REQUESTS", "adminconsole-log-http-requests", false,
		true, false,
		func() any { return GetAdminConsole().LogHttpRequests }),
	strVar("GOIABADA_ADMINCONSOLE_LOG_LEVEL", "adminconsole-log-level", "info",
		"debug", "warn",
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

	// Auth server: the two endpoints this process talks to. The other 22 GOIABADA_AUTHSERVER_*
	// variables are the peer's own and are not loaded here, so they have no row -- and the drift
	// guard below checks that in both directions, against config.go.
	strVar("GOIABADA_AUTHSERVER_BASEURL", "authserver-baseurl", "http://localhost:9090",
		"https://auth.env.example.com", "https://auth.flag.example.com",
		func() any { return GetAuthServer().BaseURL }),
	strVar("GOIABADA_AUTHSERVER_INTERNALBASEURL", "authserver-internalbaseurl", "",
		"http://auth-env.internal:9090", "http://auth-flag.internal:9090",
		func() any { return GetAuthServer().InternalBaseURL }),
}

// nonLiveEnvVars are the GOIABADA_* names loadFrom's file mentions that are not live
// configuration. They land on no field, so they have no row, and the drift guard carries them as
// named exceptions rather than as silence.
//
// The first is the removed cookie setting this binary warns about, because the Secure flag is
// derived from an https base URL (#293). The second is the auth server's, which this binary
// stopped warning about (#351) and now spells only in the comment saying so: the drift guard
// reads names wherever they appear in the source, so a name in prose needs an entry here just as
// one in a warning list does. What holds the warning itself to naming only the admin console's is
// TestLoadFrom_WarnsAboutThisProcessesRemovedSettingOnly, not this list. The last two are the
// variables ValidateRemovedAdminConsoleVars refuses outright rather than loads (#285).
var nonLiveEnvVars = []string{
	"GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE",
	"GOIABADA_AUTHSERVER_SET_COOKIE_SECURE",
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

// -----------------------------------------------------------------------------
// Seam 2: the registered flag set of this binary
// -----------------------------------------------------------------------------

// adminConsoleFlags is the 17 flags the admin console registers after the split (#351): its own
// 15, and the two auth server endpoints it talks to.
//
// It is written out rather than derived from configVariables, and that is the whole point. A
// derived expectation cannot fail when a flag is dropped from the table and from config.go
// together, which is exactly what an import change or a careless narrowing does. This list and
// refusedFlags are the only two places in this module that say what its command line is, and the
// narrowing is the one observable behaviour change this issue makes.
var adminConsoleFlags = []string{
	"adminconsole-baseurl",
	"adminconsole-certfile",
	"adminconsole-keyfile",
	"adminconsole-listen-host-http",
	"adminconsole-listen-host-https",
	"adminconsole-listen-port-http",
	"adminconsole-listen-port-https",
	"adminconsole-log-format",
	"adminconsole-log-http-requests",
	"adminconsole-log-level",
	"adminconsole-oauth-client-secret",
	"adminconsole-staticdir",
	"adminconsole-templatedir",
	"adminconsole-trust-proxy-headers",
	"adminconsole-trusted-proxies",
	"authserver-baseurl",
	"authserver-internalbaseurl",
}

// refusedFlags is the other half of the narrowing, named rather than merely absent: the 28
// settings this binary used to accept and ignore -- the auth server's own 17, the 8 database
// flags and the 3 initial-setup flags, none of which the admin console can act on, since it has
// no listener of the auth server's, no database access and seeds nothing. flag.CommandLine is
// built with ExitOnError, so `goiabada-adminconsole -db-type=mysql` now prints "flag provided but
// not defined" and exits 2 where it used to parse and change nothing.
//
// Asserting these by name is what makes the case fail for its stated reason. "Not in the expected
// set" would also pass if loadFrom registered nothing at all.
var refusedFlags = []string{
	"admin-email",
	"admin-password",
	"appname",
	"authserver-bootstrap-env-outfile",
	"authserver-certfile",
	"authserver-debug-api-requests",
	"authserver-keyfile",
	"authserver-listen-host-http",
	"authserver-listen-host-https",
	"authserver-listen-port-http",
	"authserver-listen-port-https",
	"authserver-log-format",
	"authserver-log-http-requests",
	"authserver-log-level",
	"authserver-log-sql",
	"authserver-ratelimiter-enabled",
	"authserver-staticdir",
	"authserver-templatedir",
	"authserver-trust-proxy-headers",
	"authserver-trusted-proxies",
	"db-create",
	"db-dsn",
	"db-host",
	"db-name",
	"db-password",
	"db-port",
	"db-type",
	"db-username",
}

// TestLoadFrom_RegistersExactlyTheAdminConsoleFlags holds what this binary's command line is, in
// both directions: a flag in the list that loadFrom does not register, and a flag it registers
// that the list does not claim.
func TestLoadFrom_RegistersExactlyTheAdminConsoleFlags(t *testing.T) {
	fs := loadMatrix(t, nil, nil)

	registered := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) { registered[f.Name] = true })

	if len(registered) == 0 {
		t.Fatal("loadFrom registered no flags at all, so this case checked nothing")
	}

	expected := map[string]bool{}
	for _, name := range adminConsoleFlags {
		expected[name] = true
	}

	for _, name := range adminConsoleFlags {
		if !registered[name] {
			t.Errorf("the admin console is meant to register %q and loadFrom does not", name)
		}
	}
	for _, name := range sortedKeys(registered) {
		if !expected[name] {
			t.Errorf("loadFrom registers %q, which is not one of the admin console's flags", name)
		}
	}
}

// TestLoadFrom_RefusesTheAuthServersOwnFlags is decision 3's narrowing asserted as a refusal.
// Registering the peer's listener, logging and database flags is loading the peer's
// configuration, and a flag this binary cannot act on reads to an operator as having configured
// something: `goiabada-adminconsole -db-type=mysql` parsed and was ignored before the split.
func TestLoadFrom_RefusesTheAuthServersOwnFlags(t *testing.T) {
	fs := loadMatrix(t, nil, nil)

	registered := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) { registered[f.Name] = true })

	for _, name := range refusedFlags {
		if registered[name] {
			t.Errorf("the admin console registers %q, which belongs to the auth server and which this binary cannot act on", name)
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
	for _, name := range adminConsoleFlags {
		if expected[name] {
			t.Errorf("adminConsoleFlags names %q twice", name)
		}
		expected[name] = true
		if !inTable[name] {
			t.Errorf("adminConsoleFlags names %q, which no row in configVariables claims", name)
		}
	}
	for _, name := range sortedKeys(inTable) {
		if !expected[name] {
			t.Errorf("a row in configVariables claims the flag %q, which adminConsoleFlags does not list", name)
		}
	}

	for _, name := range refusedFlags {
		if expected[name] {
			t.Errorf("%q is in both adminConsoleFlags and refusedFlags", name)
		}
	}

	// 45 flags were registered by both binaries before the split, and the admin console keeps 17
	// of them. The two lists partition that surface, so a flag that quietly left both is a flag
	// nobody decided about.
	if got := len(adminConsoleFlags) + len(refusedFlags); got != 45 {
		t.Errorf("the two lists cover %d flags, want the 45 both binaries registered before the split", got)
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

// TestLoadFrom_WarnsAboutThisProcessesRemovedSettingOnly is decision 4 of #351: each process warns
// about its own removed settings. Both binaries used to warn about both removed cookie variables,
// so the admin console's log carried a line about a setting whose cookies it never wrote.
//
// Both variables are set, so the case cannot pass by the auth server's simply being absent, and
// the record naming it would be a failure rather than a silence.
func TestLoadFrom_WarnsAboutThisProcessesRemovedSettingOnly(t *testing.T) {
	capture := testutil.CaptureSlog(t)

	loadMatrix(t, map[string]string{
		"GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE": "true",
		"GOIABADA_AUTHSERVER_SET_COOKIE_SECURE":   "true",
	}, nil)

	records := capture.Records()
	if len(records) != 1 {
		t.Fatalf("got %d records, want exactly one: %v", len(records), capture.Text())
	}
	if records[0].Level != slog.LevelWarn {
		t.Errorf("the record is at %v, want warn: a removed setting an operator still sets is a handled configuration problem", records[0].Level)
	}
	if got := records[0].Attrs["setting"]; got != "GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE" {
		t.Errorf(`setting = %v, want "GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE"`, got)
	}
	if strings.Contains(capture.Text(), "GOIABADA_AUTHSERVER_SET_COOKIE_SECURE") {
		t.Errorf("the admin console named the auth server's removed setting, which is the auth server's to warn about: %s", capture.Text())
	}
}

// TestLoadFrom_SaysNothingWhenNoRemovedSettingIsSet is the quiet half. Without it the case above
// passes for a loadFrom that warns unconditionally.
func TestLoadFrom_SaysNothingWhenNoRemovedSettingIsSet(t *testing.T) {
	capture := testutil.CaptureSlog(t)

	loadMatrix(t, nil, nil)

	if records := capture.Records(); len(records) != 0 {
		t.Errorf("got %d records loading a clean environment, want none: %v", len(records), capture.Text())
	}
}
