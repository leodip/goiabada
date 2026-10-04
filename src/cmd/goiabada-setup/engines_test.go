package main

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// A server engine's row is read field by field by the prompts, the Compose generator and the
// connection check, so an empty field is a blank in a generated file or a nil call at run time.
// An engine with no server must carry none of them: each is read only behind hasServer, and a
// value set there would read as a fact the wizard acts on.
func TestEngines_EveryRowIsComplete(t *testing.T) {
	for _, e := range engines {
		t.Run(e.name, func(t *testing.T) {
			for field, value := range map[string]string{
				"number": e.number, "name": e.name, "label": e.label, "volume": e.volume, "mount": e.mount,
			} {
				if value == "" {
					t.Errorf("%s is empty", field)
				}
			}

			serverFields := map[string]string{
				"image": e.image, "defaultPort": e.defaultPort, "defaultUser": e.defaultUser,
				"kubernetesHost": e.kubernetesHost, "composeService": e.composeService,
				"healthcheck": e.healthcheck, "healthInterval": e.healthInterval, "healthTimeout": e.healthTimeout,
				"driver": e.driver, "existenceQuery": e.existenceQuery, "emptinessQuery": e.emptinessQuery,
				"composePasswordVariable": e.composePasswordVariable,
			}
			serverFuncs := map[string]bool{
				"dsn":            e.dsn != nil,
				"maintenanceDSN": e.maintenanceDSN != nil,
			}

			if !e.hasServer {
				for field, value := range serverFields {
					if value != "" {
						t.Errorf("%s is %q on an engine with no server", field, value)
					}
				}
				for field, set := range serverFuncs {
					if set {
						t.Errorf("%s is set on an engine with no server", field)
					}
				}
				if e.kubernetes {
					t.Errorf("an engine with no server is offered to Kubernetes")
				}
				return
			}

			for field, value := range serverFields {
				if value == "" {
					t.Errorf("%s is empty on a server engine", field)
				}
			}
			for field, set := range serverFuncs {
				if !set {
					t.Fatalf("%s is nil on a server engine", field)
				}
			}
		})
	}
}

var containerVariable = regexp.MustCompile(`\$\{([A-Z_]+)\}`)

// A healthcheck carries no password. One that needs it names the database container's variable,
// which must be one the service's environment sets, to exactly the password: a misspelt name
// expands to nothing in the container's shell, and the database never reports healthy (#430). The
// environment is read as Compose gives it to the container, the Compose file's merged with the
// override's, where the password is (#396 decision 14).
func TestEngines_TheHealthcheckReadsTheContainersOwnPassword(t *testing.T) {
	const password = `pa"ss'$HOME` + "`id`" + `\x #y: z`
	for _, e := range engines {
		if !e.hasServer {
			continue
		}
		t.Run(e.name, func(t *testing.T) {
			if strings.Contains(e.healthcheck, password) {
				t.Errorf("the healthcheck carries the password")
			}
			config := goldenConfig(deploymentProduction, e.name)
			config.DBPassword = password
			description, secrets := generatedConfiguration(config)
			base := only[map[string]any](t, toAny(yamlDocuments(t, description.content)), "the Compose file's documents")
			override := only[map[string]any](t, toAny(yamlDocuments(t, secrets.content)), "the override's documents")
			set := composeMergedEnvironment(t, base, override, e.composeService)
			for _, m := range containerVariable.FindAllStringSubmatch(e.healthcheck, -1) {
				value, ok := set[m[1]]
				if !ok {
					t.Errorf("the healthcheck reads %s, which the service's environment does not set", m[1])
					continue
				}
				if value != password {
					t.Errorf("%s is set to %q, want the password %q", m[1], value, password)
				}
			}
		})
	}
	// The two whose healthcheck logs in do read a variable: without this, a row that went back
	// to a password-free command that never logs in would pass the loop above having checked
	// nothing.
	for _, name := range []string{"mysql", "mssql"} {
		if !containerVariable.MatchString(testEngine(name).healthcheck) {
			t.Errorf("%s's healthcheck reads no container variable", name)
		}
	}
}

// The --db values and menu numbers operators type today, each resolving to its engine in any case.
// A value on two rows would resolve to whichever comes first.
func TestEngines_EveryNameAliasAndNumberResolvesToItsRow(t *testing.T) {
	want := map[string][]string{
		"mysql":    {"mysql", "1"},
		"postgres": {"postgres", "postgresql", "2"},
		"mssql":    {"mssql", "sqlserver", "3"},
		"sqlite":   {"sqlite", "4"},
	}

	owner := map[string]string{}
	for _, e := range engines {
		values := append([]string{e.name, e.number}, e.aliases...)
		if len(values) != len(want[e.name]) {
			t.Errorf("%s answers to %v, want %v", e.name, values, want[e.name])
		}
		for _, value := range values {
			if other, taken := owner[value]; taken {
				t.Errorf("%q names both %s and %s", value, other, e.name)
			}
			owner[value] = e.name
		}
	}

	for name, values := range want {
		for _, value := range values {
			for _, spelling := range []string{value, strings.ToUpper(value)} {
				got, ok := resolveEngine(spelling)
				if !ok || got.name != name {
					t.Errorf("resolveEngine(%q) = %v, %v, want %s", spelling, got, ok, name)
				}
			}
		}
	}

	for _, value := range []string{"", "5", "0", "oracle", "sqlite3"} {
		if got, ok := resolveEngine(value); ok {
			t.Errorf("resolveEngine(%q) = %s, want no engine", value, got.name)
		}
	}
}

// The menu prints each engine's number, and the numbers are the menu's order.
func TestEngines_NumbersAreMenuPositions(t *testing.T) {
	for i, e := range engines {
		if want := strconv.Itoa(i + 1); e.number != want {
			t.Errorf("%s is number %s at menu position %s", e.name, e.number, want)
		}
	}
}

// The driver each row opens is the one the auth server opens (sql.Open in each engine's
// New*Database), and the existence query is the server's own databaseExists where it has one,
// asked over the maintenance connection the server creates the database from. The connection
// strings are pinned by testdata/connection-strings.json instead (#430).
func TestEngines_TheConnectionCheckIsTheServers(t *testing.T) {
	testCases := []struct {
		engine, driver, existenceQuery, emptinessQuery string
	}{
		{
			engine:         "mysql",
			driver:         "mysql",
			existenceQuery: "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?",
			emptinessQuery: "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'users'",
		},
		{
			engine:         "postgres",
			driver:         "pgx",
			existenceQuery: "SELECT COUNT(*) FROM pg_database WHERE datname = $1",
			emptinessQuery: "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users'",
		},
		{
			engine:         "mssql",
			driver:         "sqlserver",
			existenceQuery: "SELECT COUNT(*) FROM sys.databases WHERE name = @p1",
			emptinessQuery: "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'users'",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.engine, func(t *testing.T) {
			e := testEngine(testCase.engine)
			if e.driver != testCase.driver {
				t.Errorf("driver is %q, want %q", e.driver, testCase.driver)
			}
			if e.existenceQuery != testCase.existenceQuery {
				t.Errorf("existence query is %q, want %q", e.existenceQuery, testCase.existenceQuery)
			}
			if e.emptinessQuery != testCase.emptinessQuery {
				t.Errorf("emptiness query is %q, want %q", e.emptinessQuery, testCase.emptinessQuery)
			}
		})
	}
}

// The --type and --db help and error text list the tables' names this way.
func TestOrList(t *testing.T) {
	testCases := []struct {
		values []string
		want   string
	}{
		{nil, ""},
		{[]string{"a"}, "a"},
		{[]string{"a", "b"}, "a, or b"},
		{engineNames(), "mysql, postgres, mssql, or sqlite"},
		{deploymentNames(), "local, production, kubernetes, or native"},
	}
	for _, testCase := range testCases {
		if got := orList(testCase.values); got != testCase.want {
			t.Errorf("orList(%q) = %q, want %q", testCase.values, got, testCase.want)
		}
	}
}
