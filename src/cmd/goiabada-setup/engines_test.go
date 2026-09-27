package main

import (
	"strconv"
	"strings"
	"testing"
)

// A server engine's row is read field by field by the prompts, the Compose generator and the
// connection check, so an empty field is a blank in a generated file or a nil call at run time.
// An engine with no server must carry none of them: each is read only behind hasServer, and a
// value set there would read as a fact the wizard acts on.
func TestEngines_EveryRowIsComplete(t *testing.T) {
	const password = "row-password"
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
				"healthInterval": e.healthInterval, "healthTimeout": e.healthTimeout,
				"checkDriver": e.checkDriver, "emptinessQuery": e.emptinessQuery,
			}
			serverFuncs := map[string]bool{
				"composeEnvironment": e.composeEnvironment != nil,
				"composeHealthcheck": e.composeHealthcheck != nil,
				"checkDSN":           e.checkDSN != nil,
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
			// The database container is where the password is set: a row whose environment
			// drops it starts a database nobody can log in to.
			if !strings.Contains(strings.Join(e.composeEnvironment(password), "\n"), password) {
				t.Errorf("the database service's environment does not carry the password")
			}
		})
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

// Today's connection check, byte for byte, so the move of its per-engine switch into the rows is
// checked; the auth server's own connection strings replace these (#430).
func TestEngines_ConnectionCheckIsTodays(t *testing.T) {
	testCases := []struct {
		engine, driver, dsn, emptinessQuery string
	}{
		{
			engine:         "mysql",
			driver:         "mysql",
			dsn:            "db-user:db-pass@tcp(db.example:3307)/db-name?timeout=5s",
			emptinessQuery: "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'users'",
		},
		{
			engine:         "postgres",
			driver:         "postgres",
			dsn:            "host=db.example port=3307 user=db-user password=db-pass dbname=db-name sslmode=require connect_timeout=5",
			emptinessQuery: "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users'",
		},
		{
			engine:         "mssql",
			driver:         "sqlserver",
			dsn:            "sqlserver://db-user:db-pass@db.example:3307?database=db-name&connection+timeout=5",
			emptinessQuery: "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'users'",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.engine, func(t *testing.T) {
			e := testEngine(testCase.engine)
			if e.checkDriver != testCase.driver {
				t.Errorf("driver is %q, want %q", e.checkDriver, testCase.driver)
			}
			if got := e.checkDSN("db.example", "3307", "db-name", "db-user", "db-pass"); got != testCase.dsn {
				t.Errorf("connection string is\n  %s\nwant\n  %s", got, testCase.dsn)
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
