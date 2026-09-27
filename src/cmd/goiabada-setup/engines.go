package main

import (
	"fmt"
	"slices"
	"strings"
)

// engine is one database the wizard can configure. Every fact that differs between engines is a
// field here, code included, so the prompts, the generators and the connection check read a row
// and never name an engine: adding one is adding a row (#430).
type engine struct {
	// number is the engine's place in the database menu and its numeric --db value, one field so
	// the two cannot disagree.
	number string
	// name is the --db flag's canonical value and what GOIABADA_DB_TYPE carries.
	name    string
	aliases []string
	label   string

	// hasServer is false for an engine that is a file in the auth server's own volume, which
	// asks for no host, credentials or connection check.
	hasServer bool
	// kubernetes says whether the Kubernetes manifests may use it: a pod's filesystem is not
	// where an auth server's only copy of its data can live.
	kubernetes bool

	image       string
	defaultPort string
	defaultUser string
	// kubernetesHost is the database host the Kubernetes prompt offers.
	kubernetesHost string

	composeService string
	// volume holds the data, mounted at mount: in the database's service, or in the auth
	// server's for an engine with no server.
	volume string
	mount  string
	// composeEnvironment is the database service's environment lines, in order, each value
	// written through composeQuote.
	composeEnvironment func(password string) []string
	// healthcheck is the shell command the database service's CMD-SHELL healthcheck runs. It
	// carries no password: one that needs it reads the variable composeEnvironment sets, from the
	// container's own environment, so the secret is neither written twice nor shell-quoted inside
	// YAML, where a `"`, `\` or `'` in it broke the file or the shell (#430). The generator writes
	// it through composeQuote, which turns its `${NAME}` into the `$${NAME}` Compose hands over.
	healthcheck    string
	healthInterval string
	healthTimeout  string

	// checkDriver and checkDSN are how the wizard reaches the database to test the operator's
	// details, and emptinessQuery counts the Goiabada tables already there.
	checkDriver    string
	checkDSN       func(host, port, name, user, password string) string
	emptinessQuery string
}

// engines is the database menu, in its order. SQLite is last, so the three engines Kubernetes
// accepts keep their numbers when it is left out.
var engines = []*engine{
	{
		number:         "1",
		name:           "mysql",
		label:          "MySQL",
		hasServer:      true,
		kubernetes:     true,
		image:          "mysql:latest",
		defaultPort:    "3306",
		defaultUser:    "root",
		kubernetesHost: "mysql-service",
		composeService: "mysql-server",
		volume:         "mysql-data",
		mount:          "/var/lib/mysql",
		composeEnvironment: func(password string) []string {
			return []string{"MYSQL_ROOT_PASSWORD: " + composeQuote(password)}
		},
		healthcheck:    `mysqladmin ping -uroot -p"${MYSQL_ROOT_PASSWORD}" --protocol tcp`,
		healthInterval: "1s",
		healthTimeout:  "2s",
		checkDriver:    "mysql",
		checkDSN: func(host, port, name, user, password string) string {
			return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?timeout=5s", user, password, host, port, name)
		},
		emptinessQuery: "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'users'",
	},
	{
		number:         "2",
		name:           "postgres",
		aliases:        []string{"postgresql"},
		label:          "PostgreSQL",
		hasServer:      true,
		kubernetes:     true,
		image:          "postgres:latest",
		defaultPort:    "5432",
		defaultUser:    "postgres",
		kubernetesHost: "postgres-service",
		composeService: "postgres-server",
		volume:         "postgres-data",
		mount:          "/var/lib/postgresql",
		composeEnvironment: func(password string) []string {
			return []string{"POSTGRES_PASSWORD: " + composeQuote(password), "POSTGRES_DB: goiabada"}
		},
		healthcheck:    "pg_isready -U postgres",
		healthInterval: "1s",
		healthTimeout:  "2s",
		checkDriver:    "postgres",
		checkDSN: func(host, port, name, user, password string) string {
			return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=require connect_timeout=5", host, port, user, password, name)
		},
		emptinessQuery: "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users'",
	},
	{
		number:         "3",
		name:           "mssql",
		aliases:        []string{"sqlserver"},
		label:          "SQL Server",
		hasServer:      true,
		kubernetes:     true,
		image:          "mcr.microsoft.com/mssql/server:2022-latest",
		defaultPort:    "1433",
		defaultUser:    "sa",
		kubernetesHost: "mssql-service",
		composeService: "mssql-server",
		volume:         "mssql-data",
		mount:          "/var/opt/mssql",
		composeEnvironment: func(password string) []string {
			return []string{"ACCEPT_EULA: Y", "MSSQL_SA_PASSWORD: " + composeQuote(password)}
		},
		healthcheck:    `/opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "${MSSQL_SA_PASSWORD}" -C -Q 'SELECT 1' || exit 1`,
		healthInterval: "10s",
		healthTimeout:  "5s",
		checkDriver:    "sqlserver",
		checkDSN: func(host, port, name, user, password string) string {
			return fmt.Sprintf("sqlserver://%s:%s@%s:%s?database=%s&connection+timeout=5", user, password, host, port, name)
		},
		emptinessQuery: "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'users'",
	},
	{
		number: "4",
		name:   "sqlite",
		label:  "SQLite",
		volume: "sqlite-data",
		mount:  "/data",
	},
}

// resolveEngine reads a --db value or a menu answer: an engine's name, one of its aliases or its
// number, in any case.
func resolveEngine(value string) (*engine, bool) {
	value = strings.ToLower(value)
	for _, e := range engines {
		if value == e.number || value == e.name || slices.Contains(e.aliases, value) {
			return e, true
		}
	}
	return nil, false
}

func engineNames() []string {
	names := make([]string, 0, len(engines))
	for _, e := range engines {
		names = append(names, e.name)
	}
	return names
}

// orList joins values the way the usage text lists them: "a, b, or c".
func orList(values []string) string {
	if len(values) < 2 {
		return strings.Join(values, "")
	}
	return strings.Join(values[:len(values)-1], ", ") + ", or " + values[len(values)-1]
}
