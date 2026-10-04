package main

import (
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

	image string
	// imageComment is the comment written above the database service's image, saying why its tag
	// names a major and what upgrading past it takes; empty where the tag already names its line.
	imageComment []string
	defaultPort  string
	defaultUser  string
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

	// driver, dsn and maintenanceDSN are how the auth server reaches the database, copied in
	// dbcheck.go, and so how the connection check does. existenceQuery counts the databases named
	// its one parameter, over the maintenance connection; emptinessQuery counts the Goiabada
	// tables already in the application database.
	driver         string
	dsn            func(t dbTarget) string
	maintenanceDSN func(t dbTarget) string
	existenceQuery string
	emptinessQuery string
}

// engines is the database menu, in its order. SQLite is last, so the three engines Kubernetes
// accepts keep their numbers when it is left out.
var engines = []*engine{
	{
		number:     "1",
		name:       "mysql",
		label:      "MySQL",
		hasServer:  true,
		kubernetes: true,
		image:      "mysql:26",
		imageComment: []string{
			"A major, the one latest named when this file's generator was released. A major upgrade",
			"is a dump and restore, not a tag edit: MySQL upgrades a data directory in place only",
			"along its documented paths, and does not start on one it cannot.",
		},
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
		driver:         "mysql",
		dsn:            mysqlDSN,
		maintenanceDSN: mysqlMaintenanceDSN,
		existenceQuery: "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?",
		emptinessQuery: "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'users'",
	},
	{
		number:     "2",
		name:       "postgres",
		aliases:    []string{"postgresql"},
		label:      "PostgreSQL",
		hasServer:  true,
		kubernetes: true,
		image:      "postgres:18",
		imageComment: []string{
			"A major, the one latest named when this file's generator was released. A major upgrade",
			"is a dump and restore or pg_upgrade, not a tag edit: PostgreSQL does not start on a",
			"data directory another major wrote.",
		},
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
		driver:         "pgx",
		dsn:            postgresDSN,
		maintenanceDSN: postgresMaintenanceDSN,
		existenceQuery: "SELECT COUNT(*) FROM pg_database WHERE datname = $1",
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
		driver:         "sqlserver",
		dsn:            mssqlDSN,
		maintenanceDSN: mssqlMaintenanceDSN,
		existenceQuery: "SELECT COUNT(*) FROM sys.databases WHERE name = @p1",
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
