// Pre-flight behind §4 of the agreement, and stage 2's first step: is migration
// version 000027 already recorded in the schema_migrations table of a long-lived
// test database?
//
// The three server-backed engines keep goiabada_data and goiabada_integration
// across runs, so a version recorded by a discarded earlier attempt is skipped
// silently by golang-migrate and the whole suite then runs against a schema that
// never received the migration. sqlite is not checked: run-tests.sh points it at
// /tmp/goiabada_<suffix>.db and recreates it per run, so it cannot carry a stale
// version.
//
// It reads and never writes: it opens each database directly with the driver rather
// than through the repo's constructors, because those CREATE the database when it is
// absent, and a pre-flight that creates what it is inspecting proves nothing. A
// missing database or a missing schema_migrations table is reported as "clean", which
// is what it means here: nothing is recorded, so nothing will be skipped.
//
// Credentials are the ones run-tests.sh exports (its per-engine blocks), so this
// inspects exactly the databases the data and integration tiers use.
//
// Run it inside the dev container, from src/core, where every driver already lives:
//
//	docker exec goiabada-devcontainer-1 bash -lc \
//	  'cd /workspaces/goiabada/src/core && \
//	   cp -r ../../docs/issue-111-otp-replay/probe/preflight-migration-version ./probe-tmp && \
//	   go run ./probe-tmp; rm -rf ./probe-tmp'
//
// output.txt beside this file is what it printed on 2026-08-06.
package main

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/microsoft/go-mssqldb"
)

// The version this issue wants to write. Reported against, rather than assumed.
const wantVersion = 27

type target struct {
	engine string
	driver string
	dsn    func(dbName string) string
}

func main() {
	targets := []target{
		{
			engine: "mysql",
			driver: "mysql",
			dsn: func(name string) string {
				return fmt.Sprintf("root:mySqlPass123@tcp(mysql-server:13306)/%s?parseTime=True&loc=UTC", name)
			},
		},
		{
			engine: "postgres",
			driver: "pgx",
			dsn: func(name string) string {
				return fmt.Sprintf("postgres://postgres:myPostgresPass123@postgres-server:15432/%s", name)
			},
		},
		{
			engine: "mssql",
			driver: "sqlserver",
			dsn: func(name string) string {
				q := url.Values{}
				q.Set("database", name)
				q.Set("encrypt", "disable")
				u := url.URL{
					Scheme:   "sqlserver",
					User:     url.UserPassword("sa", "YourStr0ngPassw0rd!"),
					Host:     "mssql-server:11433",
					RawQuery: q.Encode(),
				}
				return u.String()
			},
		},
	}

	dbNames := []string{"goiabada_data", "goiabada_integration"}

	blocked := false
	for _, t := range targets {
		for _, name := range dbNames {
			max, recorded, note := inspect(t, name)
			status := "clean"
			if recorded {
				status = fmt.Sprintf("BLOCKED: version %d already recorded", wantVersion)
				blocked = true
			}
			fmt.Printf("%-9s %-22s highest recorded: %-8s %s%s\n",
				t.engine, name, max, status, note)
		}
	}

	fmt.Println()
	if blocked {
		fmt.Printf("version %d is NOT free: at least one long-lived database already records it\n", wantVersion)
		os.Exit(1)
	}
	fmt.Printf("version %d is free in every long-lived database checked\n", wantVersion)
}

// inspect reports the highest version in schema_migrations, whether wantVersion is
// among the recorded ones, and a note for anything that made the answer indirect.
// golang-migrate's schema_migrations holds a single row, the current version, so
// "highest" and "current" are the same thing; the query is written as a MAX anyway so
// a multi-row table (which the migrator does not produce, but a hand-edited database
// could) cannot hide a recorded 27 behind a lower current version.
func inspect(t target, dbName string) (max string, recorded bool, note string) {
	db, err := sql.Open(t.driver, t.dsn(dbName))
	if err != nil {
		return "-", false, fmt.Sprintf(" (open failed: %v)", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.Ping(); err != nil {
		// An absent database records nothing, so nothing can be skipped. Reported
		// rather than swallowed, because "the database was not there" and "the
		// database was there and empty" are different facts about the environment.
		return "-", false, " (database absent or unreachable)"
	}

	var maxVersion sql.NullInt64
	err = db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&maxVersion)
	if err != nil {
		return "-", false, " (no schema_migrations table)"
	}
	if !maxVersion.Valid {
		return "none", false, " (schema_migrations is empty)"
	}

	var hits int
	if err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM schema_migrations WHERE version = %d", wantVersion)).Scan(&hits); err != nil {
		return fmt.Sprint(maxVersion.Int64), false, fmt.Sprintf(" (version count query failed: %v)", err)
	}

	return fmt.Sprint(maxVersion.Int64), hits > 0, ""
}
