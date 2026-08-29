// Command schemadump regenerates the four committed golden files, one per database engine,
// each recording what that engine's migration chain actually builds (#284).
//
//	cd src/core && go run ./cmd/schemadump
//
// It has to run inside the dev container, because nothing else resolves mysql-server,
// postgres-server or mssql-server. Run it whenever a migration lands: the data tier compares
// a freshly migrated database against the file for the engine it is running on, so a
// migration that moved without a regeneration turns CI red on that engine.
//
// All four files move together or none does. Every engine is dumped first and nothing is
// written until all four have succeeded, so one server being down leaves the committed set
// exactly as it was rather than half regenerated, which is what decision 4 asked for by
// putting all four engines in one process.
//
// Every dump comes from a scratch database this command creates and drops, never from the
// long-lived goiabada_data: a migration number a discarded attempt already recorded there is
// skipped in silence, so a golden file generated from it would record a schema nobody chose.
package main

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/leodip/goiabada/core/data/mssqldb"
	"github.com/leodip/goiabada/core/data/mysqldb"
	"github.com/leodip/goiabada/core/data/postgresdb"
	"github.com/leodip/goiabada/core/data/schemadump"
	"github.com/leodip/goiabada/core/data/sqlitedb"
	_ "github.com/microsoft/go-mssqldb"
)

// target is one engine's connection details.
//
// The defaults are the dev container's compose services, which is the fifth place those
// values are written down after run-tests.sh, check.yml and the two compose files. Reading
// them from the compose file instead would mean parsing YAML at runtime, and the repository
// is actively shedding dependencies rather than adding one for a developer tool. A wrong
// value fails at connect time, before anything is written.
type target struct {
	dialect  schemadump.Dialect
	host     string
	port     int
	username string
	password string
}

func targets() []target {
	return []target{
		{dialect: schemadump.SQLite},
		{dialect: schemadump.MySQL, host: "mysql-server", port: 13306, username: "root", password: "mySqlPass123"},
		{dialect: schemadump.Postgres, host: "postgres-server", port: 15432, username: "postgres", password: "myPostgresPass123"},
		{dialect: schemadump.MSSQL, host: "mssql-server", port: 11433, username: "sa", password: "YourStr0ngPassw0rd!"},
	}
}

// withOverrides applies GOIABADA_SCHEMADUMP_<ENGINE>_{HOST,PORT,USERNAME,PASSWORD}, so the
// command runs somewhere the compose service names do not resolve without editing it.
func (t target) withOverrides() (target, error) {
	prefix := "GOIABADA_SCHEMADUMP_" + up(string(t.dialect)) + "_"
	if v, ok := os.LookupEnv(prefix + "HOST"); ok {
		t.host = v
	}
	if v, ok := os.LookupEnv(prefix + "USERNAME"); ok {
		t.username = v
	}
	if v, ok := os.LookupEnv(prefix + "PASSWORD"); ok {
		t.password = v
	}
	if v, ok := os.LookupEnv(prefix + "PORT"); ok {
		port, err := strconv.Atoi(v)
		if err != nil {
			return t, fmt.Errorf("%sPORT is %q, which is not a port number: %w", prefix, v, err)
		}
		t.port = port
	}
	return t, nil
}

func up(s string) string {
	out := []byte(s)
	for i := range out {
		if out[i] >= 'a' && out[i] <= 'z' {
			out[i] -= 'a' - 'A'
		}
	}
	return string(out)
}

func main() {
	// The database constructors log every connection step at info. Useful when a server
	// is down and noise otherwise, so only warnings and worse reach the terminal.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "schemadump: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	dumps := map[schemadump.Dialect][]byte{}
	for _, t := range targets() {
		t, err := t.withOverrides()
		if err != nil {
			return err
		}
		fmt.Printf("dumping %s...\n", t.dialect)
		encoded, err := dumpOne(t)
		if err != nil {
			return fmt.Errorf("%s: %w", t.dialect, err)
		}
		dumps[t.dialect] = encoded
	}

	// Written only now, once every engine has answered. A run that fails part way through
	// leaves the four committed files as they were, rather than three refreshed and one
	// describing the schema from before the migration.
	for _, t := range targets() {
		path, err := schemadump.GoldenPath(t.dialect)
		if err != nil {
			return err
		}
		if err := writeAtomically(path, dumps[t.dialect]); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", path)
	}
	return nil
}

// dumpOne creates a scratch database, migrates it to head, reads its catalog and drops it.
// The drop is deferred, so a database that failed to migrate is cleaned up like any other
// rather than left behind for the next run to trip over.
func dumpOne(t target) ([]byte, error) {
	name := scratchName(t.dialect)

	db, sqlDB, cleanup, err := open(t, name)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	if err := db.Migrate(); err != nil {
		return nil, fmt.Errorf("migrate the scratch database to head: %w", err)
	}
	schema, err := schemadump.Dump(sqlDB, t.dialect)
	if err != nil {
		return nil, err
	}
	return schemadump.Encode(schema, t.dialect)
}

// migratable is what the four concrete database types have in common here. Declared over the
// two methods this command calls rather than over data.Database, whose seventy-odd methods
// none of this needs.
type migratable interface {
	Migrate() error
}

// open creates the scratch database and returns a handle to it plus the cleanup that closes
// and drops it. Each constructor creates the database it is pointed at, which is the same
// path the data tier's isolated databases take.
func open(t target, name string) (migratable, *sql.DB, func(), error) {
	switch t.dialect {
	case schemadump.SQLite:
		// A file rather than :memory:, because the SQLite driver requires WAL and an
		// in-memory database cannot provide it. The whole directory goes at cleanup.
		dir, err := os.MkdirTemp("", "goiabada-schemadump-")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("create a scratch directory: %w", err)
		}
		db, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{
			Type: "sqlite", DSN: filepath.Join(dir, "schemadump.db"),
		}, false)
		if err != nil {
			_ = os.RemoveAll(dir)
			return nil, nil, nil, err
		}
		return db, db.DB, func() { _ = db.DB.Close(); _ = os.RemoveAll(dir) }, nil

	case schemadump.MySQL:
		db, err := mysqldb.NewMySQLDatabase(&mysqldb.DatabaseConfig{
			Type: "mysql", Username: t.username, Password: t.password,
			Host: t.host, Port: t.port, Name: name,
		}, false)
		if err != nil {
			return nil, nil, nil, err
		}
		return db, db.DB, func() {
			_ = db.DB.Close()
			dropDatabase("mysql",
				fmt.Sprintf("%s:%s@tcp(%s:%d)/?charset=utf8mb4&parseTime=True&loc=UTC", t.username, t.password, t.host, t.port),
				"DROP DATABASE IF EXISTS "+name, name)
		}, nil

	case schemadump.Postgres:
		db, err := postgresdb.NewPostgresDatabase(&postgresdb.DatabaseConfig{
			Type: "postgres", Username: t.username, Password: t.password,
			Host: t.host, Port: t.port, Name: name,
		}, false)
		if err != nil {
			return nil, nil, nil, err
		}
		return db, db.DB, func() {
			_ = db.DB.Close()
			// FORCE terminates lingering connections (PostgreSQL 13+).
			dropDatabase("pgx",
				fmt.Sprintf("postgres://%s:%s@%s:%d/postgres", t.username, t.password, t.host, t.port),
				fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", name), name)
		}, nil

	case schemadump.MSSQL:
		db, err := mssqldb.NewMsSQLDatabase(&mssqldb.DatabaseConfig{
			Type: "mssql", Username: t.username, Password: t.password,
			Host: t.host, Port: t.port, Name: name,
		}, false)
		if err != nil {
			return nil, nil, nil, err
		}
		return db, db.DB, func() {
			_ = db.DB.Close()
			dropDatabase("sqlserver", msSQLMasterDSN(t),
				fmt.Sprintf("IF DB_ID(N'%s') IS NOT NULL BEGIN ALTER DATABASE [%s] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [%s]; END",
					name, name, name), name)
		}, nil
	}
	return nil, nil, nil, fmt.Errorf("unrecognised dialect %q", t.dialect)
}

// dropDatabase removes a scratch database, reporting a failure rather than returning it: it
// runs from a deferred cleanup, where the interesting error is the one that got us there. A
// leftover scratch database is harmless to the next run, which picks a new name, but it is
// worth saying so out loud.
func dropDatabase(driver, dsn, stmt, name string) {
	sqlDB, err := sql.Open(driver, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "schemadump: could not connect to drop the scratch database %s: %v\n", name, err)
		return
	}
	defer func() { _ = sqlDB.Close() }()
	if _, err := sqlDB.Exec(stmt); err != nil {
		fmt.Fprintf(os.Stderr, "schemadump: could not drop the scratch database %s: %v\n", name, err)
	}
}

// msSQLMasterDSN is the connection string for the master database, which is where a database
// is created and dropped from.
func msSQLMasterDSN(t target) string {
	q := url.Values{}
	q.Add("database", "master")
	q.Add("encrypt", "disable")
	u := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(t.username, t.password),
		Host:     fmt.Sprintf("%s:%d", t.host, t.port),
		RawQuery: q.Encode(),
	}
	return u.String()
}

// scratchName is unique to this process, so two runs against one server cannot collide and
// a leftover from a previous run is never reused. Lowercase, because PostgreSQL folds an
// unquoted identifier and the drop above spells it unquoted.
func scratchName(d schemadump.Dialect) string {
	return fmt.Sprintf("goiabada_golden_%s_%d", d, os.Getpid())
}

// writeAtomically writes through a temporary file in the destination's own directory and
// renames it into place, so an interrupted run cannot leave a truncated golden file behind.
// A truncated file is the worst thing to leave here: it is a valid smaller record, and the
// per-engine assertion would report it as a schema diff rather than as a broken file.
//
// The temporary file is in the destination directory rather than /tmp because rename is only
// atomic within one filesystem.
func writeAtomically(path string, content []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".schema.golden-*")
	if err != nil {
		return fmt.Errorf("create a temporary file beside %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // a no-op once the rename below succeeded

	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	// CreateTemp makes the file 0600, which would make the committed file's mode differ
	// from every other file in the tree.
	if err := os.Chmod(tmp, 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s into place: %w", tmp, err)
	}
	return nil
}
