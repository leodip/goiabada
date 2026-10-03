// Command schemadump regenerates the four committed golden files, one per database engine,
// each recording what that engine's migration chain actually builds (#284).
//
//	cd src/authserver && go run ./cmd/schemadump
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
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/mssqldb"
	"github.com/leodip/goiabada/authserver/internal/data/mysqldb"
	"github.com/leodip/goiabada/authserver/internal/data/postgresdb"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/core/buildinfo"
	"github.com/leodip/goiabada/core/errs"
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
	dialect  data.Dialect
	host     string
	port     int
	username string
	password string
}

func targets() []target {
	return []target{
		{dialect: data.SQLite},
		{dialect: data.MySQL, host: "mysql-server", port: 13306, username: "root", password: "mySqlPass123"},
		{dialect: data.Postgres, host: "postgres-server", port: 15432, username: "postgres", password: "myPostgresPass123"},
		{dialect: data.MSSQL, host: "mssql-server", port: 11433, username: "sa", password: "YourStr0ngPassw0rd!"},
	}
}

// withOverrides applies GOIABADA_SCHEMADUMP_<ENGINE>_{HOST,PORT,USERNAME,PASSWORD}, so the
// command runs somewhere the compose service names do not resolve without editing it.
func (t target) withOverrides() (target, error) {
	prefix := "GOIABADA_SCHEMADUMP_" + strings.ToUpper(string(t.dialect)) + "_"
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
			return t, errs.Errorf("%sPORT is %q, which is not a port number: %w", prefix, v, err)
		}
		t.port = port
	}
	return t, nil
}

// mysqlConfig, postgresConfig and mssqlConfig are the engine configs this target's scratch
// database is created through, which is also what the engine's own DSN builders take for the
// drop: one mapping, so the constructor and the cleanup connect with the same credentials (#424).
func (t target) mysqlConfig(name string) *mysqldb.DatabaseConfig {
	return &mysqldb.DatabaseConfig{
		Username: t.username, Password: t.password,
		Host: t.host, Port: t.port, Name: name, Create: true,
	}
}

func (t target) postgresConfig(name string) *postgresdb.DatabaseConfig {
	return &postgresdb.DatabaseConfig{
		Username: t.username, Password: t.password,
		Host: t.host, Port: t.port, Name: name, Create: true,
	}
}

func (t target) mssqlConfig(name string) *mssqldb.DatabaseConfig {
	return &mssqldb.DatabaseConfig{
		Username: t.username, Password: t.password,
		Host: t.host, Port: t.port, Name: name, Create: true,
	}
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
	dumps := map[data.Dialect][]byte{}
	for _, t := range targets() {
		resolved, err := t.withOverrides()
		if err != nil {
			return err
		}
		fmt.Printf("dumping %s...\n", resolved.dialect)
		encoded, err := dumpOne(resolved)
		if err != nil {
			return errs.Errorf("%s: %w", resolved.dialect, err)
		}
		dumps[resolved.dialect] = encoded
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
	// The command owns this root: it is a one-shot generator with no request above it. It
	// exists so that every driver call below takes a context rather than opening one where it
	// lands (#386).
	ctx := context.Background()

	name := scratchName(t.dialect)

	db, sqlDB, cleanup, err := open(ctx, t, name)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	m, err := db.NewMigrator(ctx)
	if err != nil {
		return nil, errs.Errorf("prepare the scratch database's migration runner: %w", err)
	}
	if _, migrateErr := m.UpToHead(ctx, buildinfo.Version); migrateErr != nil {
		return nil, errs.Errorf("migrate the scratch database to head: %w", migrateErr)
	}
	// Read off the database that was just migrated rather than counted from the files on
	// disk, so the header records what the chain actually reached. The two agree unless a
	// migration was skipped, and that disagreement is the one worth catching.
	migrated, err := schemadump.MigratedVersion(ctx, sqlDB, t.dialect)
	if err != nil {
		return nil, err
	}
	schema, err := schemadump.Dump(ctx, sqlDB, t.dialect)
	if err != nil {
		return nil, err
	}
	return schemadump.Encode(schemadump.Golden{Dialect: t.dialect, Migrated: migrated, Schema: schema})
}

// migratable is what the four concrete database types have in common here. Declared over the
// one method this command calls on them rather than over data.Database, whose two hundred-odd
// methods none of this needs.
type migratable interface {
	NewMigrator(ctx context.Context) (*migrator.Migrator, error)
}

// open creates the scratch database and returns a handle to it plus the cleanup that closes
// and drops it. Each constructor creates the database it is pointed at, which is the same
// path the data tier's isolated databases take.
func open(ctx context.Context, t target, name string) (migratable, *sql.DB, func(), error) {
	switch t.dialect {
	case data.SQLite:
		// A file rather than :memory:, because the SQLite driver requires WAL and an
		// in-memory database cannot provide it. The whole directory goes at cleanup.
		dir, err := os.MkdirTemp("", "goiabada-schemadump-")
		if err != nil {
			return nil, nil, nil, errs.Errorf("create a scratch directory: %w", err)
		}
		db, err := sqlitedb.New(ctx, filepath.Join(dir, "schemadump.db"), false)
		if err != nil {
			_ = os.RemoveAll(dir)
			return nil, nil, nil, err
		}
		return db, db.DB, func() { _ = db.DB.Close(); _ = os.RemoveAll(dir) }, nil

	case data.MySQL:
		cfg := t.mysqlConfig(name)
		db, err := mysqldb.New(ctx, cfg, false)
		if err != nil {
			return nil, nil, nil, err
		}
		return db, db.DB, func() {
			_ = db.DB.Close()
			reportDrop(name, mysqldb.DropDatabase(context.Background(), cfg))
		}, nil

	case data.Postgres:
		cfg := t.postgresConfig(name)
		db, err := postgresdb.New(ctx, cfg, false)
		if err != nil {
			return nil, nil, nil, err
		}
		return db, db.DB, func() {
			_ = db.DB.Close()
			reportDrop(name, postgresdb.DropDatabase(context.Background(), cfg))
		}, nil

	case data.MSSQL:
		cfg := t.mssqlConfig(name)
		db, err := mssqldb.New(ctx, cfg, false)
		if err != nil {
			return nil, nil, nil, err
		}
		return db, db.DB, func() {
			_ = db.DB.Close()
			reportDrop(name, mssqldb.DropDatabase(context.Background(), cfg))
		}, nil
	}
	return nil, nil, nil, errs.Errorf("unrecognised dialect %q", t.dialect)
}

// reportDrop reports a scratch database's drop failing rather than returning it: the drop runs
// from a deferred cleanup, where the interesting error is the one that got us there. A leftover
// scratch database is harmless to the next run, which picks a new name, but it is worth saying
// so out loud. The drop itself is the engine package's DropDatabase, the one spelling every tool
// that discards a database shares (#433).
//
// Each cleanup owns a root context of its own rather than taking dumpOne's, because it runs from
// a closure built before that context exists and outlives the call that made it. The rule is the
// same one the rest of this command follows: a driver call takes a context, and a command with no
// request above it declares the root (#386).
func reportDrop(name string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "schemadump: could not drop the scratch database %s: %v\n", name, err)
	}
}

// scratchName is unique to this process, so two runs against one server cannot collide and
// a leftover from a previous run is never reused. Lowercase, so the name is the same whether
// or not a statement quotes it: PostgreSQL folds an unquoted identifier.
func scratchName(d data.Dialect) string {
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
		return errs.Errorf("create a temporary file beside %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // a no-op once the rename below succeeded

	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		return errs.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return errs.Errorf("close %s: %w", tmp, err)
	}
	// CreateTemp makes the file 0600, which would make the committed file's mode differ
	// from every other file in the tree.
	if err := os.Chmod(tmp, 0o644); err != nil {
		return errs.Errorf("chmod %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return errs.Errorf("rename %s into place: %w", tmp, err)
	}
	return nil
}
