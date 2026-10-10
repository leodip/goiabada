// Package datafactory composes the auth server's database: it reads this process's GOIABADA_DB_*
// configuration, selects the engine, opens it, refuses a schema the stored data cannot survive,
// migrates it and runs the startup data tasks.
//
// It sits under internal/data beside the four engines it chooses between, but in a package of its
// own: selecting an engine means importing all four of them, and in the interface's own package
// every importer of the Database interface would compile every driver. internal/data declares
// the interface and imports none of its implementations; only this package and its importers link
// the drivers (#353, #359, #438).
//
// It is one of the four places that names the whole data.Database, and the one that produces
// it: OpenDatabase and NewDatabase hand it out, and Migratable embeds it. The two functions here
// that read through a database take ports like every other consumer, the email case pre-flight
// one read and the startup task the signing keys and the re-key (#386 decision 8, #438 decision 8).
package datafactory

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/mssqldb"
	"github.com/leodip/goiabada/authserver/internal/data/mysqldb"
	"github.com/leodip/goiabada/authserver/internal/data/postgresdb"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/buildinfo"
	"github.com/leodip/goiabada/core/errs"
)

// Migratable is an opened engine: the data.Database every consumer narrows, and a migrator over
// that engine's embedded migration set. All four engine types implement it, and OpenDatabase
// returns it, so reaching the migrator is a method call rather than a type assertion with a
// fallback for an engine that forgot.
//
// NewMigrator stays off data.Database deliberately. That interface is what the generated mock
// doubles and what every handler test is written against, and nothing above the data layer steps
// a schema; the two callers that do, NewDatabase and the `migrate` subcommand, take this (#268,
// #438).
type Migratable interface {
	data.Database
	NewMigrator(ctx context.Context, progress migrator.Progress) (*migrator.Migrator, error)
	// ScanEmailCaseOn is ScanEmailCase read on the migration runner's connection, which is where
	// the startup pre-flight runs, under the migration lock (#542 decision 2).
	ScanEmailCaseOn(ctx context.Context, conn *sql.Conn) ([]record.EmailCaseRow, error)
}

// OpenDatabase constructs the concrete database for the configured engine and returns it having
// migrated nothing and run no startup task. It is NewDatabase's engine switch and nothing else.
//
// It is exported for the `migrate` subcommand, which needs an engine's migrator without the schema
// being brought to head first, which is what NewDatabase does and what makes NewDatabase useless
// for a rollback. Every other caller wants NewDatabase (#268).
//
// ctx is the caller's and reaches every statement the engine's constructor issues, so a start
// waiting on an unreachable server or a held creation lock ends when the caller stops waiting
// (#438 decision 3).
func OpenDatabase(ctx context.Context, dbConfig *config.DatabaseConfig, logSQL bool) (Migratable, error) {
	// The parse comes before the record, so a refused type writes only its refusal and never an
	// opening record naming an engine nothing opened (#438 decision 6).
	dialect, err := data.ParseDialect(dbConfig.Type)
	if err != nil {
		return nil, err
	}

	// One record for the whole choice. This used to write "db type is x" here and "creating x
	// database" in the arm, and each engine's constructor then wrote "using database x" a line
	// later: three records saying the same thing, none of them structured (#320).
	slog.InfoContext(ctx, "opening the database", "type", string(dialect))

	// Each arm takes the constructor's two results into a local pair and returns nil on the error
	// path rather than returning the call directly: all four constructors answer a typed nil
	// pointer beside their error, and returning that straight out would put a non-nil
	// Migratable over it, so an `if database == nil` at a caller would read false (#353).
	switch dialect {
	case data.MySQL:
		engineConfig := mysqlConfig(dbConfig)
		database, err := mysqldb.New(ctx, engineConfig, logSQL)
		if err != nil {
			return nil, err
		}
		recordPool(ctx, *engineConfig.Pool)
		return database, nil
	case data.SQLite:
		// The DSN is all SQLite reads. GOIABADA_DB_CREATE has nowhere to go here: SQLite has no
		// create statement and no maintenance connection to issue one over, so `mode=rw` in the
		// operator's DSN is the equivalent (#293, #438 decision 4). A chosen leniency rather than
		// an oversight, so TestOpenDatabase_Dispatch has a row for it.
		//
		// The four pool settings have nowhere to go either: SQLite's pool is one connection, and
		// the record says so rather than repeating what was configured (#394).
		database, err := sqlitedb.New(ctx, dbConfig.DSN, logSQL)
		if err != nil {
			return nil, err
		}
		recordPool(ctx, sqlitedb.Pool())
		return database, nil
	case data.Postgres:
		engineConfig := postgresConfig(dbConfig)
		database, err := postgresdb.New(ctx, engineConfig, logSQL)
		if err != nil {
			return nil, err
		}
		recordPool(ctx, *engineConfig.Pool)
		return database, nil
	case data.MSSQL:
		engineConfig := mssqlConfig(dbConfig)
		database, err := mssqldb.New(ctx, engineConfig, logSQL)
		if err != nil {
			return nil, err
		}
		recordPool(ctx, *engineConfig.Pool)
		return database, nil
	default:
		// Unreachable: ParseDialect answers one of the four or refuses. It names the dialect rather
		// than falling through, so a fifth constant added there without an arm here fails loudly.
		return nil, errs.Errorf("no engine for database dialect %q", dialect)
	}
}

// recordPool writes the one record of the pool a start opened, once the engine has opened it. It is
// the one place all four values are visible, since database/sql reads back only the open cap, so
// an operator sizing max_connections reads it off here, SQLite's fixed values included (#394).
func recordPool(ctx context.Context, pool data.PoolConfig) {
	slog.InfoContext(ctx, "database connection pool",
		"max_open_conns", pool.MaxOpenConns,
		"max_idle_conns", pool.MaxIdleConns,
		"conn_max_lifetime", pool.ConnMaxLifetime,
		"conn_max_idle_time", pool.ConnMaxIdleTime)
}

// mysqlConfig is the switch arm's struct literal and nothing else, extracted so that field
// placement is a pure function a table can check. Six fields copied by hand is six chances to
// write one of them into the wrong place, and neither the engine's error nor the dispatch record
// can see the difference: a swapped Host and Name still answers `dial tcp`, and Password appears
// in no error at all (#353). Only what the engine reads is copied: the type has been dispatched
// on by now, and the DSN is SQLite's (#438 decision 3).
func mysqlConfig(c *config.DatabaseConfig) *mysqldb.DatabaseConfig {
	return &mysqldb.DatabaseConfig{
		Username: c.Username,
		Password: c.Password,
		Host:     c.Host,
		Port:     c.Port,
		Name:     c.Name,
		Create:   c.Create,
		Pool:     serverPool(c),
	}
}

// serverPool is the pool the three server engines open with, as configured: the idle cap the one
// set or, unset, the open cap (#394 decision 6). Each mapper takes its own copy.
func serverPool(c *config.DatabaseConfig) *data.PoolConfig {
	return &data.PoolConfig{
		MaxOpenConns:    c.MaxOpenConns,
		MaxIdleConns:    c.EffectiveMaxIdleConns(),
		ConnMaxLifetime: c.ConnMaxLifetime,
		ConnMaxIdleTime: c.ConnMaxIdleTime,
	}
}

// postgresConfig is mysqlConfig's counterpart for PostgreSQL; the comment there covers why the
// mapping is extracted.
func postgresConfig(c *config.DatabaseConfig) *postgresdb.DatabaseConfig {
	return &postgresdb.DatabaseConfig{
		Username: c.Username,
		Password: c.Password,
		Host:     c.Host,
		Port:     c.Port,
		Name:     c.Name,
		Create:   c.Create,
		Pool:     serverPool(c),
	}
}

// mssqlConfig is mysqlConfig's counterpart for SQL Server; the comment there covers why the
// mapping is extracted.
func mssqlConfig(c *config.DatabaseConfig) *mssqldb.DatabaseConfig {
	return &mssqldb.DatabaseConfig{
		Username: c.Username,
		Password: c.Password,
		Host:     c.Host,
		Port:     c.Port,
		Name:     c.Name,
		Create:   c.Create,
		Pool:     serverPool(c),
	}
}

// NewDatabase opens the configured database, refuses it if the stored email addresses cannot
// survive migration 000047, brings the schema to head and then runs the startup data tasks.
//
// The migrator runs the pre-flight under its lock, on the version it read there, and then steps to
// head, and the startup
// records are written here, by the process starting, rather than by the runner or by each engine:
// the runner, and SQL Server's schema_migrations pre-create before it, report a wait for the
// migration lock, and the runner the migration around its files, through startupProgress, and the
// record saying nothing needed migrating is this function's own (#438, #390 decision 7).
//
// ctx is the start's, and its end is a shutdown signal (#390 decision 9): it cancels a wait, for
// the engine, its creation or the migration lock, at once; a migration file already running runs
// to its end and no further one starts, and the start says where the schema stopped; the
// data-key rotation finishes if it is under way and does not start otherwise. What NewDatabase
// answers after a stop then matches context.Canceled, which is how main tells it from a failure.
//
// The two data-encryption keys are parameters rather than reads of a configuration singleton, so
// that the refusal below is one call away from a test rather than unreachable (#351). aesKey is
// required and must be 32 bytes; previousAESKey is optional and is acted on only at that length,
// by the env-to-env rotation inside runStartupDataTasks.
func NewDatabase(ctx context.Context, dbConfig *config.DatabaseConfig, aesKey []byte, previousAESKey []byte, logSQL bool) (data.Database, error) {
	database, err := OpenDatabase(ctx, dbConfig, logSQL)
	if err != nil {
		return nil, err
	}
	// A start that fails or is stopped past this point closes what it opened, so a SQLite
	// migration a signal stopped part of the way leaves its WAL checkpointed, as a stopped server
	// does. The caller owns the database only once it is returned.
	opened := false
	defer func() {
		if !opened {
			_ = database.Close()
		}
	}()

	// One progress for the whole start: SQL Server's schema_migrations pre-create can wait for the
	// migration lock before the runner does, and the start says it is waiting once.
	progress := &startupProgress{ctx: ctx}

	m, err := database.NewMigrator(ctx, progress)
	if err != nil {
		return nil, errs.Wrap(err, "unable to prepare the migration runner")
	}

	// The email case pre-flight runs inside the migration, under its lock: see emailCasePreflight.
	migrated, err := m.UpToHead(ctx, buildinfo.Version, progress, emailCasePreflight(database))
	if err != nil {
		var stopped migrator.StoppedError
		if errors.As(err, &stopped) {
			slog.InfoContext(ctx, "database migration stopped",
				"from_version", recordedVersion(stopped.From),
				"reached_version", recordedVersion(stopped.Reached),
				"applied", stopped.Applied,
				"remaining", stopped.Remaining)
		}
		return nil, err
	}
	if !migrated {
		slog.InfoContext(ctx, "no need to migrate the database")
	}

	// The data-encryption key is supplied from the environment (issue #83), never
	// co-located with the ciphertext. It is validated fatally in each app's main
	// before this point; guard here too so any entry path (including tests) fails
	// closed rather than encrypting with a bad key.
	if len(aesKey) != 32 {
		return nil, errs.New("GOIABADA_AES_ENCRYPTION_KEY must be set to a 32-byte hex key")
	}

	if err := runStartupDataTasks(ctx, database, aesKey, previousAESKey); err != nil {
		return nil, err
	}

	opened = true
	return database, nil
}

// startupProgress writes the startup records the migration runner reports, so a start waiting
// for the migration lock or running a long migration says so rather than looking hung (#390
// decision 7). A queued start that finds another process has already migrated writes the wait
// record and then "no need to migrate the database".
//
// The wait record is written once per start, however many times the start queues: SQL Server's
// schema_migrations pre-create takes the migration lock before the runner does, and a start can
// find it held at both.
type startupProgress struct {
	ctx    context.Context
	waited bool
}

func (p *startupProgress) WaitingForLock() {
	if p.waited {
		return
	}
	p.waited = true
	slog.InfoContext(p.ctx, "waiting for the migration lock")
}

func (p *startupProgress) Migrating(from, to, pending int) {
	slog.InfoContext(p.ctx, "migrating the database",
		"from_version", recordedVersion(from), "to_version", to, "pending", pending)
}

func (p *startupProgress) Migrated(from, to, applied int, took time.Duration) {
	slog.InfoContext(p.ctx, "database migrated",
		"from_version", recordedVersion(from), "to_version", to, "applied", applied, "duration", took)
}

// recordedVersion is a schema version as the startup records carry it: a database never migrated
// is 0, since no Goiabada migration is numbered 0, rather than the runner's NilVersion, which is
// its own marker and nothing an operator should have to recognise.
func recordedVersion(v int) int {
	if v == migrator.NilVersion {
		return 0
	}
	return v
}
