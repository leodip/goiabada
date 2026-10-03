// Package datafactory composes the auth server's database: it reads this process's GOIABADA_DB_*
// configuration, selects the engine, opens it, refuses a schema the stored data cannot survive,
// migrates it and runs the startup data tasks.
//
// It sits under internal/data beside the four engines it chooses between, but in a package of its
// own: selecting an engine means importing all four of them, and when that was the interface's own
// package every importer of the Database interface compiled every driver. internal/data declares
// the interface and imports none of its implementations; only this package and its importers link
// the drivers (#353, #359, #438).
//
// It is one of the four places that still names the whole data.Database, and the one that produces
// it: OpenDatabase and NewDatabase hand it out, and Migratable embeds it. The two functions here
// that read through a database take ports like every other consumer, the email case pre-flight
// one read and the startup task the signing keys and the re-key (#386 decision 8, #438 decision 8).
package datafactory

import (
	"context"
	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/mssqldb"
	"github.com/leodip/goiabada/authserver/internal/data/mysqldb"
	"github.com/leodip/goiabada/authserver/internal/data/postgresdb"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
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
	NewMigrator(ctx context.Context) (*migrator.Migrator, error)
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
		database, err := mysqldb.New(ctx, mysqlConfig(dbConfig), logSQL)
		if err != nil {
			return nil, err
		}
		return database, nil
	case data.SQLite:
		// The DSN is all SQLite reads. GOIABADA_DB_CREATE has nowhere to go here: SQLite has no
		// create statement and no maintenance connection to issue one over, so `mode=rw` in the
		// operator's DSN is the equivalent (#293, #438 decision 4). A chosen leniency rather than
		// an oversight, so TestOpenDatabase_Dispatch has a row for it.
		database, err := sqlitedb.New(ctx, dbConfig.DSN, logSQL)
		if err != nil {
			return nil, err
		}
		return database, nil
	case data.Postgres:
		database, err := postgresdb.New(ctx, postgresConfig(dbConfig), logSQL)
		if err != nil {
			return nil, err
		}
		return database, nil
	case data.MSSQL:
		database, err := mssqldb.New(ctx, mssqlConfig(dbConfig), logSQL)
		if err != nil {
			return nil, err
		}
		return database, nil
	default:
		// Unreachable: ParseDialect answers one of the four or refuses. It names the dialect rather
		// than falling through, so a fifth constant added there without an arm here fails loudly.
		return nil, errs.Errorf("no engine for database dialect %q", dialect)
	}
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
	}
}

// NewDatabase opens the configured database, refuses it if the stored email addresses cannot
// survive migration 000047, brings the schema to head and then runs the startup data tasks.
//
// One migrator serves both the pre-flight's version read and the step to head, and the startup
// record saying nothing needed migrating is written here, by the process starting, rather than by
// the runner or by each engine (#438).
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

	m, err := database.NewMigrator(ctx)
	if err != nil {
		return nil, errs.Wrap(err, "unable to prepare the migration runner")
	}

	if preflightEmailCaseErr := preflightEmailCase(ctx, database, m); preflightEmailCaseErr != nil {
		return nil, preflightEmailCaseErr
	}

	migrated, err := m.UpToHead(ctx, buildinfo.Version)
	if err != nil {
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

	return database, nil
}
