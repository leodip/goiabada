// Package datafactory composes the auth server's database: it reads this process's GOIABADA_DB_*
// configuration, selects the engine, opens it, refuses a schema the stored data cannot survive,
// migrates it and runs the startup data tasks.
//
// It is its own package and not the data package's because selecting an engine means importing
// all four of them, which made every importer of the Database interface compile every driver back
// when that interface was core/data's. internal/data declares the interface and nothing that
// chooses between implementations of it (#353, #359).
//
// It is one of the four places that still names the whole data.Database, and the one that produces
// it. Everything here opens, migrates or pre-flights a database rather than reading rows through
// one, so there is no narrower capability to declare; the ports are at the consumers this hands
// the result to (#386 decision 8).
package datafactory

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/mssqldb"
	"github.com/leodip/goiabada/authserver/internal/data/mysqldb"
	"github.com/leodip/goiabada/authserver/internal/data/postgresdb"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/core/errs"
)

// MigratorProvider is the one thing a caller needs beyond data.Database to step a schema by hand:
// a migrator built over this engine's embedded migration set. All four concrete engine types have
// the method already, and it stays off the data.Database interface deliberately, so the generated
// mock and every application path keep seeing a database that migrates itself on open.
//
// The authserver's `migrate` subcommand is the only user: it opens through OpenDatabase and
// type-asserts to this, because it must be able to step DOWN, and anything that went through
// NewDatabase would have migrated up before it got the chance (#268).
type MigratorProvider interface {
	NewMigrator(ctx context.Context) (*migrator.Migrator, error)
}

// OpenDatabase constructs the concrete database for the configured engine and returns it having
// migrated nothing and run no startup task. It is NewDatabase's engine switch and nothing else.
//
// It exists so that the `migrate` subcommand can reach an engine's migrator without the schema
// being brought to head first, which is what NewDatabase does and what makes NewDatabase useless
// for a rollback. Every other caller wants NewDatabase (#268).
func OpenDatabase(dbConfig *config.DatabaseConfig, logSQL bool) (data.Database, error) {
	// Remove leading and trailing single or double quotes from dbType
	dbType := strings.Trim(dbConfig.Type, "\"'")

	// One record for the whole choice. This used to write "db type is x" here and "creating x
	// database" in the arm, and each engine's constructor then wrote "using database x" a line
	// later: three records saying the same thing, none of them structured (#320).
	slog.Info("opening the database", "type", dbType)

	// Each arm takes the constructor's two results into a local pair and returns nil on the error
	// path rather than returning the call directly: all four constructors answer a typed nil
	// pointer beside their error, and returning that straight out would put a non-nil
	// data.Database over it, so an `if database == nil` at a caller would read false (#353).
	switch dbType {
	case "mysql":
		database, err := mysqldb.NewMySQLDatabase(mysqlConfig(dbConfig), logSQL)
		if err != nil {
			return nil, err
		}
		return database, nil
	case "sqlite":
		database, err := sqlitedb.NewSQLiteDatabase(sqliteConfig(dbConfig), logSQL)
		if err != nil {
			return nil, err
		}
		return database, nil
	case "postgres":
		database, err := postgresdb.NewPostgresDatabase(postgresConfig(dbConfig), logSQL)
		if err != nil {
			return nil, err
		}
		return database, nil
	case "mssql":
		database, err := mssqldb.NewMsSQLDatabase(mssqlConfig(dbConfig), logSQL)
		if err != nil {
			return nil, err
		}
		return database, nil
	default:
		msg := fmt.Sprintf("unsupported database type: %s (string length %d). supported types are: mysql, sqlite, postgres, mssql", dbType, len(dbType))
		return nil, errs.New(msg)
	}
}

// mysqlConfig is the switch arm's struct literal and nothing else, extracted so that field
// placement is a pure function a table can check. Eight fields copied by hand is eight chances to
// write one of them into the wrong place, and neither the engine's error nor the dispatch record
// can see the difference: a swapped Host and Name still answers `dial tcp`, and Password appears
// in no error at all (#353).
func mysqlConfig(c *config.DatabaseConfig) *mysqldb.DatabaseConfig {
	return &mysqldb.DatabaseConfig{
		Type:     c.Type,
		Username: c.Username,
		Password: c.Password,
		Host:     c.Host,
		Port:     c.Port,
		Name:     c.Name,
		DSN:      c.DSN,
		Create:   c.Create,
	}
}

// sqliteConfig copies seven fields and deliberately not Create, which sqlitedb.DatabaseConfig does
// not declare: SQLite has no create statement and no maintenance connection to issue one over, so
// `mode=rw` in the operator's DSN is the equivalent and GOIABADA_DB_CREATE does not apply (#293).
// It is a chosen leniency rather than an oversight, so it has its own test case.
func sqliteConfig(c *config.DatabaseConfig) *sqlitedb.DatabaseConfig {
	return &sqlitedb.DatabaseConfig{
		Type:     c.Type,
		Username: c.Username,
		Password: c.Password,
		Host:     c.Host,
		Port:     c.Port,
		Name:     c.Name,
		DSN:      c.DSN,
	}
}

// postgresConfig is mysqlConfig's counterpart for PostgreSQL; the comment there covers why the
// mapping is extracted.
func postgresConfig(c *config.DatabaseConfig) *postgresdb.DatabaseConfig {
	return &postgresdb.DatabaseConfig{
		Type:     c.Type,
		Username: c.Username,
		Password: c.Password,
		Host:     c.Host,
		Port:     c.Port,
		Name:     c.Name,
		DSN:      c.DSN,
		Create:   c.Create,
	}
}

// mssqlConfig is mysqlConfig's counterpart for SQL Server; the comment there covers why the
// mapping is extracted.
func mssqlConfig(c *config.DatabaseConfig) *mssqldb.DatabaseConfig {
	return &mssqldb.DatabaseConfig{
		Type:     c.Type,
		Username: c.Username,
		Password: c.Password,
		Host:     c.Host,
		Port:     c.Port,
		Name:     c.Name,
		DSN:      c.DSN,
		Create:   c.Create,
	}
}

// NewDatabase opens the configured database, refuses it if the stored email addresses cannot
// survive migration 000047, brings the schema to head and then runs the startup data tasks.
//
// The two data-encryption keys are parameters rather than reads of a configuration singleton, so
// that the refusal below is one call away from a test rather than unreachable (#351). aesKey is
// required and must be 32 bytes; previousAESKey is optional and is acted on only at that length,
// by the env-to-env rotation inside runStartupDataTasks.
func NewDatabase(ctx context.Context, dbConfig *config.DatabaseConfig, aesKey []byte, previousAESKey []byte, logSQL bool) (data.Database, error) {
	database, err := OpenDatabase(dbConfig, logSQL)
	if err != nil {
		return nil, err
	}

	if preflightEmailCaseErr := preflightEmailCase(ctx, database); preflightEmailCaseErr != nil {
		return nil, preflightEmailCaseErr
	}

	err = database.Migrate(ctx)
	if err != nil {
		return nil, err
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
