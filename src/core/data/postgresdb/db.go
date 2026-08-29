package postgresdb

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"strings"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/huandu/go-sqlbuilder"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/leodip/goiabada/core/data/commondb"
	"github.com/pkg/errors"
)

//go:embed migrations/*.sql
var postgresMigrationsFs embed.FS

type PostgresDatabase struct {
	DB       *sql.DB
	CommonDB *commondb.CommonDatabase
	dbConfig *DatabaseConfig
}

type DatabaseConfig struct {
	Type     string
	Username string
	Password string
	Host     string
	Port     int
	Name     string
	DSN      string
	// Create decides whether the constructor may create the database when it is absent. It is
	// positive-sense, so the zero value does not create: every literal has to set it (#293).
	Create bool
}

func NewPostgresDatabase(dbConfig *DatabaseConfig, logSQL bool) (*PostgresDatabase, error) {

	slog.Info("using database postgres")
	slog.Info(fmt.Sprintf("db username: %v", dbConfig.Username))
	slog.Info(fmt.Sprintf("db host: %v", dbConfig.Host))
	slog.Info(fmt.Sprintf("db port: %v", dbConfig.Port))
	slog.Info(fmt.Sprintf("db name: %v", dbConfig.Name))

	dbURL := fmt.Sprintf("postgres://%v:%v@%v:%v/%v",
		dbConfig.Username,
		dbConfig.Password,
		dbConfig.Host,
		dbConfig.Port,
		dbConfig.Name)

	// Open with database/sql for commondb compatibility
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	if dbConfig.Create {
		// Create database if not exists
		defaultDB, err := sql.Open("pgx", fmt.Sprintf("postgres://%v:%v@%v:%v/postgres",
			dbConfig.Username,
			dbConfig.Password,
			dbConfig.Host,
			dbConfig.Port))
		if err != nil {
			return nil, errors.Wrap(err, "unable to connect to default database")
		}
		defer func() { _ = defaultDB.Close() }()

		_, err = defaultDB.Exec(fmt.Sprintf("CREATE DATABASE %v;", dbConfig.Name))
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return nil, errors.Wrap(err, "unable to create database")
		}
	} else {
		// The operator says the database is already there, so nothing is created and no
		// connection is opened to the postgres maintenance database: a role owning the
		// application database and holding no CREATEDB is enough to start, which is what the
		// production checklist's "don't use root/admin accounts" asks for and what this
		// engine refused to allow before (#293).
		slog.Info("db create: disabled, the database must already exist (GOIABADA_DB_CREATE=false)")

		// sql.Open only parses the URL, so without this an absent database would come back as
		// a usable handle and a nil error, and the failure would surface inside the migrator
		// as somebody else's problem. Ping forces first use here, so the caller gets
		// PostgreSQL's own `database "x" does not exist (SQLSTATE 3D000)` from the
		// constructor. Not on the creating arm, where the CREATE DATABASE above already forces
		// the question.
		if err := db.Ping(); err != nil {
			_ = db.Close()
			return nil, errors.Wrap(err, "unable to connect to database")
		}
	}

	commonDb := commondb.NewCommonDatabase(db, sqlbuilder.PostgreSQL, logSQL)

	postgresDb := PostgresDatabase{
		DB:       db,
		CommonDB: commonDb,
		dbConfig: dbConfig,
	}
	return &postgresDb, nil
}

func (d *PostgresDatabase) BeginTransaction() (*sql.Tx, error) {
	return d.CommonDB.BeginTransaction()
}

func (d *PostgresDatabase) CommitTransaction(tx *sql.Tx) error {
	return d.CommonDB.CommitTransaction(tx)
}

func (d *PostgresDatabase) RollbackTransaction(tx *sql.Tx) error {
	return d.CommonDB.RollbackTransaction(tx)
}

// NewMigrator builds a golang-migrate instance bound to this database and the
// embedded migration files. Migrate delegates to it; tests use it to step to a
// specific version (e.g. seed at 000020, then apply 000021 in isolation).
// schemaMigrationsTableDDL pins the shape of golang-migrate's own version table, which
// Goiabada creates before handing the database over rather than leaving to the driver
// (#284 decision 7). It is the statement golang-migrate v4.19.1's PostgreSQL driver would
// issue itself, verbatim, and the driver reaches it behind an information_schema count.
//
// Issuing it first makes the driver's own statement a no-op and the shape Goiabada's, so
// this table has one shape on all four engines and a dependency bump that changed the
// driver's DDL cannot silently change what Goiabada builds. SQLite is the engine where this
// actually differs today; here it pins what is already true.
//
// Unqualified, so it lands in the connection's current schema, which is the same one
// postgres.WithInstance resolves through CURRENT_SCHEMA().
const schemaMigrationsTableDDL = "CREATE TABLE IF NOT EXISTS schema_migrations " +
	"(version bigint not null primary key, dirty boolean not null)"

// ensureSchemaMigrationsTable creates the version table at Goiabada's shape when it is not
// there yet.
func (d *PostgresDatabase) ensureSchemaMigrationsTable() error {
	if _, err := d.DB.Exec(schemaMigrationsTableDDL); err != nil {
		return errors.Wrap(err, "unable to create the schema_migrations table")
	}
	return nil
}

func (d *PostgresDatabase) NewMigrator() (*gomigrate.Migrate, error) {
	if err := d.ensureSchemaMigrationsTable(); err != nil {
		return nil, err
	}

	driver, err := postgres.WithInstance(d.DB, &postgres.Config{
		DatabaseName: d.dbConfig.Name,
	})
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration driver")
	}

	iofs, err := iofs.New(postgresMigrationsFs, "migrations")
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration filesystem")
	}

	migrator, err := gomigrate.NewWithInstance("iofs", iofs, "postgres", driver)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration instance")
	}
	return migrator, nil
}

func (d *PostgresDatabase) Migrate() error {
	migrator, err := d.NewMigrator()
	if err != nil {
		return err
	}

	err = migrator.Up()
	if err != nil && err != gomigrate.ErrNoChange {
		return errors.Wrap(err, "unable to migrate the database")
	} else if err != nil && err == gomigrate.ErrNoChange {
		slog.Info("no need to migrate the database")
	}

	return nil
}

func (d *PostgresDatabase) IsEmpty() (bool, error) {
	return d.CommonDB.IsEmpty()
}
