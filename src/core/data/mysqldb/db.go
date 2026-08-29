package mysqldb

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"

	_ "github.com/go-sql-driver/mysql"
	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/data/commondb"
	"github.com/pkg/errors"
)

//go:embed migrations/*.sql
var mysqlMigrationsFs embed.FS

type MySQLDatabase struct {
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

func NewMySQLDatabase(dbConfig *DatabaseConfig, logSQL bool) (*MySQLDatabase, error) {

	slog.Info("using database mysql")
	slog.Info(fmt.Sprintf("db username: %v", dbConfig.Username))
	slog.Info(fmt.Sprintf("db host: %v", dbConfig.Host))
	slog.Info(fmt.Sprintf("db port: %v", dbConfig.Port))
	slog.Info(fmt.Sprintf("db name: %v", dbConfig.Name))

	dsnWithoutDBname := fmt.Sprintf("%v:%v@tcp(%v:%v)/?charset=utf8mb4&parseTime=True&loc=UTC",
		dbConfig.Username,
		dbConfig.Password,
		dbConfig.Host,
		dbConfig.Port)

	dsnWithDBname := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?charset=utf8mb4&parseTime=True&loc=UTC&multiStatements=true",
		dbConfig.Username,
		dbConfig.Password,
		dbConfig.Host,
		dbConfig.Port,
		dbConfig.Name)

	if dbConfig.Create {
		tempDB, err := sql.Open("mysql", dsnWithoutDBname)
		if err != nil {
			return nil, errors.Wrap(err, "unable to open database")
		}
		defer func() { _ = tempDB.Close() }()

		// create the database if it does not exist.
		//
		// No lock around this, unlike PostgreSQL and SQL Server, and that asymmetry is measured
		// rather than assumed. MySQL serialises on the schema metadata lock and demotes the
		// duplicate: 23 of every 24 concurrent racers receive Note 1007, "Can't create database
		// 'x'; database exists", which is a NOTE the driver never raises as an error. 288 full
		// constructor sequences at 24-way concurrency against an absent database produced zero
		// failures and the target collation every round. So there is nothing here for a lock to
		// fix, and adding one for symmetry would buy a startup round-trip and a stuck-holder
		// failure mode for nothing (#293 decision 6).
		//
		// The collation is case- and accent-SENSITIVE, so a value that differs in case is a
		// different value here exactly as it is on SQLite and PostgreSQL. RFC 6749 section 1.9
		// requires that of client_id, section 3.3 of scope and OpenID Connect Core section 2 of
		// sub; the previous _ai_ci collation folded all three, so client_id=myapp resolved a
		// client registered as MyApp (#283). Migration 000040 converts an existing database,
		// its default included, so a fresh install and a migrated one agree.
		createDatabaseCommand := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %v CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;", dbConfig.Name)
		_, err = tempDB.Exec(createDatabaseCommand)
		if err != nil {
			return nil, errors.Wrap(err, "unable to create database")
		}
	} else {
		// The operator says the database is already there, so nothing is created and the
		// maintenance connection above is never opened: a login with rights only inside the
		// application schema is enough to start (#293). Logged because the operator who set
		// this weeks ago needs the missing-database error below connected back to it.
		slog.Info("db create: disabled, the database must already exist (GOIABADA_DB_CREATE=false)")
	}

	db, err := sql.Open("mysql", dsnWithDBname)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	if !dbConfig.Create {
		// sql.Open only parses the DSN, so without this an absent database would come back as
		// a usable handle and a nil error, and the failure would surface inside the migrator
		// as somebody else's problem. Ping forces first use here, so the caller gets MySQL's
		// own "Error 1049 (42000): Unknown database" from the constructor. Not on the creating
		// arm, where the CREATE DATABASE above already forces it (#293).
		if err := db.Ping(); err != nil {
			_ = db.Close()
			return nil, errors.Wrap(err, "unable to connect to database")
		}
	}

	commonDb := commondb.NewCommonDatabase(db, sqlbuilder.MySQL, logSQL)

	mysqlDb := MySQLDatabase{
		DB:       db,
		CommonDB: commonDb,
		dbConfig: dbConfig,
	}
	return &mysqlDb, nil
}

func (d *MySQLDatabase) BeginTransaction() (*sql.Tx, error) {
	return d.CommonDB.BeginTransaction()
}

func (d *MySQLDatabase) CommitTransaction(tx *sql.Tx) error {
	return d.CommonDB.CommitTransaction(tx)
}

func (d *MySQLDatabase) RollbackTransaction(tx *sql.Tx) error {
	return d.CommonDB.RollbackTransaction(tx)
}

// NewMigrator builds a golang-migrate instance bound to this database and the
// embedded migration files. Migrate delegates to it; tests use it to step to a
// specific version (e.g. seed at 000020, then apply 000021 in isolation).
// schemaMigrationsTableDDL pins the shape of golang-migrate's own version table, which
// Goiabada creates before handing the database over rather than leaving to the driver
// (#284 decision 7). It is the statement golang-migrate v4.19.1's MySQL driver would issue
// itself, verbatim, behind IF NOT EXISTS instead of the driver's SHOW TABLES LIKE check.
//
// Issuing it first makes the driver's own statement a no-op and the shape Goiabada's, so
// this table has one shape on all four engines and a dependency bump that changed the
// driver's DDL cannot silently change what Goiabada builds. SQLite is the engine where this
// actually differs today; here it pins what is already true.
//
// Unqualified, so it lands in the schema the connection is bound to, which is the same one
// mysql.WithInstance resolves through DATABASE(). No column holds a string, so there is no
// collation to spell (#283).
const schemaMigrationsTableDDL = "CREATE TABLE IF NOT EXISTS schema_migrations " +
	"(version bigint not null primary key, dirty boolean not null)"

// ensureSchemaMigrationsTable creates the version table at Goiabada's shape when it is not
// there yet. MySQL's CREATE TABLE IF NOT EXISTS takes a metadata lock, so two processes
// starting against one empty database cannot both create it.
func (d *MySQLDatabase) ensureSchemaMigrationsTable() error {
	if _, err := d.DB.Exec(schemaMigrationsTableDDL); err != nil {
		return errors.Wrap(err, "unable to create the schema_migrations table")
	}
	return nil
}

func (d *MySQLDatabase) NewMigrator() (*gomigrate.Migrate, error) {
	if err := d.ensureSchemaMigrationsTable(); err != nil {
		return nil, err
	}

	driver, err := mysql.WithInstance(d.DB, &mysql.Config{
		DatabaseName: d.dbConfig.Name,
	})
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration driver")
	}

	iofs, err := iofs.New(mysqlMigrationsFs, "migrations")
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration filesystem")
	}

	migrator, err := gomigrate.NewWithInstance("iofs", iofs, "mysql", driver)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration instance")
	}
	return migrator, nil
}

func (d *MySQLDatabase) Migrate() error {
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

func (d *MySQLDatabase) IsEmpty() (bool, error) {
	return d.CommonDB.IsEmpty()
}
