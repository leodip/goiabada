package mysqldb

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data/commondb"
	"github.com/leodip/goiabada/core/data/migrator"
	"github.com/leodip/goiabada/core/errs"
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
			return nil, errs.Wrap(err, "unable to open database")
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
		createDatabaseCommand := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;", quoteIdentifier(dbConfig.Name))
		_, err = tempDB.Exec(createDatabaseCommand)
		if err != nil {
			return nil, errs.Wrap(err, "unable to create database")
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
		return nil, errs.Wrap(err, "unable to open database")
	}

	if !dbConfig.Create {
		// sql.Open only parses the DSN, so without this an absent database would come back as
		// a usable handle and a nil error, and the failure would surface inside the migrator
		// as somebody else's problem. Ping forces first use here, so the caller gets MySQL's
		// own "Error 1049 (42000): Unknown database" from the constructor. Not on the creating
		// arm, where the CREATE DATABASE above already forces it (#293).
		if err := db.Ping(); err != nil {
			_ = db.Close()
			return nil, errs.Wrap(err, "unable to connect to database")
		}
	}

	commonDb := commondb.NewCommonDatabase(db, sqlbuilder.MySQL, logSQL)
	commonDb.IsDeadlock = isDeadlock
	commonDb.IsUniqueViolation = isUniqueViolation

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

func (d *MySQLDatabase) RunInTransaction(fn func(tx *sql.Tx) error) error {
	return d.CommonDB.RunInTransaction(fn)
}

// isDeadlock is MySQL's half of RunInTransaction's classifier: error 1213, ER_LOCK_DEADLOCK,
// which InnoDB raises on the transaction it rolled back to break the cycle. 1205,
// ER_LOCK_WAIT_TIMEOUT, is deliberately not here: the row is still held by somebody who has
// not deadlocked, so rerunning would wait the same timeout again (#301).
func isDeadlock(err error) bool {
	var mysqlErr *mysqldriver.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == 1213
}

// mysqlDuplicateEntry is ER_DUP_ENTRY, the error MySQL returns when a write collides with a unique
// index. Observed rather than remembered: the probe recorded `*mysql.MySQLError "Error 1062
// (23000): Duplicate entry 'a@b' for key 'zzprobe279.email'"` with Number 1062 (#279).
const mysqlDuplicateEntry = 1062

// isUniqueViolation is MySQL's row of the unique-key classifier table WrapSQLError consults.
//
// mysql.MySQLError has pointer receivers, so the pointer is the only form that is an error and the
// only form the driver returns; there is no value form to check.
func isUniqueViolation(err error) bool {
	var mysqlErr *mysqldriver.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == mysqlDuplicateEntry
}

func (d *MySQLDatabase) CommitTransaction(tx *sql.Tx) error {
	return d.CommonDB.CommitTransaction(tx)
}

func (d *MySQLDatabase) RollbackTransaction(tx *sql.Tx) error {
	return d.CommonDB.RollbackTransaction(tx)
}

// schemaMigrationsTableDDL pins the shape of the version table the runner keeps, which
// Goiabada creates before anything migrates rather than leaving to whatever applies the files
// (#284 decision 7). It is the statement golang-migrate v4.19.1's MySQL driver would have
// issued itself, verbatim, behind IF NOT EXISTS instead of that driver's SHOW TABLES LIKE
// check.
//
// So a database created under the library and one created under the runner have the same
// shape, and this table reads the same on all four engines. SQLite is the engine where the
// library's shape actually differed; here it pins what was already true.
//
// Unqualified, so it lands in the schema the connection is bound to. No column holds a
// string, so there is no collation to spell (#283).
const schemaMigrationsTableDDL = "CREATE TABLE IF NOT EXISTS schema_migrations " +
	"(version bigint not null primary key, dirty boolean not null)"

// ensureSchemaMigrationsTable creates the version table at Goiabada's shape when it is not
// there yet. MySQL's CREATE TABLE IF NOT EXISTS takes a metadata lock, so two processes
// starting against one empty database cannot both create it.
func (d *MySQLDatabase) ensureSchemaMigrationsTable() error {
	if _, err := d.DB.Exec(schemaMigrationsTableDDL); err != nil {
		return errs.Wrap(err, "unable to create the schema_migrations table")
	}
	return nil
}

// NewMigrator builds a runner bound to this database and the embedded migration files.
// Migrate delegates to it; tests use it to step to a specific version (e.g. seed at
// 000020, then apply 000021 in isolation).
//
// There is nothing to close. The runner takes a connection out of the pool for the duration
// of one operation and gives it back before returning (#268 decision 8).
func (d *MySQLDatabase) NewMigrator() (*migrator.Migrator, error) {
	if err := d.ensureSchemaMigrationsTable(); err != nil {
		return nil, err
	}

	m, err := migrator.New(d.DB, mysqlMigrationsFs, "migrations", migrator.MySQL(d.dbConfig.Name))
	if err != nil {
		return nil, errs.Wrap(err, "unable to create migration instance")
	}
	return m, nil
}

func (d *MySQLDatabase) Migrate() error {
	m, err := d.NewMigrator()
	if err != nil {
		return err
	}

	err = m.Up()
	// IsNoChange rather than errors.Is: a run whose unlock failed answers the sentinel JOINED
	// with that failure, and errors.Is would report this start as successful while the migration
	// lock stays held against every other process on the database (#268).
	if migrator.IsNoChange(err) {
		slog.Info("no need to migrate the database")
		return nil
	}
	if err != nil {
		// StartupRefusal explains the one failure a starting server can be talked out of: a
		// database a newer release already migrated. Everything else passes through.
		return errs.Wrap(migrator.StartupRefusal(err, constants.Version), "unable to migrate the database")
	}

	return nil
}

func (d *MySQLDatabase) IsEmpty() (bool, error) {
	return d.CommonDB.IsEmpty()
}

// quoteIdentifier wraps name in the backticks MySQL spells an identifier with, doubling any
// backtick inside it.
//
// MySQL was never broken the way PostgreSQL was: an unquoted identifier is not folded here, so
// the name in this statement and the name in the DSN's path already agreed. What quoting buys is
// the rest of the class. A name needing quotes for any other reason, a hyphen or a space, was a
// syntax error, and the name reaches this statement by interpolation because an identifier
// cannot be a bind parameter. GOIABADA_DB_NAME is operator-supplied configuration rather than
// user input, so the doubling is hardening and not a live hole, but it is the only answer
// available and it costs one line. Kept in the same shape on all three server engines (#293).
func quoteIdentifier(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}
