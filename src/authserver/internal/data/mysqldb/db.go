// Package mysqldb is the MySQL adapter: the constructor that opens, and when asked creates, the
// application database, the migration chain MySQL runs, and the handful of Database methods whose
// SQL differs from commondb's. Everything else is promoted from the embedded common
// implementation.
package mysqldb

import (
	"context"
	"crypto/x509"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/commondb"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/core/errs"
)

//go:embed migrations/*.sql
var mysqlMigrationsFs embed.FS

// Database declares only the methods MySQL needs its own SQL for; the rest are promoted
// from the embedded common implementation. See commondb.Database for what embedding does
// and does not buy (#416).
type Database struct {
	*commondb.Database
	dbConfig *DatabaseConfig
}

// The compiler holds the adapter to the whole interface here, in its own package, so an engine
// missing a method fails where the method is missing rather than only where datafactory hands
// the adapter out (#438).
var _ data.Database = (*Database)(nil)

// DatabaseConfig is what MySQL reads to connect: the credentials, the address, the database name,
// and whether it may create that database (#438 decision 3).
type DatabaseConfig struct {
	Username string
	Password string
	Host     string
	Port     int
	Name     string
	// Create decides whether the constructor may create the database when it is absent. It is
	// positive-sense, so the zero value does not create: every literal has to set it (#293).
	Create bool
	// Pool is the application database's connection pool; the maintenance connection a creating
	// start opens is not under it. nil leaves database/sql's own pool, unlimited, which only the
	// tools and the data tier's fixtures that call this constructor directly open with: the
	// server's comes through datafactory, which always passes one (#394).
	Pool *data.PoolConfig
	// TLSMode is GOIABADA_DB_TLS_MODE, the zero value reading as prefer, and TLSRoots the
	// authorities GOIABADA_DB_TLS_CA_FILE holds, nil for the system's roots. Both cover every
	// connection the constructor opens, the maintenance one included (#502).
	TLSMode  data.TLSMode
	TLSRoots *x509.CertPool
}

// New opens the MySQL database dbConfig names, creating it first when dbConfig.Create says so.
// Every statement it issues runs under ctx, the caller's, so a start that cannot reach the server
// ends when the caller stops waiting (#438 decision 3).
func New(ctx context.Context, dbConfig *DatabaseConfig, logSQL bool) (*Database, error) {

	// One record where five used to be, and no password: the connection is configured below from
	// the same four values, so a startup problem is read off this line rather than off four
	// consecutive ones that a collector had no way to join (#320 decision 6).
	tlsMode := dbConfig.TLSMode.OrPrefer()
	slog.InfoContext(ctx, "using database", "type", "mysql", "username", dbConfig.Username,
		"host", dbConfig.Host, "port", dbConfig.Port, "name", dbConfig.Name, "tls_mode", string(tlsMode))

	// The configuration's load refuses any other value, so only a configuration built directly
	// reaches this, and it must not connect as prefer under another name (#502).
	if !tlsMode.Known() {
		return nil, errs.Errorf("GOIABADA_DB_TLS_MODE %q is not one of the five modes", tlsMode)
	}

	if dbConfig.Create {
		tempDB, err := open(MaintenanceConnConfig(dbConfig))
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
		_, err = tempDB.ExecContext(ctx, createDatabaseCommand)
		if err != nil {
			return nil, errs.Wrap(err, "unable to create database")
		}
	} else {
		// The operator says the database is already there, so nothing is created and the
		// maintenance connection above is never opened: a login with rights only inside the
		// application schema is enough to start (#293). Logged because the operator who set
		// this weeks ago needs the missing-database error below connected back to it.
		slog.InfoContext(ctx, "database creation is disabled, so the database must already exist", "setting", "GOIABADA_DB_CREATE")
	}

	db, err := open(ConnConfig(dbConfig))
	if err != nil {
		return nil, errs.Wrap(err, "unable to open database")
	}
	if dbConfig.Pool != nil {
		dbConfig.Pool.ApplyTo(db)
	}

	if !dbConfig.Create {
		// Opening only builds the connector, so without this an absent database would come back as
		// a usable handle and a nil error, and the failure would surface inside the migrator
		// as somebody else's problem. Ping forces first use here, so the caller gets MySQL's
		// own "Error 1049 (42000): Unknown database" from the constructor. Not on the creating
		// arm, where the CREATE DATABASE above already forces it (#293).
		if err := db.PingContext(ctx); err != nil {
			_ = db.Close()
			return nil, errs.Wrap(err, "unable to connect to database")
		}
	}

	commonDb := commondb.New(db, sqlbuilder.MySQL, logSQL)
	commonDb.IsDeadlock = isDeadlock
	commonDb.IsUniqueViolation = isUniqueViolation

	mysqlDb := Database{
		Database: commonDb,
		dbConfig: dbConfig,
	}
	return &mysqlDb, nil
}

// open is sql.Open("mysql", dsn) for a configuration rather than a string, which is what carries
// a TLS configuration of the builder's own and a username containing `:` (#502 decision 11): the
// "mysql" driver builds the same connector from what ParseDSN reads. Like sql.Open it dials
// nothing.
func open(c *mysqldriver.Config, err error) (*sql.DB, error) {
	if err != nil {
		return nil, err
	}
	connector, err := mysqldriver.NewConnector(c)
	if err != nil {
		return nil, errs.Wrap(err, "unable to configure the connection")
	}
	return sql.OpenDB(connector), nil
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

// isUniqueViolation is MySQL's row of the unique-key classifier table commondb's wrapSQLError consults.
//
// mysql.MySQLError has pointer receivers, so the pointer is the only form that is an error and the
// only form the driver returns; there is no value form to check.
func isUniqueViolation(err error) bool {
	var mysqlErr *mysqldriver.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == mysqlDuplicateEntry
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
func (d *Database) ensureSchemaMigrationsTable(ctx context.Context) error {
	if _, err := d.DB.ExecContext(ctx, schemaMigrationsTableDDL); err != nil {
		return errs.Wrap(err, "unable to create the schema_migrations table")
	}
	return nil
}

// NewMigrator builds a runner bound to this database and the embedded migration files.
// Startup brings it to head through UpToHead; tests use it to step to a specific version (e.g.
// seed at 000020, then apply 000021 in isolation).
//
// There is nothing to close. The runner takes a connection out of the pool for the duration
// of one operation and gives it back before returning (#268 decision 8).
//
// The Progress SQL Server's pre-create reports a lock wait to goes unused: the version table here is
// created by one idempotent statement, which waits for no migration lock.
func (d *Database) NewMigrator(ctx context.Context, _ migrator.Progress) (*migrator.Migrator, error) {
	if err := d.ensureSchemaMigrationsTable(ctx); err != nil {
		return nil, err
	}

	m, err := migrator.New(d.DB, mysqlMigrationsFs, "migrations", migrator.MySQL(d.dbConfig.Name))
	if err != nil {
		return nil, errs.Wrap(err, "unable to create migration instance")
	}
	return m, nil
}

// quoteIdentifier wraps name in the backticks MySQL spells an identifier with, doubling any
// backtick inside it.
//
// MySQL was never broken the way PostgreSQL was: an unquoted identifier is not folded here, so
// the name in this statement and the database the connection selects already agreed. What quoting buys is
// the rest of the class. A name needing quotes for any other reason, a hyphen or a space, was a
// syntax error, and the name reaches this statement by interpolation because an identifier
// cannot be a bind parameter. GOIABADA_DB_NAME is operator-supplied configuration rather than
// user input, so the doubling is hardening and not a live hole, but it is the only answer
// available and it costs one line. Kept in the same shape on all three server engines (#293).
func quoteIdentifier(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}
