package mssqldb

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/sqlserver"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/data/commondb"
	_ "github.com/microsoft/go-mssqldb"
	"github.com/pkg/errors"
)

//go:embed migrations/*.sql
var mssqlMigrationsFs embed.FS

type MsSQLDatabase struct {
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

func NewMsSQLDatabase(dbConfig *DatabaseConfig, logSQL bool) (*MsSQLDatabase, error) {

	slog.Info("using database mssql")
	slog.Info(fmt.Sprintf("db username: %v", dbConfig.Username))
	slog.Info(fmt.Sprintf("db host: %v", dbConfig.Host))
	slog.Info(fmt.Sprintf("db port: %v", dbConfig.Port))
	slog.Info(fmt.Sprintf("db name: %v", dbConfig.Name))

	// SQL Server connection string format
	queryParams := url.Values{}
	queryParams.Add("database", "master") // Connect to master first to create DB
	queryParams.Add("encrypt", "disable") // Disable encryption requirement

	if dbConfig.Create {
		connStringMaster := url.URL{
			Scheme:   "sqlserver",
			User:     url.UserPassword(dbConfig.Username, dbConfig.Password),
			Host:     fmt.Sprintf("%s:%d", dbConfig.Host, dbConfig.Port),
			RawQuery: queryParams.Encode(),
		}

		// Connect to master database first
		masterDB, err := sql.Open("sqlserver", connStringMaster.String())
		if err != nil {
			return nil, errors.Wrap(err, "unable to open master database")
		}
		defer func() { _ = masterDB.Close() }() // Ensure we close the master connection

		// Test the connection
		err = masterDB.Ping()
		if err != nil {
			return nil, errors.Wrap(err, "unable to connect to master database")
		}

		if err := createDatabaseUnderAppLock(masterDB, dbConfig.Name); err != nil {
			return nil, err
		}
	} else {
		// The operator says the database is already there, so nothing is created and master is
		// never opened, let alone pinged. That matters more here than on the other two engines:
		// an Azure SQL contained user cannot reach master at all, so the ping above would stop
		// a start that has everything it needs inside the application database (#293).
		slog.Info("db create: disabled, the database must already exist (GOIABADA_DB_CREATE=false)")
	}

	// Now connect to the actual database
	queryParams.Set("database", dbConfig.Name)
	connString := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(dbConfig.Username, dbConfig.Password),
		Host:     fmt.Sprintf("%s:%d", dbConfig.Host, dbConfig.Port),
		RawQuery: queryParams.Encode(),
	}

	// Connect to the actual database
	db, err := sql.Open("sqlserver", connString.String())
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	// Test the connection to the application database. This is also what makes an absent
	// database the constructor's error rather than the migrator's on the skipping arm: SQL
	// Server answers "Cannot open database ... requested by the login" here (#293).
	err = db.Ping()
	if err != nil {
		_ = db.Close()
		return nil, errors.Wrap(err, "unable to connect to database")
	}

	commonDb := commondb.NewCommonDatabase(db, sqlbuilder.SQLServer, logSQL)

	mssqlDb := MsSQLDatabase{
		DB:       db,
		CommonDB: commonDb,
		dbConfig: dbConfig,
	}
	return &mssqlDb, nil
}

// CreateDatabaseResource is the sp_getapplock resource createDatabaseUnderAppLock serializes on.
// It carries NO database name, deliberately.
//
// A name-bearing resource looks tighter and is broken. sp_getapplock compares its resource as
// binary, while sys.databases.name is compared under master's collation, which on a stock
// instance folds case, trailing space, Unicode normalization form and character width. Two
// Goiabada instances configured `goiabada` and `Goiabada` would take two DIFFERENT locks, both
// see zero rows from the IF NOT EXISTS check, and both run CREATE DATABASE: exactly the defect
// the lock exists to close, with a lock bolted on. Normalizing the name in Go cannot close it,
// because the equivalences are whatever the instance's collation says they are and any instance
// may be running a different one.
//
// So the lock is strictly wider than the thing it guards, which is the safe direction. The cost,
// stated so nobody has to rediscover it: creating two DIFFERENT Goiabada databases on one
// instance now serializes against each other, and with an untimed lock a stuck holder blocks
// both rather than one. That is bounded, because the lock spans a catalog check and one
// CREATE DATABASE and is taken once per database in the life of a deployment. That last clause
// is true only because createDatabaseUnderAppLock checks the catalog BEFORE reaching for the
// lock. See the note there.
//
// Deliberately distinct from database.GenerateAdvisoryLockId, which ensureSchemaMigrationsTable
// takes below: that guards the schema_migrations table INSIDE an existing database, a different
// thing one layer down, and the two must not share a resource (#293).
//
// Exported because the resource is an inter-process contract rather than an implementation
// detail: anything that has to interoperate with a starting Goiabada, a test holding the lock
// from outside included, needs the identity itself and cannot restate it without becoming a
// second definition that is free to drift.
const CreateDatabaseResource = "goiabada:create-database"

// createDatabaseUnderAppLock runs the check-then-create batch with an exclusive application lock
// held across it, so that at most one process ever issues CREATE DATABASE.
//
// SQL Server has no atomic CREATE DATABASE IF NOT EXISTS, so the batch below is a check followed
// by a create and racing processes can all pass the check. Measured: 5 of 8 concurrent starts
// against an absent database failed. That is also why this serializes rather than tolerating the
// error and re-checking, which is what the issue proposed: most losers carry no error number and
// no message at all, only "Request failed but didn't provide reason", so there is frequently
// nothing to recognise. Two replicas against one fresh server is an ordinary topology (#293).
//
// sp_getapplock at LockOwner = 'Session' is scoped to one session, so the lock has to be taken,
// used and released on a single connection pinned out of the pool. Issued against the pooled
// *sql.DB, the release could land on a different session and leave the lock held for the life of
// the process, blocking every later start against this instance. Same hazard, same remedy, as
// ensureSchemaMigrationsTable below.
//
// Application locks are scoped to the database the session is in, and every racer is in master,
// so they do share one lock space. That is the whole reason this works.
//
// LockTimeout = -1 blocks until the lock is free rather than failing, which is what the migration
// lock already does: the holder is another process's create, and it is short.
//
// That is affordable only because the lock is reached ONLY when the database is absent. An
// application lock taken in master is shared with every session on the instance, so ANY login
// that can reach master (ordinary public access is enough, and it needs no rights at all
// inside Goiabada's database) can hold this resource indefinitely. Reaching for it
// unconditionally would put that stranger on the path of every ordinary restart for the life of
// the deployment, which is not the cost #293 decision 5 weighed. The unlocked pre-check below
// keeps the exposure inside the window where the database really is absent, which is the one
// start that has to create it.
//
// The pre-check cannot let a second creator through. It only returns early when the database is
// already there, and what decides whether CREATE DATABASE runs is still the IF NOT EXISTS inside
// the batch, under the lock. It is also no weaker than that check: both compare
// sys.databases.name against an nvarchar value under master's collation, so both fold case,
// trailing space, normalization form and width identically. Two instances configured `goiabada`
// and `Goiabada` against an absent database therefore both find nothing here, both take the
// constant resource, and the batch collapses them to one database exactly as before (#293).
func createDatabaseUnderAppLock(masterDB *sql.DB, name string) error {
	ctx := context.Background()

	exists, err := databaseExists(ctx, masterDB, name)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	// Create database if it doesn't exist.
	//
	// The collation is case-, accent-, width- and kanatype-SENSITIVE, so a value that differs
	// in case is a different value here exactly as it is on SQLite and PostgreSQL. RFC 6749
	// section 1.9 requires that of client_id, section 3.3 of scope and OpenID Connect Core
	// section 2 of sub; the previous CI_AI collation folded all three, so client_id=myapp
	// resolved a client registered as MyApp (#283). Migration 000040 converts an existing
	// database's 92 string columns to the same collation.
	//
	// IF NOT EXISTS, so a database an OPERATOR pre-created keeps their collation: the database
	// default cannot be moved from a migration, because ALTER DATABASE ... COLLATE blocks until
	// it times out with a second session attached, which is what a running application is. That
	// is why every string column a future migration adds must spell its own COLLATE clause
	// explicitly, naming the collation below, rather than relying on this line, and why a data
	// test migrates the whole chain into a hostile database and asserts all 92 columns.
	createDatabaseCommand := fmt.Sprintf(`
        IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = N%s)
        BEGIN
            CREATE DATABASE %s
            COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8
        END`,
		quoteLiteral(name),
		quoteIdentifier(name),
	)

	conn, err := masterDB.Conn(ctx)
	if err != nil {
		return errors.Wrap(err, "unable to pin a connection for the database creation lock")
	}
	defer func() { _ = conn.Close() }()

	const takeLock = `DECLARE @lockResult int;
		EXEC @lockResult = sp_getapplock @Resource = @p1, @LockMode = 'Exclusive', @LockOwner = 'Session', @LockTimeout = -1;
		SELECT @lockResult;`
	var status int
	if err := conn.QueryRowContext(ctx, takeLock, CreateDatabaseResource).Scan(&status); err != nil {
		return errors.Wrap(err, "unable to take the database creation lock")
	}
	if status < 0 {
		return errors.Errorf("unable to take the database creation lock: sp_getapplock returned %d", status)
	}
	defer func() {
		_, _ = conn.ExecContext(ctx, `EXEC sp_releaseapplock @Resource = @p1, @LockOwner = 'Session'`, CreateDatabaseResource)
	}()

	if _, err := conn.ExecContext(ctx, createDatabaseCommand); err != nil {
		return errors.Wrap(err, "unable to create database")
	}
	return nil
}

// databaseExists asks sys.databases whether name is there, through master.
//
// The comparison is master's collation, which on a stock instance folds case and more. That is
// the same comparison the IF NOT EXISTS inside createDatabaseUnderAppLock's batch makes, and it
// has to be: this check stands in front of the lock, so anything it treats as present must be
// something the batch would also treat as present (#293).
func databaseExists(ctx context.Context, masterDB *sql.DB, name string) (bool, error) {
	var found int
	if err := masterDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sys.databases WHERE name = @p1", name).Scan(&found); err != nil {
		return false, errors.Wrap(err, "unable to check whether the database exists")
	}
	return found > 0, nil
}

func (d *MsSQLDatabase) BeginTransaction() (*sql.Tx, error) {
	return d.CommonDB.BeginTransaction()
}

func (d *MsSQLDatabase) CommitTransaction(tx *sql.Tx) error {
	return d.CommonDB.CommitTransaction(tx)
}

func (d *MsSQLDatabase) RollbackTransaction(tx *sql.Tx) error {
	return d.CommonDB.RollbackTransaction(tx)
}

// NewMigrator builds a golang-migrate instance bound to this database and the
// embedded migration files. Migrate delegates to it; tests use it to step to a
// specific version (e.g. seed at 000020, then apply 000021 in isolation).
// schemaMigrationsTableDDL pins the shape of golang-migrate's own version table, which
// Goiabada creates before handing the database over rather than leaving to the driver
// (#284 decision 7). It builds what golang-migrate v4.19.1's SQL Server driver would build
// itself, so issuing it first makes the driver's own statement a no-op and the shape
// Goiabada's: this table then has one shape on all four engines and a dependency bump that
// changed the driver's DDL cannot silently change what Goiabada builds. SQLite is the
// engine where this actually differs today; here it pins what is already true.
//
// Unqualified, so it lands in the caller's default schema, which is the same one
// sqlserver.WithInstance resolves through SCHEMA_NAME().
const schemaMigrationsTableDDL = `IF OBJECT_ID(N'schema_migrations', N'U') IS NULL
	CREATE TABLE schema_migrations (
		version BIGINT PRIMARY KEY NOT NULL,
		dirty BIT NOT NULL
	);`

// ensureSchemaMigrationsTable creates the version table at Goiabada's shape when it is not
// there yet, holding golang-migrate's own migration lock while it does.
//
// SQL Server has no atomic CREATE TABLE IF NOT EXISTS, so the statement above is a check
// followed by a create and two processes starting against one empty database can both pass
// the check: the loser gets Msg 2714, "There is already an object named
// 'schema_migrations'", and fails to start. Two replicas against one database is an
// ordinary topology, not a hypothetical one. golang-migrate's own ensureVersionTable runs
// exactly this sequence and is safe only because it holds sp_getapplock around it, so this
// takes the same lock on the same resource, and it must go on doing so: without it this
// function REMOVES a property the driver already had.
//
// The resource name is computed by the library's own exported function from the library's
// own two arguments, rather than by a formula copied out of the driver, so the two cannot
// drift onto different resources. schemaName is what sqlserver.WithInstance fills its empty
// Config.SchemaName from.
//
// sp_getapplock at LockOwner = 'Session' is scoped to one session, so the lock has to be
// taken, used and released on a single connection pinned out of the pool. Issued against
// the pooled *sql.DB, the release could land on a different session and leave the lock held
// for the life of the process, blocking every later migrator.
func (d *MsSQLDatabase) ensureSchemaMigrationsTable() error {
	ctx := context.Background()

	var schemaName string
	if err := d.DB.QueryRowContext(ctx, "SELECT SCHEMA_NAME()").Scan(&schemaName); err != nil {
		return errors.Wrap(err, "unable to read the default schema name")
	}
	lockID, err := database.GenerateAdvisoryLockId(d.dbConfig.Name, schemaName)
	if err != nil {
		return errors.Wrap(err, "unable to derive the migration lock id")
	}

	conn, err := d.DB.Conn(ctx)
	if err != nil {
		return errors.Wrap(err, "unable to pin a connection for the migration lock")
	}
	defer func() { _ = conn.Close() }()

	// LockTimeout = -1 blocks until the lock is free, which is what the driver does: the
	// holder is another process's pre-create or migration, and both are short.
	const takeLock = `DECLARE @lockResult int;
		EXEC @lockResult = sp_getapplock @Resource = @p1, @LockMode = 'Exclusive', @LockOwner = 'Session', @LockTimeout = -1;
		SELECT @lockResult;`
	var status int
	if err := conn.QueryRowContext(ctx, takeLock, lockID).Scan(&status); err != nil {
		return errors.Wrap(err, "unable to take the migration lock")
	}
	if status < 0 {
		return errors.Errorf("unable to take the migration lock: sp_getapplock returned %d", status)
	}
	defer func() {
		_, _ = conn.ExecContext(ctx, `EXEC sp_releaseapplock @Resource = @p1, @LockOwner = 'Session'`, lockID)
	}()

	if _, err := conn.ExecContext(ctx, schemaMigrationsTableDDL); err != nil {
		return errors.Wrap(err, "unable to create the schema_migrations table")
	}
	return nil
}

func (d *MsSQLDatabase) NewMigrator() (*gomigrate.Migrate, error) {
	if err := d.ensureSchemaMigrationsTable(); err != nil {
		return nil, err
	}

	driver, err := sqlserver.WithInstance(d.DB, &sqlserver.Config{
		DatabaseName: d.dbConfig.Name,
	})
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration driver")
	}

	iofs, err := iofs.New(mssqlMigrationsFs, "migrations")
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration filesystem")
	}

	migrator, err := gomigrate.NewWithInstance("iofs", iofs, "sqlserver", driver)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration instance")
	}
	return migrator, nil
}

func (d *MsSQLDatabase) Migrate() error {
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

func (d *MsSQLDatabase) IsEmpty() (bool, error) {
	return d.CommonDB.IsEmpty()
}

// quoteIdentifier wraps name in the brackets SQL Server spells an identifier with, doubling any
// closing bracket inside it, and quoteLiteral wraps it in the single quotes of a string literal,
// doubling any single quote inside it.
//
// The batch above needs both, because it names the database twice in two different syntaxes: as
// an identifier in CREATE DATABASE and as an nvarchar value compared against sys.databases.name.
// It was already bracketed, so SQL Server was never broken the way PostgreSQL was, where an
// unquoted CREATE DATABASE folds the name and the connection string does not. What these close
// is the rest of the class: a name carrying `]` used to escape the brackets and one carrying `'`
// used to end the literal early, and the name reaches both places by interpolation because an
// identifier cannot be a bind parameter and the literal sits inside a batch that is executed as
// one statement. GOIABADA_DB_NAME is operator-supplied configuration rather than user input, so
// this is hardening and not a live hole. Kept in the same shape on all three server engines
// (#293).
//
// Neither of these makes the check any narrower than it was. sys.databases.name is still
// compared under master's collation, which folds case and more, which is why CreateDatabaseResource
// above carries no name.
func quoteIdentifier(name string) string {
	return "[" + strings.ReplaceAll(name, "]", "]]") + "]"
}

func quoteLiteral(name string) string {
	return "'" + strings.ReplaceAll(name, "'", "''") + "'"
}
