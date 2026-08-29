package datatests

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/data/mssqldb"
	"github.com/leodip/goiabada/core/data/mysqldb"
	"github.com/leodip/goiabada/core/data/postgresdb"
	"github.com/leodip/goiabada/core/data/schemadump"
	"github.com/leodip/goiabada/core/data/sqlitedb"
	"github.com/stretchr/testify/require"
)

// The collations migration 000040 moves between. MySQL and SQL Server only: SQLite compares
// BINARY and PostgreSQL's en_US.utf8 is deterministic, so both already answer `=` the way
// #283 asks for and neither has a 000040 file.
//
// Declared HERE rather than beside the 000040 test because this file is the package's only
// non-test file, so it cannot see a constant a _test.go file declares, and
// assertCreatedDatabaseCollation below needs the same two target names the migration test
// asserts columns against. One definition is the point: the constructor and the migration have
// to land on the same collation or a fresh install and a migrated one disagree, which is
// exactly what #283 decision 4 is about.
const (
	mysqlCollationBefore000040        = "utf8mb4_0900_ai_ci"
	mysqlUnicodeCollationBefore000040 = "utf8mb4_unicode_ci"
	mysqlCollationAfter000040         = "utf8mb4_0900_as_cs"

	mssqlCollationBefore000040 = "Latin1_General_100_CI_AI_SC_UTF8"
	mssqlCollationAfter000040  = "Latin1_General_100_CS_AS_KS_WS_SC_UTF8"
)

// isolatedDB is a throwaway database of the CONFIGURED dialect, used by
// migration tests that must control the exact schema version. The shared test
// database (data_test.go) is always fully migrated, so it can't be used to
// exercise a single migration against seeded pre-migration data.
type isolatedDB struct {
	DB       data.Database      // concrete dialect DB (implements the interface)
	SQL      *sql.DB            // raw handle for seeding / asserting
	Migrator *gomigrate.Migrate // bound to DB, starts at version 0
}

var isolatedDBCounter atomic.Int64

// isolatedDBName returns a server-DB name unique to this process + call.
// Lowercase so it's valid unquoted for PostgreSQL.
func isolatedDBName() string {
	return fmt.Sprintf("goiabada_mig_%d_%d", os.Getpid(), isolatedDBCounter.Add(1))
}

func dbType() string {
	return strings.Trim(strings.TrimSpace(config.GetDatabase().Type), `"'`)
}

// newIsolatedDB creates a fresh, empty database of the configured dialect and a
// migrator bound to it (at version 0). Cleanup (close + drop) is registered on t.
func newIsolatedDB(t *testing.T) *isolatedDB {
	t.Helper()
	cfg := config.GetDatabase()

	switch dbType() {
	case "", "sqlite":
		// A file-based DB in a temp dir: the sqlite driver requires WAL, which
		// an in-memory database cannot provide.
		dsn := filepath.Join(t.TempDir(), "migration_test.db")
		db, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{Type: "sqlite", DSN: dsn}, false)
		require.NoError(t, err, "NewSQLiteDatabase")
		t.Cleanup(func() { _ = db.DB.Close() }) // temp dir is removed by t.TempDir
		return newIsolated(t, db, db.DB)

	case "mysql":
		name := isolatedDBName()
		db, err := mysqldb.NewMySQLDatabase(&mysqldb.DatabaseConfig{
			Type: "mysql", Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: true,
		}, false)
		require.NoError(t, err, "NewMySQLDatabase")
		t.Cleanup(func() { _ = db.DB.Close(); dropMySQL(t, cfg, name) })
		assertCreatedDatabaseCollation(t, db.DB)
		return newIsolated(t, db, db.DB)

	case "postgres":
		name := isolatedDBName()
		db, err := postgresdb.NewPostgresDatabase(&postgresdb.DatabaseConfig{
			Type: "postgres", Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: true,
		}, false)
		require.NoError(t, err, "NewPostgresDatabase")
		t.Cleanup(func() { _ = db.DB.Close(); dropPostgres(t, cfg, name) })
		return newIsolated(t, db, db.DB)

	case "mssql":
		name := isolatedDBName()
		db, err := mssqldb.NewMsSQLDatabase(&mssqldb.DatabaseConfig{
			Type: "mssql", Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: true,
		}, false)
		require.NoError(t, err, "NewMsSQLDatabase")
		t.Cleanup(func() { _ = db.DB.Close(); dropMsSQL(t, cfg, name) })
		assertCreatedDatabaseCollation(t, db.DB)
		return newIsolated(t, db, db.DB)

	default:
		t.Fatalf("unsupported db type %q", dbType())
		return nil
	}
}

// assertCreatedDatabaseCollation holds a database Goiabada CREATED to the collation decision 4
// pins for it, read out of the engine's own catalog rather than trusted from the statement that
// made it.
//
// It runs immediately after the constructor and BEFORE any migration, and that order is
// load-bearing on MySQL: 000040 issues its own ALTER DATABASE, so a fixture asserted after the
// chain would report the target collation with the constructor still wrong.
//
// Why it needs asserting at all, which is not obvious. Migration 000040 pins all 92 SQL Server
// columns and all 25 MySQL tables EXPLICITLY, so no column collation any other assertion in
// this package reads is decided by the database default; reverting either constructor to the
// case-insensitive collation it used before #283 leaves the whole four-engine data tier green.
// What the default still decides is what a string column added by a LATER migration inherits.
// That is the whole of the residue decision 4 accepts on SQL Server, where ALTER DATABASE
// blocks against a live connection pool and the migration therefore cannot repair it, and the
// whole of decision 12's finding that MySQL is not exposed to the same problem.
//
// SQL Server and MySQL only. PostgreSQL's CREATE DATABASE inherits the cluster template and is
// deterministic whatever the locale, and SQLite has no database-level collation.
func assertCreatedDatabaseCollation(t *testing.T, sqlDB *sql.DB) {
	t.Helper()

	var want string
	switch dbType() {
	case "mysql":
		want = mysqlCollationAfter000040
	case "mssql":
		want = mssqlCollationAfter000040
	default:
		return
	}

	require.Equalf(t, want, readDatabaseDefaultCollation(t, sqlDB),
		"a database Goiabada creates must be created at %s (#283 decision 4), because every string column a later migration adds inherits it and no migration can repair that on SQL Server", want)
}

// readDatabaseDefaultCollation returns the DATABASE-level default collation, which is a
// different thing from any column's: nothing existing inherits it, and what it decides is the
// collation a string column added later lands at when its DDL does not spell COLLATE.
//
// Read from the engine's own catalog on both engines that have one. MySQL reports it in
// information_schema.SCHEMATA for the connection's current database; SQL Server has no
// catalog view for it and answers through DATABASEPROPERTYEX.
func readDatabaseDefaultCollation(t *testing.T, sqlDB *sql.DB) string {
	t.Helper()

	var query string
	switch dbType() {
	case "mysql":
		query = "SELECT DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = DATABASE()"
	case "mssql":
		query = `SELECT CAST(DATABASEPROPERTYEX(DB_NAME(), 'Collation') AS NVARCHAR(128))`
	default:
		t.Fatalf("%s has no database-level default collation to read", dbType())
		return ""
	}

	var got string
	require.NoError(t, sqlDB.QueryRow(query).Scan(&got), "read the database's default collation")
	return got
}

// migratable is satisfied by every concrete dialect DB (they all expose
// NewMigrator via the seam added in chunk 3).
type migratable interface {
	data.Database
	NewMigrator() (*gomigrate.Migrate, error)
}

func newIsolated(t *testing.T, db migratable, sqlDB *sql.DB) *isolatedDB {
	t.Helper()
	m, err := db.NewMigrator()
	require.NoError(t, err, "NewMigrator")
	// Release the migrator's source + database resources. Registered after the
	// per-dialect close/drop cleanup, so (LIFO) it runs first, before the drop.
	t.Cleanup(func() { _, _ = m.Close() })
	return &isolatedDB{DB: db, SQL: sqlDB, Migrator: m}
}

// The shapes and the dumper live in the core module now, at data/schemadump, because the
// generator command that writes the golden files cannot reach an unexported helper in
// another module's test package (#284). What stays here is the thin layer this package's
// migration tests were written against.
//
// tableShape is a defined type over schemadump.TableShape rather than an alias or an
// embedding. An alias would forbid the three methods below, which Go can only hang on a type
// declared in this package; an embedding would break every composite literal the migration
// tests build. Identical fields make the two directly convertible.
type (
	columnShape     = schemadump.ColumnShape
	indexShape      = schemadump.IndexShape
	foreignKeyShape = schemadump.ForeignKeyShape

	tableShape schemadump.TableShape
)

// dumpDialect is the configured dialect in the vocabulary schemadump takes. The package
// takes it as a parameter rather than reading the configuration itself, because the
// generator connects to all four engines in one process.
func dumpDialect(t *testing.T) schemadump.Dialect {
	t.Helper()
	d, err := schemadump.ParseDialect(config.GetDatabase().Type)
	require.NoErrorf(t, err, "the configured database type %q is not one of the four dialects", dbType())
	return d
}

// dumpTable reads a table's columns, indexes and foreign keys out of the configured
// dialect's catalog, failing the test on the errors schemadump returns rather than handing
// them back. Every failure it can report means the dump is not usable: a table that read no
// columns, or one carrying a construct the shape cannot record.
func dumpTable(t *testing.T, h *isolatedDB, table string) tableShape {
	t.Helper()
	shape, err := schemadump.DumpTable(h.SQL, dumpDialect(t), table)
	require.NoErrorf(t, err, "dump table %s on %s", table, dbType())
	return tableShape(shape)
}

// describeIndex reads one index's uniqueness, key columns and origin from the configured
// dialect's catalog, returning a zero indexShape (Exists false) when the table does not
// carry it.
func describeIndex(t *testing.T, h *isolatedDB, table, index string) indexShape {
	t.Helper()
	shape, err := schemadump.DescribeIndex(h.SQL, dumpDialect(t), table, index)
	require.NoErrorf(t, err, "describe index %s on %s (%s)", index, table, dbType())
	return shape
}

// listTables is every application table in the isolated database, sorted. It fails the test
// on an empty list, which schemadump treats as a fault rather than a result: a dump of no
// tables compared against a golden file of no tables reads as "nothing changed".
func listTables(t *testing.T, h *isolatedDB) []string {
	t.Helper()
	names, err := schemadump.Tables(h.SQL, dumpDialect(t))
	require.NoErrorf(t, err, "list tables on %s", dbType())
	return names
}

// dumpSchema is every table in the isolated database, which is what the generator writes a
// golden file from and what the per-engine assertion reads through.
func dumpSchema(t *testing.T, h *isolatedDB) schemadump.Schema {
	t.Helper()
	schema, err := schemadump.Dump(h.SQL, dumpDialect(t))
	require.NoErrorf(t, err, "dump the whole schema on %s", dbType())
	return schema
}

// column returns the named column, failing the test when the dump does not carry it.
func (s tableShape) column(t *testing.T, name string) columnShape {
	t.Helper()
	c, ok := schemadump.TableShape(s).Column(name)
	if !ok {
		require.FailNowf(t, "column not found", "no column %q in the dump (%d columns read on %s)",
			name, len(s.Columns), dbType())
	}
	return c
}

// index returns the named index, or a zero indexShape (Exists false) when the table does
// not carry it, matching describeIndex's contract.
func (s tableShape) index(name string) indexShape {
	return schemadump.TableShape(s).Index(name)
}

// foreignKey returns the foreign key whose LOCAL column is name, failing the test when
// there is none. Keyed by local column because that is what identifies a foreign key
// without a constraint name, per schemadump.ForeignKeyShape.
func (s tableShape) foreignKey(t *testing.T, column string) foreignKeyShape {
	t.Helper()
	fk, ok := schemadump.TableShape(s).ForeignKey(column)
	if !ok {
		require.FailNowf(t, "foreign key not found", "no foreign key on column %q in the dump (%d read on %s)",
			column, len(s.ForeignKeys), dbType())
	}
	return fk
}

func dropMySQL(t *testing.T, cfg *config.DatabaseConfig, name string) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?charset=utf8mb4&parseTime=True&loc=UTC",
		cfg.Username, cfg.Password, cfg.Host, cfg.Port)
	sqlDB, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Logf("dropMySQL open: %v", err)
		return
	}
	defer func() { _ = sqlDB.Close() }()
	if _, err := sqlDB.Exec("DROP DATABASE IF EXISTS " + name); err != nil {
		t.Logf("dropMySQL exec: %v", err)
	}
}

func dropPostgres(t *testing.T, cfg *config.DatabaseConfig, name string) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres",
		cfg.Username, cfg.Password, cfg.Host, cfg.Port)
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Logf("dropPostgres open: %v", err)
		return
	}
	defer func() { _ = sqlDB.Close() }()
	// FORCE terminates lingering connections (PostgreSQL 13+).
	if _, err := sqlDB.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", name)); err != nil {
		t.Logf("dropPostgres exec: %v", err)
	}
}

// newPreCreatedMsSQLDB is newIsolatedDB for the case an OPERATOR would produce: the
// database already exists, at a collation somebody else chose, before Goiabada ever
// connects. NewMsSQLDatabase creates IF NOT EXISTS, so its own CREATE DATABASE does not
// fire and the collation stands.
//
// Two tests need it and they need different collations, which is why it takes one.
// Migration 000040's own test needs a fixture at Latin1_General_100_CI_AI_SC_UTF8,
// Goiabada's collation before #283, because newIsolatedDB would build the fixture through
// NewMsSQLDatabase and that now creates at the TARGET collation: no migration before
// 000040 declares a column collation, so all 92 columns would inherit the target from the
// database default and satisfy the post-migration assertion before the migration existed.
// The pre-created guard needs it at SQL_Latin1_General_CP1_CI_AS, a stock server default,
// to prove every column is pinned explicitly rather than inherited.
//
// SQL Server only. MySQL's 000040 repairs the database default and every table with it,
// PostgreSQL's database collation is deterministic whatever the locale, and SQLite has no
// database collation at all.
func newPreCreatedMsSQLDB(t *testing.T, collation string) *isolatedDB {
	t.Helper()
	require.Equal(t, "mssql", dbType(), "newPreCreatedMsSQLDB is SQL Server only")

	cfg := config.GetDatabase()
	name := isolatedDBName()

	master, err := sql.Open("sqlserver", msSQLMasterDSN(cfg))
	require.NoErrorf(t, err, "open master to pre-create %s", name)
	defer func() { _ = master.Close() }()

	// The collation is interpolated because SQL Server takes no parameter in a CREATE
	// DATABASE clause. It is a constant from this package's own tests, never a value that
	// reached the process from outside it.
	_, err = master.Exec(fmt.Sprintf("CREATE DATABASE [%s] COLLATE %s", name, collation))
	require.NoErrorf(t, err, "pre-create %s at %s", name, collation)

	db, err := mssqldb.NewMsSQLDatabase(&mssqldb.DatabaseConfig{
		Type: "mssql", Username: cfg.Username, Password: cfg.Password,
		Host: cfg.Host, Port: cfg.Port, Name: name,
		// The operator created this one, so the constructor must not: that is what the
		// collation assertion below is checking (#293).
		Create: false,
	}, false)
	require.NoError(t, err, "NewMsSQLDatabase over a pre-created database")
	t.Cleanup(func() { _ = db.DB.Close(); dropMsSQL(t, cfg, name) })

	// Asserted rather than assumed: with Create false nothing in the constructor may touch
	// the database at all, so one that started creating or altering one would be caught here
	// rather than leaving every test built on this fixture passing for the wrong reason.
	//
	// That IF NOT EXISTS on the CREATING arm still leaves an operator's database alone is a
	// different claim and it has its own case, in database_create_test.go: this fixture used
	// to be what held it, and once it stopped issuing the statement it stopped being evidence
	// about it (#293).
	require.Equal(t, collation, readDatabaseDefaultCollation(t, db.DB),
		"NewMsSQLDatabase with Create false must leave the operator's database exactly as it found it")

	return newIsolated(t, db, db.DB)
}

// msSQLMasterDSN is the connection string for the master database, which is where a
// database is created and dropped from.
func msSQLMasterDSN(cfg *config.DatabaseConfig) string {
	q := url.Values{}
	q.Add("database", "master")
	q.Add("encrypt", "disable")
	u := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(cfg.Username, cfg.Password),
		Host:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		RawQuery: q.Encode(),
	}
	return u.String()
}

func dropMsSQL(t *testing.T, cfg *config.DatabaseConfig, name string) {
	sqlDB, err := sql.Open("sqlserver", msSQLMasterDSN(cfg))
	if err != nil {
		t.Logf("dropMsSQL open: %v", err)
		return
	}
	defer func() { _ = sqlDB.Close() }()
	stmt := fmt.Sprintf(
		"IF DB_ID(N'%s') IS NOT NULL BEGIN ALTER DATABASE [%s] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [%s]; END",
		name, name, name)
	if _, err := sqlDB.Exec(stmt); err != nil {
		t.Logf("dropMsSQL exec: %v", err)
	}
}

// restrictedLoginDB is the deployment goals 2 and 3 of #293 are about: the database already
// exists, and the credential Goiabada connects with holds only the rights it needs INSIDE it.
// No CREATEDB on PostgreSQL, no server-wide CREATE on MySQL, no access to master on SQL Server.
//
// It is the load-bearing fixture for the skipping path, and the reason is that this tier
// connects as root/sa/postgres. A test that merely pre-created the database and set
// Create: false would pass with the maintenance connection still opened and the create
// statement still issued, because a superuser can do both. A restricted login is what observes
// their absence from outside the constructor, which is why §5 of the agreement rejects counting
// connections and decision 8 chose this instead.
//
// MySQL is the one engine where that is not enough, and the shortfall is measured rather than
// assumed: MySQL has no per-schema CONNECT privilege, so a login granted ALL PRIVILEGES ON
// <db>.* connects with no database selected AND its CREATE DATABASE IF NOT EXISTS <db>
// succeeds, the engine short-circuiting because the database is there. No credential can deny
// the maintenance DSN while allowing the application one. connectionCount below is what covers
// MySQL instead.
type restrictedLoginDB struct {
	// name is the pre-created application database.
	name string
	// username and password are the restricted credential. The account is created for one
	// test and dropped with it, on a throwaway container, and on MySQL it is also the key
	// the connection counter reads, so it must belong to no other test.
	username string
	password string
	// admin is this tier's own privileged handle, kept open for the life of the test so
	// assertions can read the server's catalogs from outside the restricted login.
	admin *sql.DB
}

// restrictedLoginPassword satisfies SQL Server's password rules without CHECK_POLICY, which the
// fixture turns off anyway. It authenticates nothing outside the test container.
const restrictedLoginPassword = "goiabadaRestricted123!"

// restrictedLoginName is a login name unique to this process and call: lowercase so PostgreSQL
// takes it unquoted, and short enough for MySQL's 32-character limit.
func restrictedLoginName() string {
	return fmt.Sprintf("goiabada_lp_%d_%d", os.Getpid(), isolatedDBCounter.Add(1))
}

// mySQLServerDSN is a connection to the server with no database selected, which is both what
// the fixture administers through and what NewMySQLDatabase's maintenance connection uses.
func mySQLServerDSN(username, password string, cfg *config.DatabaseConfig) string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/?charset=utf8mb4&parseTime=True&loc=UTC",
		username, password, cfg.Host, cfg.Port)
}

// postgresMaintenanceDSN is a connection to the postgres database, which is both what the
// fixture administers through and what NewPostgresDatabase's maintenance connection uses.
func postgresMaintenanceDSN(username, password string, cfg *config.DatabaseConfig) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/postgres", username, password, cfg.Host, cfg.Port)
}

// newRestrictedLoginDB pre-creates an isolated database and a credential that cannot create
// one, registering the drop of both on t. Built from probe/least_privilege_startup.go, which
// measured what each engine actually allows. SQL Server and MySQL get the database at the
// collation their constructor would have used, so nothing downstream reads a different one.
func newRestrictedLoginDB(t *testing.T) *restrictedLoginDB {
	t.Helper()
	cfg := config.GetDatabase()
	r := &restrictedLoginDB{
		name:     isolatedDBName(),
		username: restrictedLoginName(),
		password: restrictedLoginPassword,
	}

	switch dbType() {
	case "mysql":
		admin, err := sql.Open("mysql", mySQLServerDSN(cfg.Username, cfg.Password, cfg))
		require.NoError(t, err, "open mysql as the tier's own login")
		r.admin = admin

		mustExec(t, admin, fmt.Sprintf(
			"CREATE DATABASE %s CHARACTER SET utf8mb4 COLLATE %s", r.name, mysqlCollationAfter000040))
		mustExec(t, admin, fmt.Sprintf(
			"CREATE USER '%s'@'%%' IDENTIFIED BY '%s'", r.username, r.password))
		// Everything inside the one schema, including the DDL the migrations need, and
		// nothing server-wide: no CREATE, so this account could not create a database it was
		// not already granted on.
		mustExec(t, admin, fmt.Sprintf(
			"GRANT ALL PRIVILEGES ON %s.* TO '%s'@'%%'", r.name, r.username))
		mustExec(t, admin, "FLUSH PRIVILEGES")

		t.Cleanup(func() {
			_, _ = admin.Exec("DROP DATABASE IF EXISTS " + r.name)
			_, _ = admin.Exec(fmt.Sprintf("DROP USER IF EXISTS '%s'@'%%'", r.username))
			_ = admin.Close()
		})

	case "postgres":
		admin, err := sql.Open("pgx", postgresMaintenanceDSN(cfg.Username, cfg.Password, cfg))
		require.NoError(t, err, "open postgres as the tier's own role")
		r.admin = admin

		// NOCREATEDB spelled out rather than left to the default, because it is the whole
		// point of the fixture: this is exactly the attribute whose absence made startup fail
		// on this engine (#293 defect 2).
		mustExec(t, admin, fmt.Sprintf(
			"CREATE ROLE %s LOGIN NOCREATEDB NOSUPERUSER PASSWORD '%s'", r.username, r.password))
		mustExec(t, admin, fmt.Sprintf("CREATE DATABASE %s OWNER %s", r.name, r.username))

		t.Cleanup(func() {
			_, _ = admin.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", r.name))
			_, _ = admin.Exec("DROP ROLE IF EXISTS " + r.username)
			_ = admin.Close()
		})

	case "mssql":
		admin, err := sql.Open("sqlserver", msSQLMasterDSN(cfg))
		require.NoError(t, err, "open master as the tier's own login")
		r.admin = admin

		mustExec(t, admin, fmt.Sprintf("CREATE DATABASE [%s] COLLATE %s", r.name, mssqlCollationAfter000040))
		mustExec(t, admin, fmt.Sprintf(
			"CREATE LOGIN [%s] WITH PASSWORD = '%s', CHECK_POLICY = OFF, DEFAULT_DATABASE = [%s]",
			r.username, r.password, r.name))

		appAsAdmin, err := sql.Open("sqlserver", msSQLDatabaseDSN(cfg.Username, cfg.Password, r.name, cfg))
		require.NoError(t, err, "open the pre-created database to map the login into it")
		mustExec(t, appAsAdmin, fmt.Sprintf(
			"CREATE USER [%s] FOR LOGIN [%s]; ALTER ROLE db_owner ADD MEMBER [%s];",
			r.username, r.username, r.username))
		_ = appAsAdmin.Close()

		// The restriction that makes this fixture observe anything on SQL Server. A login
		// mapped into the application database can reach master through guest AND sees the
		// database in sys.databases from there, so the constructor's IF NOT EXISTS would find
		// it, create nothing and succeed: §1 of the agreement measured exactly that, and a
		// constructor that ignored Create would go undetected here.
		//
		// DENY VIEW ANY DATABASE takes the catalog away instead, and then the whole creating
		// path fails the way a least-privilege deployment fails: the check reads 0 rows, the
		// CREATE DATABASE inside the batch runs, and the server answers "CREATE DATABASE
		// permission denied in database 'master'". Connecting to the application database is
		// unaffected, which is the point.
		//
		// Not DENY CONNECT in master, which looks like the more direct statement of "no access
		// to master" and is not usable: it denies the login every database, the application's
		// own included, with "Login failed for user". Measured in
		// probe/mssql_deny_connect_master.go.
		mustExec(t, admin, fmt.Sprintf("DENY VIEW ANY DATABASE TO [%s]", r.username))

		t.Cleanup(func() {
			dropMsSQL(t, cfg, r.name)
			_, _ = admin.Exec(fmt.Sprintf("IF SUSER_ID(N'%s') IS NOT NULL DROP LOGIN [%s]", r.username, r.username))
			_ = admin.Close()
		})

	default:
		t.Fatalf("newRestrictedLoginDB has nothing to restrict on %s", dbType())
	}

	return r
}

// constructRestricted runs the engine's own constructor as the restricted login with
// Create false, and returns the dialect DB with its raw handle.
//
// Deliberately stops short of building a migrator, unlike newIsolatedDB: the MySQL case has to
// read the server's connection counter at the exact instant the constructor returned, and
// anything that opened a connection in between would make the number unreadable.
func (r *restrictedLoginDB) constructRestricted(t *testing.T) (migratable, *sql.DB) {
	t.Helper()
	cfg := config.GetDatabase()

	switch dbType() {
	case "mysql":
		db, err := mysqldb.NewMySQLDatabase(&mysqldb.DatabaseConfig{
			Type: "mysql", Username: r.username, Password: r.password,
			Host: cfg.Host, Port: cfg.Port, Name: r.name, Create: false,
		}, false)
		require.NoError(t, err, "NewMySQLDatabase as a login that cannot create a database")
		t.Cleanup(func() { _ = db.DB.Close() })
		return db, db.DB

	case "postgres":
		db, err := postgresdb.NewPostgresDatabase(&postgresdb.DatabaseConfig{
			Type: "postgres", Username: r.username, Password: r.password,
			Host: cfg.Host, Port: cfg.Port, Name: r.name, Create: false,
		}, false)
		require.NoError(t, err, "NewPostgresDatabase as a role holding no CREATEDB")
		t.Cleanup(func() { _ = db.DB.Close() })
		return db, db.DB

	case "mssql":
		db, err := mssqldb.NewMsSQLDatabase(&mssqldb.DatabaseConfig{
			Type: "mssql", Username: r.username, Password: r.password,
			Host: cfg.Host, Port: cfg.Port, Name: r.name, Create: false,
		}, false)
		require.NoError(t, err, "NewMsSQLDatabase as a login that cannot create a database in master")
		t.Cleanup(func() { _ = db.DB.Close() })
		return db, db.DB

	default:
		t.Fatalf("constructRestricted has no restricted login on %s", dbType())
		return nil, nil
	}
}

// connectionCount is how many connections the fixture account has made to the server since it
// was created, read from MySQL's own counter through the admin handle.
//
// This is the MySQL substitute for a privilege the engine does not have. The account is created
// for one test and dropped with it, so every connection counted is one the constructor made:
// the skipping path makes exactly one, to the application database, and a constructor that
// still opened the maintenance DSN would make two.
func (r *restrictedLoginDB) connectionCount(t *testing.T) int {
	t.Helper()
	require.Equal(t, "mysql", dbType(), "connectionCount reads MySQL's performance_schema")

	var total sql.NullInt64
	require.NoError(t, r.admin.QueryRow(
		"SELECT SUM(TOTAL_CONNECTIONS) FROM performance_schema.accounts WHERE `USER` = ?",
		r.username).Scan(&total),
		"read performance_schema.accounts for the fixture account")
	require.True(t, total.Valid,
		"performance_schema.accounts has no row for %s, so the counter cannot say anything", r.username)
	return int(total.Int64)
}

// msSQLDatabaseDSN is the connection string for a named database rather than master.
func msSQLDatabaseDSN(username, password, name string, cfg *config.DatabaseConfig) string {
	q := url.Values{}
	q.Add("database", name)
	q.Add("encrypt", "disable")
	u := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(username, password),
		Host:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		RawQuery: q.Encode(),
	}
	return u.String()
}

// mustExec runs a fixture statement and fails the test with the statement in the message when
// it does not work. Fixture setup only: a failure here is a broken fixture, not a finding.
func mustExec(t *testing.T, sqlDB *sql.DB, stmt string) {
	t.Helper()
	_, err := sqlDB.Exec(stmt)
	require.NoErrorf(t, err, "fixture statement failed: %s", stmt)
}
