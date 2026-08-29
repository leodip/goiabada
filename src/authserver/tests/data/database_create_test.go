package datatests

import (
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/data/mssqldb"
	"github.com/leodip/goiabada/core/data/mysqldb"
	"github.com/leodip/goiabada/core/data/postgresdb"
	"github.com/leodip/goiabada/core/data/sqlitedb"
	"github.com/stretchr/testify/require"
)

// The three engine constructors that open a maintenance connection and issue a create
// statement. GOIABADA_DB_CREATE decides whether they do, and these tests own both answers at
// the constructor boundary (#293).
//
// Why the boundary and not data.NewDatabase: the factory also migrates and runs the startup
// data tasks, so a failure there could be any of three things. The constructor's contract is
// "given a config, return a usable handle or an error", and that is what an operator's
// deployment either satisfies or does not.

// TestNewDatabase_CreateFalse_StartsUnderALeastPrivilegeLogin is the case #293 exists for, and
// the one that cannot be faked.
//
// This tier connects as root, sa or postgres, so a test that pre-created the database and set
// Create: false would pass with the maintenance connection still opened and the create still
// issued: a superuser can do both. The restricted login is what observes their absence from
// outside, which is why the fixture goes to the trouble of building one per engine.
//
// PostgreSQL is where this used to be a hard failure rather than a nicety: with the database
// present and the role owning it but holding no CREATEDB, the old unconditional CREATE DATABASE
// gave "permission denied to create database (SQLSTATE 42501)", which the constructor's
// "already exists" tolerance does not match, so the server would not start. The production
// checklist's "don't use root/admin accounts" was advice a PostgreSQL reader could not follow.
func TestNewDatabase_CreateFalse_StartsUnderALeastPrivilegeLogin(t *testing.T) {
	if dbType() == "sqlite" || dbType() == "" {
		t.Skip("sqlite has no login and no create statement, so there is nothing to restrict")
	}

	r := newRestrictedLoginDB(t)
	db, sqlDB := r.constructRestricted(t)

	if dbType() == "mysql" {
		// Read before anything else touches the server. MySQL cannot deny the maintenance DSN
		// to a login it allows the application DSN to, so the privilege above proves nothing
		// here and this counter is what does: one connection is the skipping path, two is a
		// constructor that still opened the no-database DSN.
		require.Equal(t, 1, r.connectionCount(t),
			"with Create false the constructor must open exactly one connection, to the application database; a second means the maintenance DSN was still opened")
	}

	// Migrating the full chain and then reading through the handle is the rest of the claim:
	// the restricted login does not merely connect, it can do everything Goiabada needs.
	h := newIsolated(t, db, sqlDB)
	require.NoError(t, h.Migrator.Up(), "migrate the full chain as the restricted login")

	var clients int
	require.NoError(t, h.SQL.QueryRow("SELECT COUNT(*) FROM clients").Scan(&clients),
		"read through the handle the constructor returned")
	require.Equal(t, 0, clients, "the chain migrates an empty database, it does not seed one")
}

// TestNewDatabase_CreateFalse_AbsentDatabaseIsTheConstructorsError holds seam 1's third case:
// the operator said the database was there and it is not.
//
// Decision 7 chose to let the engine's own error stand rather than detect the case, so what is
// pinned here is that the error arrives AT THE CONSTRUCTOR carrying that text. Two of the three
// engines needed a change for that to be true: sql.Open only parses a DSN, so NewMySQLDatabase
// and NewPostgresDatabase used to return a usable-looking handle and a nil error, and the
// failure surfaced later inside the migrator as somebody else's problem.
func TestNewDatabase_CreateFalse_AbsentDatabaseIsTheConstructorsError(t *testing.T) {
	if dbType() == "sqlite" || dbType() == "" {
		t.Skip("sqlite has no create statement to skip; an absent file is decided by the DSN's mode")
	}

	cfg := config.GetDatabase()
	name := isolatedDBName()

	var err error
	var wantText string
	switch dbType() {
	case "mysql":
		_, err = mysqldb.NewMySQLDatabase(&mysqldb.DatabaseConfig{
			Type: "mysql", Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: false,
		}, false)
		wantText = "Unknown database"
	case "postgres":
		_, err = postgresdb.NewPostgresDatabase(&postgresdb.DatabaseConfig{
			Type: "postgres", Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: false,
		}, false)
		wantText = "does not exist"
	case "mssql":
		_, err = mssqldb.NewMsSQLDatabase(&mssqldb.DatabaseConfig{
			Type: "mssql", Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: false,
		}, false)
		wantText = "Cannot open database"
	default:
		t.Fatalf("unsupported db type %q", dbType())
	}

	require.Error(t, err, "Create false against an absent database must not return a usable handle")
	require.Containsf(t, err.Error(), wantText,
		"the engine's own missing-database error is what decision 7 chose to let stand, and it must reach the caller intact")

	// And nothing was created on the way to that error, which is the other half of the claim:
	// the whole point of the setting is that a deployment which forbids creating a database is
	// not asked to.
	require.False(t, serverDatabaseExists(t, name), "Create false must create nothing")
}

// TestNewMsSQLDatabase_CreateTrue_LeavesAPreCreatedDatabaseAlone keeps IF NOT EXISTS pinned.
//
// newPreCreatedMsSQLDB used to be what held it: it constructed over an operator's database and
// asserted the collation survived. It now passes Create: false, so its assertion is trivially
// true, no statement having run that could have changed anything. This is the same assertion on
// the arm where the statement DOES run, which is the one goal 4 is about: an operator who sets
// nothing still gets today's behaviour, and today's behaviour leaves their database alone.
//
// SQL Server only, because it is the only engine where the operator's choice is permanent:
// ALTER DATABASE ... COLLATE blocks against a live connection pool, so no migration can repair
// a database default, and every string column a future migration adds without spelling COLLATE
// inherits it (#283 decision 4).
func TestNewMsSQLDatabase_CreateTrue_LeavesAPreCreatedDatabaseAlone(t *testing.T) {
	if dbType() != "mssql" {
		t.Skipf("%s has no database default collation an operator's CREATE DATABASE could fix in place", dbType())
	}

	// The container's stock server default: case-insensitive, accent-sensitive and not UTF-8,
	// so it is neither the collation Goiabada pinned before #283 nor the one it pins after, and
	// a database that came out at it cannot be mistaken for one the constructor created.
	const operatorCollation = "SQL_Latin1_General_CP1_CI_AS"

	cfg := config.GetDatabase()
	name := isolatedDBName()

	master, err := sql.Open("sqlserver", msSQLMasterDSN(cfg))
	require.NoError(t, err, "open master to pre-create the database")
	defer func() { _ = master.Close() }()
	mustExec(t, master, "CREATE DATABASE ["+name+"] COLLATE "+operatorCollation)
	t.Cleanup(func() { dropMsSQL(t, cfg, name) })

	db, err := mssqldb.NewMsSQLDatabase(&mssqldb.DatabaseConfig{
		Type: "mssql", Username: cfg.Username, Password: cfg.Password,
		Host: cfg.Host, Port: cfg.Port, Name: name, Create: true,
	}, false)
	require.NoError(t, err, "NewMsSQLDatabase on the creating arm over a database that is already there")
	t.Cleanup(func() { _ = db.DB.Close() })

	require.Equal(t, operatorCollation, readDatabaseDefaultCollation(t, db.DB),
		"the creating arm's CREATE DATABASE is IF NOT EXISTS, so an operator's database and its collation stand")
}

// TestSQLiteConfigHasNoCreateField is seam 2, and it is a test rather than a comment because
// the compiler is otherwise the only witness and it would stop being one the moment somebody
// added the field for symmetry.
//
// Decision 4: GOIABADA_DB_CREATE does not apply to SQLite. There is no create statement and no
// maintenance connection, and what decides whether an absent file is created is the operator's
// own DSN. Giving the config a field would promise a control that does nothing.
func TestSQLiteConfigHasNoCreateField(t *testing.T) {
	_, found := reflect.TypeOf(sqlitedb.DatabaseConfig{}).FieldByName("Create")
	require.False(t, found,
		"sqlitedb.DatabaseConfig must carry no Create field: SQLite has no create statement for it to govern, and mode=rw in the DSN is the equivalent (#293 decision 4)")
}

// TestNewSQLiteDatabase_ModeRWDoesNotCreateTheFile is the other half of decision 4: the thing
// an operator who set GOIABADA_DB_CREATE=false globally actually wants on SQLite is in the DSN,
// and it works. modernc.org/sqlite honours SQLite's own mode=rw, so an absent file is an error
// rather than a new empty database.
//
// Not engine-specific: it constructs a SQLite database directly, so it is worth running in
// every engine's job.
func TestNewSQLiteDatabase_ModeRWDoesNotCreateTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "absent.db")

	_, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{
		Type: "sqlite", DSN: "file:" + path + "?mode=rw",
	}, false)
	require.Error(t, err, "mode=rw against an absent file must fail rather than create it")

	_, statErr := os.Stat(path)
	require.Truef(t, os.IsNotExist(statErr),
		"mode=rw must not have created %s, but stat says %v", path, statErr)
}

// serverDatabaseExists asks the server's own catalog, through the tier's privileged
// credential, whether a database is there. Used to show that the skipping path created nothing
// on its way to failing.
func serverDatabaseExists(t *testing.T, name string) bool {
	t.Helper()
	cfg := config.GetDatabase()

	var dsn, driver, query string
	switch dbType() {
	case "mysql":
		driver, dsn = "mysql", mySQLServerDSN(cfg.Username, cfg.Password, cfg)
		query = "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?"
	case "postgres":
		driver, dsn = "pgx", postgresMaintenanceDSN(cfg.Username, cfg.Password, cfg)
		query = "SELECT COUNT(*) FROM pg_database WHERE datname = $1"
	case "mssql":
		driver, dsn = "sqlserver", msSQLMasterDSN(cfg)
		query = "SELECT COUNT(*) FROM sys.databases WHERE name = @p1"
	default:
		t.Fatalf("%s has no server catalog of databases", dbType())
	}

	sqlDB, err := sql.Open(driver, dsn)
	require.NoError(t, err, "open the server to read its catalog")
	defer func() { _ = sqlDB.Close() }()

	var n int
	require.NoError(t, sqlDB.QueryRow(query, name).Scan(&n), "count databases named %s", name)
	return n > 0
}
