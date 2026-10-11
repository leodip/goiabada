package datatests

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/mssqldb"
	"github.com/leodip/goiabada/authserver/internal/data/mysqldb"
	"github.com/leodip/goiabada/authserver/internal/data/postgresdb"
	"github.com/stretchr/testify/require"
)

// awkwardPassword carries every character RFC 3986 section 3.2.1 refuses unescaped in a URL's
// userinfo, plus the `:` that separates user from password. No `'`, because the fixture writes it
// into a CREATE LOGIN / CREATE ROLE / CREATE USER literal.
const awkwardPassword = "p%#?/@:ss1A"

// TestNewDatabase_AwkwardPasswordAndDatabaseNameConnect is seam 5 of #424: the engine's own
// constructor, as a login whose password needs escaping, creates a database whose name carries a
// space and connects to it. Create is true, so the password travels through the maintenance
// connection to create the database and through the application one to open it, and both have to
// be read by the server exactly as written. Before #424 a Sprintf'd PostgreSQL URL failed to parse this password, and a
// hand-built MySQL or PostgreSQL string failed on a database name with `/?#`.
//
// The login may create a database and nothing else it does not need, so that what it connects to
// afterwards is the database it made, owned by it. The identity it reports back is asserted too:
// a connection that reached the server as some other login would prove nothing about escaping.
func TestNewDatabase_AwkwardPasswordAndDatabaseNameConnect(t *testing.T) {
	if dbType() == data.SQLite {
		t.Skip("sqlite's DSN is a file path the operator supplies; no builder assembles one")
	}

	cfg := &appConfig.Database
	name := isolatedDBName() + " dsn"
	username := restrictedLoginName()
	ctx := context.Background()

	var sqlDB *sql.DB
	var currentUserQuery, currentDatabaseQuery string

	switch dbType() {
	case data.MySQL:
		admin, err := sql.Open("mysql", mySQLServerDSN(t, cfg.Username, cfg.Password, cfg))
		require.NoError(t, err)
		t.Cleanup(func() { _ = admin.Close() })

		mustExec(t, admin, fmt.Sprintf("CREATE USER '%s'@'%%' IDENTIFIED BY '%s'", username, awkwardPassword))
		t.Cleanup(func() { _, _ = admin.Exec(fmt.Sprintf("DROP USER IF EXISTS '%s'@'%%'", username)) })
		// Every privilege inside the one database, CREATE included, which is what lets this login
		// issue the constructor's CREATE DATABASE for it and for nothing else.
		mustExec(t, admin, fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%%'", name, username))

		db, err := mysqldb.New(context.Background(), &mysqldb.DatabaseConfig{
			Username: username, Password: awkwardPassword,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: true,
		}, false)
		require.NoError(t, err, "mysqldb.New with an awkward password and database name")
		t.Cleanup(func() { _ = db.DB.Close(); dropMySQL(t, cfg, name) })
		sqlDB = db.DB
		currentUserQuery = "SELECT SUBSTRING_INDEX(CURRENT_USER(), '@', 1)"
		currentDatabaseQuery = "SELECT DATABASE()"

	case data.Postgres:
		admin, err := sql.Open("pgx", postgresMaintenanceDSN(cfg.Username, cfg.Password, cfg))
		require.NoError(t, err)
		t.Cleanup(func() { _ = admin.Close() })

		mustExec(t, admin, fmt.Sprintf("CREATE ROLE %s LOGIN CREATEDB NOSUPERUSER PASSWORD '%s'", username, awkwardPassword))
		t.Cleanup(func() { _, _ = admin.Exec("DROP ROLE IF EXISTS " + username) })

		db, err := postgresdb.New(context.Background(), &postgresdb.DatabaseConfig{
			Username: username, Password: awkwardPassword,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: true,
		}, false)
		require.NoError(t, err, "postgresdb.New with an awkward password and database name")
		t.Cleanup(func() { _ = db.DB.Close(); dropPostgres(t, cfg, name) })
		sqlDB = db.DB
		currentUserQuery = "SELECT current_user"
		currentDatabaseQuery = "SELECT current_database()"

	case data.MSSQL:
		admin, err := sql.Open("sqlserver", msSQLMasterDSN(cfg))
		require.NoError(t, err)
		t.Cleanup(func() { _ = admin.Close() })

		mustExec(t, admin, fmt.Sprintf("CREATE LOGIN [%s] WITH PASSWORD = '%s', CHECK_POLICY = OFF", username, awkwardPassword))
		t.Cleanup(func() {
			_, _ = admin.Exec(fmt.Sprintf("IF SUSER_ID(N'%s') IS NOT NULL DROP LOGIN [%s]", username, username))
		})
		// dbcreator is the server role CREATE DATABASE needs; the login owns what it creates.
		mustExec(t, admin, fmt.Sprintf("ALTER SERVER ROLE dbcreator ADD MEMBER [%s]", username))

		db, err := mssqldb.New(context.Background(), &mssqldb.DatabaseConfig{
			Username: username, Password: awkwardPassword,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: true,
		}, false)
		require.NoError(t, err, "mssqldb.New with an awkward password and database name")
		t.Cleanup(func() { _ = db.DB.Close(); dropMsSQL(t, cfg, name) })
		sqlDB = db.DB
		currentUserQuery = "SELECT SUSER_SNAME()"
		currentDatabaseQuery = "SELECT DB_NAME()"

	default:
		t.Fatalf("unsupported db type %q", dbType())
	}

	require.NoError(t, sqlDB.PingContext(ctx), "the handle the constructor returned must reach the server")

	var gotUser, gotDatabase string
	require.NoError(t, sqlDB.QueryRowContext(ctx, currentUserQuery).Scan(&gotUser))
	require.Equal(t, username, gotUser, "the connection must be the fixture login, authenticated by the awkward password")
	require.NoError(t, sqlDB.QueryRowContext(ctx, currentDatabaseQuery).Scan(&gotDatabase))
	require.Equal(t, name, gotDatabase, "the connection must be to the database whose name carries a space")
}

// TestMySQLNew_AUsernameContainingAColonConnects: a MySQL login whose name carries a `:`, holding
// privileges on its one database and nothing else, creates that database through the constructor
// and connects to it as itself. The driver's connection-string grammar splits the user from the
// password at the first `:` and has no escape for one, so while MySQL was opened from a string
// such a login reached the server as someone else; it is opened from the driver's configuration
// now, which carries the username as written (#502 decision 11).
func TestMySQLNew_AUsernameContainingAColonConnects(t *testing.T) {
	if dbType() != data.MySQL {
		t.Skip("the `:` ceiling was the MySQL driver's connection-string grammar")
	}

	cfg := &appConfig.Database
	name := isolatedDBName() + "_colon"
	username := restrictedLoginName() + ":c"
	ctx := context.Background()

	admin, err := sql.Open("mysql", mySQLServerDSN(t, cfg.Username, cfg.Password, cfg))
	require.NoError(t, err)
	t.Cleanup(func() { _ = admin.Close() })

	mustExec(t, admin, fmt.Sprintf("CREATE USER '%s'@'%%' IDENTIFIED BY '%s'", username, awkwardPassword))
	t.Cleanup(func() { _, _ = admin.Exec(fmt.Sprintf("DROP USER IF EXISTS '%s'@'%%'", username)) })
	mustExec(t, admin, fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%%'", name, username))

	db, err := mysqldb.New(ctx, &mysqldb.DatabaseConfig{
		Username: username, Password: awkwardPassword,
		Host: cfg.Host, Port: cfg.Port, Name: name, Create: true,
	}, false)
	require.NoError(t, err, "mysqldb.New as a login whose name carries a colon")
	t.Cleanup(func() { _ = db.DB.Close(); dropMySQL(t, cfg, name) })

	var gotUser, gotDatabase string
	require.NoError(t, db.DB.QueryRowContext(ctx, "SELECT SUBSTRING_INDEX(CURRENT_USER(), '@', 1)").Scan(&gotUser))
	require.Equal(t, username, gotUser, "the connection must be the login whose name carries the colon")
	require.NoError(t, db.DB.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&gotDatabase))
	require.Equal(t, name, gotDatabase)
}
