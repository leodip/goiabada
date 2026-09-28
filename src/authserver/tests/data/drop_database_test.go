package datatests

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data/mssqldb"
	"github.com/leodip/goiabada/authserver/internal/data/mysqldb"
	"github.com/leodip/goiabada/authserver/internal/data/postgresdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDropDatabase_DropsTheDatabaseAndToleratesAnAbsentOne is each server engine's
// DropDatabase, which droptestdb runs before every local data and integration run, schemadump
// runs after each dump and this tier's fixtures run in their cleanups (#433).
//
// The database is made by the engine's own constructor at a mixed-case name, so the drop has to
// quote it the way the create did: unquoted, PostgreSQL folds the name and drops nothing. The
// constructor's handle is still open, with a live session, when the drop runs, because that is
// what WITH (FORCE) on PostgreSQL and SINGLE_USER WITH ROLLBACK IMMEDIATE on SQL Server are for,
// and a plain DROP DATABASE refuses it on both. A second drop of the database, absent by then,
// answers nil, because droptestdb runs before a tier whose database may never have been created.
//
// SQLite is skipped: it has no server to drop a database from, only a file.
func TestDropDatabase_DropsTheDatabaseAndToleratesAnAbsentOne(t *testing.T) {
	if dbType() == "sqlite" || dbType() == "" {
		t.Skip("sqlite has no server to drop a database from, only a file")
	}

	cfg := config.GetDatabase()
	name := "Goiabada_Drop_" + strings.TrimPrefix(isolatedDBName(), "goiabada_mig_")
	t.Cleanup(func() { dropServerDatabase(t, cfg, name) })

	var handle *sql.DB
	var drop func() error
	switch dbType() {
	case "mysql":
		engineCfg := &mysqldb.DatabaseConfig{
			Type: "mysql", Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: true,
		}
		db, err := mysqldb.NewMySQLDatabase(engineCfg, false)
		require.NoErrorf(t, err, "NewMySQLDatabase at %s", name)
		handle = db.DB
		drop = func() error { return mysqldb.DropDatabase(context.Background(), engineCfg) }
	case "postgres":
		engineCfg := &postgresdb.DatabaseConfig{
			Type: "postgres", Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: true,
		}
		db, err := postgresdb.NewPostgresDatabase(engineCfg, false)
		require.NoErrorf(t, err, "NewPostgresDatabase at %s", name)
		handle = db.DB
		drop = func() error { return postgresdb.DropDatabase(context.Background(), engineCfg) }
	case "mssql":
		engineCfg := &mssqldb.DatabaseConfig{
			Type: "mssql", Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: true,
		}
		db, err := mssqldb.NewMsSQLDatabase(engineCfg, false)
		require.NoErrorf(t, err, "NewMsSQLDatabase at %s", name)
		handle = db.DB
		drop = func() error { return mssqldb.DropDatabase(context.Background(), engineCfg) }
	default:
		t.Fatalf("unsupported db type %q", dbType())
	}
	t.Cleanup(func() { _ = handle.Close() })

	require.NoError(t, handle.PingContext(context.Background()), "open a session on the database before dropping it")
	require.True(t, serverDatabaseExists(t, name), "the constructor created nothing to drop")

	require.NoError(t, drop())
	assert.False(t, serverDatabaseExists(t, name), "the database is still on the server after its drop")

	assert.NoError(t, drop(), "dropping a database that is not there is not an error")
}
