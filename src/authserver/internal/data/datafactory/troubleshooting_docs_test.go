package datafactory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The deploying troubleshooting pages are titled and searched by the message an operator reads in
// the auth server's log, so each message they quote is held here to what a start actually answers:
// a page quoting a message the server no longer writes sends its reader nowhere (#522 decision 17).
const (
	readonlyDatabasePage = "site/src/content/docs/troubleshooting/attempt-to-write-a-readonly-database.mdx"
	migrationLockPage    = "site/src/content/docs/troubleshooting/waiting-for-the-migration-lock-or-marked-dirty.mdx"
	databaseConnectPage  = "site/src/content/docs/troubleshooting/crashloopbackoff-or-unable-to-create-the-database-connection.mdx"
)

func troubleshootingPage(t *testing.T, page string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(filepath.Dir(guard.SourceRoot(t)), page))
	require.NoError(t, err, "the troubleshooting page is where the docs send an operator reading this message")
	return string(body)
}

// sqliteAt writes a SQLite database migrated to version, closed, and answers its path.
func sqliteAt(t *testing.T, dir string, version int) string {
	t.Helper()
	dsn := filepath.Join(dir, "goiabada.db")
	database, err := sqlitedb.New(context.Background(), dsn, false)
	require.NoError(t, err)
	m, err := database.NewMigrator(context.Background(), nil)
	require.NoError(t, err)
	require.NoError(t, m.Migrate(context.Background(), version))
	require.NoError(t, database.DB.Close())
	return dsn
}

// sqliteHead is the version this binary migrates a SQLite database to.
func sqliteHead(t *testing.T) int {
	t.Helper()
	head, _ := sqliteMigrationSet(t)
	return head
}

// sqliteBelowHead is the version the SQLite set carries just under head, so a start has one
// migration to run.
func sqliteBelowHead(t *testing.T) int {
	t.Helper()
	database, err := sqlitedb.New(context.Background(), filepath.Join(t.TempDir(), "probe.db"), false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.DB.Close() })
	m, err := database.NewMigrator(context.Background(), nil)
	require.NoError(t, err)
	plan, err := m.Plan(context.Background(), m.Head())
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(plan), 2, "the SQLite set carries more than one migration")
	return plan[len(plan)-2]
}

func startSQLite(t *testing.T, dsn string) error {
	t.Helper()
	database, err := NewDatabase(context.Background(), &config.DatabaseConfig{Type: "sqlite", DSN: dsn},
		[]byte("0123456789abcdef0123456789abcdef"), nil, false)
	if err == nil {
		concrete, ok := database.(*sqlitedb.Database)
		require.True(t, ok)
		require.NoError(t, concrete.DB.Close())
	}
	return err
}

// TestReadonlyDatabasePage_QuotesWhatAStartAnswers: a SQLite file the auth server's user cannot
// write is refused at start in one of two words, depending on what it cannot write. A directory it
// cannot create the WAL's files in fails the connection; a file it cannot write, beside a directory
// it can, connects read-only and fails the first write, which on an upgrade is the migration's
// version marker. With nothing to migrate the start writes nothing and succeeds, which the page says
// too. The permissions are the file owner's own, and root writes a file whatever its mode, so as
// root the test runs itself again as an unprivileged user. It used to skip there, and since the dev
// container and CI's test containers run as root, no automated run checked the page.
func TestReadonlyDatabasePage_QuotesWhatAStartAnswers(t *testing.T) {
	if os.Geteuid() == 0 {
		runAsUnprivileged(t, "TestReadonlyDatabasePage_QuotesWhatAStartAnswers")
		return
	}
	page := troubleshootingPage(t, readonlyDatabasePage)

	t.Run("a directory the server cannot write", func(t *testing.T) {
		dir := t.TempDir()
		dsn := sqliteAt(t, dir, sqliteBelowHead(t))
		require.NoError(t, os.Chmod(dir, 0o555))
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

		err := startSQLite(t, dsn)
		require.Error(t, err)
		assert.Contains(t, page, "`"+err.Error()+"`", "the page quotes the refusal a start answers")
	})

	t.Run("a file the server cannot write, with a migration to run", func(t *testing.T) {
		dir := t.TempDir()
		dsn := sqliteAt(t, dir, sqliteBelowHead(t))
		require.NoError(t, os.Chmod(dsn, 0o444))

		err := startSQLite(t, dsn)
		require.Error(t, err)
		assert.Contains(t, page, "`"+err.Error()+"`", "the page quotes the refusal a start answers")
	})

	t.Run("a file the server cannot write, with nothing to migrate", func(t *testing.T) {
		dir := t.TempDir()
		dsn := sqliteAt(t, dir, sqliteHead(t))
		require.NoError(t, os.Chmod(dsn, 0o444))

		assert.NoError(t, startSQLite(t, dsn), "a start that writes nothing is not refused, so the first request that writes is")
	})
}

// TestMigrationLockPage_QuotesTheRecordsAndTheRefusals: the page names the start's records about
// the schema and quotes the opening of the two refusals a start gives a database it will not
// migrate, a dirty one and one a newer release migrated. The versions are the ones this test sets,
// which the page uses as its examples.
func TestMigrationLockPage_QuotesTheRecordsAndTheRefusals(t *testing.T) {
	page := troubleshootingPage(t, migrationLockPage)

	t.Run("the records", func(t *testing.T) {
		capture := logtest.CaptureSlog(t)
		progress := &startupProgress{ctx: context.Background()}
		progress.WaitingForLock()
		progress.Migrating(46, 47, 1)
		require.NoError(t, startSQLite(t, sqliteAt(t, t.TempDir(), sqliteHead(t))))

		for _, message := range []string{"waiting for the migration lock", "migrating the database", "no need to migrate the database"} {
			require.Len(t, recordsNamed(capture, message), 1, "the start writes %q", message)
			assert.Contains(t, page, "`"+message+"`", "the page names the record")
		}
	})

	t.Run("a dirty schema", func(t *testing.T) {
		dsn := sqliteAt(t, t.TempDir(), 47)
		markSchema(t, dsn, "UPDATE schema_migrations SET dirty = 1")

		err := startSQLite(t, dsn)
		require.Error(t, err)
		opening, _, found := strings.Cut(err.Error(), " Goiabada will not migrate")
		require.True(t, found, "the refusal says why it will not migrate: %v", err)
		assert.Equal(t, "unable to migrate the database: the database records version 000047 and is marked dirty, so a migration did not finish.", opening)
		assert.Contains(t, page, opening, "the page quotes the refusal's opening")
	})

	t.Run("a schema a newer release migrated", func(t *testing.T) {
		dsn := sqliteAt(t, t.TempDir(), sqliteHead(t))
		markSchema(t, dsn, "UPDATE schema_migrations SET version = 999999")

		err := startSQLite(t, dsn)
		require.Error(t, err)
		opening, _, found := strings.Cut(err.Error(), ": the highest")
		require.True(t, found, "the refusal names the highest migration this release has: %v", err)
		assert.Contains(t, page, opening, "the page quotes the refusal's opening")
	})
}

func markSchema(t *testing.T, dsn, statement string) {
	t.Helper()
	database, err := sqlitedb.New(context.Background(), dsn, false)
	require.NoError(t, err)
	_, err = database.DB.ExecContext(context.Background(), statement)
	require.NoError(t, err)
	require.NoError(t, database.DB.Close())
}

// TestDatabaseConnectPage_NamesEveryEnginesConnectionFailure: a start that cannot reach the
// database is refused with a different opening on each engine and on each side of
// GOIABADA_DB_CREATE, since the creating arm connects first to a different database. Port 1 on the
// loopback refuses every connection, so each start fails at once without a database to run.
func TestDatabaseConnectPage_NamesEveryEnginesConnectionFailure(t *testing.T) {
	page := troubleshootingPage(t, databaseConnectPage)

	for _, engine := range []string{"postgres", "mysql", "mssql"} {
		for _, create := range []bool{true, false} {
			cfg := &config.DatabaseConfig{Type: engine, Host: "127.0.0.1", Port: 1, Name: "goiabada",
				Username: "goiabada", Password: "unused", Create: create, MaxOpenConns: 1}
			_, err := NewDatabase(context.Background(), cfg, []byte("0123456789abcdef0123456789abcdef"), nil, false)
			require.Error(t, err, "%s with create %v", engine, create)

			opening, _, found := strings.Cut(err.Error(), ": ")
			require.True(t, found, "%s with create %v: %v", engine, create, err)
			assert.Contains(t, page, "`"+opening+"`", "%s with create %v answers %q, which the page does not name", engine, create, opening)
		}
	}
}
