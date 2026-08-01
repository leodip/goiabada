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
	"github.com/leodip/goiabada/core/data/sqlitedb"
	"github.com/stretchr/testify/require"
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
			Host: cfg.Host, Port: cfg.Port, Name: name,
		}, false)
		require.NoError(t, err, "NewMySQLDatabase")
		t.Cleanup(func() { _ = db.DB.Close(); dropMySQL(t, cfg, name) })
		return newIsolated(t, db, db.DB)

	case "postgres":
		name := isolatedDBName()
		db, err := postgresdb.NewPostgresDatabase(&postgresdb.DatabaseConfig{
			Type: "postgres", Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name,
		}, false)
		require.NoError(t, err, "NewPostgresDatabase")
		t.Cleanup(func() { _ = db.DB.Close(); dropPostgres(t, cfg, name) })
		return newIsolated(t, db, db.DB)

	case "mssql":
		name := isolatedDBName()
		db, err := mssqldb.NewMsSQLDatabase(&mssqldb.DatabaseConfig{
			Type: "mssql", Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name,
		}, false)
		require.NoError(t, err, "NewMsSQLDatabase")
		t.Cleanup(func() { _ = db.DB.Close(); dropMsSQL(t, cfg, name) })
		return newIsolated(t, db, db.DB)

	default:
		t.Fatalf("unsupported db type %q", dbType())
		return nil
	}
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

// indexShape is one index as the engine's catalog reports it. Exists is derived from
// Columns rather than counted separately: an index with no key columns is not a thing
// any of the four engines can produce.
type indexShape struct {
	Exists  bool
	Unique  bool
	Columns []string // key columns, in index order
}

// describeIndex reads an index's uniqueness and key columns from the configured
// dialect's catalog. It exists because asserting only that an index NAME is present
// lets a wrongly built index pass: created on the wrong column, or created UNIQUE on
// a column that is deliberately repeated, both of which are the failures worth
// catching.
//
// Every query normalises uniqueness to '1' or '0' in SQL rather than in Go. The
// polarity is not consistent across the catalogs (MySQL reports NON_UNIQUE, which is
// 0 for a unique index) and the types are not either (a PostgreSQL boolean, a SQL
// Server bit, a SQLite integer), so resolving both at the source keeps one meaning
// on the Go side.
func describeIndex(t *testing.T, h *isolatedDB, table, index string) indexShape {
	t.Helper()

	var q string
	switch dbType() {
	case "mysql":
		q = fmt.Sprintf(`SELECT COLUMN_NAME, CASE WHEN NON_UNIQUE = 0 THEN '1' ELSE '0' END
			FROM information_schema.statistics
			WHERE table_schema = DATABASE() AND table_name = '%s' AND index_name = '%s'
			ORDER BY SEQ_IN_INDEX`, table, index)
	case "postgres":
		// indkey is an int2vector of column numbers; unnesting it WITH ORDINALITY is
		// what preserves the index's own column order. indkey holds INCLUDE columns
		// after the key ones, so the ordinal is bounded by indnkeyatts to keep this
		// branch reporting key columns only, which is what the mssql branch's
		// is_included_column filter does and what Columns is documented to hold.
		q = fmt.Sprintf(`SELECT a.attname, CASE WHEN ix.indisunique THEN '1' ELSE '0' END
			FROM pg_index ix
			JOIN pg_class i ON i.oid = ix.indexrelid
			JOIN pg_class tb ON tb.oid = ix.indrelid
			JOIN unnest(ix.indkey::smallint[]) WITH ORDINALITY AS k(attnum, ord) ON true
			JOIN pg_attribute a ON a.attrelid = tb.oid AND a.attnum = k.attnum
			WHERE tb.relname = '%s' AND i.relname = '%s'
			  AND k.ord <= ix.indnkeyatts
			ORDER BY k.ord`, table, index)
	case "mssql":
		// is_included_column = 0 keeps INCLUDE columns out: they are payload, not key
		// columns, and they carry key_ordinal 0.
		q = fmt.Sprintf(`SELECT c.name, CASE WHEN i.is_unique = 1 THEN '1' ELSE '0' END
			FROM sys.indexes i
			JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
			JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
			WHERE i.object_id = OBJECT_ID('dbo.%s') AND i.name = '%s'
			  AND ic.is_included_column = 0
			ORDER BY ic.key_ordinal`, table, index)
	default: // sqlite
		// The comma join is required: pragma_index_info takes its argument from the
		// row to its left, which SQLite only allows for table-valued functions in
		// that position.
		q = fmt.Sprintf(`SELECT ii.name, CASE WHEN il."unique" = 1 THEN '1' ELSE '0' END
			FROM pragma_index_list('%s') AS il, pragma_index_info(il.name) AS ii
			WHERE il.name = '%s'
			ORDER BY ii.seqno`, table, index)
	}

	rows, err := h.SQL.Query(q)
	require.NoErrorf(t, err, "index catalog lookup: %s on %s", index, table)
	defer func() { _ = rows.Close() }()

	shape := indexShape{}
	for rows.Next() {
		var col, uniqueFlag string
		require.NoErrorf(t, rows.Scan(&col, &uniqueFlag),
			"scan index catalog row: %s on %s", index, table)
		shape.Columns = append(shape.Columns, col)
		shape.Unique = uniqueFlag == "1"
	}
	require.NoErrorf(t, rows.Err(), "iterate index catalog: %s on %s", index, table)

	shape.Exists = len(shape.Columns) > 0
	return shape
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

func dropMsSQL(t *testing.T, cfg *config.DatabaseConfig, name string) {
	q := url.Values{}
	q.Add("database", "master")
	q.Add("encrypt", "disable")
	u := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(cfg.Username, cfg.Password),
		Host:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		RawQuery: q.Encode(),
	}
	sqlDB, err := sql.Open("sqlserver", u.String())
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
