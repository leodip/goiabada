package datatests

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
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
			Host: cfg.Host, Port: cfg.Port, Name: name,
		}, false)
		require.NoError(t, err, "NewMySQLDatabase")
		t.Cleanup(func() { _ = db.DB.Close(); dropMySQL(t, cfg, name) })
		assertCreatedDatabaseCollation(t, db.DB)
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

// indexShape is one index as the engine's catalog reports it. Exists is derived from
// Columns rather than counted separately: an index with no key columns is not a thing
// any of the four engines can produce.
type indexShape struct {
	Name    string
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
		// after the key ones, so the position is bounded by indnkeyatts to keep this
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

	shape := indexShape{Name: index}
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

// columnShape, foreignKeyShape and tableShape are one table as the engine's catalog
// reports it. dumpTable fills them; see its comment for why the fields are these.
type columnShape struct {
	Name     string
	Type     string // the engine's own spelling, verbatim
	Nullable bool
	Default  string // the engine's own default expression, verbatim; "" when there is none

	// Collation is what the engine says decides `=` and ordering for this column, in the
	// engine's own vocabulary: a utf8mb4_* name on MySQL, a pg_collation name on
	// PostgreSQL (which is "default" for every column here, since none carries an
	// override), a Latin1_General_* name on SQL Server, and the declared COLLATE on
	// SQLite, or BINARY when the declaration omits one. "" for a column that holds no
	// string. It is read because collation is the whole of what migration 000040 changes,
	// and nothing else in this dump can see it: two columns identical in type,
	// nullability, default and index can still disagree about whether MyApp and myapp are
	// one value (#283).
	Collation string

	// DefaultName is the default constraint's own name, which SQL Server alone gives one.
	// MySQL, PostgreSQL and SQLite attach a default to the column with no nameable object
	// behind it, so this stays "" there. It is in the shape because a migration that drops
	// an auto-named constraint and adds a named one back leaves Default identical and is
	// otherwise invisible to a before/after comparison, and the name is the entire reason
	// a later migration can drop the constraint without a catalog lookup.
	DefaultName string
}

// foreignKeyShape identifies a foreign key by the tuple every catalog reports, and
// deliberately not by its constraint name. SQLite's PRAGMA foreign_key_list returns
// (id, seq, table, from, to, on_update, on_delete, match) and omits the name even when
// the table declares CONSTRAINT fk_named, so requiring a name would force a parser over
// sqlite_schema.sql. A composite key would produce one entry per column pair, which the
// two tables this is used on do not have.
type foreignKeyShape struct {
	Column    string
	RefTable  string
	RefColumn string
	OnDelete  string // CASCADE, NO ACTION, RESTRICT, SET NULL or SET DEFAULT
}

// tableShape holds the three projections sorted, so two dumps of the same table compare
// directly. Columns are sorted by name rather than left in ordinal order on purpose:
// column order is not something this change is trying to make equal across engines, and
// a rebuild that reorders columns is not a defect.
type tableShape struct {
	Columns     []columnShape
	Indexes     []indexShape
	ForeignKeys []foreignKeyShape
}

// dumpTable reads a table's columns, indexes and foreign keys out of the configured
// dialect's catalog, so a migration that rebuilds a table can be checked by comparing
// the dump before against the dump after. That is the property a hand-written
// CREATE TABLE cannot otherwise be held to: a dropped column, a lost index or a changed
// foreign key action are all silent, and PRAGMA foreign_key_check does not see any of
// them.
//
// It compares a table against ITSELF on one engine, never across engines, so it records
// each engine's own spelling verbatim and makes no attempt to map TEXT, varchar(256) and
// nvarchar(256) onto a common vocabulary. A four-engine comparison needs that mapping
// and is #284's job, not this helper's.
//
// Every branch normalises in SQL rather than in Go, following describeIndex and for the
// same reason: nullability is a flag on SQLite, a boolean on PostgreSQL, a bit on SQL
// Server and a YES/NO string on MySQL, and the on-delete action is a word on three
// engines and a pg_constraint.confdeltype letter on the fourth. Sorting is the one thing
// done in Go, so it is one rule rather than four.
func dumpTable(t *testing.T, h *isolatedDB, table string) tableShape {
	t.Helper()

	shape := tableShape{
		Columns:     dumpColumns(t, h, table),
		Indexes:     dumpIndexes(t, h, table),
		ForeignKeys: dumpForeignKeys(t, h, table),
	}

	// A table with no columns is not something any of the four engines can produce, so
	// it means the branch above read the wrong catalog or the wrong name. Failing here
	// is what stops an empty dump being compared against another empty dump and read as
	// "nothing changed".
	require.NotEmptyf(t, shape.Columns, "dumpTable(%s) read no columns on %s", table, dbType())

	sort.Slice(shape.Columns, func(i, j int) bool { return shape.Columns[i].Name < shape.Columns[j].Name })
	sort.Slice(shape.Indexes, func(i, j int) bool { return shape.Indexes[i].Name < shape.Indexes[j].Name })
	sort.Slice(shape.ForeignKeys, func(i, j int) bool {
		a, b := shape.ForeignKeys[i], shape.ForeignKeys[j]
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		if a.RefTable != b.RefTable {
			return a.RefTable < b.RefTable
		}
		return a.RefColumn < b.RefColumn
	})
	return shape
}

// dumpColumns reads one table's columns. Every branch returns the same six values in the
// same order, so the scan below is one loop: name, type, nullability, default expression,
// collation and default constraint name. The last two are the columns migration 000040
// moves and are documented on columnShape.
func dumpColumns(t *testing.T, h *isolatedDB, table string) []columnShape {
	t.Helper()

	var q string
	switch dbType() {
	case "mysql":
		// COLUMN_TYPE rather than DATA_TYPE: it carries the length, so varchar(64)
		// shrinking to varchar(16) is visible. COLLATION_NAME is NULL for a column that
		// holds no string, which is the '' this reports.
		q = fmt.Sprintf(`SELECT COLUMN_NAME, COLUMN_TYPE,
			CASE WHEN IS_NULLABLE = 'YES' THEN '1' ELSE '0' END,
			COALESCE(COLUMN_DEFAULT, ''),
			COALESCE(COLLATION_NAME, ''), ''
			FROM information_schema.columns
			WHERE table_schema = DATABASE() AND table_name = '%s'`, table)
	case "postgres":
		// format_type renders the length the way the DDL spells it; pg_get_expr renders
		// the default the same way. information_schema would give both in two columns
		// that then have to be pasted together in Go.
		//
		// attcollation is the collation the column actually uses, which for every column
		// in this schema is the database's own: none declares an override. It resolves
		// through pg_collation to the name "default", and 0 for a column that holds no
		// string, which is the '' this reports. PostgreSQL names no default constraint,
		// so the sixth value is a literal.
		q = fmt.Sprintf(`SELECT a.attname, format_type(a.atttypid, a.atttypmod),
			CASE WHEN a.attnotnull THEN '0' ELSE '1' END,
			COALESCE(pg_get_expr(d.adbin, d.adrelid), ''),
			COALESCE((SELECT co.collname FROM pg_collation co WHERE co.oid = a.attcollation), ''), ''
			FROM pg_attribute a
			JOIN pg_class c ON c.oid = a.attrelid
			JOIN pg_namespace n ON n.oid = c.relnamespace
			LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
			WHERE c.relname = '%s' AND n.nspname = current_schema()
			  AND a.attnum > 0 AND NOT a.attisdropped`, table)
	case "mssql":
		// sys.columns.max_length is bytes, so an NVARCHAR's declared length is half of
		// it, and -1 is the (max) form. sys.default_constraints is joined rather than
		// reading INFORMATION_SCHEMA.COLUMN_DEFAULT because it is the same value and
		// this is the catalog the rest of the mssql migrations already work against.
		q = fmt.Sprintf(`SELECT c.name,
			ty.name + CASE
			  WHEN ty.name IN ('nvarchar','nchar') AND c.max_length = -1 THEN '(max)'
			  WHEN ty.name IN ('nvarchar','nchar') THEN '(' + CAST(c.max_length / 2 AS VARCHAR(10)) + ')'
			  WHEN ty.name IN ('varchar','char','varbinary','binary') AND c.max_length = -1 THEN '(max)'
			  WHEN ty.name IN ('varchar','char','varbinary','binary') THEN '(' + CAST(c.max_length AS VARCHAR(10)) + ')'
			  WHEN ty.name IN ('decimal','numeric') THEN '(' + CAST(c.precision AS VARCHAR(10)) + ',' + CAST(c.scale AS VARCHAR(10)) + ')'
			  WHEN ty.name IN ('datetime2','time','datetimeoffset') THEN '(' + CAST(c.scale AS VARCHAR(10)) + ')'
			  ELSE '' END,
			CASE WHEN c.is_nullable = 1 THEN '1' ELSE '0' END,
			COALESCE(dc.definition, ''),
			COALESCE(c.collation_name, ''), COALESCE(dc.name, '')
			FROM sys.columns c
			JOIN sys.types ty ON ty.user_type_id = c.user_type_id
			LEFT JOIN sys.default_constraints dc
			  ON dc.parent_object_id = c.object_id AND dc.parent_column_id = c.column_id
			WHERE c.object_id = OBJECT_ID('dbo.%s')`, table)
	default: // sqlite
		// pragma_table_info reports the DECLARED type, which is what a rebuild has to
		// reproduce; SQLite's own storage class would collapse every spelling onto five
		// values and hide exactly the drift this exists to catch.
		//
		// pragma_table_info projects cid, name, type, notnull, dflt_value and pk, and
		// nothing else: a TEXT column and a TEXT COLLATE NOCASE column are
		// indistinguishable through it, measured. So the collation is filled in below
		// from the declaration in sqlite_schema, and the two literals here keep every
		// branch returning the same six values.
		q = fmt.Sprintf(`SELECT name, type,
			CASE WHEN "notnull" = 0 THEN '1' ELSE '0' END,
			COALESCE(dflt_value, ''), '', ''
			FROM pragma_table_info('%s')`, table)
	}

	rows, err := h.SQL.Query(q)
	require.NoErrorf(t, err, "column catalog lookup on %s", table)
	defer func() { _ = rows.Close() }()

	var cols []columnShape
	for rows.Next() {
		var name, typ, nullable, def, collation, defName string
		require.NoErrorf(t, rows.Scan(&name, &typ, &nullable, &def, &collation, &defName),
			"scan column catalog row on %s", table)
		cols = append(cols, columnShape{Name: name, Type: typ, Nullable: nullable == "1",
			Default: def, Collation: collation, DefaultName: defName})
	}
	require.NoErrorf(t, rows.Err(), "iterate column catalog on %s", table)

	if dbType() == "" || dbType() == "sqlite" {
		declared := sqliteDeclaredCollations(t, h, table)
		for i := range cols {
			cols[i].Collation = declared[cols[i].Name]
		}
	}
	return cols
}

// sqliteDeclaredCollations reads each column's COLLATE out of the CREATE TABLE text
// SQLite keeps in sqlite_schema, which is the engine's own catalog and not the
// schema.sql documentation snapshot. A column whose declaration names no collation gets
// BINARY, which is SQLite's default and what every column in this schema is.
//
// Text rather than a projection because SQLite has no other place to read it from:
// pragma_table_info does not carry collation, and pragma_index_xinfo carries it only for
// a column an index happens to cover. Filling the field from a constant instead would
// make it assert nothing, which is the trap this exists to avoid.
func sqliteDeclaredCollations(t *testing.T, h *isolatedDB, table string) map[string]string {
	t.Helper()

	var ddl string
	require.NoErrorf(t, h.SQL.QueryRow(
		`SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?`, table).Scan(&ddl),
		"read the CREATE TABLE text for %s out of sqlite_schema", table)

	out := map[string]string{}
	for _, def := range splitTopLevel(columnDefsOf(ddl)) {
		fields := strings.Fields(def)
		if len(fields) == 0 {
			continue
		}
		name := strings.Trim(fields[0], "[]`\"'")
		switch strings.ToUpper(name) {
		case "CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN":
			continue // a table constraint, not a column
		}
		collation := "BINARY"
		for i, f := range fields {
			if strings.EqualFold(f, "COLLATE") && i+1 < len(fields) {
				collation = strings.ToUpper(strings.Trim(fields[i+1], "[]`\"',"))
			}
		}
		out[name] = collation
	}
	return out
}

// columnDefsOf returns what a CREATE TABLE statement holds between its outermost
// parentheses, which is the column and table-constraint list.
func columnDefsOf(ddl string) string {
	open := strings.Index(ddl, "(")
	close := strings.LastIndex(ddl, ")")
	if open < 0 || close < open {
		return ""
	}
	return ddl[open+1 : close]
}

// splitTopLevel splits on commas that are not inside parentheses or a quoted string, so
// a type like DECIMAL(10,2) or a default like DEFAULT 'a,b' stays in one piece.
func splitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	var quote rune
	for i, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '\'' || r == '"' || r == '`':
			quote = r
		case r == '(':
			depth++
		case r == ')':
			depth--
		case r == ',' && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func dumpIndexes(t *testing.T, h *isolatedDB, table string) []indexShape {
	t.Helper()

	// Each query returns one row per key column, ordered by index and then by the
	// index's own column order, so the loop below can fold them into one indexShape per
	// name without sorting the columns.
	var q string
	switch dbType() {
	case "mysql":
		q = fmt.Sprintf(`SELECT INDEX_NAME, CASE WHEN NON_UNIQUE = 0 THEN '1' ELSE '0' END, COLUMN_NAME
			FROM information_schema.statistics
			WHERE table_schema = DATABASE() AND table_name = '%s'
			ORDER BY INDEX_NAME, SEQ_IN_INDEX`, table)
	case "postgres":
		q = fmt.Sprintf(`SELECT i.relname, CASE WHEN ix.indisunique THEN '1' ELSE '0' END, a.attname
			FROM pg_index ix
			JOIN pg_class i ON i.oid = ix.indexrelid
			JOIN pg_class tb ON tb.oid = ix.indrelid
			JOIN pg_namespace n ON n.oid = tb.relnamespace
			JOIN unnest(ix.indkey::smallint[]) WITH ORDINALITY AS k(attnum, ord) ON true
			JOIN pg_attribute a ON a.attrelid = tb.oid AND a.attnum = k.attnum
			WHERE tb.relname = '%s' AND n.nspname = current_schema()
			  AND k.ord <= ix.indnkeyatts
			ORDER BY i.relname, k.ord`, table)
	case "mssql":
		// i.name IS NULL is the heap, which is not an index and has no shape to record.
		q = fmt.Sprintf(`SELECT i.name, CASE WHEN i.is_unique = 1 THEN '1' ELSE '0' END, c.name
			FROM sys.indexes i
			JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
			JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
			WHERE i.object_id = OBJECT_ID('dbo.%s') AND i.name IS NOT NULL
			  AND ic.is_included_column = 0
			ORDER BY i.name, ic.key_ordinal`, table)
	default: // sqlite
		q = fmt.Sprintf(`SELECT il.name, CASE WHEN il."unique" = 1 THEN '1' ELSE '0' END, ii.name
			FROM pragma_index_list('%s') AS il, pragma_index_info(il.name) AS ii
			ORDER BY il.name, ii.seqno`, table)
	}

	rows, err := h.SQL.Query(q)
	require.NoErrorf(t, err, "index catalog sweep on %s", table)
	defer func() { _ = rows.Close() }()

	var indexes []indexShape
	byName := map[string]int{}
	for rows.Next() {
		var name, uniqueFlag, col string
		require.NoErrorf(t, rows.Scan(&name, &uniqueFlag, &col), "scan index catalog row on %s", table)
		pos, seen := byName[name]
		if !seen {
			indexes = append(indexes, indexShape{Name: name, Exists: true, Unique: uniqueFlag == "1"})
			pos = len(indexes) - 1
			byName[name] = pos
		}
		indexes[pos].Columns = append(indexes[pos].Columns, col)
	}
	require.NoErrorf(t, rows.Err(), "iterate index catalog on %s", table)
	return indexes
}

func dumpForeignKeys(t *testing.T, h *isolatedDB, table string) []foreignKeyShape {
	t.Helper()

	var q string
	switch dbType() {
	case "mysql":
		q = fmt.Sprintf(`SELECT k.COLUMN_NAME, k.REFERENCED_TABLE_NAME, k.REFERENCED_COLUMN_NAME, r.DELETE_RULE
			FROM information_schema.KEY_COLUMN_USAGE k
			JOIN information_schema.REFERENTIAL_CONSTRAINTS r
			  ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
			WHERE k.TABLE_SCHEMA = DATABASE() AND k.TABLE_NAME = '%s'
			  AND k.REFERENCED_TABLE_NAME IS NOT NULL`, table)
	case "postgres":
		// confdeltype is a single letter; the CASE is what puts it in the same
		// vocabulary as the other three catalogs. conkey and confkey are parallel
		// arrays, so they are unnested together on the shared ordinality.
		q = fmt.Sprintf(`SELECT att.attname, ref.relname, ratt.attname,
			CASE con.confdeltype
			  WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT' WHEN 'c' THEN 'CASCADE'
			  WHEN 'n' THEN 'SET NULL' WHEN 'd' THEN 'SET DEFAULT' ELSE con.confdeltype::text END
			FROM pg_constraint con
			JOIN pg_class tb ON tb.oid = con.conrelid
			JOIN pg_namespace n ON n.oid = tb.relnamespace
			JOIN pg_class ref ON ref.oid = con.confrelid
			JOIN unnest(con.conkey) WITH ORDINALITY AS lk(attnum, ord) ON true
			JOIN unnest(con.confkey) WITH ORDINALITY AS rk(attnum, ord) ON rk.ord = lk.ord
			JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = lk.attnum
			JOIN pg_attribute ratt ON ratt.attrelid = con.confrelid AND ratt.attnum = rk.attnum
			WHERE con.contype = 'f' AND tb.relname = '%s' AND n.nspname = current_schema()`, table)
	case "mssql":
		// delete_referential_action_desc spells it NO_ACTION and SET_NULL, so the
		// underscore is replaced to match the other three.
		q = fmt.Sprintf(`SELECT pc.name, rt.name, rc.name,
			REPLACE(fk.delete_referential_action_desc, '_', ' ')
			FROM sys.foreign_keys fk
			JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
			JOIN sys.columns pc ON pc.object_id = fkc.parent_object_id AND pc.column_id = fkc.parent_column_id
			JOIN sys.columns rc ON rc.object_id = fkc.referenced_object_id AND rc.column_id = fkc.referenced_column_id
			JOIN sys.tables rt ON rt.object_id = fkc.referenced_object_id
			WHERE fk.parent_object_id = OBJECT_ID('dbo.%s')`, table)
	default: // sqlite
		// "to" is NULL when the reference names no column and means the referenced
		// table's primary key; every foreign key in this schema names one.
		q = fmt.Sprintf(`SELECT "from", "table", COALESCE("to", ''), UPPER(on_delete)
			FROM pragma_foreign_key_list('%s')`, table)
	}

	rows, err := h.SQL.Query(q)
	require.NoErrorf(t, err, "foreign key catalog lookup on %s", table)
	defer func() { _ = rows.Close() }()

	var fks []foreignKeyShape
	for rows.Next() {
		var col, refTable, refCol, onDelete string
		require.NoErrorf(t, rows.Scan(&col, &refTable, &refCol, &onDelete),
			"scan foreign key catalog row on %s", table)
		fks = append(fks, foreignKeyShape{Column: col, RefTable: refTable, RefColumn: refCol, OnDelete: onDelete})
	}
	require.NoErrorf(t, rows.Err(), "iterate foreign key catalog on %s", table)
	return fks
}

// column returns the named column, failing the test when the dump does not carry it.
func (s tableShape) column(t *testing.T, name string) columnShape {
	t.Helper()
	for _, c := range s.Columns {
		if c.Name == name {
			return c
		}
	}
	require.FailNowf(t, "column not found", "no column %q in the dump (%d columns read on %s)",
		name, len(s.Columns), dbType())
	return columnShape{}
}

// index returns the named index, or a zero indexShape (Exists false) when the table does
// not carry it, matching describeIndex's contract.
func (s tableShape) index(name string) indexShape {
	for _, i := range s.Indexes {
		if i.Name == name {
			return i
		}
	}
	return indexShape{Name: name}
}

// foreignKey returns the foreign key whose LOCAL column is name, failing the test when
// there is none. Keyed by local column because that is what identifies a foreign key
// without a constraint name, per foreignKeyShape.
func (s tableShape) foreignKey(t *testing.T, column string) foreignKeyShape {
	t.Helper()
	for _, fk := range s.ForeignKeys {
		if fk.Column == column {
			return fk
		}
	}
	require.FailNowf(t, "foreign key not found", "no foreign key on column %q in the dump (%d read on %s)",
		column, len(s.ForeignKeys), dbType())
	return foreignKeyShape{}
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
	}, false)
	require.NoError(t, err, "NewMsSQLDatabase over a pre-created database")
	t.Cleanup(func() { _ = db.DB.Close(); dropMsSQL(t, cfg, name) })

	// The point of the helper, asserted rather than assumed: if IF NOT EXISTS ever stopped
	// being IF NOT EXISTS, every test built on this would go on passing for the wrong
	// reason.
	require.Equal(t, collation, readDatabaseDefaultCollation(t, db.DB),
		"NewMsSQLDatabase must leave a database it did not create alone; its CREATE DATABASE is IF NOT EXISTS")

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
