// Package schemadump reads a fully migrated database's shape out of the engine's own
// catalog, in that engine's own vocabulary, so the four supported engines can be held to
// building the same schema (#284).
//
// It records what the catalog says and never what a schema file or a migration claims: the
// migrations are written four times by hand and the hand-maintained snapshots beside them
// have been wrong before. Two consumers read it. The generator writes each engine's dump to
// a committed golden file, and the data tier compares a freshly migrated database against
// that file on the engine it was written for. A third, with no database at all, compares the
// four committed files against each other.
//
// Each engine's own spelling is kept verbatim: TEXT on SQLite against nvarchar(256) on SQL
// Server, each with its own collation name. Mapping those onto a common vocabulary is the
// cross-engine comparison's job, and doing it here would make the golden file stop describing
// a real database.
package schemadump

import (
	"fmt"
	"regexp"
	"strings"
)

// Dialect names the engine whose catalog is being read. It is a parameter rather than
// something read from the process configuration because the generator connects to all four
// engines in one process, so there is no single configured dialect to read.
type Dialect string

const (
	SQLite   Dialect = "sqlite"
	MySQL    Dialect = "mysql"
	Postgres Dialect = "postgres"
	MSSQL    Dialect = "mssql"
)

// ParseDialect maps a configured database type onto a Dialect. The empty string is SQLite,
// which is what config.GetDatabase().Type reports when nothing is set, and surrounding
// quotes and whitespace are tolerated because an environment variable often carries them.
//
// Anything else is an error rather than a fallback. Every switch this package replaced fell
// through its default arm to SQLite, which in a four-engine process would read the wrong
// catalog, find nothing, and report success.
func ParseDialect(s string) (Dialect, error) {
	switch d := Dialect(strings.Trim(strings.TrimSpace(s), `"'`)); d {
	case "":
		return SQLite, nil
	case SQLite, MySQL, Postgres, MSSQL:
		return d, nil
	default:
		return "", fmt.Errorf("schemadump: unrecognised database dialect %q", s)
	}
}

// valid reports whether d is one of the four engines. Every entry point checks it, so a
// zero Dialect value cannot silently select a branch.
func (d Dialect) valid() bool {
	switch d {
	case SQLite, MySQL, Postgres, MSSQL:
		return true
	}
	return false
}

// identifier is what a table or index name may look like for this package to interpolate it
// into a catalog query. Every name it handles comes from the catalog itself or from a test's
// own constant, so this rejects nothing the package legitimately meets; it is here because
// the four catalogs take a table name in four incompatible ways (a quoted literal, an
// OBJECT_ID() argument, a table-valued function argument), none of which a placeholder
// covers on every engine.
var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func checkIdentifier(kind, name string) error {
	if !identifier.MatchString(name) {
		return fmt.Errorf("schemadump: %s name %q is not a plain identifier", kind, name)
	}
	return nil
}

// ColumnShape is one column as the engine's catalog reports it.
type ColumnShape struct {
	Name     string
	Type     string // the engine's own spelling, verbatim
	Nullable bool
	Default  string // the engine's own default expression, verbatim; "" when there is none

	// Collation is what the engine says decides `=` and ordering for this column, in the
	// engine's own vocabulary: a utf8mb4_* name on MySQL, a pg_collation name on
	// PostgreSQL (which is "default" for every column here, since none carries an
	// override), a Latin1_General_* name on SQL Server, and the declared COLLATE on
	// SQLite, or BINARY when the declaration omits one. "" for a column that holds no
	// string. It is read because collation is the one axis of the schema the specs
	// actually govern: RFC 6749 section 1.9 makes client_id case-sensitive, and two
	// columns identical in type, nullability, default and index can still disagree about
	// whether MyApp and myapp are one value (#283).
	Collation string

	// DefaultName is the default constraint's own name, which SQL Server alone gives one.
	// MySQL, PostgreSQL and SQLite attach a default to the column with no nameable object
	// behind it, so this stays "" there. It is in the shape because a migration that drops
	// an auto-named constraint and adds a named one back leaves Default identical and is
	// otherwise invisible to a before/after comparison, and the name is the entire reason
	// a later migration can drop the constraint without a catalog lookup.
	DefaultName string

	// DefaultIsSystemNamed says the engine invented DefaultName rather than a migration
	// choosing it, read from sys.default_constraints.is_system_named. SQL Server only, and
	// false everywhere else, since no other engine names a default at all.
	//
	// It is separate from DefaultName because the name itself cannot be committed: SQL
	// Server's generated names carry a per-database suffix that differs between two
	// databases built from identical DDL, so the golden file has to mask them, and
	// masking needs to know which ones the engine invented. 42 of the 64 SQL Server
	// defaults are unnamed in the migrations.
	DefaultIsSystemNamed bool

	// Generated says the engine numbers this column: AUTO_INCREMENT on MySQL, IDENTITY on
	// SQL Server, an identity or a nextval() default on PostgreSQL, AUTOINCREMENT on
	// SQLite. Read from each engine's own catalog rather than inferred from the type or
	// the default, because nothing else in this shape can see it: two MySQL tables
	// differing only by AUTO_INCREMENT report byte-identical rows for every other field,
	// and so do two SQLite tables through pragma_table_info.
	Generated bool
}

// IndexOrigin says who chose an index's name, which decides whether the name can be
// compared across engines or has to be masked. It is read from the catalog on every engine
// and never guessed from the name: SQL Server's generated names carry a random per-database
// suffix, so a name pattern would be the one thing that cannot be trusted here.
type IndexOrigin string

const (
	// OriginCreated is an index a statement created and named: CREATE INDEX, or a named
	// inline KEY. Its name is a migration's choice, so it compares across engines and a
	// later migration can drop it by name.
	OriginCreated IndexOrigin = "c"
	// OriginUnique is the index behind an inline UNIQUE constraint, which every engine
	// but MySQL names for itself.
	OriginUnique IndexOrigin = "u"
	// OriginPrimaryKey is the index behind a primary key. SQLite produces none at all for
	// a rowid-alias primary key, which is every table in this schema.
	OriginPrimaryKey IndexOrigin = "pk"
)

// IndexShape is one index as the engine's catalog reports it. Exists is derived from
// Columns rather than counted separately: an index with no key columns is not a thing
// any of the four engines can produce.
type IndexShape struct {
	Name    string
	Exists  bool
	Unique  bool
	Columns []string // key columns, in index order
	Origin  IndexOrigin
}

// ForeignKeyShape identifies a foreign key by the tuple every catalog reports, and
// deliberately not by its constraint name. SQLite's PRAGMA foreign_key_list returns
// (id, seq, table, from, to, on_update, on_delete, match) and omits the name even when
// the table declares CONSTRAINT fk_named, so requiring a name would force a parser over
// sqlite_schema.sql.
//
// One row per column pair, so a composite key would be indistinguishable from two
// single-column ones. The schema has none on any engine, and the guard refuses one rather
// than recording it wrongly.
type ForeignKeyShape struct {
	Column    string
	RefTable  string
	RefColumn string
	OnDelete  string // CASCADE, NO ACTION, RESTRICT, SET NULL or SET DEFAULT
}

// TableShape holds the three projections sorted, so two dumps of the same table compare
// directly. Columns are sorted by name rather than left in ordinal order on purpose:
// column order is not something this is trying to make equal across engines, and a rebuild
// that reorders columns is not a defect.
type TableShape struct {
	Columns     []ColumnShape
	Indexes     []IndexShape
	ForeignKeys []ForeignKeyShape
}

// Column returns the named column and whether the dump carries it.
func (s TableShape) Column(name string) (ColumnShape, bool) {
	for _, c := range s.Columns {
		if c.Name == name {
			return c, true
		}
	}
	return ColumnShape{}, false
}

// Index returns the named index, or a zero IndexShape (Exists false) when the table does
// not carry it.
func (s TableShape) Index(name string) IndexShape {
	for _, i := range s.Indexes {
		if i.Name == name {
			return i
		}
	}
	return IndexShape{Name: name}
}

// ForeignKey returns the foreign key whose LOCAL column is name. Keyed by local column
// because that is what identifies a foreign key without a constraint name.
func (s TableShape) ForeignKey(column string) (ForeignKeyShape, bool) {
	for _, fk := range s.ForeignKeys {
		if fk.Column == column {
			return fk, true
		}
	}
	return ForeignKeyShape{}, false
}

// TableEntry is one named table in a Schema.
type TableEntry struct {
	Name  string
	Table TableShape
}

// Schema is every table in one database, ordered by name. The order is total and decided
// in Go rather than by the engine, so a golden file generated on one engine's collation
// orders the same way as on another's.
type Schema []TableEntry

// Table returns the named table and whether the schema carries it.
func (s Schema) Table(name string) (TableShape, bool) {
	for _, e := range s {
		if e.Name == name {
			return e.Table, true
		}
	}
	return TableShape{}, false
}
