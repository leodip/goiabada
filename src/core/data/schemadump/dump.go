package schemadump

import (
	"database/sql"
	"fmt"
	"sort"
)

// Tables lists every application table in the connected database, sorted.
//
// The sort is done in Go rather than by the engine so that all four orderings are the same
// one: ORDER BY on a string column is decided by the server's collation, which is a
// different collation on each of the four and is exactly what #283 had to pin.
//
// An empty list is an error. A dump of no tables compared against a golden file of no
// tables reads as "nothing changed" and passes, which is the failure mode that would make
// the whole check worthless.
func Tables(db *sql.DB, d Dialect) ([]string, error) {
	if !d.valid() {
		return nil, fmt.Errorf("schemadump: unrecognised database dialect %q", d)
	}

	var q string
	switch d {
	case MySQL:
		// BASE TABLE excludes views; DATABASE() is the schema the connection is bound to.
		q = `SELECT TABLE_NAME FROM information_schema.tables
			WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'`
	case Postgres:
		q = `SELECT tablename FROM pg_tables WHERE schemaname = current_schema()`
	case MSSQL:
		q = `SELECT t.name FROM sys.tables t
			JOIN sys.schemas s ON s.schema_id = t.schema_id
			WHERE s.name = 'dbo'`
	default: // SQLite
		// NOT LIKE 'sqlite_%' is what keeps sqlite_sequence out, and it exists here:
		// every table in this schema declares AUTOINCREMENT, which is what creates it.
		q = `SELECT name FROM sqlite_schema
			WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`
	}

	rows, err := db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("schemadump: list tables on %s: %w", d, err)
	}
	defer func() { _ = rows.Close() }()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("schemadump: scan table name on %s: %w", d, err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("schemadump: iterate table names on %s: %w", d, err)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("schemadump: %s reported no tables at all, which no migrated database can have", d)
	}

	sort.Strings(names)
	return names, nil
}

// Dump reads every table in the connected database. This is the seam the generator writes a
// golden file from and the seam the per-engine data test reads through, so the file cannot
// record a shape the checker could not have produced.
func Dump(db *sql.DB, d Dialect) (Schema, error) {
	names, err := Tables(db, d)
	if err != nil {
		return nil, err
	}

	schema := make(Schema, 0, len(names))
	for _, name := range names {
		shape, err := DumpTable(db, d, name)
		if err != nil {
			return nil, err
		}
		schema = append(schema, TableEntry{Name: name, Table: shape})
	}
	return schema, nil
}

// DumpTable reads one table's columns, indexes and foreign keys out of the engine's
// catalog, so a migration that rebuilds a table can be checked by comparing the dump before
// against the dump after. That is the property a hand-written CREATE TABLE cannot otherwise
// be held to: a dropped column, a lost index or a changed foreign key action are all silent,
// and PRAGMA foreign_key_check does not see any of them.
//
// Every branch normalises in SQL rather than in Go: nullability is a flag on SQLite, a
// boolean on PostgreSQL, a bit on SQL Server and a YES/NO string on MySQL, and the on-delete
// action is a word on three engines and a pg_constraint.confdeltype letter on the fourth.
// Sorting is the one thing done in Go, so it is one rule rather than four.
//
// It refuses a table carrying a construct this shape cannot represent, rather than dropping
// it silently: see guardTable. Dropping it would put the omission in the golden file too,
// where nothing downstream could recover it.
func DumpTable(db *sql.DB, d Dialect, table string) (TableShape, error) {
	if !d.valid() {
		return TableShape{}, fmt.Errorf("schemadump: unrecognised database dialect %q", d)
	}
	if err := checkIdentifier("table", table); err != nil {
		return TableShape{}, err
	}

	columns, err := dumpColumns(db, d, table)
	if err != nil {
		return TableShape{}, err
	}
	// A table with no columns is not something any of the four engines can produce, so it
	// means the branch above read the wrong catalog or the wrong name. Failing here is
	// what stops an empty dump being compared against another empty dump and read as
	// "nothing changed".
	if len(columns) == 0 {
		return TableShape{}, fmt.Errorf("schemadump: %s read no columns for table %q", d, table)
	}

	// The guard runs before the index and foreign key projections, not after them. Some of
	// what it refuses is something those projections cannot read either, and they fail
	// worse: an expression index reports a NULL key column name on MySQL and SQLite, which
	// surfaces as a driver type-conversion error naming neither the table nor the
	// construct. Guarding first means one sentence a migration author can act on. It runs
	// after the columns, so a table that does not exist is still answered by the
	// read-no-columns error above rather than by a guard query returning zero of everything.
	if err := guardTable(db, d, table); err != nil {
		return TableShape{}, err
	}

	indexes, err := dumpIndexes(db, d, table)
	if err != nil {
		return TableShape{}, err
	}
	foreignKeys, err := dumpForeignKeys(db, d, table)
	if err != nil {
		return TableShape{}, err
	}

	shape := TableShape{Columns: columns, Indexes: indexes, ForeignKeys: foreignKeys}
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
	return shape, nil
}

// DescribeIndex reads one index's uniqueness, key columns and origin from the engine's
// catalog, returning a zero IndexShape (Exists false) when the table does not carry it.
//
// It exists because asserting only that an index NAME is present lets a wrongly built index
// pass: created on the wrong column, or created UNIQUE on a column that is deliberately
// repeated, both of which are the failures worth catching. Unlike DumpTable it does not run
// the guard, because a migration test calls it against a table part way through the chain
// rather than against a finished schema.
func DescribeIndex(db *sql.DB, d Dialect, table, index string) (IndexShape, error) {
	if !d.valid() {
		return IndexShape{}, fmt.Errorf("schemadump: unrecognised database dialect %q", d)
	}
	if err := checkIdentifier("table", table); err != nil {
		return IndexShape{}, err
	}
	if err := checkIdentifier("index", index); err != nil {
		return IndexShape{}, err
	}

	indexes, err := dumpIndexes(db, d, table)
	if err != nil {
		return IndexShape{}, err
	}
	for _, i := range indexes {
		if i.Name == index {
			return i, nil
		}
	}
	return IndexShape{Name: index}, nil
}
