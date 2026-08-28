package schemadump

import (
	"database/sql"
	"fmt"
	"strings"
)

// unrepresentable is one construct a table can carry that TableShape has no field for.
//
// The dumper refuses such a table rather than dropping the construct silently, because the
// same code writes the golden file and checks it: a fact discarded here is discarded from
// the committed record too, and no later stage can recover it. Every one of these is absent
// from all four engines' migration chains today, verified, so the guard fires on nothing and
// exists for the migration somebody writes next.
type unrepresentable struct {
	// construct is what the error names, in the words a migration author would use.
	construct string
	// count is a per-dialect query returning one row of one integer, the number of
	// offending objects on the table. A dialect absent from the map cannot express the
	// construct at all.
	count map[Dialect]string
}

var unrepresentableChecks = []unrepresentable{
	{
		// ForeignKeyShape is one row per column pair with no constraint name, so a
		// composite (a,b) key is indistinguishable from two single-column ones.
		construct: "a composite foreign key",
		count: map[Dialect]string{
			MySQL: `SELECT COUNT(*) FROM (
				SELECT CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE
				WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '%s'
				  AND REFERENCED_TABLE_NAME IS NOT NULL
				GROUP BY CONSTRAINT_NAME HAVING COUNT(*) > 1) c`,
			Postgres: `SELECT COUNT(*) FROM pg_constraint con
				JOIN pg_class tb ON tb.oid = con.conrelid
				JOIN pg_namespace n ON n.oid = tb.relnamespace
				WHERE con.contype = 'f' AND tb.relname = '%s' AND n.nspname = current_schema()
				  AND array_length(con.conkey, 1) > 1`,
			MSSQL: `SELECT COUNT(*) FROM (
				SELECT fkc.constraint_object_id FROM sys.foreign_key_columns fkc
				WHERE fkc.parent_object_id = OBJECT_ID('dbo.%s')
				GROUP BY fkc.constraint_object_id HAVING COUNT(*) > 1) c`,
			// seq is the column's position within its own foreign key, so any row
			// past the first means that key spans more than one column.
			SQLite: `SELECT COUNT(*) FROM pragma_foreign_key_list('%s') WHERE seq > 0`,
		},
	},
	{
		// Nothing in ColumnShape carries a predicate, so a CHECK constraint present on
		// one engine and missing on another would compare equal.
		construct: "a CHECK constraint",
		count: map[Dialect]string{
			MySQL: `SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
				WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '%s' AND CONSTRAINT_TYPE = 'CHECK'`,
			Postgres: `SELECT COUNT(*) FROM pg_constraint con
				JOIN pg_class tb ON tb.oid = con.conrelid
				JOIN pg_namespace n ON n.oid = tb.relnamespace
				WHERE con.contype = 'c' AND tb.relname = '%s' AND n.nspname = current_schema()`,
			MSSQL: `SELECT COUNT(*) FROM sys.check_constraints WHERE parent_object_id = OBJECT_ID('dbo.%s')`,
			// SQLite has no catalog view for constraints, so its answer is read from
			// the declaration; see sqliteUnrepresentableDeclarations.
		},
	},
	{
		// A computed column's expression is not in the shape, and this is a different
		// thing from ColumnShape.Generated, which is the engine numbering a column.
		construct: "a generated (computed) column",
		count: map[Dialect]string{
			// GENERATION_EXPRESSION and not EXTRA: MySQL puts DEFAULT_GENERATED in
			// EXTRA for any column whose DEFAULT is an expression, which
			// audit_logs.details is, so matching GENERATED there refuses a table
			// the chain actually builds. Measured on the mysql data tier.
			MySQL: `SELECT COUNT(*) FROM information_schema.columns
				WHERE table_schema = DATABASE() AND table_name = '%s'
				  AND COALESCE(GENERATION_EXPRESSION, '') <> ''`,
			Postgres: `SELECT COUNT(*) FROM pg_attribute a
				JOIN pg_class c ON c.oid = a.attrelid
				JOIN pg_namespace n ON n.oid = c.relnamespace
				WHERE c.relname = '%s' AND n.nspname = current_schema()
				  AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated <> ''`,
			MSSQL: `SELECT COUNT(*) FROM sys.computed_columns WHERE object_id = OBJECT_ID('dbo.%s')`,
			// pragma_table_xinfo.hidden is 2 for a virtual generated column and 3 for
			// a stored one; 0 and 1 are ordinary and hidden-ordinary columns.
			SQLite: `SELECT COUNT(*) FROM pragma_table_xinfo('%s') WHERE hidden IN (2, 3)`,
		},
	},
	{
		// ForeignKeyShape carries OnDelete and nothing else, so an ON UPDATE action
		// would be invisible. NO ACTION is what every engine reports for a foreign key
		// that declares none.
		construct: "an ON UPDATE referential action",
		count: map[Dialect]string{
			MySQL: `SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS
				WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = '%s' AND UPDATE_RULE <> 'NO ACTION'`,
			Postgres: `SELECT COUNT(*) FROM pg_constraint con
				JOIN pg_class tb ON tb.oid = con.conrelid
				JOIN pg_namespace n ON n.oid = tb.relnamespace
				WHERE con.contype = 'f' AND tb.relname = '%s' AND n.nspname = current_schema()
				  AND con.confupdtype <> 'a'`,
			MSSQL: `SELECT COUNT(*) FROM sys.foreign_keys
				WHERE parent_object_id = OBJECT_ID('dbo.%s') AND update_referential_action <> 0`,
			SQLite: `SELECT COUNT(*) FROM pragma_foreign_key_list('%s') WHERE UPPER(on_update) <> 'NO ACTION'`,
		},
	},
	{
		// IndexShape has no predicate, so a filtered index and a full one over the same
		// columns are the same shape.
		construct: "a partial or filtered index",
		count: map[Dialect]string{
			Postgres: `SELECT COUNT(*) FROM pg_index ix
				JOIN pg_class tb ON tb.oid = ix.indrelid
				JOIN pg_namespace n ON n.oid = tb.relnamespace
				WHERE tb.relname = '%s' AND n.nspname = current_schema() AND ix.indpred IS NOT NULL`,
			MSSQL:  `SELECT COUNT(*) FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.%s') AND has_filter = 1`,
			SQLite: `SELECT COUNT(*) FROM pragma_index_list('%s') WHERE partial = 1`,
			// MySQL has no filtered index.
		},
	},
	{
		// IndexShape.Columns holds key columns only, by design, so INCLUDE payload
		// columns would vanish.
		construct: "an index with INCLUDE columns",
		count: map[Dialect]string{
			Postgres: `SELECT COUNT(*) FROM pg_index ix
				JOIN pg_class tb ON tb.oid = ix.indrelid
				JOIN pg_namespace n ON n.oid = tb.relnamespace
				WHERE tb.relname = '%s' AND n.nspname = current_schema()
				  AND ix.indnatts > ix.indnkeyatts`,
			MSSQL: `SELECT COUNT(*) FROM sys.index_columns
				WHERE object_id = OBJECT_ID('dbo.%s') AND is_included_column = 1`,
			// Neither MySQL nor SQLite has INCLUDE columns.
		},
	},
	{
		// IndexShape.Columns records order but not direction, so an index built
		// descending on one engine and ascending on another compares equal.
		construct: "a descending index key",
		count: map[Dialect]string{
			// information_schema.statistics.COLLATION is 'A' ascending, 'D'
			// descending, NULL for an unsorted key.
			MySQL: `SELECT COUNT(*) FROM information_schema.statistics
				WHERE table_schema = DATABASE() AND table_name = '%s' AND COLLATION = 'D'`,
			// indoption is a bitmask per key column; bit 0 is DESC.
			Postgres: `SELECT COUNT(*) FROM pg_index ix
				JOIN pg_class tb ON tb.oid = ix.indrelid
				JOIN pg_namespace n ON n.oid = tb.relnamespace
				JOIN unnest(ix.indoption::smallint[]) WITH ORDINALITY AS o(opt, ord) ON o.ord <= ix.indnkeyatts
				WHERE tb.relname = '%s' AND n.nspname = current_schema() AND (o.opt & 1) = 1`,
			MSSQL: `SELECT COUNT(*) FROM sys.index_columns
				WHERE object_id = OBJECT_ID('dbo.%s') AND is_included_column = 0 AND is_descending_key = 1`,
			SQLite: `SELECT COUNT(*) FROM pragma_index_list('%s') AS il, pragma_index_xinfo(il.name) AS ix
				WHERE ix."desc" = 1 AND ix.key = 1`,
		},
	},
	{
		// When a constraint is checked is not in the shape at all.
		construct: "a DEFERRABLE constraint",
		count: map[Dialect]string{
			Postgres: `SELECT COUNT(*) FROM pg_constraint con
				JOIN pg_class tb ON tb.oid = con.conrelid
				JOIN pg_namespace n ON n.oid = tb.relnamespace
				WHERE tb.relname = '%s' AND n.nspname = current_schema() AND con.condeferrable`,
			// SQLite's DEFERRABLE is read from the declaration; neither MySQL nor SQL
			// Server accepts the keyword.
		},
	},
	{
		// MySQL names an index the declaration left unnamed after its first key column,
		// suffixing _2, _3 on collision. That name is the engine's invention and would
		// have to be masked in the golden file, which is a distinction MySQL's catalog
		// cannot report: see dumpIndexes. Every index in this schema is named, so this
		// refuses the first one that is not rather than recording a name that is not a
		// migration's choice.
		//
		// The REGEXP is built from a column name, which on all four engines here is
		// [a-z_]+ and carries no regular expression metacharacter.
		construct: "an index MySQL named for itself, from a declaration that gave no name",
		count: map[Dialect]string{
			MySQL: `SELECT COUNT(*) FROM information_schema.statistics s
				WHERE s.table_schema = DATABASE() AND s.table_name = '%s'
				  AND s.INDEX_NAME <> 'PRIMARY' AND s.SEQ_IN_INDEX = 1
				  AND (s.INDEX_NAME = s.COLUMN_NAME
				       OR s.INDEX_NAME REGEXP CONCAT('^', s.COLUMN_NAME, '_[0-9]+$'))`,
		},
	},
}

// guardTable refuses a table carrying anything TableShape cannot record.
func guardTable(db *sql.DB, d Dialect, table string) error {
	for _, check := range unrepresentableChecks {
		q, ok := check.count[d]
		if !ok {
			continue
		}
		var n int
		if err := db.QueryRow(fmt.Sprintf(q, table)).Scan(&n); err != nil {
			return fmt.Errorf("schemadump: look for %s on %s.%s: %w", check.construct, d, table, err)
		}
		if n > 0 {
			return fmt.Errorf("schemadump: %s.%s carries %s (%d), which the dump cannot represent; widen the shape rather than letting it go unrecorded (#284)",
				d, table, check.construct, n)
		}
	}
	if d == SQLite {
		return sqliteUnrepresentableDeclarations(db, table)
	}
	return nil
}

// sqliteUnrepresentableDeclarations covers the two constructs SQLite has no catalog view
// for. It has no table for constraints at all, so CHECK and DEFERRABLE are read out of the
// CREATE TABLE text, which is the same source the collation and AUTOINCREMENT facts come
// from.
func sqliteUnrepresentableDeclarations(db *sql.DB, table string) error {
	ddl, err := sqliteTableDDL(db, table)
	if err != nil {
		return err
	}
	return sqliteUnrepresentableInDDL(ddl, table)
}

// sqliteUnrepresentableInDDL is the parsing half of the check above, split out so it can be
// exercised over hand-written DDL with no database.
func sqliteUnrepresentableInDDL(ddl, table string) error {
	for _, def := range splitTopLevel(columnDefsOf(ddl)) {
		fields := strings.Fields(def)
		for i, f := range fields {
			word := strings.ToUpper(strings.Trim(f, "[]`\"',"))
			switch {
			case word == "DEFERRABLE":
				return fmt.Errorf("schemadump: sqlite.%s declares a DEFERRABLE constraint, which the dump cannot represent (#284)", table)
			case strings.HasPrefix(word, "CHECK(") ||
				(word == "CHECK" && i+1 < len(fields) && strings.HasPrefix(fields[i+1], "(")):
				return fmt.Errorf("schemadump: sqlite.%s declares a CHECK constraint, which the dump cannot represent (#284)", table)
			}
		}
	}
	return nil
}
