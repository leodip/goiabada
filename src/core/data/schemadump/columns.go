package schemadump

import (
	"database/sql"
	"fmt"
)

// dumpColumns reads one table's columns. Every branch returns the same nine values in the
// same order, so the scan below is one loop: name, type, nullability, default expression,
// whether there is a default at all, collation, default constraint name, whether the engine
// invented that name, and whether the engine numbers the column.
//
// The default expression and the has-a-default flag are two values because one cannot carry
// both facts: MySQL's catalog reports DEFAULT ” as the empty string, which is also what a
// column with no default reads as (#284).
func dumpColumns(db *sql.DB, d Dialect, table string) ([]ColumnShape, error) {
	var q string
	switch d {
	case MySQL:
		// COLUMN_TYPE rather than DATA_TYPE: it carries the length, so varchar(64)
		// shrinking to varchar(16) is visible. COLLATION_NAME is NULL for a column that
		// holds no string, which is the '' this reports.
		//
		// EXTRA is where MySQL records auto_increment, and it is the only place: two
		// tables differing by nothing else report identical rows for every value
		// above it.
		q = fmt.Sprintf(`SELECT COLUMN_NAME, COLUMN_TYPE,
			CASE WHEN IS_NULLABLE = 'YES' THEN '1' ELSE '0' END,
			COALESCE(COLUMN_DEFAULT, ''),
			CASE WHEN COLUMN_DEFAULT IS NULL THEN '0' ELSE '1' END,
			COALESCE(COLLATION_NAME, ''), '', '0',
			CASE WHEN LOCATE('auto_increment', EXTRA) > 0 THEN '1' ELSE '0' END
			FROM information_schema.columns
			WHERE table_schema = DATABASE() AND table_name = '%s'`, table)
	case Postgres:
		// format_type renders the length the way the DDL spells it; pg_get_expr renders
		// the default the same way. information_schema would give both in two columns
		// that then have to be pasted together in Go.
		//
		// attcollation is the collation the column actually uses, which for every column
		// in this schema is the database's own: none declares an override. It resolves
		// through pg_collation to the name "default", and 0 for a column that holds no
		// string, which is the '' this reports. PostgreSQL names no default constraint,
		// so the seventh and eighth values are literals.
		//
		// Generation is read in both spellings PostgreSQL has: attidentity is set for a
		// declared GENERATED ... AS IDENTITY column, and a nextval() default is what
		// BIGSERIAL expands to, which is what all 26 tables here use. Reading only one
		// would make a future migration written the other way look ungenerated.
		q = fmt.Sprintf(`SELECT a.attname, format_type(a.atttypid, a.atttypmod),
			CASE WHEN a.attnotnull THEN '0' ELSE '1' END,
			COALESCE(pg_get_expr(d.adbin, d.adrelid), ''),
			CASE WHEN d.adbin IS NULL THEN '0' ELSE '1' END,
			COALESCE((SELECT co.collname FROM pg_collation co WHERE co.oid = a.attcollation), ''), '', '0',
			CASE WHEN a.attidentity <> '' OR COALESCE(pg_get_expr(d.adbin, d.adrelid), '') LIKE 'nextval(%%' THEN '1' ELSE '0' END
			FROM pg_attribute a
			JOIN pg_class c ON c.oid = a.attrelid
			JOIN pg_namespace n ON n.oid = c.relnamespace
			LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
			WHERE c.relname = '%s' AND n.nspname = current_schema()
			  AND a.attnum > 0 AND NOT a.attisdropped`, table)
	case MSSQL:
		// sys.columns.max_length is bytes, so an NVARCHAR's declared length is half of
		// it, and -1 is the (max) form. sys.default_constraints is joined rather than
		// reading INFORMATION_SCHEMA.COLUMN_DEFAULT because it is the same value and
		// this is the catalog the rest of the mssql migrations already work against.
		//
		// is_system_named separates the 42 defaults SQL Server named for itself from the
		// 22 a migration named, which is what the golden file needs to know before it can
		// mask the generated ones. It is NULL for a column with no default at all, and
		// the CASE reports that as '0'.
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
			CASE WHEN dc.object_id IS NULL THEN '0' ELSE '1' END,
			COALESCE(c.collation_name, ''), COALESCE(dc.name, ''),
			CASE WHEN dc.is_system_named = 1 THEN '1' ELSE '0' END,
			CASE WHEN c.is_identity = 1 THEN '1' ELSE '0' END
			FROM sys.columns c
			JOIN sys.types ty ON ty.user_type_id = c.user_type_id
			LEFT JOIN sys.default_constraints dc
			  ON dc.parent_object_id = c.object_id AND dc.parent_column_id = c.column_id
			WHERE c.object_id = OBJECT_ID('dbo.%s')`, table)
	default: // SQLite
		// pragma_table_info reports the DECLARED type, which is what a rebuild has to
		// reproduce; SQLite's own storage class would collapse every spelling onto five
		// values and hide exactly the drift this exists to catch.
		//
		// pragma_table_info projects cid, name, type, notnull, dflt_value and pk, and
		// nothing else: a TEXT column and a TEXT COLLATE NOCASE column are
		// indistinguishable through it, and so are an AUTOINCREMENT primary key and a
		// plain one, both measured. So the collation and the generation flag are filled
		// in below from the declaration in sqlite_schema, and the four literals here
		// keep every branch returning the same nine values.
		q = fmt.Sprintf(`SELECT name, type,
			CASE WHEN "notnull" = 0 THEN '1' ELSE '0' END,
			COALESCE(dflt_value, ''),
			CASE WHEN dflt_value IS NULL THEN '0' ELSE '1' END,
			'', '', '0', '0'
			FROM pragma_table_info('%s')`, table)
	}

	rows, err := db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("schemadump: column catalog lookup on %s.%s: %w", d, table, err)
	}
	defer func() { _ = rows.Close() }()

	var cols []ColumnShape
	for rows.Next() {
		var name, typ, nullable, def, hasDefault, collation, defName, defSystemNamed, generated string
		if err := rows.Scan(&name, &typ, &nullable, &def, &hasDefault, &collation, &defName, &defSystemNamed, &generated); err != nil {
			return nil, fmt.Errorf("schemadump: scan column catalog row on %s.%s: %w", d, table, err)
		}
		cols = append(cols, ColumnShape{
			Name: name, Type: typ, Nullable: nullable == "1", Default: def,
			HasDefault: hasDefault == "1",
			Collation:  collation, DefaultName: defName,
			DefaultIsSystemNamed: defSystemNamed == "1",
			Generated:            generated == "1",
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("schemadump: iterate column catalog on %s.%s: %w", d, table, err)
	}

	if d == SQLite && len(cols) > 0 {
		declared, err := sqliteDeclaredColumnFacts(db, table)
		if err != nil {
			return nil, err
		}
		for i := range cols {
			cols[i].Collation = declared[cols[i].Name].Collation
			cols[i].Generated = declared[cols[i].Name].Generated
		}
	}
	return cols, nil
}
