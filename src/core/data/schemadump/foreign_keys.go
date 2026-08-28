package schemadump

import (
	"database/sql"
	"fmt"
)

// dumpForeignKeys reads one table's foreign keys as the tuple ForeignKeyShape documents.
func dumpForeignKeys(db *sql.DB, d Dialect, table string) ([]ForeignKeyShape, error) {
	var q string
	switch d {
	case MySQL:
		q = fmt.Sprintf(`SELECT k.COLUMN_NAME, k.REFERENCED_TABLE_NAME, k.REFERENCED_COLUMN_NAME, r.DELETE_RULE
			FROM information_schema.KEY_COLUMN_USAGE k
			JOIN information_schema.REFERENTIAL_CONSTRAINTS r
			  ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
			WHERE k.TABLE_SCHEMA = DATABASE() AND k.TABLE_NAME = '%s'
			  AND k.REFERENCED_TABLE_NAME IS NOT NULL`, table)
	case Postgres:
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
	case MSSQL:
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
	default: // SQLite
		// "to" is NULL when the reference names no column and means the referenced
		// table's primary key; every foreign key in this schema names one.
		q = fmt.Sprintf(`SELECT "from", "table", COALESCE("to", ''), UPPER(on_delete)
			FROM pragma_foreign_key_list('%s')`, table)
	}

	rows, err := db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("schemadump: foreign key catalog lookup on %s.%s: %w", d, table, err)
	}
	defer func() { _ = rows.Close() }()

	var fks []ForeignKeyShape
	for rows.Next() {
		var col, refTable, refCol, onDelete string
		if err := rows.Scan(&col, &refTable, &refCol, &onDelete); err != nil {
			return nil, fmt.Errorf("schemadump: scan foreign key catalog row on %s.%s: %w", d, table, err)
		}
		fks = append(fks, ForeignKeyShape{Column: col, RefTable: refTable, RefColumn: refCol, OnDelete: onDelete})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("schemadump: iterate foreign key catalog on %s.%s: %w", d, table, err)
	}
	return fks, nil
}
