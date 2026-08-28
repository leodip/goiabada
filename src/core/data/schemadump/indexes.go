package schemadump

import (
	"database/sql"
	"fmt"
)

// dumpIndexes reads every index on one table. Each query returns one row per key column,
// ordered by index and then by the index's own column order, so the loop below folds them
// into one IndexShape per name without sorting the columns.
//
// Origin is the catalog's own answer to who named the index, never a pattern matched
// against the name: see IndexOrigin.
func dumpIndexes(db *sql.DB, d Dialect, table string) ([]IndexShape, error) {
	var q string
	switch d {
	case MySQL:
		// MySQL cannot answer the second half of the origin question and this says so
		// rather than guessing. It maps CREATE UNIQUE INDEX onto ALTER TABLE ADD UNIQUE
		// INDEX, so both spellings report CONSTRAINT_TYPE = 'UNIQUE' in TABLE_CONSTRAINTS
		// and are indistinguishable. The distinction is only needed to mask a name the
		// engine invented, and MySQL invents one only for an index declared without a
		// name: there are none in this schema, and guardTable refuses one rather than
		// letting a later migration introduce it silently.
		q = fmt.Sprintf(`SELECT INDEX_NAME, CASE WHEN NON_UNIQUE = 0 THEN '1' ELSE '0' END,
			CASE WHEN INDEX_NAME = 'PRIMARY' THEN 'pk' ELSE 'c' END, COLUMN_NAME
			FROM information_schema.statistics
			WHERE table_schema = DATABASE() AND table_name = '%s'
			ORDER BY INDEX_NAME, SEQ_IN_INDEX`, table)
	case Postgres:
		// indkey is an int2vector of column numbers; unnesting it WITH ORDINALITY is
		// what preserves the index's own column order. indkey holds INCLUDE columns
		// after the key ones, so the position is bounded by indnkeyatts to keep this
		// branch reporting key columns only.
		//
		// The LEFT JOIN onto pg_constraint is the origin: an index backing a primary key
		// or a UNIQUE constraint is reachable from it through conindid, and one created
		// by CREATE INDEX is not, so the null case is 'c'.
		q = fmt.Sprintf(`SELECT i.relname, CASE WHEN ix.indisunique THEN '1' ELSE '0' END,
			CASE con.contype WHEN 'p' THEN 'pk' WHEN 'u' THEN 'u' ELSE 'c' END, a.attname
			FROM pg_index ix
			JOIN pg_class i ON i.oid = ix.indexrelid
			JOIN pg_class tb ON tb.oid = ix.indrelid
			JOIN pg_namespace n ON n.oid = tb.relnamespace
			LEFT JOIN pg_constraint con ON con.conindid = ix.indexrelid AND con.contype IN ('p','u')
			JOIN unnest(ix.indkey::smallint[]) WITH ORDINALITY AS k(attnum, ord) ON true
			JOIN pg_attribute a ON a.attrelid = tb.oid AND a.attnum = k.attnum
			WHERE tb.relname = '%s' AND n.nspname = current_schema()
			  AND k.ord <= ix.indnkeyatts
			ORDER BY i.relname, k.ord`, table)
	case MSSQL:
		// i.name IS NULL is the heap, which is not an index and has no shape to record.
		// is_included_column = 0 keeps INCLUDE columns out: they are payload, not key
		// columns, and they carry key_ordinal 0.
		q = fmt.Sprintf(`SELECT i.name, CASE WHEN i.is_unique = 1 THEN '1' ELSE '0' END,
			CASE WHEN i.is_primary_key = 1 THEN 'pk' WHEN i.is_unique_constraint = 1 THEN 'u' ELSE 'c' END,
			c.name
			FROM sys.indexes i
			JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
			JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
			WHERE i.object_id = OBJECT_ID('dbo.%s') AND i.name IS NOT NULL
			  AND ic.is_included_column = 0
			ORDER BY i.name, ic.key_ordinal`, table)
	default: // SQLite
		// The comma join is required: pragma_index_info takes its argument from the row
		// to its left, which SQLite only allows for table-valued functions in that
		// position. pragma_index_list.origin is the catalog answering the origin
		// question directly, in the same three values the other engines are mapped onto.
		q = fmt.Sprintf(`SELECT il.name, CASE WHEN il."unique" = 1 THEN '1' ELSE '0' END,
			il.origin, ii.name
			FROM pragma_index_list('%s') AS il, pragma_index_info(il.name) AS ii
			ORDER BY il.name, ii.seqno`, table)
	}

	rows, err := db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("schemadump: index catalog sweep on %s.%s: %w", d, table, err)
	}
	defer func() { _ = rows.Close() }()

	var indexes []IndexShape
	byName := map[string]int{}
	for rows.Next() {
		var name, uniqueFlag, origin, col string
		if err := rows.Scan(&name, &uniqueFlag, &origin, &col); err != nil {
			return nil, fmt.Errorf("schemadump: scan index catalog row on %s.%s: %w", d, table, err)
		}
		pos, seen := byName[name]
		if !seen {
			indexes = append(indexes, IndexShape{
				Name: name, Exists: true, Unique: uniqueFlag == "1", Origin: IndexOrigin(origin),
			})
			pos = len(indexes) - 1
			byName[name] = pos
		}
		indexes[pos].Columns = append(indexes[pos].Columns, col)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("schemadump: iterate index catalog on %s.%s: %w", d, table, err)
	}

	for _, ix := range indexes {
		switch ix.Origin {
		case OriginCreated, OriginUnique, OriginPrimaryKey:
		default:
			return nil, fmt.Errorf("schemadump: %s reported index %q on %q with origin %q, which is none of c, u or pk",
				d, ix.Name, table, ix.Origin)
		}
	}
	return indexes, nil
}
