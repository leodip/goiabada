package schemadump

import (
	"database/sql"
	"fmt"
	"strings"
)

// sqliteColumnFacts are the two things about a SQLite column that exist only in the
// declaration SQLite keeps in sqlite_schema, and nowhere a pragma can project them.
type sqliteColumnFacts struct {
	// Collation is the declared COLLATE, or BINARY when the declaration omits one, which
	// is SQLite's default and what every column in this schema is.
	Collation string
	// Generated is the declared AUTOINCREMENT.
	Generated bool
}

// sqliteTableDDL returns the CREATE TABLE text SQLite keeps in its own catalog, which is
// not the schema documentation snapshot beside the migrations.
func sqliteTableDDL(db *sql.DB, table string) (string, error) {
	var ddl string
	err := db.QueryRow(`SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?`, table).Scan(&ddl)
	if err != nil {
		return "", fmt.Errorf("schemadump: read the CREATE TABLE text for %q out of sqlite_schema: %w", table, err)
	}
	return ddl, nil
}

// sqliteDeclaredColumnFacts parses each column's declaration out of the CREATE TABLE text.
//
// Text rather than a projection because SQLite has no other place to read either fact from.
// pragma_table_info does not carry collation, and pragma_index_xinfo carries it only for a
// column an index happens to cover. Generation is worse: pragma_table_info returns
// byte-identical rows for `integer PRIMARY KEY AUTOINCREMENT` and plain `integer PRIMARY
// KEY`, and sqlite_sequence holds no row for a table until that table's first insert, so on
// a migrated-but-empty database, which is what the generator dumps, every table would read
// as not auto-numbered. Filling either field from a constant instead would make it assert
// nothing, which is the trap this exists to avoid.
func sqliteDeclaredColumnFacts(db *sql.DB, table string) (map[string]sqliteColumnFacts, error) {
	ddl, err := sqliteTableDDL(db, table)
	if err != nil {
		return nil, err
	}
	return parseSqliteColumnFacts(ddl), nil
}

// parseSqliteColumnFacts is the parsing half of sqliteDeclaredColumnFacts, split out so the
// two facts it reads can be exercised over hand-written DDL with no database at all.
func parseSqliteColumnFacts(ddl string) map[string]sqliteColumnFacts {
	out := map[string]sqliteColumnFacts{}
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
		facts := sqliteColumnFacts{Collation: "BINARY"}
		for i, f := range fields {
			switch {
			case strings.EqualFold(f, "COLLATE") && i+1 < len(fields):
				facts.Collation = strings.ToUpper(strings.Trim(fields[i+1], "[]`\"',"))
			case strings.EqualFold(strings.Trim(f, ","), "AUTOINCREMENT"):
				facts.Generated = true
			}
		}
		out[name] = facts
	}
	return out
}

// columnDefsOf returns what a CREATE TABLE statement holds between its outermost
// parentheses, which is the column and table-constraint list.
func columnDefsOf(ddl string) string {
	open := strings.Index(ddl, "(")
	closing := strings.LastIndex(ddl, ")")
	if open < 0 || closing < open {
		return ""
	}
	return ddl[open+1 : closing]
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
