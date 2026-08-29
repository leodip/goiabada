package schemadump

import (
	"database/sql"
	"fmt"
)

// MigratedVersion reads the migration version of the connected database out of
// schema_migrations, which is the number the golden file's header records (#288).
//
// The query is the same on all four engines, unlike everything else this package reads,
// because schema_migrations is not a catalog view: it is a table golang-migrate created and
// #284 pinned to one shape on all four, so `SELECT version, dirty FROM schema_migrations` is
// literally golang-migrate's own Version() query.
//
// Every failure is an error and never a zero. A reader that answered 0 when the table was
// missing, empty or unreadable would make the version rule compare 0 against 0 and pass on a
// file nobody regenerated, which is the one outcome that would make the rule worthless. So a
// dirty row is refused, because a half-applied database's catalog is not a record of any
// migration chain, and an empty table is refused, because that is an unmigrated database.
func MigratedVersion(db *sql.DB, d Dialect) (int, error) {
	if !d.valid() {
		return 0, fmt.Errorf("schemadump: unrecognised database dialect %q", d)
	}

	rows, err := db.Query(`SELECT version, dirty FROM schema_migrations`)
	if err != nil {
		return 0, fmt.Errorf("schemadump: read schema_migrations on %s: %w", d, err)
	}
	defer func() { _ = rows.Close() }()

	var (
		version int
		dirty   bool
		found   bool
	)
	for rows.Next() {
		if err := rows.Scan(&version, &dirty); err != nil {
			return 0, fmt.Errorf("schemadump: scan schema_migrations on %s: %w", d, err)
		}
		found = true
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("schemadump: iterate schema_migrations on %s: %w", d, err)
	}
	if !found {
		return 0, fmt.Errorf("schemadump: schema_migrations on %s holds no row, so the database has never been migrated", d)
	}
	if dirty {
		return 0, fmt.Errorf("schemadump: schema_migrations on %s records version %d as dirty, so migration %d failed part way and the catalog is not a record of anything", d, version, version)
	}
	if version <= 0 {
		return 0, fmt.Errorf("schemadump: schema_migrations on %s records version %d, which is not a migration this repository has", d, version)
	}
	return version, nil
}
