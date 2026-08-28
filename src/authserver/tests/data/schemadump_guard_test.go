package datatests

import (
	"testing"

	"github.com/leodip/goiabada/core/data/schemadump"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSchemaDump_RefusesWhatItCannotRead covers the three ways the dumper answers with an
// error rather than a shape. Each is a case where the alternative is an empty or partial dump
// that a comparison reads as "nothing changed" and passes, which is the one failure mode that
// would make the whole of #284 worthless.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestSchemaDump_RefusesWhatItCannotRead
func TestSchemaDump_RefusesWhatItCannotRead(t *testing.T) {
	h := newIsolatedDB(t)
	require.NoError(t, h.Migrator.Migrate(35), "migrate to 000035")

	// An unrecognised dialect. Every switch this package replaced fell through its default
	// arm to SQLite, so in the generator's four-engine process a misspelling would have read
	// SQLite's catalog against another engine's connection and reported success.
	_, err := schemadump.DumpTable(h.SQL, schemadump.Dialect("postgresql"), "refresh_tokens")
	assert.ErrorContains(t, err, "unrecognised database dialect",
		"an unrecognised dialect must be refused, not treated as SQLite")
	_, err = schemadump.Tables(h.SQL, schemadump.Dialect(""))
	assert.ErrorContains(t, err, "unrecognised database dialect",
		"the zero Dialect selects no engine")

	// A table that does not exist. Every catalog answers with an empty row set rather than
	// an error, so this is the dumper's own guard and not the driver's.
	_, err = schemadump.DumpTable(h.SQL, dumpDialect(t), "no_such_table")
	assert.ErrorContains(t, err, "read no columns",
		"a table with no columns is not something any of the four engines can produce")

	// A name the package would have to interpolate into a catalog query.
	_, err = schemadump.DumpTable(h.SQL, dumpDialect(t), "refresh_tokens; DROP TABLE codes")
	assert.ErrorContains(t, err, "not a plain identifier")
}

// TestSchemaDump_RefusesAnEmptyTableList is the enumeration half of the same guard, and it
// needs a database with no tables at all to state it.
//
// schema_migrations is dropped to get there, which is safe because the isolated database is
// thrown away at the end of this test and has never been migrated past version 0.
func TestSchemaDump_RefusesAnEmptyTableList(t *testing.T) {
	h := newIsolatedDB(t)

	// NewMigrator's driver creates schema_migrations at construction, so an isolated
	// database at version 0 already holds exactly one table.
	names := listTables(t, h)
	require.Equalf(t, []string{"schema_migrations"}, names,
		"an isolated database at version 0 holds only the migrator's own table on %s", dbType())

	_, err := h.SQL.Exec("DROP TABLE schema_migrations")
	require.NoErrorf(t, err, "drop schema_migrations on %s", dbType())

	_, err = schemadump.Tables(h.SQL, dumpDialect(t))
	assert.ErrorContains(t, err, "reported no tables at all",
		"an empty dump compared against an empty golden file reads as no change and passes")
	_, err = schemadump.Dump(h.SQL, dumpDialect(t))
	assert.ErrorContains(t, err, "reported no tables at all",
		"Dump fails for the same reason Tables does, rather than returning an empty schema")
}

// guardCase is one construct TableShape has no field for, built as scratch DDL on an engine
// whose syntax has it.
type guardCase struct {
	construct string   // what the error must name
	ddl       []string // statements building the probe, in order
}

// TestSchemaDump_RefusesUnrepresentableConstructs holds the dumper to failing rather than
// dropping a construct it cannot record. Silence would be worse than an error here than
// anywhere else in the change, because the same code writes the golden file and checks it:
// a fact discarded during the dump is discarded from the committed record too, and no later
// stage can recover it.
//
// Every construct below is absent from all four migration chains today, so the guard fires
// on nothing that exists and each case has to build its own table to fire at all.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestSchemaDump_RefusesUnrepresentableConstructs
func TestSchemaDump_RefusesUnrepresentableConstructs(t *testing.T) {
	h := newIsolatedDB(t)
	d := dumpDialect(t)

	for _, stmt := range []string{
		"CREATE TABLE guard_parent1 (id BIGINT NOT NULL PRIMARY KEY)",
		"CREATE TABLE guard_parent2 (a BIGINT NOT NULL, b BIGINT NOT NULL, PRIMARY KEY (a, b))",
	} {
		_, err := h.SQL.Exec(stmt)
		require.NoErrorf(t, err, "create the guard probe's parent tables on %s", dbType())
	}
	t.Cleanup(func() {
		_, _ = h.SQL.Exec("DROP TABLE guard_parent2")
		_, _ = h.SQL.Exec("DROP TABLE guard_parent1")
	})

	cases := guardCasesFor(dbType())
	require.NotEmptyf(t, cases, "no guard cases are defined for %s", dbType())

	for _, c := range cases {
		t.Run(c.construct, func(t *testing.T) {
			for _, stmt := range c.ddl {
				_, err := h.SQL.Exec(stmt)
				require.NoErrorf(t, err, "build the probe for %q on %s: %s", c.construct, dbType(), stmt)
			}
			defer func() { _, _ = h.SQL.Exec("DROP TABLE guard_probe") }()

			_, err := schemadump.DumpTable(h.SQL, d, "guard_probe")
			require.Errorf(t, err, "%s must be refused on %s, not dropped from the dump", c.construct, dbType())
			assert.ErrorContains(t, err, c.construct)
		})
	}
}

// guardCasesFor is the per-engine DDL. A construct is listed only for the engines whose
// syntax has it: MySQL has no filtered index, no INCLUDE columns and no DEFERRABLE, SQL
// Server has no DEFERRABLE, and the unnamed-index case is MySQL's alone because it is the
// only engine that invents a name for an index whose declaration gave none.
func guardCasesFor(engine string) []guardCase {
	composite := guardCase{
		construct: "a composite foreign key",
		ddl: []string{`CREATE TABLE guard_probe (a BIGINT NOT NULL, b BIGINT NOT NULL,
			CONSTRAINT fk_guard_probe FOREIGN KEY (a, b) REFERENCES guard_parent2 (a, b))`},
	}
	check := guardCase{
		construct: "a CHECK constraint",
		ddl:       []string{"CREATE TABLE guard_probe (a BIGINT NOT NULL CHECK (a > 0))"},
	}
	onUpdate := guardCase{
		construct: "an ON UPDATE referential action",
		ddl: []string{`CREATE TABLE guard_probe (a BIGINT NOT NULL,
			CONSTRAINT fk_guard_probe FOREIGN KEY (a) REFERENCES guard_parent1 (id) ON UPDATE CASCADE)`},
	}
	descending := guardCase{
		construct: "a descending index key",
		ddl: []string{
			"CREATE TABLE guard_probe (a BIGINT NOT NULL)",
			"CREATE INDEX idx_guard_probe ON guard_probe (a DESC)",
		},
	}
	partial := guardCase{
		construct: "a partial or filtered index",
		ddl: []string{
			"CREATE TABLE guard_probe (a BIGINT NOT NULL)",
			"CREATE INDEX idx_guard_probe ON guard_probe (a) WHERE a > 0",
		},
	}
	include := guardCase{
		construct: "an index with INCLUDE columns",
		ddl: []string{
			"CREATE TABLE guard_probe (a BIGINT NOT NULL, b BIGINT NOT NULL)",
			"CREATE INDEX idx_guard_probe ON guard_probe (a) INCLUDE (b)",
		},
	}
	deferrable := guardCase{
		construct: "a DEFERRABLE constraint",
		ddl: []string{`CREATE TABLE guard_probe (a BIGINT NOT NULL,
			CONSTRAINT fk_guard_probe FOREIGN KEY (a) REFERENCES guard_parent1 (id) DEFERRABLE INITIALLY DEFERRED)`},
	}

	generated := guardCase{construct: "a generated (computed) column"}
	switch engine {
	case "mysql":
		generated.ddl = []string{"CREATE TABLE guard_probe (a BIGINT NOT NULL, g BIGINT AS (a + 1))"}
	case "postgres":
		generated.ddl = []string{"CREATE TABLE guard_probe (a bigint NOT NULL, g bigint GENERATED ALWAYS AS (a + 1) STORED)"}
	case "mssql":
		generated.ddl = []string{"CREATE TABLE guard_probe (a BIGINT NOT NULL, g AS (a + 1))"}
	default: // sqlite
		generated.ddl = []string{"CREATE TABLE guard_probe (a BIGINT NOT NULL, g BIGINT GENERATED ALWAYS AS (a + 1) VIRTUAL)"}
	}

	switch engine {
	case "mysql":
		return []guardCase{composite, check, generated, onUpdate, descending, {
			construct: "an index MySQL named for itself",
			ddl:       []string{"CREATE TABLE guard_probe (a BIGINT NOT NULL, KEY (a))"},
		}}
	case "postgres":
		return []guardCase{composite, check, generated, onUpdate, descending, partial, include, deferrable}
	case "mssql":
		return []guardCase{composite, check, generated, onUpdate, descending, partial, include}
	default: // sqlite
		return []guardCase{composite, check, generated, onUpdate, descending, partial, deferrable}
	}
}
