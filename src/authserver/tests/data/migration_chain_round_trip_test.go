package datatests

import (
	"fmt"
	"testing"

	"github.com/leodip/goiabada/core/data/migrator"
	"github.com/leodip/goiabada/core/data/schemadump"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigrationChain_EveryDownRestoresTheCatalog walks one engine's whole migration chain up,
// back down to an unmigrated database, and up again, holding the catalog at every version to
// what it was the first time that version was reached.
//
// Why the 21 per-migration round-trip tests are not this. Each of them rolls back its own
// migration and checks the two or three things that migration touched, and every one of them
// starts at 000024 or above: the downs from 000001 to 000023 had never been executed by anything
// at all. Two of them do not even run. SQL Server's 000004 and 000017 add columns with unnamed
// DEFAULT constraints and their downs DROP COLUMN, which SQL Server refuses while a default
// constraint depends on the column, so the rollback a release note would promise fails at the
// first step off a fresh install (#268 decision 12).
//
// What it asserts, and what it deliberately does not. Catalog equality: columns with their types,
// nullability and defaults, indexes with their key columns and uniqueness, and foreign keys with
// their actions, read out of the engine's own catalog through schemadump and compared as the
// encoded text a golden file is written in. It says nothing about rows. A down loses data by
// construction, so row preservation is the migration author's job and 000039's down is the model
// for it; what this test exists to catch is the down that RUNS and leaves a column, an index or a
// nullability behind, which nothing else in the repository can see.
//
// The recorded version is part of the compared bytes rather than a separate assertion, because
// schemadump.Encode puts it in the header. So a step that moved the schema correctly and the
// marker wrongly, or the reverse, fails here as a difference in the first line.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigrationChain_EveryDownRestoresTheCatalog
func TestMigrationChain_EveryDownRestoresTheCatalog(t *testing.T) {
	h := newIsolatedDB(t)

	// The engine's own carried versions, ascending. Plan answers exactly the versions a
	// Migrate to head would step through, read off the empty database, so the four sets' gaps
	// (postgres has no 000002, three engines have no 000015, and 000036 to 000043 are each on
	// one or two engines) come from the source rather than from a list written down here that
	// the next migration would make wrong.
	versions, err := h.Migrator.Plan(h.Migrator.Head())
	require.NoErrorf(t, err, "plan the whole chain on %s", dbType())
	require.NotEmptyf(t, versions, "%s carries no migrations at all", dbType())

	// Up, recording the catalog at every version.
	recorded := make(map[int]string, len(versions))
	for _, v := range versions {
		require.NoErrorf(t, h.Migrator.Migrate(v), "apply %06d on %s", v, dbType())
		recorded[v] = encodeCatalogAt(t, h, v, "on the way up")
	}
	require.Equalf(t, h.Migrator.Head(), versions[len(versions)-1],
		"the plan must end at the head this binary carries for %s", dbType())

	mismatches := newCatalogMismatches()

	// Down to an unmigrated database, comparing at every landing. The landing is the PREVIOUS
	// version the engine carries, which is the marker a down step writes, and below the first
	// migration it is NilVersion.
	for i := len(versions) - 1; i >= 0; i-- {
		target := migrator.NilVersion
		if i > 0 {
			target = versions[i-1]
		}
		require.NoErrorf(t, h.Migrator.Migrate(target),
			"roll back %06d on %s. A down that will not run is a rollback an operator cannot perform",
			versions[i], dbType())

		if target == migrator.NilVersion {
			assertUnmigratedCatalog(t, h, versions[i])
			continue
		}
		mismatches.compare(t, recorded[target], encodeCatalogAt(t, h, target, "after rolling back "+formatChainVersion(versions[i])),
			target, fmt.Sprintf("rolling %06d back left the catalog at %06d different from what applying %06d built",
				versions[i], target, target))
	}

	// Up again, comparing at every version. This is what catches a down whose residue the
	// catalog comparison cannot see but the next up can: a row a data migration re-inserts, or
	// a column an ALTER refuses to add twice.
	for _, v := range versions {
		require.NoErrorf(t, h.Migrator.Migrate(v), "re-apply %06d on %s after the full rollback", v, dbType())
		mismatches.compare(t, recorded[v], encodeCatalogAt(t, h, v, "on the second way up"),
			v, fmt.Sprintf("re-applying %06d after a full rollback built a different catalog from the first time", v))
	}

	mismatches.report(t)
}

// encodeCatalogAt reads the application catalog and the recorded migration version and encodes
// them the way a golden file is written, which is the form the comparison is made in: canonical,
// ordered, and with engine-invented names masked, so two dumps of the same schema are the same
// bytes whatever order the catalog answered in.
func encodeCatalogAt(t *testing.T, h *isolatedDB, want int, when string) string {
	t.Helper()

	migrated, err := schemadump.MigratedVersion(h.SQL, dumpDialect(t))
	require.NoErrorf(t, err, "read the recorded version %s at %06d on %s", when, want, dbType())

	encoded, err := schemadump.Encode(schemadump.Golden{
		Dialect: dumpDialect(t), Migrated: migrated, Schema: applicationTables(t, h, want),
	})
	require.NoErrorf(t, err, "encode the catalog %s at %06d on %s", when, want, dbType())
	return string(encoded)
}

// applicationTables is the dump with the runner's own bookkeeping table taken out, and it is the
// one exclusion this comparison makes.
//
// schema_migrations legitimately has two shapes below 000041 on SQLite, and which one a database
// has depends on how it got there rather than on which version it is at. NewMigrator pre-creates
// the table at the pinned shape (#284), so a database walking UP has the pinned shape from before
// 000001 ran. 000041 is the migration that levels an OLD SQLite install up to that shape, and its
// down deliberately restores golang-migrate's original (version uint64, dirty bool), nullable and
// keyless, because that is the shape the release being rolled back to expects. So on the way down
// past 000041 the table changes and never changes back, and both readings are correct: the whole
// point of that down is that it does this.
//
// Comparing it anyway would report every version below 000041 on SQLite as a broken round trip,
// which is the cascade that buries a real one. The version the table RECORDS is still compared,
// in the encoded header, so nothing about the bookkeeping goes unchecked here except a shape that
// has no single right answer.
func applicationTables(t *testing.T, h *isolatedDB, version int) schemadump.Schema {
	t.Helper()

	full := dumpSchema(t, h)
	out := make(schemadump.Schema, 0, len(full))
	for _, entry := range full {
		if entry.Name == "schema_migrations" {
			continue
		}
		if maskCollation(version) {
			for i := range entry.Table.Columns {
				entry.Table.Columns[i].Collation = ""
			}
		}
		out = append(out, entry)
	}
	require.NotEmptyf(t, out, "the %s dump read no application tables at all", dbType())
	return out
}

// collationPinnedFrom is the migration that makes a SQL Server column's collation something a
// migration decides. 000040 is #283's, and it spells Latin1_General_100_CS_AS_KS_WS_SC_UTF8 on
// all 92 string columns.
const collationPinnedFrom = 40

// maskCollation reports whether the collation column of the dump is meaningless at this version,
// which on SQL Server it is below 000040 and nowhere else.
//
// No migration below 000040 declares a collation, so every string column down there takes
// whichever one the DATABASE default gives it, and this fixture's database was created at the
// post-#283 default. That makes the two directions legitimately disagree: walking UP, the columns
// inherit the new collation from before 000001 ran, and walking DOWN, 000040's down sets all 92
// of them back to Latin1_General_100_CI_AI_SC_UTF8, which is exactly its job, because that is
// what the release being rolled back to expects. Both readings are correct and neither is a
// property of a down migration, so comparing the field below 000040 reports every version there
// as broken and hides anything that really is.
//
// The other three engines have nothing to mask: PostgreSQL and SQLite compare byte-wise and have
// no per-column collation to inherit, and MySQL's 000040 repairs the database default and every
// table with it.
func maskCollation(version int) bool {
	return dbType() == "mssql" && version < collationPinnedFrom
}

// assertUnmigratedCatalog holds the floor of the chain: rolling the first migration back leaves
// the database with nothing but schema_migrations, which Goiabada's own constructor pre-creates
// and no migration drops (#284).
//
// Asserted rather than assumed, because it is the one landing with no recording to compare
// against and so the one place a down that dropped nothing would go unnoticed.
func assertUnmigratedCatalog(t *testing.T, h *isolatedDB, first int) {
	t.Helper()

	left := listTables(t, h)
	assert.Equalf(t, []string{"schema_migrations"}, left,
		"rolling %06d back must leave an unmigrated database on %s, and %s is what it left. "+
			"A table still standing here is one some down did not drop",
		first, dbType(), left)
}

// catalogMismatches collects every version whose catalog disagreed, so one run of the chain names
// all of them.
//
// Only the first prints its diff. A down that leaves a column behind leaves it behind at every
// lower version too, so the cascade is longer than the finding and printing all of it buries the
// step that caused it.
type catalogMismatches struct {
	versions []int
	shown    bool
}

func newCatalogMismatches() *catalogMismatches { return &catalogMismatches{} }

func (c *catalogMismatches) compare(t *testing.T, want, got string, version int, what string) {
	t.Helper()
	if want == got {
		return
	}

	c.versions = append(c.versions, version)
	if c.shown {
		t.Errorf("%s on %s", what, dbType())
		return
	}
	c.shown = true
	t.Errorf("%s on %s.\n%s", what, dbType(), diffLines(want, got))
}

func (c *catalogMismatches) report(t *testing.T) {
	t.Helper()
	if len(c.versions) == 0 {
		return
	}
	t.Errorf("%d version(s) on %s do not round trip: %v. Each one is a down that ran and left the catalog different from what the up built",
		len(c.versions), dbType(), c.versions)
}

func formatChainVersion(v int) string { return fmt.Sprintf("%06d", v) }
