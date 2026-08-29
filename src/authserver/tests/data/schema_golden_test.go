package datatests

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/data/schemadump"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSchemaGolden_MatchesTheCommittedFile is seam 2, and the half of #284 that runs on all
// four engines: migrate a fresh database to head, read its catalog, and hold it to the file
// committed beside that engine's migrations.
//
// This is what makes CI red when a migration landed and `go run ./cmd/schemadump` was not
// run. It is also the only check that can see a migration building something other than what
// its author intended, because it compares against a record rather than against the same
// hand-written SQL a second time.
//
// The comparison is against the ENCODED form rather than against the parsed shape, on
// purpose: the committed bytes are what a reviewer reads in the pull request, so the thing
// asserted equal is the thing they are looking at.
func TestSchemaGolden_MatchesTheCommittedFile(t *testing.T) {
	h := newIsolatedDB(t)
	require.NoError(t, h.Migrator.Up(), "migrate the isolated database to head on %s", dbType())

	migrated, err := schemadump.MigratedVersion(h.SQL, dumpDialect(t))
	require.NoErrorf(t, err, "read the migration version of the freshly migrated %s database", dbType())

	encoded, err := schemadump.Encode(schemadump.Golden{
		Dialect: dumpDialect(t), Migrated: migrated, Schema: dumpSchema(t, h),
	})
	require.NoErrorf(t, err, "encode the %s dump", dbType())

	path, err := schemadump.GoldenPath(dumpDialect(t))
	require.NoErrorf(t, err, "locate the %s golden file", dbType())
	committed, err := os.ReadFile(path)
	require.NoErrorf(t, err, "read the committed golden file at %s", path)

	if string(committed) == string(encoded) {
		return
	}
	t.Fatalf("the %s catalog is not what %s records.\n%s\n\nRegenerate all four with:\n"+
		"  cd src/core && go run ./cmd/schemadump\n"+
		"and commit the result. The four files move together.",
		dbType(), path, diffLines(string(committed), string(encoded)))
}

// TestSchemaGolden_CommittedFileParses holds the committed file to being readable by the
// parser the cross-engine comparison will read it with, on the engine it describes.
//
// Separate from the comparison above because the two fail for different reasons and a reader
// needs to be told which: a file that does not parse is damaged or hand-edited, and a file
// that parses but disagrees is a schema that moved. schema_migrations is named because
// decision 7 makes it a table like any other rather than one excluded by name, and a dump
// that quietly stopped including it would still compare equal to a golden file generated
// from the same mistake.
func TestSchemaGolden_CommittedFileParses(t *testing.T) {
	path, err := schemadump.GoldenPath(dumpDialect(t))
	require.NoErrorf(t, err, "locate the %s golden file", dbType())
	committed, err := os.ReadFile(path)
	require.NoErrorf(t, err, "read the committed golden file at %s", path)

	g, err := schemadump.Parse(committed)
	require.NoErrorf(t, err, "parse the committed golden file at %s", path)
	assert.Equal(t, dumpDialect(t), g.Dialect, "%s names the engine it describes", path)

	_, ok := g.Schema.Table("schema_migrations")
	assert.Truef(t, ok, "%s records schema_migrations, which #284 decision 7 dumps like any other table", path)
	assert.Greaterf(t, len(g.Schema), 25, "%s records the whole schema, not a fragment of it", path)

	// The header's migration version, compared rather than merely carried. Encode writes it
	// and Parse reads it back, and the round-trip test in schemadump says those two agree;
	// what neither of them can say is that the number describes this engine's real chain. So
	// it is read off a database migrated to head here, on the engine the file is committed
	// for (#288). The four numbers legitimately differ between engines, which is why this is
	// asserted per engine and never across them.
	h := newIsolatedDB(t)
	require.NoError(t, h.Migrator.Up(), "migrate the isolated database to head on %s", dbType())
	migrated, err := schemadump.MigratedVersion(h.SQL, dumpDialect(t))
	require.NoErrorf(t, err, "read the migration version of the freshly migrated %s database", dbType())
	assert.Equalf(t, migrated, g.Migrated,
		"%s records migration version %d, but %s migrates to %d. Regenerate all four with:\n"+
			"  cd src/core && go run ./cmd/schemadump",
		path, g.Migrated, dbType(), migrated)
}

// diffLines reports the lines each side has and the other does not. A line-by-line diff would
// be more familiar, but every record in a golden file carries its own table name, so a bare
// set difference already names what moved and where, and it does not drown a real change in
// the realignment that follows it.
func diffLines(committed, current string) string {
	inCurrent := map[string]int{}
	for _, l := range strings.Split(current, "\n") {
		inCurrent[l]++
	}
	inCommitted := map[string]int{}
	for _, l := range strings.Split(committed, "\n") {
		inCommitted[l]++
	}

	var b strings.Builder
	b.WriteString(describe("only in the committed file", committed, inCurrent))
	b.WriteString(describe("only in the database", current, inCommitted))
	return b.String()
}

// describe lists, in file order, the lines of side that the other side does not carry. The
// count map is decremented so a line the other side carries twice is only excused twice.
func describe(heading, side string, other map[string]int) string {
	const limit = 40

	var b strings.Builder
	shown := 0
	for _, l := range strings.Split(side, "\n") {
		if other[l] > 0 {
			other[l]--
			continue
		}
		if shown == 0 {
			b.WriteString("\n" + heading + ":\n")
		}
		if shown < limit {
			b.WriteString("  " + l + "\n")
		}
		shown++
	}
	if shown > limit {
		fmt.Fprintf(&b, "  ... and %d more\n", shown-limit)
	}
	return b.String()
}
