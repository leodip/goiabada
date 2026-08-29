package data

// The one place the four committed migration directories are judged.
//
// migration_rules_test.go is the machinery and its synthetic cases; this points the same
// function at the real tree. The split is the one parity/golden makes for itself: a rule that
// has quietly stopped matching anything is caught by the synthetic half, and this half is a
// claim about what is actually on disk.
//
// It reads files and nothing else: no database, no git, no network, so it runs in the core tier
// on every CI job rather than only the four database ones, and it gives the same answer in a
// tarball, in a worktree and on a shallow clone (#288 decision 1).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/data/schemadump"
	"github.com/stretchr/testify/require"
)

// TestMigrationSource_TheFourCommittedDirectories is #288's goal 1: a migration that breaks
// four-engine parity in a way decidable from source text cannot land.
//
// A failure here names the file and the rule. Every one of them is a migration to fix rather
// than a rule to relax: the tree passes all of these today, so a new finding is something this
// branch wrote.
func TestMigrationSource_TheFourCommittedDirectories(t *testing.T) {
	tree := committedMigrationTree(t)

	findings := checkMigrationSource(tree)
	findings = append(findings, checkGoldenVersion(tree, committedGoldenVersions(t))...)
	if len(findings) == 0 {
		return
	}
	t.Fatalf("the migration sources break %d rule(s):\n%s\n\n"+
		"Every entry above is a file to fix. A migration is written four times by hand, and "+
		"these are the divergences decidable from the text alone: #282 found five structural "+
		"ones that had shipped for months and #283 found the collation of every string column "+
		"wrong on two engines. Catalog SHAPE parity is a separate guard (#284), so green here "+
		"is a floor rather than a proof.",
		len(findings), joinMigrationFindings(findings))
}

// TestMigrationCutoffs_AreTight is what stops a cutoff being inflated to step over the migration
// being written right now, which is the one way to use this check that is worse than not running
// it. Each cutoff names the last migration that breaks its rule, so lowering it by a single
// number has to make that exact migration report: a cutoff set higher than the evidence supports
// fails here rather than silently exempting the file the rule exists to check.
//
// It is the other half of the main test above. That one says the tree passes with the real
// cutoffs; this one says each cutoff is where the violations actually stop.
func TestMigrationCutoffs_AreTight(t *testing.T) {
	tree := committedMigrationTree(t)

	// The number under test is READ OFF migrationCutoffsDefault rather than written again here.
	// Repeating it would make this test agree with itself: an inflated cutoff would move the
	// value the rules use and leave the value the test checks behind, and the check would pass
	// while exempting a migration nobody looked at.
	tests := []struct {
		rule   string
		cutoff int
		lower  func(*migrationCutoffs, int)
	}{
		{"mssql/nvarchar", migrationCutoffsDefault.MSSQLNVarchar,
			func(c *migrationCutoffs, n int) { c.MSSQLNVarchar = n }},
		{"mssql/named-default", migrationCutoffsDefault.MSSQLNamedDefault,
			func(c *migrationCutoffs, n int) { c.MSSQLNamedDefault = n }},
		{"mssql/collate", migrationCutoffsDefault.MSSQLCollate,
			func(c *migrationCutoffs, n int) { c.MSSQLCollate = n }},
		{"mysql/collation", migrationCutoffsDefault.MySQLCollation,
			func(c *migrationCutoffs, n int) { c.MySQLCollation = n }},
	}

	for _, tt := range tests {
		t.Run(tt.rule, func(t *testing.T) {
			cutoffs := migrationCutoffsDefault
			tt.lower(&cutoffs, tt.cutoff-1)

			var at []migrationFinding
			for _, f := range checkMigrationSourceWith(tree, cutoffs) {
				if f.Rule == tt.rule && strings.Contains(f.Where, fmt.Sprintf("%06d_", tt.cutoff)) {
					at = append(at, f)
				}
			}
			require.NotEmptyf(t, at,
				"the %s cutoff is %06d, which claims %06d is the last migration that breaks the "+
					"rule. Lowering it by one reported nothing there, so the cutoff is higher than "+
					"the evidence supports and every migration up to it is exempt for no reason. "+
					"A cutoff moves only when a new rule is added that shipped migrations would "+
					"fail, never to step over the migration being written now.",
				tt.rule, tt.cutoff, tt.cutoff)
		})
	}
}

// committedMigrationTree reads the four migration directories off disk. The directories are
// DISCOVERED rather than assembled from the four constants, so checkMigrationDirectories has
// something to disagree with: a fifth engine's directory is a failure rather than a silent skip.
func committedMigrationTree(t *testing.T) migrationTree {
	t.Helper()

	root, err := schemadump.SourceRoot()
	require.NoError(t, err, "find the source root the way schemadump.GoldenPath does")

	dirs, err := filepath.Glob(filepath.Join(root, "core", "data", "*db", "migrations"))
	require.NoError(t, err, "discover the migration directories")

	// commondb has no migrations subdirectory and so is not here.
	found := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		found = append(found, filepath.Base(filepath.Dir(dir)))
	}

	if problems := checkMigrationDirectories(found); len(problems) > 0 {
		t.Fatalf("the migration directories are not the four engines schemadump names:\n%s\n\n"+
			"An engine added to schemadump owes a migrations directory, and a directory added "+
			"beside these owes a dialect: without one the rules never read it.",
			joinMigrationFindings(problems))
	}

	tree := migrationTree{}
	for _, dir := range dirs {
		d := schemadump.Dialect(strings.TrimSuffix(filepath.Base(filepath.Dir(dir)), "db"))
		entries, err := os.ReadDir(dir)
		require.NoErrorf(t, err, "read %s", dir)

		files := map[string]string{}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
				continue
			}
			contents, err := os.ReadFile(filepath.Join(dir, e.Name()))
			require.NoErrorf(t, err, "read %s", filepath.Join(dir, e.Name()))
			files[e.Name()] = string(contents)
		}
		require.NotEmptyf(t, files, "%s holds no .sql files", dir)
		tree[d] = files
	}
	require.Len(t, tree, len(migrationDialects), "one tree entry per engine")
	return tree
}

// committedGoldenVersions reads the migration version out of each engine's committed
// schema.golden, through the same Parse the dumper and the data tier use, so a header this
// build cannot read is a failure here rather than a missing entry the rule reads as absent.
func committedGoldenVersions(t *testing.T) map[schemadump.Dialect]int {
	t.Helper()

	recorded := map[schemadump.Dialect]int{}
	for _, d := range migrationDialects {
		path, err := schemadump.GoldenPath(d)
		require.NoErrorf(t, err, "locate %s's golden file", d)

		contents, err := os.ReadFile(path)
		require.NoErrorf(t, err, "read %s", path)

		golden, err := schemadump.Parse(contents)
		require.NoErrorf(t, err, "parse %s", path)
		recorded[d] = golden.Migrated
	}
	return recorded
}
