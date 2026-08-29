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
	root, err := schemadump.SourceRoot()
	require.NoError(t, err, "find the source root the way schemadump.GoldenPath does")

	dirs, err := filepath.Glob(filepath.Join(root, "core", "data", "*db", "migrations"))
	require.NoError(t, err, "discover the migration directories")

	// Discovered rather than assembled from the four constants, so the comparison below has
	// something to disagree with. commondb has no migrations subdirectory and so is not here.
	found := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		found = append(found, filepath.Base(filepath.Dir(dir)))
	}

	if problems := checkMigrationDirectories(found); len(problems) > 0 {
		t.Fatalf("the migration directories are not the four engines schemadump names:\n%s\n\n"+
			"An engine added to schemadump owes a migrations directory, and a directory added "+
			"beside these owes a dialect: without one the rules below never read it.",
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

	findings := checkMigrationSource(tree)
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
