package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This guard was the weakest of the thirteen when the harness landed. gofmt_lint_test.go is ten
// lines whose whole body is AssertGofmted(t) against the real tree, which is formatted and passes,
// so neither the rule nor the reporting had a test of its own: a walk that had stopped matching
// anything looked exactly like a clean repository.

// writeGoFile writes one file under root, creating the directories above it.
func writeGoFile(t *testing.T, root, rel, src string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(src), 0o600))
}

const (
	formattedSource   = "package p\n\nfunc f() {}\n"
	unformattedSource = "package p\n\nfunc  f()  {}\n"
	unparseableSource = "package p\n\nfunc broken( {\n"
)

// TestGofmt_TheRuleTable covers what the walk does with each of the three shapes a file can have:
// canonical, not canonical, and not parseable. The third is the chosen leniency -- a file that does
// not compile is the build tier's to report, and calling it a formatting fault would send the
// reader to the wrong place -- and it is not counted either, so a tree of nothing but broken files
// reads as an empty walk rather than a clean one.
func TestGofmt_TheRuleTable(t *testing.T) {
	root := t.TempDir()

	writeGoFile(t, root, "a/formatted.go", formattedSource)
	writeGoFile(t, root, "b/unformatted.go", unformattedSource)
	writeGoFile(t, root, "b/nested/also_unformatted.go", unformattedSource)
	writeGoFile(t, root, "c/broken.go", unparseableSource)
	writeGoFile(t, root, "c/notgo.txt", unformattedSource)

	unformatted, files, err := findUnformatted(root)
	require.NoError(t, err)

	assert.Equal(t, 3, files, "the two formatted-or-not .go files plus the one nested, and neither "+
		"the unparseable file nor the .txt")
	assert.Equal(t, []string{"b/nested/also_unformatted.go", "b/unformatted.go"}, unformatted)
}

// TestGofmt_ACleanTreeReportsNothing is the other direction, and it is what keeps the case above
// from passing for the wrong reason.
func TestGofmt_ACleanTreeReportsNothing(t *testing.T) {
	root := t.TempDir()
	writeGoFile(t, root, "a/one.go", formattedSource)
	writeGoFile(t, root, "b/two.go", formattedSource)

	unformatted, files, err := findUnformatted(root)
	require.NoError(t, err)

	assert.Equal(t, 2, files)
	assert.Empty(t, unformatted)

	report := RunGuard(func(r Reporter) { assertGofmted(r, root) })
	assert.False(t, report.Failed(), "a formatted tree failed the guard: %s", report.Text())
}

// TestGofmt_AnUnformattedTreeFails drives the reporting half, which until the harness landed was
// reached only by the real callers and so never observed failing.
func TestGofmt_AnUnformattedTreeFails(t *testing.T) {
	root := t.TempDir()
	writeGoFile(t, root, "a/formatted.go", formattedSource)
	writeGoFile(t, root, "b/unformatted.go", unformattedSource)

	report := RunGuard(func(r Reporter) { assertGofmted(r, root) })

	require.True(t, report.Failed())
	assert.False(t, report.Stopped, "an unformatted file is an Errorf, not a Fatalf")
	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Text(), "b/unformatted.go")
	assert.Contains(t, report.Text(), "1 of 2 Go files are not gofmt'd")
	assert.Contains(t, report.Text(), "gofmt -w")
}

// TestGofmt_AWalkThatReachesNoFilesIsNotAPass pins the seam the doc comment singles out. A root
// holding no Go file walks nothing, finds nothing, and would otherwise be indistinguishable from a
// formatted repository.
func TestGofmt_AWalkThatReachesNoFilesIsNotAPass(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "empty"), 0o755))

	report := RunGuard(func(r Reporter) { assertGofmted(r, root) })

	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked no Go files under")
}

// TestGofmt_ATreeOfOnlyUnparseableFilesIsAnEmptyWalk is where the leniency above meets the seam.
// Skipping a file that does not parse is right; counting it would let a tree the walk reached no
// verdict on pass as a clean one.
func TestGofmt_ATreeOfOnlyUnparseableFilesIsAnEmptyWalk(t *testing.T) {
	root := t.TempDir()
	writeGoFile(t, root, "a/broken.go", unparseableSource)

	report := RunGuard(func(r Reporter) { assertGofmted(r, root) })

	require.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "walked no Go files under")
}

// TestGofmt_AMissingRootIsFatalRatherThanEmpty separates the two ways a walk covers nothing. A root
// that is not there is an error from the walk, and reporting it as an empty tree would hide a
// mistyped path behind the message for a tree with no Go in it.
func TestGofmt_AMissingRootIsFatalRatherThanEmpty(t *testing.T) {
	root := filepath.Join(t.TempDir(), "does-not-exist")

	report := RunGuard(func(r Reporter) { assertGofmted(r, root) })

	require.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "walking ")
	assert.NotContains(t, report.Fatal, "walked no Go files")
}

// TestSourceRoot_FindsTheDirectoryHoldingEveryModule covers the ascent every guard's root comes
// from. A wrong root is not a loud failure -- it walks a directory that exists and holds nothing,
// and the guard passes -- which is why both of its answers are pinned rather than assumed.
func TestSourceRoot_FindsTheDirectoryHoldingEveryModule(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	for _, m := range modules {
		writeGoFile(t, src, filepath.ToSlash(filepath.Join(m, "go.mod")), "module example.com/x\n")
	}
	deep := filepath.Join(src, "core", "testutil", "fake")
	require.NoError(t, os.MkdirAll(deep, 0o755))

	found, err := sourceRootFrom(deep)
	require.NoError(t, err)
	assert.Equal(t, src, found)
}

// TestSourceRoot_AnAscentThatFindsNothingIsAnError is the failure SourceRoot turns into a Fatalf.
// Requiring all four modules is what identifies the directory, so a module added to the repository
// without being added to the list fails to find the root rather than silently rooting a guard one
// directory up.
func TestSourceRoot_AnAscentThatFindsNothingIsAnError(t *testing.T) {
	root := t.TempDir()
	// Three of the four, which is what a newly added module looks like from here.
	for _, m := range modules[:len(modules)-1] {
		writeGoFile(t, root, filepath.ToSlash(filepath.Join(m, "go.mod")), "module example.com/x\n")
	}

	_, err := sourceRootFrom(root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no directory above the working directory holds all of")
}
