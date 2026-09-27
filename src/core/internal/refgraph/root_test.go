package refgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeGoMod writes one module's go.mod under root, creating the directories above it.
func writeGoMod(t *testing.T, root, module string) {
	t.Helper()
	path := filepath.Join(root, module, "go.mod")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte("module example.com/x\n"), 0o644))
}

// TestSourceRoot_FindsTheDirectoryHoldingEveryModule covers the ascent every guard's root comes
// from. A wrong root is not a loud failure -- it walks a directory that exists and holds nothing,
// and the guard passes -- which is why both of its answers are pinned rather than assumed.
func TestSourceRoot_FindsTheDirectoryHoldingEveryModule(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	for _, m := range modules {
		writeGoMod(t, src, m)
	}
	deep := filepath.Join(src, "core", "testutil", "fake")
	require.NoError(t, os.MkdirAll(deep, 0o755))

	found, err := FindSourceRoot(deep)
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
		writeGoMod(t, root, m)
	}

	_, err := FindSourceRoot(root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no directory above the working directory holds all of")
}
