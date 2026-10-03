package refgraph

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestImportGraph_ModuleIdentityIsReadFromGoMod pins that the graph names a module by its go.mod,
// not by a path this package assumes, so a renamed module is followed rather than silently read as
// third-party.
func TestImportGraph_ModuleIdentityIsReadFromGoMod(t *testing.T) {
	root := writeTree(t, map[string]string{
		"core/go.mod":       "module example.test/renamed-core\n",
		"core/errs/errs.go": "package errs\n",
	})

	graph, err := BuildImportGraph(root)
	require.NoError(t, err)

	assert.Equal(t, "example.test/renamed-core", graph.Modules["core"])
	assert.Equal(t, "core/errs", graph.TopCorePackage("example.test/renamed-core/errs"))
}

// TestImportGraph_ResolvesTheFourModulesTheRootIsFoundBy pins the other use of the one module
// declaration: the graph resolves import paths against exactly the four directories the source
// root is identified by, each under the module its go.mod declares.
func TestImportGraph_ResolvesTheFourModulesTheRootIsFoundBy(t *testing.T) {
	root := writeTree(t, nil)

	graph, err := BuildImportGraph(root)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		"core":               "example.test/core",
		"authserver":         "example.test/authserver",
		"adminconsole":       "example.test/adminconsole",
		"cmd/goiabada-setup": "example.test/setup",
	}, graph.Modules)
}
