package refgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTree writes a miniature source root: the four go.mod files every graph needs, then the
// fixture's own files, which may replace any of them. It is core/testutil's helper of the same
// name, repeated because a test here cannot import core/testutil, which imports this package.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	all := map[string]string{
		"core/go.mod":               "module example.test/core\n",
		"authserver/go.mod":         "module example.test/authserver\n",
		"adminconsole/go.mod":       "module example.test/adminconsole\n",
		"cmd/goiabada-setup/go.mod": "module example.test/setup\n",
	}
	for rel, src := range files {
		all[rel] = src
	}
	for rel, src := range all {
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	}
	return root
}

// assertFindings checks the findings one to one against the fragments, in order.
func assertFindings(t *testing.T, got []string, fragments ...string) {
	t.Helper()

	if !assert.Len(t, got, len(fragments), "findings:\n\t%s", strings.Join(got, "\n\t")) {
		return
	}
	for i, want := range fragments {
		assert.Contains(t, got[i], want)
	}
}
