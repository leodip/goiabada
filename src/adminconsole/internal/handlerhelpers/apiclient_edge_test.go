package handlerhelpers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApiclientEdge_NamesAPIErrorOnly holds this package's production files to naming one thing
// from apiclient: the *APIError the classifiers route on.
//
// The edge came with the classifiers from the handlers package (#440). It is sound layering only
// that narrowly: apiclient is a leaf that imports nothing of this module, and the classifier and the
// error type it reads change together, which is not true of the executor or any of the 106 methods
// beside them. A renderer that started calling the API would be a page reaching past its handler.
//
// Imports are parsed rather than text matched, so an alias binds the name it binds, and a dot or
// blank import, which would hide what the file takes, is refused outright.
func TestApiclientEdge_NamesAPIErrorOnly(t *testing.T) {
	const apiclientPath = "github.com/leodip/goiabada/adminconsole/internal/apiclient"

	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()
	named := map[string]bool{}
	parsed := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		require.NoError(t, err)
		parsed++

		binding := ""
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			require.NoError(t, err)
			if path != apiclientPath {
				continue
			}
			binding = "apiclient"
			if spec.Name != nil {
				binding = spec.Name.Name
			}
		}
		if binding == "" {
			continue
		}
		if binding == "." || binding == "_" {
			t.Errorf("%s imports apiclient as %q, which hides what it takes from it", name, binding)
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == binding {
				named[sel.Sel.Name] = true
			}
			return true
		})
	}

	require.NotZero(t, parsed, "parsed no production file here, so the walk is not reaching the package")

	got := make([]string, 0, len(named))
	for name := range named {
		got = append(got, name)
	}
	sort.Strings(got)
	assert.Equal(t, []string{"APIError"}, got,
		"handlerhelpers names apiclient.APIError for the classifiers, and nothing else of apiclient")
}
