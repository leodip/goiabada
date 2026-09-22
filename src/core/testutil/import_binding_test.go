package testutil

// Seam: bindImports, the resolver the call-site guards share -- AssertNoLegacyErrors,
// AssertSlogConvention, AssertAuditLogContext and AssertRequestPathContext over a call, and
// AssertNotCalledArity over a struct's embedded field. Each of them asks one question of a
// selector, "is its left side the package at this path", and each answer is only as good as the
// name the import is read as binding.
//
// The rows below are the resolver itself, over source text rather than a tree, because it is a
// pure function of one file's import declarations. The two tree-reading tests at the bottom are
// the other half: they hold each table's declared names to the package clauses in src/, so a
// watched package renamed out from under a guard turns this tier red rather than turning that
// guard's rule off -- the quiet pass that is this package's whole subject (#385).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goiabadaModulePrefix is the prefix every import path declared under src/ carries. A watched path
// starting with it is one this tree declares, and its declared name is therefore a fact a guard
// can be held to rather than a constant it has to be trusted on.
const goiabadaModulePrefix = "github.com/leodip/goiabada/"

// parseImports parses a fixture's import declarations. ImportsOnly is enough: bindImports reads
// file.Imports and nothing else.
func parseImports(t *testing.T, src string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", src, parser.ImportsOnly)
	require.NoError(t, err)
	return file
}

// TestImportBinding_TheRuleTable is one row per shape an import declaration can take, asserting
// the whole map rather than one lookup, so a row that binds something extra fails here too.
func TestImportBinding_TheRuleTable(t *testing.T) {
	// Two watched paths whose declared names their last path elements do not spell, which is the
	// shape the real tables carry: every versioned module in this tree binds a name no element of
	// its path contains.
	watched := watchedImports{
		"log/slog":                 {name: "slog"},
		"github.com/go-chi/chi/v5": {name: "chi"},
	}

	cases := []struct {
		name string
		src  string
		want map[string]string
	}{
		{
			// Go binds the package clause. chi/v5 declares package chi, so chi.Router is what the
			// file writes and v5 is a name it never mentions.
			name: "an unaliased import binds the declared name, not the last path element",
			src: `package fixture

import "github.com/go-chi/chi/v5"
`,
			want: map[string]string{"chi": "github.com/go-chi/chi/v5"},
		},
		{
			// An explicit alias is what the file writes, whatever the package calls itself.
			name: "an alias overrides the declared name",
			src: `package fixture

import router "github.com/go-chi/chi/v5"
`,
			want: map[string]string{"router": "github.com/go-chi/chi/v5"},
		},
		{
			// A blank import binds no identifier, so no selector can name the package.
			name: "a blank import binds nothing",
			src: `package fixture

import _ "log/slog"
`,
			want: map[string]string{},
		},
		{
			// A dot import binds the package's exported names unqualified, leaving no selector to
			// resolve. The two guards with something to lose refuse the dot import itself.
			name: "a dot import binds nothing",
			src: `package fixture

import . "log/slog"
`,
			want: map[string]string{},
		},
		{
			// The decisive row. Reading the last path element would record
			// example.com/vendored/slog under "slog" and, coming second in the file, overwrite
			// log/slog with it -- so every real slog.Info here would resolve to the wrong package
			// and be walked past. Recording only watched paths makes that unreachable: the
			// unwatched one is never a candidate for the name.
			name: "an unwatched path cannot occupy a watched name",
			src: `package fixture

import (
	"log/slog"

	"example.com/vendored/slog"
)
`,
			want: map[string]string{"slog": "log/slog"},
		},
		{
			// The same in the other order, because a map takes the last write and source order is
			// what decides it.
			name: "an unwatched path cannot occupy a watched name, whichever comes first",
			src: `package fixture

import (
	"example.com/vendored/slog"

	"log/slog"
)
`,
			want: map[string]string{"slog": "log/slog"},
		},
		{
			// Nothing else is recorded, which is what keeps the map an answer about the watched
			// set rather than a census of the file.
			name: "a file importing nothing watched binds nothing",
			src: `package fixture

import (
	"fmt"

	"example.com/vendored/slog"
)
`,
			want: map[string]string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, bindImports(parseImports(t, tc.src), watched))
		})
	}
}

// watchedTables is every table bindImports is called with in production, so the two tests below
// hold all four rather than whichever one was remembered.
func watchedTables() map[string]watchedImports {
	return map[string]watchedImports{
		"errorsWatchedImports":    errorsWatchedImports,
		"slogWatchedImports":      slogWatchedImports,
		"auditWatchedImports":     auditWatchedImports,
		"notCalledWatchedImports": notCalledWatchedImports,
	}
}

// TestImportBinding_EveryWatchedPackageIsNamedAsTheTableSays reads the package clause of every
// watched path this tree declares and holds the table to it.
//
// This is the half a fixture cannot cover. A fixture proves the resolver binds what the table
// says; only the tree says whether the table is still true. Rename core/errs to package errors and
// every errs constructor in a package-level var stops being reported, with nothing else going red
// -- which is the failure AssertNoDeadInterfaces demonstrated on 8883642d, and the reason this is
// a test rather than a comment asserting the names are obviously right.
func TestImportBinding_EveryWatchedPackageIsNamedAsTheTableSays(t *testing.T) {
	root := SourceRoot(t)

	for table, watched := range watchedTables() {
		for path, entry := range watched {
			if entry.dir == "" {
				continue
			}
			t.Run(table+"/"+path, func(t *testing.T) {
				dir := filepath.Join(root, filepath.FromSlash(entry.dir))
				declared := declaredPackageName(dir)
				require.NotEmpty(t, declared,
					"%s names %s, which holds no non-test Go file: the table points at a directory "+
						"that has moved, and the rule resolving %s is bound to a name nothing declares",
					table, entry.dir, path)
				assert.Equal(t, entry.name, declared,
					"%s says an unaliased import of %s binds %q, but %s declares package %s. Go "+
						"binds the clause, so every call site written through %s.X resolves to "+
						"nothing and its rule is silent",
					table, path, entry.name, entry.dir, declared, declared)
			})
		}
	}
}

// TestImportBinding_EveryInTreeWatchedPathCarriesItsDirectory is what keeps the test above
// meaningful. An entry with no dir is never checked against anything, so a path this tree declares
// that arrived without one would take that escape hatch silently. Outside src/ there is nothing to
// read -- stdlib and the module dependencies are not in the tree -- and those entries are the
// residual ceiling, held by the compiler instead: a stdlib or dependency package that renamed its
// clause would break every file importing it long before it reached a guard.
func TestImportBinding_EveryInTreeWatchedPathCarriesItsDirectory(t *testing.T) {
	for table, watched := range watchedTables() {
		for path, entry := range watched {
			if !strings.HasPrefix(path, goiabadaModulePrefix) {
				continue
			}
			assert.NotEmpty(t, entry.dir,
				"%s watches %s, which this tree declares, with no dir: give it the directory "+
					"relative to the source root so its declared name is checked rather than trusted",
				table, path)
		}
	}
}
