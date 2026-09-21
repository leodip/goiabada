package testutil

import (
	"go/ast"
	"strconv"
)

// watchedImport is one import path a rule resolves call sites against, together with the
// identifier an unaliased import of it binds.
//
// name is the package's declared name -- its package clause -- because that is what Go binds. The
// last element of the import path is only the usual spelling of it, and in this tree the two
// differ often: every versioned module binds a name the path does not spell
// (github.com/go-chi/chi/v5 binds chi, golang-jwt/jwt/v5 binds jwt, jackc/pgx/v5 binds pgx,
// jackc/puddle/v2 binds puddle, go.yaml.in/yaml/v3 binds yaml), and every generated mocks
// directory declares a name of its own (authserver/internal/data/mocks declares mocks_data).
//
// dir is where the package is declared, relative to the source root, forward slashes, and empty
// for a path outside src/ -- stdlib and the module dependencies. It carries no weight when a call
// site is resolved: it is what TestImportBinding_EveryWatchedPackageIsNamedAsTheTableSays reads to
// hold name against the package clause in the tree, so renaming a watched package turns a tier red
// rather than turning that package's rule off. It is spelled out rather than derived from the
// import path because the four modules do not map onto the tree uniformly:
// github.com/leodip/goiabada/goiabada-setup is src/cmd/goiabada-setup (#385).
type watchedImport struct {
	name string
	dir  string
}

// watchedImports is one rule's set of watched paths, keyed by import path.
type watchedImports map[string]watchedImport

// bindImports maps the identifier a file writes at a call site to the watched import path it
// names, so a rule can ask which package a selector's left side is without type-checking anything.
//
// Only watched paths are recorded, and that is what makes the answer exact rather than a guess.
// The alternative -- naming every import and inventing a name for the paths nothing is known
// about -- cannot be made sound, because an invented name can occupy a watched one: a package
// whose path ends in /slog but whose clause reads something else is recorded under slog, and every
// real slog.Info in the same file then resolves to it and is walked past. Leaving those paths out
// instead costs nothing, because no rule here asks anything about a path it does not watch, and it
// can displace nothing, because Go forbids two imports of one file binding the same identifier --
// so any entry that would need a name invented for it belongs to a package no rule names.
//
// A blank or a dot import binds no identifier a selector can name, so neither is recorded. A dot
// import of a watched path therefore hides that package's calls from its rule entirely, which is
// why the two callers with something to lose refuse the dot import itself rather than trying to
// resolve unqualified names.
func bindImports(file *ast.File, watched watchedImports) map[string]string {
	bound := map[string]string{}
	for _, spec := range file.Imports {
		if spec.Path == nil {
			continue
		}
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		entry, ok := watched[path]
		if !ok {
			continue
		}
		name := entry.name
		if spec.Name != nil {
			if spec.Name.Name == "_" || spec.Name.Name == "." {
				continue
			}
			name = spec.Name.Name
		}
		bound[name] = path
	}
	return bound
}
