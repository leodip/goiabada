package testutil

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// AssertNoParentImport holds each of children to naming no import of parent: a child handler
// package does not import the package it sits under.
//
// Both applications have one. The auth server's apihandlers and accounthandlers serve their own
// routes and need nothing their parent declares, and yet 39 of their production files imported it,
// for one reason: the collaborator ports lived there, so every child compiled against a transport
// package sitting above it and took a port eight methods wide to call one of them. #387 gave each
// child its own interfaces.go, naming only what that package calls, and the import went with them;
// #440 did the same for the admin console's six. An import list is the only honest way to state
// that: a census run once proves the edge was gone once, and the next handler written from an
// older one puts it straight back. The rule was the auth server's own lint until #440 made it one
// guard both applications call, so the twins cannot drift.
//
// parent is an import path; children are directories relative to the source root, forward
// slashes. Each child directory is read on its own and not descended into: a walk that descended
// would silently start covering a subpackage the day somebody adds one, under a rule written for
// the packages named, and the admin console's handlers/mocks, the parent's generated double the
// children's tests use, sits beside them and is not one.
//
// Test files are covered as well as production ones: a test naming the parent would rebuild the
// edge in that package's own test binary while a production census still read zero.
//
// It reads and parses files and nothing else: no database, no git, no network.
func AssertNoParentImport(t *testing.T, parent string, children ...string) {
	t.Helper()

	assertNoParentImport(t, SourceRoot(t), parent, children)
}

// assertNoParentImport is the reporting half, taking the root as a parameter and failing through a
// Reporter so a rule test can drive it against a fixture tree. See Reporter in guard.go.
func assertNoParentImport(r Reporter, root, parent string, children []string) {
	r.Helper()

	found, files, err := findParentImports(root, parent, children)
	if err != nil {
		r.Fatalf("reading the child packages under %s: %v", root, err)
	}
	// Child directories that somehow held no Go files, or a call naming none, would read nothing
	// and otherwise pass, which is the one way a guard like this fails silently in the direction
	// that matters.
	if files == 0 {
		r.Fatalf("read no Go files under %s", strings.Join(children, ", "))
	}

	if len(found) == 0 {
		return
	}
	lines := make([]string, 0, len(found))
	for _, f := range found {
		lines = append(lines, f.file+":"+strconv.Itoa(f.line))
	}

	r.Errorf("%d file(s) under the child packages import %s:\n\t%s\n\n"+
		"A child handler package takes its collaborators as ports it declares itself, in its own "+
		"interfaces.go, naming only the methods it calls (#386, #387, #440). Importing the parent "+
		"brings back the edge those issues removed and, with it, a port declared for somebody "+
		"else's call sites. Add the method to that package's own port instead.",
		len(found), parent, strings.Join(lines, "\n\t"))
}

// parentImport is one import of the parent package from a file that may not name it.
type parentImport struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
}

// findParentImports parses every Go file directly under each of children and reports each import
// of parent. It returns the number of files it parsed, so the reporting half can tell "nothing to
// report" from "nothing was read".
//
// Imports are parsed rather than matched as text, which is what makes the rule say what it means.
// The children's own paths have the parent's as a prefix, so a substring match would call every
// file in them an offence; an alias binds a different name to the same path and must still count,
// which spelling-based matching on "handlers." misses -- the auth server's
// handler_api_permissions.go imported it as srvhandlers and no census keyed on the selector ever
// saw it; and that server's api_error_code_lint_test.go names "authserver/internal/handlers" as a
// directory scope, in a string that is not an import and must not count.
func findParentImports(root, parent string, children []string) ([]parentImport, int, error) {
	var found []parentImport
	files := 0

	for _, dir := range children {
		start := filepath.Join(root, filepath.FromSlash(dir))

		entries, err := os.ReadDir(start)
		if err != nil {
			return nil, 0, err
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			path := filepath.Join(start, entry.Name())

			fset := token.NewFileSet()
			file, pErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if pErr != nil {
				// A file that does not parse is a compile error the build tier owns, and
				// reporting it here would send the reader to the wrong place.
				continue
			}
			files++

			rel := dir + "/" + entry.Name()
			for _, spec := range file.Imports {
				imported, uErr := strconv.Unquote(spec.Path.Value)
				if uErr != nil || imported != parent {
					continue
				}
				found = append(found, parentImport{
					file: rel,
					line: fset.Position(spec.Pos()).Line,
				})
			}
		}
	}

	return found, files, nil
}
