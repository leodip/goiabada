package guard

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// AssertImportsOnly holds the production files of one package to importing the standard library
// and the paths allowed names, and nothing else.
//
// Two packages are held to one. The auth server's record is the rows as they are stored and every
// other package there names it, which made it the cheapest place to put a capability and the worst:
// User.SetOTPSecret put a cipher, and KeyPair.ParsePrivateKey a JWT library, behind every package
// naming a stored user or key, until #387 moved both out and wrote this rule as record's own lint.
// core/adminpassword is the one rule for the first administrator's password, called by the setup
// wizard, which links whatever that package imports: in core/inputvalidation it brought core/i18n,
// core/oauth, a TOML parser and a JWT library into the wizard, and #500 gave it a package of its own
// and moved this rule here so the two callers share one guard. Both rules are about the import list
// and not about any one function, because an import list names every way back in.
//
// dir is relative to the source root, forward slashes. allowed maps each permitted import path to
// why it is permitted, and why is the caller's account of what the package is for, which reaches
// the reader with every finding. The standard library is allowed and is not listed, because it is
// recognised by shape (see isStdlib).
//
// Only the directory itself is read, not its subtree: a walk that descended would quietly start
// covering a subpackage the day somebody adds one, under a rule written for the package named.
// Only production files are read: the rule is about what the package compiles into every consumer,
// and a _test.go compiles into nothing. Only direct imports count, which is the rule as both callers
// need it: what an allowed path imports in turn is that package's business, and ARCHITECTURE.md's
// tables already hold it.
//
// It reads and parses files and nothing else: no database, no git, no network.
func AssertImportsOnly(t *testing.T, dir string, allowed map[string]string, why string) {
	t.Helper()

	assertImportsOnly(t, SourceRoot(t), dir, allowed, why)
}

// assertImportsOnly is the reporting half, taking the root as a parameter and failing through a
// Reporter so a rule test can drive it against a fixture tree. See Reporter in guard.go.
func assertImportsOnly(r Reporter, root, dir string, allowed map[string]string, why string) {
	r.Helper()

	found, files, err := findDisallowedImports(root, dir, allowed)
	if err != nil {
		r.Fatalf("reading %s: %v", filepath.Join(root, filepath.FromSlash(dir)), err)
	}
	// A directory that somehow held no production Go files reads nothing and would otherwise
	// pass, which is the one way a guard like this fails silently in the direction that matters.
	if files == 0 {
		r.Fatalf("read no production Go files under %s", dir)
	}

	if len(found) == 0 {
		return
	}
	lines := make([]string, 0, len(found))
	for _, f := range found {
		lines = append(lines, f.file+":"+strconv.Itoa(f.line)+": "+f.path)
	}
	permitted := "the standard library alone"
	if len(allowed) > 0 {
		paths := make([]string, 0, len(allowed))
		for path := range allowed {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		permitted = "the standard library, plus " + strings.Join(paths, ", ")
	}

	r.Errorf("%d import(s) under %s that it may not name:\n\t%s\n\n%s\n\nAllowed here: %s.",
		len(found), dir, strings.Join(lines, "\n\t"), why, permitted)
}

// disallowedImport is one import a production file in the package names that the rule does not
// allow.
type disallowedImport struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
	path string
}

// findDisallowedImports parses every non-test Go file directly under root/dir and reports each
// import path that is neither standard library nor in allowed. It returns the number of files it
// parsed, so the reporting half can tell "nothing to report" from "nothing was read".
//
// Imports are parsed rather than matched as text, so an aliased, blank or dot import counts like
// any other: an alias binds a different name to the same path, which spelling-based matching on a
// selector misses.
func findDisallowedImports(root, dir string, allowed map[string]string) ([]disallowedImport, int, error) {
	start := filepath.Join(root, filepath.FromSlash(dir))

	entries, err := os.ReadDir(start)
	if err != nil {
		return nil, 0, err
	}

	var found []disallowedImport
	files := 0

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
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
			if uErr != nil || isStdlib(imported) {
				continue
			}
			if _, ok := allowed[imported]; ok {
				continue
			}
			found = append(found, disallowedImport{
				file: rel,
				line: fset.Position(spec.Pos()).Line,
				path: imported,
			})
		}
	}

	return found, files, nil
}
