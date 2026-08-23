package testutil

import (
	"go/format"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AssertGofmted holds every Go file in the repository to gofmt's canonical
// formatting, which is what the Lint job in .github/workflows/check.yml checks
// with `gofmt -l .` per module before it runs vet, unparam or golangci-lint.
//
// The reason this is worth a test rather than being left to CI: that gofmt check
// is the first step in the Lint job's per-module loop and it exits the module on
// failure, so an unformatted file also costs that module its vet, unparam and
// golangci-lint run. Nothing executed locally noticed. The unit tiers compile
// packages, and formatting is not a compile error: a whole tier reports green,
// the work is committed and pushed, and CI is where it first goes red.
//
// That is not hypothetical. Deleting the widest key from a struct literal leaves
// the surviving fields aligned to a column gofmt no longer wants, which is
// invisible to a reader and to every test. It happened across seven files at
// once while retiring the level2AuthConfigHasChanged API surface (#242).
//
// The scope is the whole source tree rather than the calling module. The walk
// reads files instead of loading packages, so module boundaries cost it nothing,
// and cmd/goiabada-setup has no test tier of its own: a module-scoped guard
// would leave that module the one place still relying on CI to notice. Each
// module's unit tier calls this, so the guard fires whichever tier is run.
func AssertGofmted(t *testing.T) {
	t.Helper()

	root := sourceRoot(t)

	var unformatted []string
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, rErr := os.ReadFile(path)
		if rErr != nil {
			return rErr
		}
		// format.Source is the library gofmt is built on, so this is the same
		// verdict `gofmt -l` gives, reached without shelling out to a binary the
		// dev container is not guaranteed to have on PATH.
		formatted, fErr := format.Source(src)
		if fErr != nil {
			// A file that does not parse is a compile error the build tier owns,
			// and reporting it here as a formatting fault would send the reader
			// to the wrong place.
			return nil
		}
		files++
		if string(formatted) != string(src) {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			unformatted = append(unformatted, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	// A root that somehow held no Go files walks nothing and would otherwise
	// pass, which is the one way a guard like this fails silently in the
	// direction that matters.
	if files == 0 {
		t.Fatalf("walked no Go files under %s", root)
	}

	if len(unformatted) > 0 {
		t.Errorf("%d of %d Go files are not gofmt'd; run `gofmt -w` on them:\n\t%s",
			len(unformatted), files, strings.Join(unformatted, "\n\t"))
	}
}

// modules are the four go.mod directories the Lint job loops over, relative to
// the source root. Requiring all four to be present is what identifies that
// directory while ascending, and it means a module added to the repository
// without being added here is a failure to find the root rather than a walk
// that quietly skips it.
var modules = []string{"core", "authserver", "adminconsole", filepath.Join("cmd", "goiabada-setup")}

// sourceRoot returns the directory holding every module in the repository, found
// by ascending from the test's working directory.
//
// Ascending rather than accepting a relative path keeps each caller from having
// to encode how deep its own package sits. That matters because a wrong root is
// not a loud failure: it walks a directory that exists and holds nothing, and
// the guard passes.
func sourceRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting the working directory: %v", err)
	}

	for {
		if holdsEveryModule(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no directory above the working directory holds all of %s", strings.Join(modules, ", "))
		}
		dir = parent
	}
}

func holdsEveryModule(dir string) bool {
	for _, m := range modules {
		if _, err := os.Stat(filepath.Join(dir, m, "go.mod")); err != nil {
			return false
		}
	}
	return true
}
