package server

import (
	"go/format"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestModuleSourcesAreGofmted holds every Go file in this module to gofmt's canonical
// formatting, which is what the Lint job in .github/workflows/check.yml checks with
// `gofmt -l .` before it runs vet, unparam or golangci-lint.
//
// The reason this is worth a test rather than being left to CI: that gofmt check is the
// first step in the Lint job's per-module loop and it exits the module on failure, so an
// unformatted file also costs the module its vet, unparam and golangci-lint run. Nothing
// executed locally noticed. The unit tier runs `./internal/...` and `./web` (see
// run-tests.sh), so it never compiled ./tests/... at all, and formatting is not a
// compile error in any case: a whole tier reports green, the work is committed and
// pushed, and CI is where it first goes red.
//
// That is not hypothetical. Deleting the widest key from a struct literal leaves the
// surviving fields aligned to a column gofmt no longer wants, which is invisible to a
// reader and to every test. It happened across seven files at once while retiring the
// level2AuthConfigHasChanged API surface (#242).
//
// Scope is this module only, and the same gap is open in core, adminconsole and
// cmd/goiabada-setup.
func TestModuleSourcesAreGofmted(t *testing.T) {
	// go test runs with the package directory as the working directory, so this is
	// src/authserver. The walk covers ./tests/... as well as the packages the unit
	// tier compiles, because it reads files rather than loading packages, and it is
	// ./tests/... that the tier would otherwise never look at.
	root := filepath.Join("..", "..")

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

	// A wrong root walks nothing and would otherwise pass, which is the one way a
	// guard like this fails silently in the direction that matters.
	if files == 0 {
		t.Fatalf("walked no Go files under %s", root)
	}

	if len(unformatted) > 0 {
		t.Errorf("%d of %d Go files are not gofmt'd; run `gofmt -w` on them:\n\t%s",
			len(unformatted), files, strings.Join(unformatted, "\n\t"))
	}
}
