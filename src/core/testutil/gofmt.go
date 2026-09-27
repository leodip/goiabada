package testutil

import (
	"go/format"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/internal/refgraph"
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
// and cmd/goiabada-setup's own tier calls none of the tree-wide guards: a
// module-scoped guard would leave that module the one place still relying on CI
// to notice. Each of the other three module tiers calls this, so the guard fires
// whichever of them is run.
func AssertGofmted(t *testing.T) {
	t.Helper()

	assertGofmted(t, SourceRoot(t))
}

// assertGofmted is the reporting half, taking the root as a parameter and failing
// through a Reporter so a rule test can drive it against a fixture tree. See
// Reporter in guard.go for why both halves exist.
func assertGofmted(r Reporter, root string) {
	r.Helper()

	unformatted, files, err := findUnformatted(root)
	if err != nil {
		r.Fatalf("walking %s: %v", root, err)
	}

	// A root that somehow held no Go files walks nothing and would otherwise
	// pass, which is the one way a guard like this fails silently in the
	// direction that matters.
	if files == 0 {
		r.Fatalf("walked no Go files under %s", root)
	}

	if len(unformatted) > 0 {
		r.Errorf("%d of %d Go files are not gofmt'd; run `gofmt -w` on them:\n\t%s",
			len(unformatted), files, strings.Join(unformatted, "\n\t"))
	}
}

// findUnformatted walks every Go file under root and returns the ones gofmt would
// rewrite, relative to root with forward slashes, along with the number of files
// it was able to read a verdict on.
func findUnformatted(root string) ([]string, int, error) {
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
			// to the wrong place. It is not counted either: a file no verdict was
			// reached on is not evidence the walk is working.
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
		return nil, 0, err
	}
	return unformatted, files, nil
}

// SourceRoot returns the directory holding every module in the repository, found
// by ascending from the test's working directory. It is what every tree-wide
// guard walks from: AssertGofmted here, and the bare-BeginTransaction lint in
// authserver/internal/data (#301, moved there by #354 and #359).
//
// Ascending rather than accepting a relative path keeps each caller from having
// to encode how deep its own package sits. That matters because a wrong root is
// not a loud failure: it walks a directory that exists and holds nothing, and
// the guard passes. The ascent itself is refgraph.FindSourceRoot, which
// cmd/ownershipdump roots its walk with too.
func SourceRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting the working directory: %v", err)
	}
	root, err := refgraph.FindSourceRoot(dir)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return root
}
