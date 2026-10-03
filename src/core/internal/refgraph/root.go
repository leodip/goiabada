package refgraph

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// moduleDirs are the four go.mod directories the Lint job loops over, relative
// to the source root, slash-separated and in the order a reader expects them.
// This is their one declaration: FindSourceRoot requires all four to be present,
// which is what identifies that directory while ascending, and BuildImportGraph
// resolves import paths against the module each one declares. A module added to
// the repository without being added here is a failure to find the root rather
// than a walk that quietly skips it.
var moduleDirs = []string{"core", "authserver", "adminconsole", "cmd/goiabada-setup"}

// FindSourceRoot returns the directory holding the four go.mod files, ascending
// from dir. It is where every tree-wide guard roots its walk, through
// guard.SourceRoot, and where cmd/ownershipdump roots its own, which is a
// command rather than a test and still has to start in the same place.
//
// A wrong root is not a loud failure: it walks a directory that exists and holds
// nothing, and the guard passes. That is why its failure is an error rather than
// a guess, and why both of its outcomes are pinned rather than assumed.
func FindSourceRoot(dir string) (string, error) {
	for {
		if holdsEveryModule(dir) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errs.Errorf("no directory above the working directory holds all of %s",
				strings.Join(moduleDirs, ", "))
		}
		dir = parent
	}
}

func holdsEveryModule(dir string) bool {
	for _, m := range moduleDirs {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(m), "go.mod")); err != nil {
			return false
		}
	}
	return true
}
