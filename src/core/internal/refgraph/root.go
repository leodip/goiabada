package refgraph

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// modules are the four go.mod directories the Lint job loops over, relative to
// the source root. Requiring all four to be present is what identifies that
// directory while ascending, and it means a module added to the repository
// without being added here is a failure to find the root rather than a walk
// that quietly skips it.
var modules = []string{"core", "authserver", "adminconsole", filepath.Join("cmd", "goiabada-setup")}

// FindSourceRoot returns the directory holding the four go.mod files, ascending
// from dir. It is where every tree-wide guard roots its walk, through
// testutil.SourceRoot, and where cmd/ownershipdump roots its own, which is a
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
				strings.Join(modules, ", "))
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
