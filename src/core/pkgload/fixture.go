package pkgload

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// MakeLoadable makes a fixture tree under root a set of modules the go command can load. A guard's
// fixture writes each go.mod as a module line and little else, which is all a reader of syntax
// needs. The go command needs two more things. One is a go line, without which it reads the module
// at Go 1.16. The other is a way to find the tree's other modules, which no proxy holds: each go.mod
// gains a requirement of every other module in the tree, replaced by that module's directory, as the
// three modules that use core require it.
//
// A go line the fixture wrote stays. The go line it adds is this binary's Go version, the
// toolchain the tests run on. A tree holding no go.mod, or a go.mod with no module line, is an
// error naming it.
func MakeLoadable(root string) error {
	modules, err := fixtureModules(root)
	if err != nil {
		return err
	}
	version, err := goVersion()
	if err != nil {
		return err
	}

	for _, m := range modules {
		src, err := os.ReadFile(m.file)
		if err != nil {
			return errs.Wrapf(err, "reading %s", m.file)
		}
		text := string(src)
		if !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		if !hasDirective(text, "go") {
			text += "\ngo " + version + "\n"
		}
		for _, other := range modules {
			if other.path == m.path {
				continue
			}
			rel, err := filepath.Rel(filepath.Dir(m.file), filepath.Dir(other.file))
			if err != nil {
				return errs.Wrapf(err, "locating %s from %s", other.file, m.file)
			}
			rel = filepath.ToSlash(rel)
			if !strings.HasPrefix(rel, "../") {
				rel = "./" + rel
			}
			text += "\nrequire " + other.path + " v0.0.0\n\nreplace " + other.path + " => " + rel + "\n"
		}
		//nolint:gosec,nolintlint // G703: a go.mod the walk found under the fixture root a test gave; nolintlint because gosec v2.29.0 finds this G703 on some runs only (securego/gosec#1712, #494)
		if err := os.WriteFile(m.file, []byte(text), 0o600); err != nil {
			return errs.Wrapf(err, "writing %s", m.file)
		}
	}
	return nil
}

// fixtureModule is one go.mod of a fixture tree and the module path it declares.
type fixtureModule struct {
	file, path string
}

// fixtureModules finds every go.mod under root, in path order.
func fixtureModules(root string) ([]fixtureModule, error) {
	var modules []fixtureModule
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "go.mod" {
			return nil
		}
		src, err := os.ReadFile(path) //nolint:gosec // G304: a go.mod the walk found under the fixture root a test gave
		if err != nil {
			return err
		}
		module, ok := modulePath(string(src))
		if !ok {
			return errs.Errorf("%s declares no module", path)
		}
		modules = append(modules, fixtureModule{file: path, path: module})
		return nil
	})
	if err != nil {
		return nil, errs.Wrapf(err, "reading the fixture tree under %s", root)
	}
	if len(modules) == 0 {
		return nil, errs.Errorf("the fixture tree under %s holds no go.mod", root)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].file < modules[j].file })
	return modules, nil
}

// directiveLines are the lines of a go.mod with their comments removed and their space trimmed.
func directiveLines(src string) []string {
	var lines []string
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		lines = append(lines, strings.TrimSpace(line))
	}
	return lines
}

// modulePath reads the path of a go.mod's module line, quoted or not.
func modulePath(src string) (string, bool) {
	for _, line := range directiveLines(src) {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "module" {
			continue
		}
		if unquoted, err := strconv.Unquote(fields[1]); err == nil {
			return unquoted, true
		}
		return fields[1], true
	}
	return "", false
}

// hasDirective reports whether a go.mod holds a one-line directive of that name.
func hasDirective(src, name string) bool {
	for _, line := range directiveLines(src) {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == name {
			return true
		}
	}
	return false
}

// goVersion is this binary's Go version as a go line writes it, 1.27.4 for go1.27.4.
func goVersion() (string, error) {
	v := runtime.Version()
	if !strings.HasPrefix(v, "go1.") {
		return "", errs.Errorf("the Go version %q is not a release, so a fixture's go line cannot be written from it", v)
	}
	if i := strings.IndexAny(v, " -"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimPrefix(v, "go"), nil
}
