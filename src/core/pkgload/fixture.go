package pkgload

import (
	"go/version"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/leodip/goiabada/core/errs"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// MakeLoadable makes a fixture tree under root a set of modules the go command can load. A guard's
// fixture writes each go.mod as a module line and little else, which is all a reader of syntax
// needs. The go command needs two more things. One is a go line, without which it reads the module
// at Go 1.16. The other is a way to find the tree's other modules, which no proxy holds: each go.mod
// gains a requirement of every other module in the tree, replaced by that module's directory, as the
// three modules that use core require it.
//
// A go line the fixture wrote stays. Because every module then requires every other, and the go
// command refuses a module that requires one with a later go line, the go lines a fixture wrote must
// agree, and a tree whose go lines differ is an error naming both. The go line added to the other
// modules is the one the fixture wrote, or, where it wrote none, this binary's Go version, the
// toolchain the tests run on. A tree holding no go.mod, or a go.mod the go command would not parse
// or that declares no module, is an error naming it.
func MakeLoadable(root string) error {
	modules, err := fixtureModules(root)
	if err != nil {
		return err
	}
	goLine, err := fixtureGoVersion(modules)
	if err != nil {
		return err
	}

	for _, m := range modules {
		text := m.src
		if !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		if m.goVersion == "" {
			text += "\ngo " + goLine + "\n"
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
			text += "\nrequire " + other.path + " " + syntheticVersion(other.path) +
				"\n\nreplace " + other.path + " => " + quoteIfNeeded(rel) + "\n"
		}
		//nolint:gosec,nolintlint // G703: a go.mod the walk found under the fixture root a test gave; nolintlint because gosec v2.29.0 finds this G703 on some runs only (securego/gosec#1712, #494)
		if err := os.WriteFile(m.file, []byte(text), 0o600); err != nil {
			return errs.Wrapf(err, "writing %s", m.file)
		}
	}
	return nil
}

// fixtureModule is one go.mod of a fixture tree: its file, its text, the module path it declares
// and the version of its go line, empty when it has none.
type fixtureModule struct {
	file, src, path, goVersion string
}

// fixtureGoVersion is the go line a fixture's unversioned modules get: the one its other modules
// wrote, which must agree, or this binary's Go version when none wrote one.
func fixtureGoVersion(modules []fixtureModule) (string, error) {
	var pinned *fixtureModule
	for i := range modules {
		m := &modules[i]
		if m.goVersion == "" {
			continue
		}
		if !version.IsValid("go" + m.goVersion) {
			return "", errs.Errorf("%s has the go line %q, which is not a Go version", m.file, m.goVersion)
		}
		if pinned == nil {
			pinned = m
			continue
		}
		if version.Compare("go"+m.goVersion, "go"+pinned.goVersion) != 0 {
			return "", errs.Errorf("%s has go %s and %s has go %s; each module of a fixture tree requires the others, "+
				"and the go command refuses a module that requires one with a later go line, so they must agree",
				pinned.file, pinned.goVersion, m.file, m.goVersion)
		}
	}
	if pinned != nil {
		return pinned.goVersion, nil
	}
	return goVersion()
}

// syntheticVersion is the version a fixture module is required at: the major its path's version
// suffix names, which the go command holds the version to, or v0.0.0 for a path without one. The
// suffix is read as the go command reads it (go.dev/ref/mod#major-version-suffixes): /vN from v2
// on, after a slash, or for a gopkg.in path .vN with an optional -unstable, where .v0 and .v1 are
// majors too.
func syntheticVersion(modulePath string) string {
	if _, pathMajor, ok := module.SplitPathVersion(modulePath); ok && pathMajor != "" {
		return module.PathMajorPrefix(pathMajor) + ".0.0"
	}
	return "v0.0.0"
}

// quoteIfNeeded quotes a go.mod argument the go command would otherwise read as more than one
// token, such as a directory with a space in its name, and leaves any other unquoted.
func quoteIfNeeded(arg string) string {
	if arg == "" || strings.Contains(arg, "//") || strings.Contains(arg, "/*") ||
		strings.ContainsFunc(arg, func(r rune) bool {
			return unicode.IsSpace(r) || !unicode.IsPrint(r) || strings.ContainsRune("\"'`()[]{},", r)
		}) {
		return strconv.Quote(arg)
	}
	return arg
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
		// The go command's own parser, so the module directive reads as the go command reads it, on
		// one line or as a block, its path quoted or not.
		parsed, err := modfile.Parse(path, src, nil)
		if err != nil {
			return err
		}
		if parsed.Module == nil {
			return errs.Errorf("%s declares no module", path)
		}
		m := fixtureModule{file: path, src: string(src), path: parsed.Module.Mod.Path}
		if parsed.Go != nil {
			m.goVersion = parsed.Go.Version
		}
		modules = append(modules, m)
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
