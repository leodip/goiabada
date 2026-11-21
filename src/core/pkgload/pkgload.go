// Package pkgload loads a module's packages type-checked, through golang.org/x/tools/go/packages,
// for one build: the machine's own, or one of the release builds a release ships. It is the one
// loader the guards that need types read the tree through, in place of a hand-written importer
// each (#420), and it holds the one declaration of the release platforms, which rule 8 of
// ARCHITECTURE.md and the release-build test read too.
//
// It is an exported leaf rather than part of core/internal/refgraph because the auth server's
// tests load through it, and Go's internal rule keeps them out of core/internal, as it did for
// core/sourceroot (#480). It imports the standard library, core/errs, golang.org/x/tools and
// golang.org/x/mod, whose go.mod parser reads a fixture's go.mod files, and neither testing nor
// testify, so ownershipdump can load through it and still link no test framework.
// ARCHITECTURE.md's refused-packages table keeps golang.org/x/tools out of every shipped binary.
package pkgload

import (
	"errors"
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/leodip/goiabada/core/errs"
	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/packages"
)

// Platform is one GOOS and GOARCH pair a build selects files for.
type Platform struct {
	GOOS, GOARCH string
}

// String is the pair as the go command writes it, linux/amd64.
func (p Platform) String() string { return p.GOOS + "/" + p.GOARCH }

// releasePlatforms are the platforms a release ships every shipped main for: the five
// build_platform calls of src/build/build-binaries.sh and of the setup wizard's build-binaries.sh,
// the Docker images being the first two. This is their one declaration.
// TestReleaseBuilds_TheRealReleaseBuildsSetProduction in core/guard fails when either script's
// calls differ from it as a set (#463).
var releasePlatforms = []Platform{
	{GOOS: "linux", GOARCH: "amd64"},
	{GOOS: "linux", GOARCH: "arm64"},
	{GOOS: "darwin", GOARCH: "amd64"},
	{GOOS: "darwin", GOARCH: "arm64"},
	{GOOS: "windows", GOARCH: "amd64"},
}

// ReleasePlatforms returns the platforms a release ships, as a fresh copy on every call.
func ReleasePlatforms() []Platform {
	out := make([]Platform, len(releasePlatforms))
	copy(out, releasePlatforms)
	return out
}

// Build is one way the go command selects a module's files.
type Build struct {
	// Platform is the platform files are selected for. The zero value is the go command's own,
	// the machine the tests run on unless the environment says otherwise.
	Platform Platform
	// Release sets the production tag and turns cgo off, as every release build does, and holds
	// GOAMD64 and GOARM64 at the go command's defaults, v1 and v8.0, which a release compiles at
	// because nothing that builds one sets them. Without it no tag is set, and cgo and those levels
	// are as the environment has them.
	Release bool
	// Tests adds each package's test files: the package compiled with its internal tests, its
	// external test package, and the test main, beside the package itself.
	Tests bool
}

// ReleaseBuilds returns the release build of every release platform: the production tag set, cgo
// off, the default architecture levels and no test files, in the order of ReleasePlatforms.
func ReleaseBuilds() []Build {
	builds := make([]Build, 0, len(releasePlatforms))
	for _, p := range releasePlatforms {
		builds = append(builds, Build{Platform: p, Release: true})
	}
	return builds
}

// ErrNoPackages is what Load returns, wrapped with the directory, for a module the build selects no
// package of: a module holding no Go file, or one whose every file another build selects. A guard
// tells it apart from a failed load to say that its walk reached nothing.
var ErrNoPackages = errors.New("the build selects no package")

// mode is what every load reads: the files, the syntax and the types of each package, and the
// import edges, which name the packages imported without loading them a second time.
const mode = packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
	packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax |
	packages.NeedTypesInfo | packages.NeedModule

// loaded is one load's result, filled once.
type loaded struct {
	once sync.Once
	pkgs []*packages.Package
	err  error
}

var (
	loadsMu sync.Mutex
	// loads holds every load of the process, by build and then by module directory.
	loads = map[Build]map[string]*loaded{}
	// goCommandMu lets one load at a time run the go command, whichever goroutines call Load. Each
	// run already compiles on every CPU, so loads run at once multiply the CPU demand without
	// finishing sooner, and on a four-core CI runner with a cold build cache they starve the tests
	// running beside them, such as the auth server's process tests and their 30 s bound (#420).
	goCommandMu sync.Mutex
)

// Load returns every package of the module rooted at dir, type-checked for build, as the go command
// lists ./... there. A module is loaded at most once for each build in a process: a second call, from
// whichever guard, returns the first call's packages, or its error, so a caller must not modify them.
// Calls from several goroutines are safe, and their loads run one at a time.
//
// A package that does not load or does not type-check is an error naming the package and its first
// error, the first package in import-path order when several fail, because a reading of a
// half-checked tree misses references. So is a package that imports a package of its own module
// that ./... does not match, one in a directory whose name, or a parent's, begins with _ or . or is
// testdata: the build compiles it, and no guard reading the load would. A module the build selects
// no package of is ErrNoPackages, and a directory the go command cannot load at all is an error
// naming it.
func Load(dir string, build Build) ([]*packages.Package, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, errs.Wrapf(err, "resolving %s", dir)
	}
	loadsMu.Lock()
	if loads[build] == nil {
		loads[build] = map[string]*loaded{}
	}
	entry, ok := loads[build][abs]
	if !ok {
		entry = &loaded{}
		loads[build][abs] = entry
	}
	loadsMu.Unlock()

	entry.once.Do(func() { entry.pkgs, entry.err = load(abs, build) })
	return entry.pkgs, entry.err
}

// LoadBuilds loads the modules rooted at dirs for each of builds through Load, one load after
// another, and returns one slice per build, in the order of builds, holding every dir's packages in
// the order of dirs. Each build's packages stay apart, because each build is a type-check of its
// own. A dir a build selects no package of adds nothing to that build's slice. The first error in
// build and then dir order that is not ErrNoPackages stops the loads and is the one returned.
func LoadBuilds(builds []Build, dirs ...string) ([][]*packages.Package, error) {
	out := make([][]*packages.Package, len(builds))
	for b, build := range builds {
		for _, dir := range dirs {
			pkgs, err := Load(dir, build)
			if errors.Is(err, ErrNoPackages) {
				continue
			}
			if err != nil {
				return nil, err
			}
			// out[b] starts nil, so this copies: a caller appending to a build's slice cannot write
			// into the one Load keeps.
			out[b] = append(out[b], pkgs...)
		}
	}
	return out, nil
}

// Position is where pos, in one of the syntax trees of a package Load returned, is in the source a
// developer edits. In a file of the package's own it is the physical position, which a //line
// directive does not move: two files that map to one template line are two places, each at its own
// line. A file that imports "C" is compiled from what cmd/cgo generates from it, a file in the build
// cache in its place, whose own //line directives lead back to it, so there it is the position those
// give: the original file's, at its line. A //line directive the original carries itself is copied
// into cgo's output after cgo's own and moves the position there, as it moves the go command's
// diagnostics: in that file Position reads the adjusted position, which follows every directive.
func Position(p *packages.Package, pos token.Pos) token.Position {
	at := p.Fset.PositionFor(pos, false)
	if slices.Contains(p.GoFiles, at.Filename) {
		return at
	}
	return p.Fset.PositionFor(pos, true)
}

func load(dir string, build Build) ([]*packages.Package, error) {
	// GOWORK=off and -mod=readonly read each module through its own go.mod, as the four modules are
	// built, whatever workspace file or flags the machine running the tests has. GOPACKAGESDRIVER=off
	// keeps the go command the one that lists the packages: go/packages otherwise hands the load to
	// a driver the environment names, or one named gopackagesdriver on the PATH.
	env := append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=readonly", "GOPACKAGESDRIVER=off")
	var flags []string
	if build.Platform.GOOS != "" {
		env = append(env, "GOOS="+build.Platform.GOOS)
	}
	if build.Platform.GOARCH != "" {
		env = append(env, "GOARCH="+build.Platform.GOARCH)
	}
	if build.Release {
		// The levels explicitly rather than cleared: an empty variable falls through to a level
		// go env -w wrote, which a release build would not see either.
		env = append(env, "CGO_ENABLED=0", "GOAMD64=v1", "GOARM64=v8.0")
		flags = append(flags, "-tags=production")
	}

	cfg := &packages.Config{
		Mode:       mode,
		Dir:        dir,
		Env:        env,
		BuildFlags: flags,
		Tests:      build.Tests,
		Fset:       token.NewFileSet(),
	}
	goCommandMu.Lock()
	pkgs, err := packages.Load(cfg, "./...")
	goCommandMu.Unlock()
	if err != nil {
		return nil, errs.Wrapf(err, "loading the packages of %s for %s", dir, describe(build))
	}
	if len(pkgs) == 0 {
		return nil, errs.Wrapf(ErrNoPackages, "%s for %s", dir, describe(build))
	}

	sorted := append([]*packages.Package(nil), pkgs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	for _, p := range sorted {
		if len(p.Errors) > 0 {
			return nil, errs.Errorf("%s in %s does not load or type-check for %s, and the tree cannot be read until it does: %s",
				p.ID, dir, describe(build), p.Errors[0])
		}
	}
	p, path, err := unmatchedImport(sorted)
	if err != nil {
		return nil, errs.Wrapf(err, "reading the requirements of %s for %s", dir, describe(build))
	}
	if p != nil {
		return nil, errs.Errorf("%s in %s imports %s for %s, a package of %s that ./... does not match, so no guard "+
			"reads it: the go command skips a directory whose name begins with _ or . or is testdata, and the "+
			"package belongs in one it reads", p.ID, dir, path, describe(build), p.Module.Path)
	}
	return pkgs, nil
}

// unmatchedImport returns the first package, in the order given, that imports a package of its own
// module that is not among the packages loaded, and that import's path. An import path that extends
// the module's own belongs to another module when the module requires one whose path prefixes it, as
// the go command resolves an import to the longest such path: a module nested in this one's
// directory, or one elsewhere that only shares its path. ./... leaves those out rightly.
func unmatchedImport(sorted []*packages.Package) (*packages.Package, string, error) {
	loaded := map[string]bool{}
	for _, p := range sorted {
		loaded[p.PkgPath] = true
	}
	required := map[string][]string{}
	for _, p := range sorted {
		if p.Module == nil {
			continue
		}
		modules, ok := required[p.Module.GoMod]
		if !ok {
			var err error
			if modules, err = requiredModules(p.Module.GoMod); err != nil {
				return nil, "", err
			}
			required[p.Module.GoMod] = modules
		}
		paths := make([]string, 0, len(p.Imports))
		for path := range p.Imports {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		for _, path := range paths {
			if strings.HasPrefix(path, p.Module.Path+"/") && !loaded[path] && !providedBy(path, modules) {
				return p, path, nil
			}
		}
	}
	return nil, "", nil
}

// requiredModules is the path of every module a go.mod requires.
func requiredModules(goMod string) ([]string, error) {
	src, err := os.ReadFile(goMod) //nolint:gosec // G304: the go.mod the go command reported for a loaded module
	if err != nil {
		return nil, err
	}
	parsed, err := modfile.Parse(goMod, src, nil)
	if err != nil {
		return nil, err
	}
	modules := make([]string, 0, len(parsed.Require))
	for _, r := range parsed.Require {
		modules = append(modules, r.Mod.Path)
	}
	return modules, nil
}

// providedBy reports whether one of modules provides the package at path: its path is the import
// path or a prefix of it ending at a slash.
func providedBy(path string, modules []string) bool {
	for _, m := range modules {
		if path == m || strings.HasPrefix(path, m+"/") {
			return true
		}
	}
	return false
}

// describe names a build in an error: its platform, the release build's tag and cgo, and tests.
func describe(b Build) string {
	platform := "the default platform"
	if b.Platform != (Platform{}) {
		platform = b.Platform.String()
	}
	kind := "the default build"
	if b.Release {
		kind = "the release build"
	}
	if b.Tests {
		kind += " with tests"
	}
	return fmt.Sprintf("%s on %s", kind, platform)
}
