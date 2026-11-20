// Package pkgload loads a module's packages type-checked, through golang.org/x/tools/go/packages,
// for one build: the machine's own, or one of the release builds a release ships. It is the one
// loader the guards that need types read the tree through, in place of a hand-written importer
// each (#420), and it holds the one declaration of the release platforms, which rule 9 of
// ARCHITECTURE.md and the release-build test read too.
//
// It is an exported leaf rather than part of core/internal/refgraph because the auth server's
// tests load through it, and Go's internal rule keeps them out of core/internal, as it did for
// core/sourceroot (#480). It imports the standard library, core/errs and golang.org/x/tools, and
// neither testing nor testify, so ownershipdump can load through it and still link no test
// framework. ARCHITECTURE.md's refused-packages table keeps golang.org/x/tools out of every
// shipped binary.
package pkgload

import (
	"errors"
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/leodip/goiabada/core/errs"
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
	// Release sets the production tag and turns cgo off, as every release build does. Without it
	// no tag is set and cgo is as the environment has it.
	Release bool
	// Tests adds each package's test files: the package compiled with its internal tests, its
	// external test package, and the test main, beside the package itself.
	Tests bool
}

// ReleaseBuilds returns the release build of every release platform: the production tag set, cgo
// off and no test files, in the order of ReleasePlatforms.
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
)

// Load returns every package of the module rooted at dir, type-checked for build, as the go command
// lists ./... there. A module is loaded at most once for each build in a process: a second call, from
// whichever guard, returns the first call's packages, or its error, so a caller must not modify them.
//
// A package that does not load or does not type-check is an error naming the package and its first
// error, the first package in import-path order when several fail, because a reading of a
// half-checked tree misses references. A module the build selects no package of is ErrNoPackages,
// and a directory the go command cannot load at all is an error naming it.
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

func load(dir string, build Build) ([]*packages.Package, error) {
	// GOWORK=off and -mod=readonly read each module through its own go.mod, as the four modules are
	// built, whatever workspace file or flags the machine running the tests has.
	env := append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=readonly")
	var flags []string
	if build.Platform.GOOS != "" {
		env = append(env, "GOOS="+build.Platform.GOOS)
	}
	if build.Platform.GOARCH != "" {
		env = append(env, "GOARCH="+build.Platform.GOARCH)
	}
	if build.Release {
		env = append(env, "CGO_ENABLED=0")
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
	pkgs, err := packages.Load(cfg, "./...")
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
	return pkgs, nil
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
