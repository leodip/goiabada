package pkgload_test

import (
	"go/ast"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/pkgload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

// writeTree writes a fixture tree into a fresh temp directory and returns its root.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	}
	return root
}

// loadable writes a fixture tree and makes it loadable, for the tests not about MakeLoadable.
func loadable(t *testing.T, files map[string]string) string {
	t.Helper()
	root := writeTree(t, files)
	require.NoError(t, pkgload.MakeLoadable(root))
	return root
}

// byPath indexes loaded packages by ID, failing on a duplicate.
func byPath(t *testing.T, pkgs []*packages.Package) map[string]*packages.Package {
	t.Helper()
	out := map[string]*packages.Package{}
	for _, p := range pkgs {
		require.NotContains(t, out, p.ID)
		out[p.ID] = p
	}
	return out
}

// fileNames is the base names of a package's Go files, sorted.
func fileNames(p *packages.Package) []string {
	var names []string
	for _, f := range p.GoFiles {
		names = append(names, filepath.Base(f))
	}
	sort.Strings(names)
	return names
}

// ---- the release platforms ------------------------------------------------------------------

func TestReleasePlatforms_AreTheFivePairsAReleaseShips(t *testing.T) {
	assert.Equal(t, []pkgload.Platform{
		{GOOS: "linux", GOARCH: "amd64"},
		{GOOS: "linux", GOARCH: "arm64"},
		{GOOS: "darwin", GOARCH: "amd64"},
		{GOOS: "darwin", GOARCH: "arm64"},
		{GOOS: "windows", GOARCH: "amd64"},
	}, pkgload.ReleasePlatforms())
}

func TestReleasePlatforms_ACallerCannotChangeTheDeclaration(t *testing.T) {
	first := pkgload.ReleasePlatforms()
	require.NotEmpty(t, first)
	first[0] = pkgload.Platform{GOOS: "plan9", GOARCH: "386"}
	assert.Equal(t, pkgload.Platform{GOOS: "linux", GOARCH: "amd64"}, pkgload.ReleasePlatforms()[0])
}

func TestReleaseBuilds_AreOneReleaseBuildPerPlatformWithoutTests(t *testing.T) {
	assert.Equal(t, []pkgload.Build{
		{Platform: pkgload.Platform{GOOS: "linux", GOARCH: "amd64"}, Release: true},
		{Platform: pkgload.Platform{GOOS: "linux", GOARCH: "arm64"}, Release: true},
		{Platform: pkgload.Platform{GOOS: "darwin", GOARCH: "amd64"}, Release: true},
		{Platform: pkgload.Platform{GOOS: "darwin", GOARCH: "arm64"}, Release: true},
		{Platform: pkgload.Platform{GOOS: "windows", GOARCH: "amd64"}, Release: true},
	}, pkgload.ReleaseBuilds())
}

func TestPlatform_StringIsTheGoOSSlashGoARCHPair(t *testing.T) {
	assert.Equal(t, "darwin/arm64", pkgload.Platform{GOOS: "darwin", GOARCH: "arm64"}.String())
}

// ---- what a build selects -------------------------------------------------------------------

// constrainedTree is one package whose files each a different build selects: the production tag,
// its absence, cgo on, cgo off, and one platform each.
var constrainedTree = map[string]string{
	"mod/go.mod":            "module example.test/mod\n",
	"mod/p/common.go":       "package p\n",
	"mod/p/prod.go":         "//go:build production\n\npackage p\n",
	"mod/p/dev.go":          "//go:build !production\n\npackage p\n",
	"mod/p/withcgo.go":      "//go:build cgo\n\npackage p\n",
	"mod/p/nocgo.go":        "//go:build !cgo\n\npackage p\n",
	"mod/p/only_linux.go":   "package p\n",
	"mod/p/only_windows.go": "package p\n",
	"mod/p/p_test.go":       "package p\n",
}

// The environment turns cgo on, as the race tier does, so the release build has to turn it off
// itself rather than inherit an environment that already had it off.
func TestLoad_AReleaseBuildSetsProductionAndTurnsCgoOff(t *testing.T) {
	t.Setenv("CGO_ENABLED", "1")
	root := loadable(t, constrainedTree)

	pkgs, err := pkgload.Load(filepath.Join(root, "mod"), pkgload.Build{
		Platform: pkgload.Platform{GOOS: "linux", GOARCH: "amd64"}, Release: true,
	})
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, []string{"common.go", "nocgo.go", "only_linux.go", "prod.go"}, fileNames(pkgs[0]))
}

func TestLoad_AReleaseBuildSelectsItsOwnPlatformsFiles(t *testing.T) {
	root := loadable(t, constrainedTree)

	pkgs, err := pkgload.Load(filepath.Join(root, "mod"), pkgload.Build{
		Platform: pkgload.Platform{GOOS: "windows", GOARCH: "amd64"}, Release: true,
	})
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, []string{"common.go", "nocgo.go", "only_windows.go", "prod.go"}, fileNames(pkgs[0]))
}

// The default build is the machine's own: no production tag, and cgo as the environment has it.
func TestLoad_TheDefaultBuildLeavesProductionOffAndCgoToTheEnvironment(t *testing.T) {
	t.Setenv("CGO_ENABLED", "1")
	root := loadable(t, constrainedTree)

	pkgs, err := pkgload.Load(filepath.Join(root, "mod"), pkgload.Build{
		Platform: pkgload.Platform{GOOS: "linux", GOARCH: "amd64"},
	})
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, []string{"common.go", "dev.go", "only_linux.go", "withcgo.go"}, fileNames(pkgs[0]))
}

func TestLoad_ATestBuildCarriesTheTestFiles(t *testing.T) {
	root := loadable(t, constrainedTree)
	dir := filepath.Join(root, "mod")
	linux := pkgload.Platform{GOOS: "linux", GOARCH: "amd64"}

	plain, err := pkgload.Load(dir, pkgload.Build{Platform: linux})
	require.NoError(t, err)
	assert.Equal(t, []string{"example.test/mod/p"}, ids(plain))

	tests, err := pkgload.Load(dir, pkgload.Build{Platform: linux, Tests: true})
	require.NoError(t, err)
	got := byPath(t, tests)
	require.Contains(t, got, "example.test/mod/p [example.test/mod/p.test]")
	assert.Contains(t, fileNames(got["example.test/mod/p [example.test/mod/p.test]"]), "p_test.go")
}

func ids(pkgs []*packages.Package) []string {
	var out []string
	for _, p := range pkgs {
		out = append(out, p.ID)
	}
	sort.Strings(out)
	return out
}

// ---- type-checked packages ------------------------------------------------------------------

func TestLoad_ReturnsEveryPackageOfTheModuleTypeChecked(t *testing.T) {
	root := loadable(t, map[string]string{
		"mod/go.mod": "module example.test/mod\n",
		"mod/a/a.go": "package a\n\nfunc F() int { return 1 }\n",
		"mod/b/b.go": "package b\n\nimport renamed \"example.test/mod/a\"\n\nvar V = renamed.F()\n",
	})

	pkgs, err := pkgload.Load(filepath.Join(root, "mod"), pkgload.Build{})
	require.NoError(t, err)
	got := byPath(t, pkgs)
	assert.Equal(t, []string{"example.test/mod/a", "example.test/mod/b"}, ids(pkgs))

	b := got["example.test/mod/b"]
	require.NotNil(t, b.Types)
	require.NotNil(t, b.TypesInfo)
	require.Len(t, b.Syntax, 1)

	// The selector renamed.F resolves to F declared in package a, whatever the import is called.
	var resolved []string
	ast.Inspect(b.Syntax[0], func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if obj := b.TypesInfo.Uses[sel.Sel]; obj != nil {
				resolved = append(resolved, obj.Pkg().Path()+"."+obj.Name())
			}
		}
		return true
	})
	assert.Equal(t, []string{"example.test/mod/a.F"}, resolved)
	assert.Equal(t, "int", b.Types.Scope().Lookup("V").Type().String())
}

// ---- what stops a load ----------------------------------------------------------------------

func TestLoad_APackageThatDoesNotCompileIsAnErrorNamingIt(t *testing.T) {
	root := loadable(t, map[string]string{
		"mod/go.mod":       "module example.test/mod\n",
		"mod/good/good.go": "package good\n",
		"mod/bad/bad.go":   "package bad\n\nvar X int = \"not a number\"\n",
	})

	_, err := pkgload.Load(filepath.Join(root, "mod"), pkgload.Build{})
	require.Error(t, err)
	require.NotErrorIs(t, err, pkgload.ErrNoPackages)
	assert.Contains(t, err.Error(), "example.test/mod/bad")
	assert.Contains(t, err.Error(), "bad.go:3")
	assert.Contains(t, err.Error(), "cannot use \"not a number\"")
	assert.NotContains(t, err.Error(), "example.test/mod/good")
}

func TestLoad_AnImportTheGoCommandCannotFindIsAnErrorNamingThePackage(t *testing.T) {
	root := loadable(t, map[string]string{
		"mod/go.mod":     "module example.test/mod\n",
		"mod/user/u.go":  "package user\n\nimport _ \"example.test/mod/nowhere\"\n",
		"mod/other/o.go": "package other\n",
	})

	_, err := pkgload.Load(filepath.Join(root, "mod"), pkgload.Build{})
	require.Error(t, err)
	require.NotErrorIs(t, err, pkgload.ErrNoPackages)
	assert.Contains(t, err.Error(), "example.test/mod/user")
	assert.Contains(t, err.Error(), "example.test/mod/nowhere")
}

func TestLoad_ASyntaxErrorIsAnErrorNamingThePackage(t *testing.T) {
	root := loadable(t, map[string]string{
		"mod/go.mod":    "module example.test/mod\n",
		"mod/torn/t.go": "package torn\n\nfunc (\n",
	})

	_, err := pkgload.Load(filepath.Join(root, "mod"), pkgload.Build{})
	require.Error(t, err)
	require.NotErrorIs(t, err, pkgload.ErrNoPackages)
	assert.Contains(t, err.Error(), "example.test/mod/torn")
}

// The first failing package is reported, in import-path order, so the message is the same on
// every run.
func TestLoad_TwoBrokenPackagesReportTheFirstByPath(t *testing.T) {
	root := loadable(t, map[string]string{
		"mod/go.mod":   "module example.test/mod\n",
		"mod/zed/z.go": "package zed\n\nvar Z int = \"z\"\n",
		"mod/alf/a.go": "package alf\n\nvar A int = \"a\"\n",
	})

	_, err := pkgload.Load(filepath.Join(root, "mod"), pkgload.Build{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "example.test/mod/alf")
	assert.NotContains(t, err.Error(), "example.test/mod/zed")
}

func TestLoad_AModuleWithNoPackagesIsToldApart(t *testing.T) {
	root := loadable(t, map[string]string{
		"mod/go.mod":       "module example.test/mod\n",
		"mod/notes/README": "no Go here\n",
	})

	pkgs, err := pkgload.Load(filepath.Join(root, "mod"), pkgload.Build{})
	assert.Empty(t, pkgs)
	require.ErrorIs(t, err, pkgload.ErrNoPackages)
	assert.Contains(t, err.Error(), filepath.Join(root, "mod"))
}

// A build whose constraints exclude every file reads nothing, which is the empty case too.
func TestLoad_ABuildThatSelectsNoFileIsToldApart(t *testing.T) {
	root := loadable(t, map[string]string{
		"mod/go.mod":   "module example.test/mod\n",
		"mod/w/w.go":   "//go:build windows\n\npackage w\n",
		"mod/w/doc.go": "//go:build windows\n\n// Package w is Windows-only.\npackage w\n",
	})

	_, err := pkgload.Load(filepath.Join(root, "mod"), pkgload.Build{
		Platform: pkgload.Platform{GOOS: "linux", GOARCH: "amd64"}, Release: true,
	})
	require.ErrorIs(t, err, pkgload.ErrNoPackages)
}

func TestLoad_ADirectoryThatIsNoModuleIsAFailedLoadAndNotAnEmptyOne(t *testing.T) {
	root := writeTree(t, map[string]string{"loose/l.go": "package loose\n"})

	_, err := pkgload.Load(filepath.Join(root, "loose"), pkgload.Build{})
	require.Error(t, err)
	require.NotErrorIs(t, err, pkgload.ErrNoPackages)
	assert.Contains(t, err.Error(), filepath.Join(root, "loose"))
}

// ---- one load per build ---------------------------------------------------------------------

// A second load of the same build in the same binary is the first one's result: the tree is changed
// between the two, and the second still sees it as it was.
func TestLoad_EachBuildOfAModuleIsLoadedOnce(t *testing.T) {
	root := loadable(t, map[string]string{
		"mod/go.mod": "module example.test/mod\n",
		"mod/a/a.go": "package a\n",
	})
	dir := filepath.Join(root, "mod")

	first, err := pkgload.Load(dir, pkgload.Build{})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a", "b.go"), []byte("package a\n\nvar B = 1\n"), 0o644))

	again, err := pkgload.Load(dir, pkgload.Build{})
	require.NoError(t, err)
	require.Len(t, again, 1)
	assert.Same(t, first[0], again[0])
	assert.Equal(t, []string{"a.go"}, fileNames(again[0]))

	other, err := pkgload.Load(dir, pkgload.Build{Tests: true})
	require.NoError(t, err)
	assert.Contains(t, fileNames(byPath(t, other)["example.test/mod/a"]), "b.go",
		"another build of the module is a load of its own")
}

// The same module named through another spelling of its path is still one load.
func TestLoad_TheSameModuleThroughAnotherPathIsLoadedOnce(t *testing.T) {
	root := loadable(t, map[string]string{
		"mod/go.mod": "module example.test/mod\n",
		"mod/a/a.go": "package a\n",
	})

	dir := filepath.Join(root, "mod")
	// Joined by hand, because filepath.Join would clean the a/.. away before Load saw it.
	other := dir + string(filepath.Separator) + "a" + string(filepath.Separator) + ".."
	require.NotEqual(t, dir, other)

	first, err := pkgload.Load(dir, pkgload.Build{})
	require.NoError(t, err)
	again, err := pkgload.Load(other, pkgload.Build{})
	require.NoError(t, err)
	require.Len(t, again, 1)
	assert.Same(t, first[0], again[0])
}

// A package driver the environment names would answer in the go command's place, with whatever
// package set it lists; the loader turns drivers off, so one that does not even exist is not run.
func TestLoad_APackageDriverTheEnvironmentNamesIsNotUsed(t *testing.T) {
	t.Setenv("GOPACKAGESDRIVER", filepath.Join(t.TempDir(), "no-such-driver"))
	root := loadable(t, map[string]string{
		"mod/go.mod": "module example.test/mod\n",
		"mod/a/a.go": "package a\n",
	})

	pkgs, err := pkgload.Load(filepath.Join(root, "mod"), pkgload.Build{})
	require.NoError(t, err)
	assert.Equal(t, []string{"example.test/mod/a"}, ids(pkgs))
}

// A failed load is remembered as well, so a guard that meets it twice reports the same error.
func TestLoad_AFailedLoadIsRememberedToo(t *testing.T) {
	root := loadable(t, map[string]string{
		"mod/go.mod":     "module example.test/mod\n",
		"mod/bad/bad.go": "package bad\n\nvar X int = \"x\"\n",
	})
	dir := filepath.Join(root, "mod")

	_, first := pkgload.Load(dir, pkgload.Build{})
	require.Error(t, first)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad", "bad.go"), []byte("package bad\n"), 0o644))
	_, again := pkgload.Load(dir, pkgload.Build{})
	assert.Equal(t, first, again)
}

// ---- making a fixture tree loadable ---------------------------------------------------------

// A fixture writes its go.mod files with a module line and nothing else. Without a go line the go
// command reads the module at Go 1.16, where ranging over an integer does not compile, and without
// a requirement one module cannot import another.
var twoModuleTree = map[string]string{
	"core/go.mod":     "module example.test/core\n",
	"core/lib/lib.go": "package lib\n\nfunc Count() (n int) {\n\tfor range 3 {\n\t\tn++\n\t}\n\treturn n\n}\n",
	"app/go.mod":      "module example.test/app\n",
	"app/main.go":     "package main\n\nimport \"example.test/core/lib\"\n\nfunc main() { _ = lib.Count() }\n",
}

func TestMakeLoadable_TheFixtureTreeDoesNotLoadWithoutIt(t *testing.T) {
	root := writeTree(t, twoModuleTree)

	_, err := pkgload.Load(filepath.Join(root, "app"), pkgload.Build{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "example.test/core/lib")
	_, err = pkgload.Load(filepath.Join(root, "core"), pkgload.Build{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires go1.22")
}

func TestMakeLoadable_GivesEveryModuleAGoVersionAndTheOthersLocally(t *testing.T) {
	root := writeTree(t, twoModuleTree)
	require.NoError(t, pkgload.MakeLoadable(root))

	core, err := pkgload.Load(filepath.Join(root, "core"), pkgload.Build{})
	require.NoError(t, err)
	assert.Equal(t, []string{"example.test/core/lib"}, ids(core))

	app, err := pkgload.Load(filepath.Join(root, "app"), pkgload.Build{})
	require.NoError(t, err)
	assert.Equal(t, []string{"example.test/app"}, ids(app))

	// The app's import resolves to the core module's own directory, not to a copy anywhere else.
	require.Contains(t, app[0].Imports, "example.test/core/lib")
	var paths []string
	for _, p := range app[0].Types.Imports() {
		paths = append(paths, p.Path())
	}
	assert.Equal(t, []string{"example.test/core/lib"}, paths)
	assert.Equal(t, filepath.Join(root, "core"), core[0].Module.Dir)
}

// A go line the fixture wrote is its own, and stays.
func TestMakeLoadable_KeepsAGoLineTheFixtureWrote(t *testing.T) {
	root := writeTree(t, map[string]string{
		"mod/go.mod": "module example.test/mod\n\ngo 1.21\n",
		"mod/a/a.go": "package a\n",
	})
	require.NoError(t, pkgload.MakeLoadable(root))

	src, err := os.ReadFile(filepath.Join(root, "mod", "go.mod"))
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(src), "\ngo "))
	assert.Contains(t, string(src), "\ngo 1.21\n")

	pkgs, err := pkgload.Load(filepath.Join(root, "mod"), pkgload.Build{})
	require.NoError(t, err)
	assert.Equal(t, "1.21", pkgs[0].Module.GoVersion)
}

// A module with no go line takes the one the fixture wrote for another, since a module that requires
// one with a later go line does not load.
func TestMakeLoadable_AModuleWithNoGoLineTakesTheOneAnotherWrote(t *testing.T) {
	root := writeTree(t, map[string]string{
		"app/go.mod":  "module example.test/app\n\ngo 1.24\n",
		"app/main.go": "package main\n\nimport \"example.test/lib/l\"\n\nfunc main() { l.F() }\n",
		"lib/go.mod":  "module example.test/lib\n",
		"lib/l/l.go":  "package l\n\nfunc F() {}\n",
	})
	require.NoError(t, pkgload.MakeLoadable(root))

	app, err := pkgload.Load(filepath.Join(root, "app"), pkgload.Build{})
	require.NoError(t, err)
	assert.Equal(t, []string{"example.test/app"}, ids(app))
	lib, err := pkgload.Load(filepath.Join(root, "lib"), pkgload.Build{})
	require.NoError(t, err)
	assert.Equal(t, "1.24", lib[0].Module.GoVersion)
}

// Go lines the fixture wrote that differ cannot all load, and setting the tree up says so rather
// than leaving the load to fail.
func TestMakeLoadable_GoLinesTheFixtureWroteThatDifferAreAnError(t *testing.T) {
	root := writeTree(t, map[string]string{
		"app/go.mod": "module example.test/app\n\ngo 1.24\n",
		"lib/go.mod": "module example.test/lib\n\ngo 1.25\n",
	})
	err := pkgload.MakeLoadable(root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), filepath.Join(root, "app", "go.mod")+" has go 1.24")
	assert.Contains(t, err.Error(), filepath.Join(root, "lib", "go.mod")+" has go 1.25")
}

// A module path ending in a major version suffix is required at that major, which the go command
// holds it to, and a directory whose name has a space is quoted in the replace line.
func TestMakeLoadable_RequiresAVersionedModuleAtItsMajorAndQuotesADirectoryWithASpace(t *testing.T) {
	root := writeTree(t, map[string]string{
		"app/go.mod":       "module example.test/app\n",
		"app/main.go":      "package main\n\nimport (\n\t\"example.test/lib/v2/l\"\n\t\"example.test/spaced/s\"\n)\n\nfunc main() { l.F(); s.G() }\n",
		"lib/go.mod":       "module example.test/lib/v2\n",
		"lib/l/l.go":       "package l\n\nfunc F() {}\n",
		"local lib/go.mod": "module example.test/spaced\n",
		"local lib/s/s.go": "package s\n\nfunc G() {}\n",
	})
	require.NoError(t, pkgload.MakeLoadable(root))

	src, err := os.ReadFile(filepath.Join(root, "app", "go.mod"))
	require.NoError(t, err)
	assert.Contains(t, string(src), "require example.test/lib/v2 v2.0.0\n")
	assert.Contains(t, string(src), "require example.test/spaced v0.0.0\n")
	assert.Contains(t, string(src), "replace example.test/spaced => \"../local lib\"\n")
	assert.Contains(t, string(src), "replace example.test/lib/v2 => ../lib\n")

	app, err := pkgload.Load(filepath.Join(root, "app"), pkgload.Build{})
	require.NoError(t, err)
	assert.Equal(t, []string{"example.test/app"}, ids(app))
}

func TestMakeLoadable_ATreeWithNoModuleIsAnError(t *testing.T) {
	root := writeTree(t, map[string]string{"a/a.go": "package a\n"})
	assert.Error(t, pkgload.MakeLoadable(root))
}

func TestMakeLoadable_AGoModWithNoModuleLineIsAnError(t *testing.T) {
	root := writeTree(t, map[string]string{"mod/go.mod": "go 1.21\n"})
	err := pkgload.MakeLoadable(root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), filepath.Join(root, "mod", "go.mod"))
}
