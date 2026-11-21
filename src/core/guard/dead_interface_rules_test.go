package guard

// Seam 1: the rule table AssertNoDeadInterfaces enforces, over fixture modules written into a temp
// tree and walked through the same function the real callers use.
//
// The synthetic half exists because the real half cannot fail informatively. Stage 1 of #333
// deleted every dead interface in the tree, so from here on the two real call sites walk a clean
// tree and would pass identically whether the rule still fires or has quietly stopped matching
// anything. Every "dead" row below is a shape that was in the tree or that broke the census;
// every "live" row is a shape that must survive untouched.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leodip/goiabada/core/pkgload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeFixture writes one file into a fixture tree, creating its directories.
func writeFixture(t *testing.T, root, rel, src string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
}

// makeLoadable makes a fixture tree a set of modules the go command can load, which is how the
// guard reads it. Every tree it is called on compiles: a package that does not is fatal (#420).
func makeLoadable(t *testing.T, root string) {
	t.Helper()
	require.NoError(t, pkgload.MakeLoadable(root))
}

// deadNames renders the findings as "<package>.<Name>" so a failure names what was missed rather
// than printing a struct.
func deadNames(dead []deadInterface) []string {
	names := make([]string, 0, len(dead))
	for _, d := range dead {
		names = append(names, d.pkg+"."+d.name)
	}
	return names
}

// TestNoDeadInterfaces_TheRuleTable builds one module carrying every shape at once and asserts the
// exact set of findings. One module rather than one per row, because the interesting half of this
// rule is cross-package resolution: a row that cannot see its neighbours cannot exercise it.
func TestNoDeadInterfaces_TheRuleTable(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")

	// ---- the declaring package ------------------------------------------------------------
	writeFixture(t, root, "mod/handlers/interfaces.go", `package handlers

// DeadOne is named by its own declaration and by nothing else, which is the whole defect: nine
// interfaces in this shape shipped in adminconsole/internal/handlers.
type DeadOne interface{ A() }

// SameFile is consumed by a declaration in this same file, which a file-level exclusion would
// report dead.
type SameFile interface{ B() }

func useSameFile(x SameFile) { _ = x }

// Embedded is consumed by embedding, again from this same file.
type Embedded interface{ J() }

type Embedder interface {
	Embedded
	K()
}

func useEmbedder(x Embedder) { _ = x }

// Result is consumed as another interface's method result.
type Result interface{ L() }

type Producer interface{ Produce() Result }

func useProducer(x Producer) { _ = x }

// OtherFile is consumed by another file in this package.
type OtherFile interface{ C() }

// FromSubpackage is consumed as handlers.FromSubpackage from elsewhere in the module.
type FromSubpackage interface{ D() }

// FromTest is consumed only from a _test.go, which is a consumer: the guard holds production and
// test alike.
type FromTest interface{ E() }

// FromExternalTest is consumed only from the external test package, which imports the test build
// of this package rather than the package itself.
type FromExternalTest interface{ M() }

// ViaAlias is consumed through an import given another name at the call site.
type ViaAlias interface{ F() }

// ShadowedLocal is spelled inside this package by a local variable and by nothing else. A
// same-package search by spelling reads it as live.
type ShadowedLocal interface{ G() }

func shadow() int {
	ShadowedLocal := 1
	return ShadowedLocal
}

// ShadowedLocalType is spelled inside this package by a type a function body declares, and by
// nothing else. Both are types of this package, and only one of them is this declaration.
type ShadowedLocalType interface{ N() }

func shadowType() {
	type ShadowedLocalType int
	var x ShadowedLocalType
	_ = x
}

// Collides is spelled by a same-named type in a different package and by nothing else. This is the
// TCPConnectionTester case: a bare-name grep credited it with four references that belonged to
// another package's type, and the first census called it live.
type Collides interface{ H() }

// ShadowedImport is spelled in a selector whose base is a local value wearing the import's name.
type ShadowedImport interface{ I() }

// Plain is no interface, so the guard holds nothing about it. It is what the shadowimport package
// names through the import, which a package that compiles has to use somewhere.
func Plain() {}
`)

	writeFixture(t, root, "mod/handlers/other.go", `package handlers

func useOtherFile(x OtherFile) { _ = x }
`)

	writeFixture(t, root, "mod/handlers/handlers_test.go", `package handlers

var fromTest FromTest
`)

	writeFixture(t, root, "mod/handlers/external_test.go", `package handlers_test

import "example.com/mod/handlers"

var fromExternalTest handlers.FromExternalTest
`)

	// ---- a package with no interfaces at all, guarded alongside ----------------------------
	writeFixture(t, root, "mod/nointerfaces/plain.go", `package nointerfaces

type Plain struct{ N int }

func New() *Plain { return &Plain{} }
`)

	// ---- consumers elsewhere in the module -------------------------------------------------
	writeFixture(t, root, "mod/sub/sub.go", `package sub

import "example.com/mod/handlers"

func Use(x handlers.FromSubpackage) { _ = x }
`)

	writeFixture(t, root, "mod/aliased/aliased.go", `package aliased

import h "example.com/mod/handlers"

func Use(x h.ViaAlias) { _ = x }
`)

	// ---- the two shapes that only look like consumers ---------------------------------------
	writeFixture(t, root, "mod/collide/collide.go", `package collide

// Collides is a different type in a different package. Nothing here binds to handlers.Collides.
type Collides interface{ H() }

func Use(x Collides) { _ = x }
`)

	writeFixture(t, root, "mod/shadowimport/shadowimport.go", `package shadowimport

import "example.com/mod/handlers"

var _ = handlers.Plain

type box struct{ ShadowedImport int }

// The selector reads handlers.ShadowedImport, but handlers here is this function's parameter, so
// the base binds to a value and not to the import.
func Use(handlers box) int { return handlers.ShadowedImport }
`)

	makeLoadable(t, root)

	dead, files, err := findDeadInterfaces(root, []string{"mod/handlers", "mod/nointerfaces"})
	require.NoError(t, err)
	assert.Equal(t, 5, files, "four files in mod/handlers and one in mod/nointerfaces")

	assert.ElementsMatch(t, []string{
		"example.com/mod/handlers.DeadOne",
		"example.com/mod/handlers.ShadowedLocal",
		"example.com/mod/handlers.ShadowedLocalType",
		"example.com/mod/handlers.Collides",
		"example.com/mod/handlers.ShadowedImport",
	}, deadNames(dead))
}

// TestNoDeadInterfaces_AWalkThatReachesNoFilesIsNotAPass pins the one way a guard like this stops
// guarding without anything going red: a dirs argument that no longer names any Go source walks
// nothing, finds nothing, and would otherwise be indistinguishable from a clean tree.
func TestNoDeadInterfaces_AWalkThatReachesNoFilesIsNotAPass(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "mod", "empty"), 0o755))

	dead, files, err := findDeadInterfaces(root, []string{"mod/empty"})
	require.NoError(t, err)
	assert.Empty(t, dead)
	assert.Zero(t, files, "AssertNoDeadInterfaces turns a zero file count into a t.Fatalf")
}

// TestNoDeadInterfaces_ADotImportIsAnOrdinaryReference holds that a name reaching a file through a
// dot import is a reference like any other. The type checker binds it to the declaration it names,
// so an interface used only that way is live (#420).
func TestNoDeadInterfaces_ADotImportIsAnOrdinaryReference(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")
	writeFixture(t, root, "mod/handlers/interfaces.go", `package handlers

type DotUsed interface{ A() }

type DotUnused interface{ B() }
`)
	writeFixture(t, root, "mod/consumer/consumer.go", `package consumer

import . "example.com/mod/handlers"

func Use(x DotUsed) { _ = x }
`)
	makeLoadable(t, root)

	dead, files, err := findDeadInterfaces(root, []string{"mod/handlers"})
	require.NoError(t, err)
	assert.Equal(t, 1, files)
	assert.Equal(t, []string{"example.com/mod/handlers.DotUnused"}, deadNames(dead),
		"the dot-imported name is live and its unnamed neighbour is not")
}

// An external test package's import path is its package's with _test appended, which a real
// package can also have. A reference to the external test's Seam is no reference to the real
// package's Seam of the same name.
func TestNoDeadInterfaces_AnExternalTestIsNotThePackageItsPathSpells(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")
	writeFixture(t, root, "mod/handlers/handlers.go", "package handlers\n")
	writeFixture(t, root, "mod/handlers/external_test.go", `package handlers_test

type Seam interface{ A() }

var _ Seam
`)
	writeFixture(t, root, "mod/handlers_test/seam.go", `package handlers_test

type Seam interface{ B() }
`)
	makeLoadable(t, root)

	dead, files, err := findDeadInterfaces(root, []string{"mod/handlers_test"})
	require.NoError(t, err)
	assert.Equal(t, 1, files)
	assert.Equal(t, []string{"example.com/mod/handlers_test.Seam"}, deadNames(dead))
}

// A dead interface is reported at its own file and line, not where a //line directive maps it, so
// the finding names the file to edit.
func TestNoDeadInterfaces_ReportsTheDeclarationsOwnFileAndLine(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")
	writeFixture(t, root, "mod/handlers/generated.go", `package handlers

//line interfaces.tmpl:100
type Unused interface{ A() }
`)
	makeLoadable(t, root)

	dead, _, err := findDeadInterfaces(root, []string{"mod/handlers"})
	require.NoError(t, err)
	require.Len(t, dead, 1)
	assert.Equal(t, "mod/handlers/generated.go", dead[0].file)
	assert.Equal(t, 4, dead[0].line)
}

// TestNoDeadInterfaces_DeclarationsOutsideTheGuardedDirsAreNotHeld keeps the dirs argument
// meaningful: the module is searched whole for references, but only what the caller named is held
// to the rule. Without this, a caller guarding one handler package would fail on every unreferenced
// interface anywhere in its module.
func TestNoDeadInterfaces_DeclarationsOutsideTheGuardedDirsAreNotHeld(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")
	writeFixture(t, root, "mod/handlers/interfaces.go", `package handlers

type Live interface{ A() }

func use(x Live) { _ = x }
`)
	writeFixture(t, root, "mod/elsewhere/elsewhere.go", `package elsewhere

type AlsoDeadButNotGuarded interface{ B() }
`)
	makeLoadable(t, root)

	dead, files, err := findDeadInterfaces(root, []string{"mod/handlers"})
	require.NoError(t, err)
	assert.Equal(t, 1, files)
	assert.Empty(t, deadNames(dead))
}

// A directory named for the guard that ./... skips, one whose name begins with _, would be walked and
// read none of, since the guards load ./...: the walk refuses it, naming it, rather than pass an
// unused interface there.
func TestNoDeadInterfaces_ADirectoryTheWildcardSkipsIsRefused(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")
	writeFixture(t, root, "mod/handlers/interfaces.go", `package handlers

type Live interface{ A() }

func use(x Live) { _ = x }
`)
	writeFixture(t, root, "mod/_tools/tools.go", `package tools

type Dead interface{ B() }
`)
	makeLoadable(t, root)

	_, _, err := findDeadInterfaces(root, []string{"mod/handlers", "mod/_tools"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mod/_tools holds Go files, but ./... skips a directory named _tools")
}

// Seam 2: the reporting half. Everything above asserts on what findDeadInterfaces returned, which
// leaves the roughly ten lines that turn those findings into a failure untested -- and those are
// the lines whose loss disables the guard in both modules at once. Blinding them is exactly what
// left the whole core tier green on 8883642d.

// TestNoDeadInterfaces_TheGuardFailsOnADeadInterface drives the reporting half against a tree that
// holds one, and asserts the reader is told where it is and what to do.
func TestNoDeadInterfaces_TheGuardFailsOnADeadInterface(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")
	writeFixture(t, root, "mod/handlers/interfaces.go", `package handlers

type Abandoned interface{ A() }
`)
	makeLoadable(t, root)

	report := Run(func(r Reporter) {
		assertNoDeadInterfaces(r, root, []string{"mod/handlers"})
	})

	require.True(t, report.Failed(), "a tree with a dead interface passed the guard")
	assert.False(t, report.Stopped, "a dead interface is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "mod/handlers/interfaces.go:3")
	assert.Contains(t, report.Text(), "example.com/mod/handlers.Abandoned")
	assert.Contains(t, report.Text(), "1 interface declaration(s)")
	assert.Contains(t, report.Text(), "#333")
}

// TestNoDeadInterfaces_TheGuardPassesALiveOne is the other direction, and it is what keeps the case
// above from passing for the wrong reason. A harness that called everything a failure would satisfy
// that assertion on a clean tree too.
func TestNoDeadInterfaces_TheGuardPassesALiveOne(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")
	writeFixture(t, root, "mod/handlers/interfaces.go", `package handlers

type Consumed interface{ A() }

func use(x Consumed) { _ = x }
`)
	makeLoadable(t, root)

	report := Run(func(r Reporter) {
		assertNoDeadInterfaces(r, root, []string{"mod/handlers"})
	})

	assert.False(t, report.Failed(), "a referenced interface failed the guard: %s", report.Text())
}

// TestNoDeadInterfaces_TheGuardIsFatalOnAnEmptyWalk completes the seam the finder test at
// TestNoDeadInterfaces_AWalkThatReachesNoFilesIsNotAPass could only assert indirectly, through the
// file count. A dirs argument that no longer names any Go source is the way this guard stops
// guarding without anything going red, so the empty walk has to be fatal rather than clean.
func TestNoDeadInterfaces_TheGuardIsFatalOnAnEmptyWalk(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "mod", "empty"), 0o755))

	report := Run(func(r Reporter) {
		assertNoDeadInterfaces(r, root, []string{"mod/empty"})
	})

	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked no Go files under")
	assert.Contains(t, report.Fatal, "mod/empty", "the fatal names the dirs that covered nothing")
}

// TestNoDeadInterfaces_ABuildSelectingNoPackageIsAnEmptyWalk: a module whose only file a custom
// build tag selects holds no package the test build reads. That is an empty walk, reported as one,
// and not a load failure.
func TestNoDeadInterfaces_ABuildSelectingNoPackageIsAnEmptyWalk(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")
	writeFixture(t, root, "mod/handlers/interfaces.go", "//go:build customtag\n\npackage handlers\n\ntype Hidden interface{ A() }\n")
	makeLoadable(t, root)

	report := Run(func(r Reporter) {
		assertNoDeadInterfaces(r, root, []string{"mod/handlers"})
	})

	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked no Go files under")
	assert.NotContains(t, report.Fatal, "selects no package", "an empty build is no load failure")
}

// TestNoDeadInterfaces_AModuleSelectingNoPackageDoesNotStopTheOthers: a module the build selects no
// package of contributes nothing, and the modules beside it are still read and reported.
func TestNoDeadInterfaces_AModuleSelectingNoPackageDoesNotStopTheOthers(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "first/go.mod", "module example.com/first\n\ngo 1.24\n")
	writeFixture(t, root, "first/handlers/interfaces.go", "//go:build customtag\n\npackage handlers\n\ntype Hidden interface{ A() }\n")
	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")
	writeFixture(t, root, "mod/handlers/interfaces.go", "package handlers\n\ntype Abandoned interface{ A() }\n")
	makeLoadable(t, root)

	report := Run(func(r Reporter) {
		assertNoDeadInterfaces(r, root, []string{"first/handlers", "mod/handlers"})
	})

	require.False(t, report.Stopped, "an empty module stopped the walk: %s", report.Fatal)
	assert.Contains(t, report.Text(), "mod/handlers/interfaces.go:3")
	assert.Contains(t, report.Text(), "example.com/mod/handlers.Abandoned")
}

// TestNoDeadInterfaces_TheGuardIsFatalOnAPackageThatDoesNotCompile holds decision 3 of #420. The
// module is read type-checked, and a package that does not compile would leave its references
// unread, so an interface only it names would be reported dead. The guard stops instead, naming the
// package, even when the package is outside the guarded dirs.
func TestNoDeadInterfaces_TheGuardIsFatalOnAPackageThatDoesNotCompile(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")
	writeFixture(t, root, "mod/handlers/interfaces.go", `package handlers

type Consumed interface{ A() }
`)
	writeFixture(t, root, "mod/broken/broken.go", `package broken

import "example.com/mod/handlers"

var _ handlers.Consumed = undeclared
`)
	makeLoadable(t, root)

	report := Run(func(r Reporter) {
		assertNoDeadInterfaces(r, root, []string{"mod/handlers"})
	})

	require.True(t, report.Stopped, "a package that does not compile must stop the guard: %s", report.Text())
	assert.Contains(t, report.Fatal, "example.com/mod/broken")
	assert.Contains(t, report.Fatal, "undeclared")
	assert.Contains(t, report.Fatal, "cannot be read until it does")
	assert.NotContains(t, report.Text(), "interface declaration(s)",
		"a half-read module reports no finding")
}
