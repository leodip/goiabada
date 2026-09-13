package testutil

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

// ViaAlias is consumed through an import given another name at the call site.
type ViaAlias interface{ F() }

// ShadowedLocal is spelled inside this package by a local variable and by nothing else. A
// same-package search by spelling reads it as live.
type ShadowedLocal interface{ G() }

func shadow() int {
	ShadowedLocal := 1
	return ShadowedLocal
}

// Collides is spelled by a same-named type in a different package and by nothing else. This is the
// TCPConnectionTester case: a bare-name grep credited it with four references that belonged to
// another package's type, and the first census called it live.
type Collides interface{ H() }

// ShadowedImport is spelled in a selector whose base is a local value wearing the import's name.
type ShadowedImport interface{ I() }
`)

	writeFixture(t, root, "mod/handlers/other.go", `package handlers

func useOtherFile(x OtherFile) { _ = x }
`)

	writeFixture(t, root, "mod/handlers/handlers_test.go", `package handlers

var fromTest FromTest
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

type box struct{ ShadowedImport int }

// The selector reads handlers.ShadowedImport, but handlers here is this function's parameter, so
// the base binds to a value and not to the import.
func Use(handlers box) int { return handlers.ShadowedImport }
`)

	dead, blocked, files, err := findDeadInterfaces(root, []string{"mod/handlers", "mod/nointerfaces"})
	require.NoError(t, err)
	assert.Empty(t, blocked, "no fixture here carries a shape the walk cannot resolve")
	assert.Equal(t, 4, files, "three files in mod/handlers and one in mod/nointerfaces")

	assert.ElementsMatch(t, []string{
		"example.com/mod/handlers.DeadOne",
		"example.com/mod/handlers.ShadowedLocal",
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

	dead, blocked, files, err := findDeadInterfaces(root, []string{"mod/empty"})
	require.NoError(t, err)
	assert.Empty(t, dead)
	assert.Empty(t, blocked)
	assert.Zero(t, files, "AssertNoDeadInterfaces turns a zero file count into a t.Fatalf")
}

// TestNoDeadInterfaces_ADotImportIsReportedRatherThanSkipped covers the walk's one boundary. An
// unqualified name reaching a file through a dot import binds to a declaration in a package this
// walk never named, so the honest answer is a finding at the dot import rather than a silent pass
// on the interface. There is no dot import in the tree today, which is what makes refusing one
// free.
func TestNoDeadInterfaces_ADotImportIsReportedRatherThanSkipped(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")
	writeFixture(t, root, "mod/handlers/interfaces.go", `package handlers

type DotUsed interface{ A() }
`)
	writeFixture(t, root, "mod/consumer/consumer.go", `package consumer

import . "example.com/mod/handlers"

func Use(x DotUsed) { _ = x }
`)

	dead, blocked, files, err := findDeadInterfaces(root, []string{"mod/handlers"})
	require.NoError(t, err)
	assert.Equal(t, 1, files)

	require.Len(t, blocked, 1)
	assert.Equal(t, "mod/consumer/consumer.go", blocked[0].file)
	assert.Contains(t, blocked[0].why, "dot import")

	// And the interface is still reported, because the walk genuinely cannot show it referenced.
	assert.Equal(t, []string{"example.com/mod/handlers.DotUsed"}, deadNames(dead))
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

	dead, blocked, files, err := findDeadInterfaces(root, []string{"mod/handlers"})
	require.NoError(t, err)
	assert.Empty(t, blocked)
	assert.Equal(t, 1, files)
	assert.Empty(t, deadNames(dead))
}
