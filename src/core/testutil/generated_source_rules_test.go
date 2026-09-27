package testutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The reporting half of AssertGeneratedSourceTypeChecks, over fixture packages. Its real callers are
// the two generators' render tests, which pass on a sound generator, so nothing there observes the
// helper failing -- which is the shape guard.go exists to stop.

// fixtureHandWritten is the hand-written half of a fixture package: the type the generated table
// fills, as countries.go declares Country.
const fixtureHandWritten = `package fixture

type Row struct {
	Name string
}
`

// fixtureGenerated is a sound rendering of the table into that type.
const fixtureGenerated = `package fixture

var rows = []Row{{Name: "a"}}
`

func writeGeneratedFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFixture(t, dir, "fixture.go", fixtureHandWritten)
	return dir
}

func TestGeneratedSource_ASoundRenderingPasses(t *testing.T) {
	dir := writeGeneratedFixture(t)

	report := RunGuard(func(r Reporter) {
		AssertGeneratedSourceTypeChecks(r, dir, "data_generated.go", []byte(fixtureGenerated))
	})

	assert.False(t, report.Failed(), report.Text())
}

// The shape the timezones generator had: formatted, parseable, and refused by the compiler.
func TestGeneratedSource_AnUnusedImportFails(t *testing.T) {
	dir := writeGeneratedFixture(t)
	src := "package fixture\n\nimport \"fmt\"\n\nvar rows = []Row{{Name: \"a\"}}\n"

	report := RunGuard(func(r Reporter) {
		AssertGeneratedSourceTypeChecks(r, dir, "data_generated.go", []byte(src))
	})

	require.True(t, report.Failed())
	assert.False(t, report.Stopped, "a type error is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), `"fmt" imported and not used`)
	assert.Contains(t, report.Text(), "data_generated.go")
}

// The rendering has to agree with the hand-written type, which is what checking it alone misses.
func TestGeneratedSource_AFieldTheTypeLacksFails(t *testing.T) {
	dir := writeGeneratedFixture(t)
	src := "package fixture\n\nvar rows = []Row{{Name: \"a\", Abbr: \"b\"}}\n"

	report := RunGuard(func(r Reporter) {
		AssertGeneratedSourceTypeChecks(r, dir, "data_generated.go", []byte(src))
	})

	require.True(t, report.Failed())
	assert.Contains(t, report.Text(), "Abbr")
}

// The copy on disk is what the generator is about to replace. Were it read, a broken one would fail
// a sound rendering, and a sound one would redeclare rows and fail it too.
func TestGeneratedSource_TheCopyOnDiskIsIgnored(t *testing.T) {
	dir := writeGeneratedFixture(t)
	writeFixture(t, dir, "data_generated.go", "package fixture\n\nthis is not Go\n")

	report := RunGuard(func(r Reporter) {
		AssertGeneratedSourceTypeChecks(r, dir, "data_generated.go", []byte(fixtureGenerated))
	})

	assert.False(t, report.Failed(), report.Text())
}

// Test files are not part of the package a binary compiles, so they are not what the output is
// checked against either.
func TestGeneratedSource_TestFilesAreNotRead(t *testing.T) {
	dir := writeGeneratedFixture(t)
	writeFixture(t, dir, "fixture_test.go", "package fixture\n\nvar rows = 1\n")

	report := RunGuard(func(r Reporter) {
		AssertGeneratedSourceTypeChecks(r, dir, "data_generated.go", []byte(fixtureGenerated))
	})

	assert.False(t, report.Failed(), report.Text())
}

func TestGeneratedSource_ARenderingThatDoesNotParseFails(t *testing.T) {
	dir := writeGeneratedFixture(t)

	report := RunGuard(func(r Reporter) {
		AssertGeneratedSourceTypeChecks(r, dir, "data_generated.go", []byte("package fixture\n\nvar rows = []Row{\n"))
	})

	require.True(t, report.Failed())
	assert.Contains(t, report.Text(), "does not parse")
}

// Checking the output with nothing beside it would pass whatever type it names.
func TestGeneratedSource_ADirectoryWithNoOtherGoFileIsFatal(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "data_generated.go", fixtureGenerated)

	report := RunGuard(func(r Reporter) {
		AssertGeneratedSourceTypeChecks(r, dir, "data_generated.go", []byte(fixtureGenerated))
	})

	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "no Go file besides data_generated.go")
}
