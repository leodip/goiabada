package guard

// The rule table AssertNoGuardInTestsReachedFrom enforces, over miniature four-module trees written
// by writeTree, with the fixture module paths it gives them.
//
// The synthetic half exists because the real half cannot fail informatively: since #500 no test
// the setup wizard reaches imports core/guard, so the call over the real tree passes whether the
// rule still fires or has quietly stopped matching anything.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fixtureGuard = "example.test/core/guard"
	fixtureSetup = "cmd/goiabada-setup"
)

// guardInTestsTree is the shape the finder is read against: a wizard reaching core/leaf, core/deep
// through core/leaf, and core/viatest through its own tests alone, with a guard that imports
// core/metrics the way the real one does.
func guardInTestsTree(extra map[string]string) map[string]string {
	files := map[string]string{
		"cmd/goiabada-setup/main.go":      pkg("main", "example.test/core/leaf", "os"),
		"core/leaf/leaf.go":               pkg("leaf", "example.test/core/deep"),
		"core/deep/deep.go":               pkg("deep"),
		"core/viatest/viatest.go":         pkg("viatest"),
		"core/guard/guard.go":             pkg("guard", "example.test/core/metrics", "testing"),
		"core/metrics/metrics.go":         pkg("metrics"),
		"core/helper/helper.go":           pkg("helper", "example.test/core/guard"),
		"core/unrelated/unrelated.go":     pkg("unrelated"),
		"cmd/goiabada-setup/main_test.go": pkg("main", "example.test/core/viatest", "testing"),
	}
	for rel, src := range extra {
		files[rel] = src
	}
	return files
}

// TestGuardInTests_ReadsWhatTheModuleReaches holds each shape, so a finder that has quietly stopped
// matching anything is caught here rather than trusted.
func TestGuardInTests_ReadsWhatTheModuleReaches(t *testing.T) {
	root := writeTree(t, guardInTestsTree(map[string]string{
		// Rejected: a test of a package the wizard imports, naming the guard directly. This is the
		// leak #500 shipped and review found.
		"core/leaf/leaf_test.go": pkg("leaf", fixtureGuard, "testing"),
		// Rejected: a test two packages down, in an external test package, naming the guard
		// through a first-party helper whose production code imports it.
		"core/deep/deep_test.go": pkg("deep_test", "example.test/core/helper"),
		// Rejected: a test of a package the wizard reaches only through its own tests.
		"core/viatest/viatest_test.go": pkg("viatest", fixtureGuard),
		// Rejected: the wizard's own test.
		"cmd/goiabada-setup/flags_test.go": pkg("main", fixtureGuard),
		// Accepted: a package nothing in the wizard reaches.
		"core/unrelated/unrelated_test.go": pkg("unrelated", fixtureGuard),
		// Accepted: another module's test, the way the auth server's tiers call every guard.
		"authserver/internal/thing/thing.go":      pkg("thing"),
		"authserver/internal/thing/thing_test.go": pkg("thing", fixtureGuard),
		// Accepted: a reached package's test naming a package that does not reach the guard,
		// and a third-party one.
		"core/leaf/other_test.go": pkg("leaf", "example.test/core/metrics", "github.com/stretchr/testify/assert"),
		// Accepted: the guard's own tests, which import nothing of themselves.
		"core/guard/guard_test.go": pkg("guard", "example.test/core/helper"),
	}))

	found, reached, err := findGuardInTests(root, fixtureSetup)
	require.NoError(t, err)
	// The wizard, leaf and deep through its production code, viatest through its tests, and
	// core/guard and core/metrics through flags_test.go's import, which is itself the finding.
	assert.Equal(t, 6, reached, "the walk reached the wrong set")

	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, f.file+": "+strings.Join(f.chain, " -> "))
	}
	assert.ElementsMatch(t, []string{
		"cmd/goiabada-setup/flags_test.go: " + fixtureGuard,
		"core/leaf/leaf_test.go: " + fixtureGuard,
		"core/deep/deep_test.go: example.test/core/helper -> " + fixtureGuard,
		"core/viatest/viatest_test.go: " + fixtureGuard,
	}, got, "the finder matched the wrong set")
}

// TestGuardInTests_TheChainIsTheShortest pins the breadth-first chain: with a long and a short way
// to the guard, the failure names the short one, which is the edge worth breaking.
func TestGuardInTests_TheChainIsTheShortest(t *testing.T) {
	root := writeTree(t, guardInTestsTree(map[string]string{
		"core/long1/long1.go":    pkg("long1", "example.test/core/long2"),
		"core/long2/long2.go":    pkg("long2", "example.test/core/helper"),
		"core/both/both.go":      pkg("both", "example.test/core/long1", "example.test/core/helper"),
		"core/leaf/leaf_test.go": pkg("leaf", "example.test/core/both"),
	}))

	found, _, err := findGuardInTests(root, fixtureSetup)
	require.NoError(t, err)
	require.Len(t, found, 1)
	assert.Equal(t, []string{"example.test/core/both", "example.test/core/helper", fixtureGuard}, found[0].chain)
}

// TestGuardInTests_FailsOnALeak drives the reporting half: the cases above assert on what the
// finder returned, and the lines that turn a finding into a failure are reached only here.
func TestGuardInTests_FailsOnALeak(t *testing.T) {
	root := writeTree(t, guardInTestsTree(map[string]string{
		"core/leaf/leaf_test.go": "package leaf\n\nimport (\n\t\"testing\"\n\n\t\"example.test/core/guard\"\n)\n",
	}))

	report := Run(func(r Reporter) {
		assertNoGuardInTestsReachedFrom(r, root, fixtureSetup)
	})

	require.True(t, report.Failed(), "a test importing core/guard from a package the wizard imports passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "core/leaf/leaf_test.go:6: "+fixtureGuard)
	assert.Contains(t, report.Text(), "go.sum")
	assert.Contains(t, report.Text(), "#500")
	// The failure says what to do instead.
	assert.Contains(t, report.Text(), "TestAdminPassword_ImportsNothingButErrsAndTheStandardLibrary")
}

// TestGuardInTests_PassesACleanTree is the other direction, over the shape the real wizard has: its
// own tests and every reached package's tests name testify and first-party packages that never
// reach the guard.
func TestGuardInTests_PassesACleanTree(t *testing.T) {
	root := writeTree(t, guardInTestsTree(map[string]string{
		"core/leaf/leaf_test.go": pkg("leaf", "github.com/stretchr/testify/assert", "testing"),
		"core/deep/deep_test.go": pkg("deep_test", "example.test/core/deep", "example.test/core/metrics"),
	}))

	report := Run(func(r Reporter) {
		assertNoGuardInTestsReachedFrom(r, root, fixtureSetup)
	})

	assert.False(t, report.Failed(), "a clean tree failed the guard: %s", report.Text())
}

// TestGuardInTests_IsFatalOnAnEmptyWalk pins the walk that reached nothing: a module directory
// holding no Go package, which is also what a misspelled argument reads as.
func TestGuardInTests_IsFatalOnAnEmptyWalk(t *testing.T) {
	root := writeTree(t, map[string]string{
		"cmd/goiabada-setup/README.md": "the wizard moved\n",
		"core/leaf/leaf.go":            pkg("leaf"),
	})

	report := Run(func(r Reporter) {
		assertNoGuardInTestsReachedFrom(r, root, fixtureSetup)
	})

	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "reached no package from "+fixtureSetup)
}

// TestGuardInTests_IsFatalWhenTheGraphCannotBeRead is the other way the walk disappears: a tree
// missing a module's go.mod, which the import graph refuses rather than reads as half a tree.
func TestGuardInTests_IsFatalWhenTheGraphCannotBeRead(t *testing.T) {
	root := writeTree(t, guardInTestsTree(nil))
	require.NoError(t, os.Remove(filepath.Join(root, "cmd", "goiabada-setup", "go.mod")))

	report := Run(func(r Reporter) {
		assertNoGuardInTestsReachedFrom(r, root, fixtureSetup)
	})

	require.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "reading the import graph")
	assert.NotContains(t, report.Fatal, "reached no package")
}
