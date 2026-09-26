package testutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pointingSource = `package p

// Measured in the agreement's section 1.
func a() {}

// As §5 of the agreement rejects.
func b() {}

/*
Recorded in probe/cancel.out, and grown from probe/wire_probe_test.go.
*/
func c() {}

// The ordering the agreement requires.
func d() {}
`

const statingSource = `package p

// A disagreement between the two engines, measured on all four (#301).
func a() {}

// RFC 7516 section 4.6: Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static.
func b() {}

func c() string {
	return "the agreement's section 1, probe/cancel.out"
}
`

// TestAgreementPointers_TheRuleTable is the tree that must fail: each refused shape once, the
// block comment's path and the second path on one line included, each named at its own line.
func TestAgreementPointers_TheRuleTable(t *testing.T) {
	root := t.TempDir()
	writeGoFile(t, root, "a/pointing.go", pointingSource)
	writeGoFile(t, root, "b/broken.go", unparseableSource)

	findings, files, err := findAgreementPointers(root)
	require.NoError(t, err)

	assert.Equal(t, 1, files, "the unparseable file is not counted")
	assert.Equal(t, []string{
		"a/pointing.go:3: // Measured in the agreement's section 1.",
		"a/pointing.go:6: // As §5 of the agreement rejects.",
		"a/pointing.go:10: Recorded in probe/cancel.out, and grown from probe/wire_probe_test.go.",
		"a/pointing.go:14: // The ordering the agreement requires.",
	}, findings)
}

// TestAgreementPointers_AStatingTreeReportsNothing is the tree that must pass: a word containing
// the noun, RFC 7516's term, and the refused phrases inside a string literal rather than a comment.
func TestAgreementPointers_AStatingTreeReportsNothing(t *testing.T) {
	root := t.TempDir()
	writeGoFile(t, root, "a/stating.go", statingSource)

	findings, files, err := findAgreementPointers(root)
	require.NoError(t, err)
	assert.Equal(t, 1, files)
	assert.Empty(t, findings)

	report := RunGuard(func(r Reporter) { assertNoAgreementPointers(r, root) })
	assert.False(t, report.Failed(), "a stating tree failed the guard: %s", report.Text())
}

// TestAgreementPointers_APointingTreeFails drives the reporting half on the failing tree.
func TestAgreementPointers_APointingTreeFails(t *testing.T) {
	root := t.TempDir()
	writeGoFile(t, root, "a/pointing.go", pointingSource)

	report := RunGuard(func(r Reporter) { assertNoAgreementPointers(r, root) })

	require.True(t, report.Failed())
	assert.False(t, report.Stopped, "a pointer is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "a/pointing.go:14:")
}

// TestAgreementPointers_AnEmptyWalkIsFatal is the walk that reached nothing.
func TestAgreementPointers_AnEmptyWalkIsFatal(t *testing.T) {
	root := t.TempDir()

	report := RunGuard(func(r Reporter) { assertNoAgreementPointers(r, root) })

	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "walked no Go files")
}
