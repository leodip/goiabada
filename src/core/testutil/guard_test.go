package testutil

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The real Reporter is *testing.T, and the whole harness rests on that staying true. A method
// added to Reporter that *testing.T does not carry would be caught here at compile time rather
// than at the thirteen call sites.
var _ Reporter = (*testing.T)(nil)

// TestRunGuard_RecordsEveryErrorfInOrder covers the ordinary path: a guard that reports findings
// and returns. Formatting happens at the recorder, so an assertion can match the rendered message.
func TestRunGuard_RecordsEveryErrorfInOrder(t *testing.T) {
	report := RunGuard(func(r Reporter) {
		r.Helper()
		r.Errorf("%s:%d: first", "a.go", 7)
		r.Errorf("%s:%d: second", "b.go", 9)
	})

	assert.Equal(t, []string{"a.go:7: first", "b.go:9: second"}, report.Errors)
	assert.Empty(t, report.Fatal)
	assert.False(t, report.Stopped, "the guard returned rather than reaching a Fatalf")
	assert.True(t, report.Failed())
	assert.Equal(t, "a.go:7: first\nb.go:9: second", report.Text())
}

// TestRunGuard_AGuardThatReportsNothingHasNotFailed is the other direction, and it is the one that
// keeps every per-guard test honest: a harness that called everything a failure would pass each
// "this fixture fails" case for the wrong reason.
func TestRunGuard_AGuardThatReportsNothingHasNotFailed(t *testing.T) {
	report := RunGuard(func(r Reporter) { r.Helper() })

	assert.Empty(t, report.Errors)
	assert.Empty(t, report.Fatal)
	assert.False(t, report.Stopped)
	assert.False(t, report.Failed())
	assert.Empty(t, report.Text())
}

// TestRunGuard_FatalfStopsTheGuardWhereItStands pins the property the goroutine exists for. On a
// *testing.T, Fatalf is Logf followed by FailNow, and FailNow is runtime.Goexit, so nothing after
// the call runs. A recorder that returned instead would run code the guard's author had already
// decided was unreachable.
func TestRunGuard_FatalfStopsTheGuardWhereItStands(t *testing.T) {
	reached := false

	report := RunGuard(func(r Reporter) {
		r.Fatalf("walked no Go files under %s", "/fixture")
		reached = true
		r.Errorf("this line is past the Fatalf")
	})

	assert.False(t, reached, "execution continued past Fatalf")
	assert.Empty(t, report.Errors)
	assert.Equal(t, "walked no Go files under /fixture", report.Fatal)
	assert.True(t, report.Stopped)
	assert.True(t, report.Failed())
	assert.Equal(t, "walked no Go files under /fixture", report.Text())
}

// TestRunGuard_FatalfRunsTheGuardsDefers is the half of Goexit that separates it from a panic
// recovered at the top: a deferred close or cleanup inside the guard still runs.
func TestRunGuard_FatalfRunsTheGuardsDefers(t *testing.T) {
	deferred := false

	report := RunGuard(func(r Reporter) {
		defer func() { deferred = true }()
		r.Fatalf("stop here")
	})

	assert.True(t, deferred, "a deferred function did not run on the way out of Fatalf")
	assert.True(t, report.Stopped)
}

// TestRunGuard_ErrorsBeforeAFatalfAreBothKept covers the shape AssertNoCredentialQueryFallback
// has: findings reported one at a time, then a fatal for an empty walk. Text carries both.
func TestRunGuard_ErrorsBeforeAFatalfAreBothKept(t *testing.T) {
	report := RunGuard(func(r Reporter) {
		r.Errorf("a.go:1: a finding")
		r.Fatalf("and then the walk covered nothing")
	})

	assert.Equal(t, []string{"a.go:1: a finding"}, report.Errors)
	assert.Equal(t, "and then the walk covered nothing", report.Fatal)
	assert.True(t, report.Stopped)
	assert.Equal(t, "a.go:1: a finding\nand then the walk covered nothing", report.Text())
}

// TestRunGuard_APanicIsReRaisedOnTheCallersGoroutine keeps a broken fixture legible. Left on the
// guard's own goroutine a panic takes the test binary down from somewhere the testing package
// cannot attribute, so the tier reports a crash with no test name against it.
func TestRunGuard_APanicIsReRaisedOnTheCallersGoroutine(t *testing.T) {
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		RunGuard(func(Reporter) { panic("the fixture tree is wrong") })
	}()

	require.NotNil(t, recovered, "the panic did not reach the caller")
	message, ok := recovered.(string)
	require.True(t, ok, "expected the re-raised panic to carry a string, got %T", recovered)
	assert.Contains(t, message, "the fixture tree is wrong")
	assert.Contains(t, message, "guard_test.go", "the original stack did not survive")
}

// TestRunGuard_TextOmitsAFatalThatWasNeverReached keeps Text from inventing a line. Fatal is only
// ever set alongside Stopped today, and this pins that Text reads Stopped rather than the string.
func TestRunGuard_TextOmitsAFatalThatWasNeverReached(t *testing.T) {
	report := GuardReport{Errors: []string{"one"}, Fatal: "never reached", Stopped: false}

	assert.Equal(t, "one", report.Text())
	assert.False(t, strings.Contains(report.Text(), "never reached"))
}
