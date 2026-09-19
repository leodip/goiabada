package testutil

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Every tree-wide guard in this repository splits in two. A finder walks the tree and returns what
// it found; a reporting half turns those findings into t.Errorf, and turns a walk that reached
// nothing into t.Fatalf. The rule tests have always exercised the finders against fixture trees and
// asserted on their return values. The reporting half was reached only by the real callers, and
// every one of those walks the real tree, which is clean and passes.
//
// So nothing anywhere observed a guard failing. A defect in the handful of lines that report -- or
// a future edit to them -- disabled the guard across every module with nothing going red.
// Demonstrated on 8883642d: replacing `if len(dead) == 0 { return }` with `if true { return }` in
// dead_interface_lint.go, so the guard can never report a dead interface, left the entire core
// module tier green. The equivalent blinding of credential_read_lint.go survived its own rule test
// likewise, and that guard is the sole enforcement of CLAUDE.md pattern 5, which exists to stop a
// bearer token or a password reaching a proxy log.
//
// Reporter and RunGuard close that. Each guard's reporting half takes a Reporter rather than a
// *testing.T, the exported Assert wrapper passes the real one, and a rule test passes a recorder
// and asserts on what the guard said.

// Reporter is the whole of *testing.T that a guard uses to fail. Three methods is not a
// minimization for its own sake: it is the measured surface, since the reporting halves in this
// package between them call Helper, Errorf and Fatalf and nothing else.
//
// It is an interface rather than a testing.TB parameter because testing.TB cannot be implemented
// outside the testing package -- it carries an unexported method precisely to prevent it -- so
// there is no recording fake that satisfies it. It is exported rather than internal because six
// of the sixteen guards live outside this package, in the _test.go files of three auth server
// directories -- internal/audit, internal/data and internal/handlers/apihandlers -- and they report
// through the same harness. Recount with
// `git grep -n 'func assert.*\(r Reporter\|r testutil\.Reporter\)' -- '*.go'` rather than trusting
// the number: #333, #338 and #354 each moved or added a guard without touching this sentence, which
// is how it came to be wrong on the path and on both counts at once (#359).
//
// *testing.T satisfies it, so no exported guard signature changes and no caller moves.
type Reporter interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// GuardReport is what one guard said when it was run against a fixture tree.
type GuardReport struct {
	// Errors holds one entry per Errorf, formatted, in the order the guard reported them.
	Errors []string
	// Fatal is the Fatalf message, empty when the guard never reached one.
	Fatal string
	// Stopped records that a Fatalf ended the run. It is separate from Fatal being non-empty
	// because the distinction it makes is the one that matters: a guard that formats a message and
	// then keeps going has not stopped, and a recorder that quietly let it continue would report a
	// clean pass on a tree that should have been fatal.
	Stopped bool
}

// Failed reports whether the guard failed the test at all, by either route.
func (g GuardReport) Failed() bool {
	return len(g.Errors) > 0 || g.Stopped
}

// Text renders everything the guard said as one string, which is what a rule test matches against
// when it cares that a particular file, line or explanation reached the reader. It mirrors
// SlogCapture.Text for the same reason: an assertion on rendered output is the only one that
// catches a message whose arguments are in the wrong order.
func (g GuardReport) Text() string {
	lines := make([]string, 0, len(g.Errors)+1)
	lines = append(lines, g.Errors...)
	if g.Stopped {
		lines = append(lines, g.Fatal)
	}
	return strings.Join(lines, "\n")
}

// RunGuard runs one guard's reporting half against a recording Reporter and returns what it
// reported. The guard is handed the recorder, so a rule test writes:
//
//	report := testutil.RunGuard(func(r testutil.Reporter) {
//	        assertNoDeadInterfaces(r, root, "mod/handlers")
//	})
//	assert.True(t, report.Failed())
//
// It runs the guard on its own goroutine because that is the only way to reproduce what Fatalf
// means. The real one is Logf followed by FailNow, and FailNow is runtime.Goexit: the calling
// goroutine stops there, its deferred functions run, and nothing after the call executes. A
// recorder that merely recorded the message and returned would let the guard run on through code
// its author had already decided was unreachable, which is a harness that lies in the direction
// that matters -- it would pass a guard whose fatal path falls through into a nil dereference.
// Goexit on a goroutine of its own reproduces it exactly, defers included.
//
// A panic inside the guard is caught and re-raised on the caller's goroutine, carrying the original
// stack. Left alone it would take the whole test binary down from a goroutine the testing package
// cannot attribute, so the tier would report a crash with no test name against it.
func RunGuard(fn func(Reporter)) GuardReport {
	rec := &guardRecorder{}
	done := make(chan struct{})

	go func() {
		defer close(done)
		defer func() {
			if p := recover(); p != nil {
				rec.panicked = p
				rec.stack = debug.Stack()
			}
		}()
		fn(rec)
		rec.returned = true
	}()
	// The receive happens after the close, which happens after every write above, so the reads
	// below are ordered behind them and the race detector agrees.
	<-done

	if rec.panicked != nil {
		panic(fmt.Sprintf("the guard under RunGuard panicked: %v\n\n%s", rec.panicked, rec.stack))
	}
	return GuardReport{Errors: rec.errors, Fatal: rec.fatal, Stopped: !rec.returned}
}

// guardRecorder is the Reporter a guard is handed under RunGuard. It is written by exactly one
// goroutine, the one RunGuard starts, and read only after that goroutine has finished, so it needs
// no lock.
type guardRecorder struct {
	errors   []string
	fatal    string
	returned bool
	panicked any
	stack    []byte
}

// Helper is a no-op. What it does on a *testing.T is adjust which line number the failure is
// attributed to, and a recording reporter attributes nothing.
func (g *guardRecorder) Helper() {}

func (g *guardRecorder) Errorf(format string, args ...any) {
	g.errors = append(g.errors, fmt.Sprintf(format, args...))
}

func (g *guardRecorder) Fatalf(format string, args ...any) {
	g.fatal = fmt.Sprintf(format, args...)
	runtime.Goexit()
}
