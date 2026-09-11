package errs

// Seam 1: the exported surface of this package, held to the behaviour table the agreement for
// #279 rests on. The table is here rather than spread over the callers because every one of the
// call sites in the tree inherits it, and because the three properties it pins are invisible at a
// call site: the message text has to stay byte-identical to github.com/pkg/errors' so nothing
// that reads an error's text moves, errors.Is and errors.As have to traverse every wrapper, and
// an error tree has to carry exactly one stack however many constructors ran over it.
//
// The tests live in package errs, not errs_test, so the frame-count rows can read pcs directly
// and count the owners in a tree rather than inferring them from formatted output.
//
// Frame text is asserted by function name only. File paths and line numbers move with every edit
// above them, so asserting on those buys a test that fails for reasons that are not defects.

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- the failure the table is built on -------------------------------------------------------
//
// Three layers, each in a named function, so a frame assertion can say which layer captured the
// stack rather than only how many there were.

func dataLayer() error { return Wrap(sql.ErrConnDone, "unable to query database") }
func service() error   { return Wrap(dataLayer(), "unable to load the user") }

// origins, one per exported constructor, each ending in the constructor call so the first frame
// of whatever it produces is the helper itself.

func originNew() error       { return New("origin") }
func originErrorf() error    { return Errorf("origin %d", 1) }
func originWrap() error      { return Wrap(sql.ErrConnDone, "origin") }
func originWrapf() error     { return Wrapf(sql.ErrConnDone, "origin %d", 1) }
func originWithStack() error { return WithStack(sql.ErrConnDone) }
func originJoin() error      { return Join(errors.New("close failed"), errors.New("unlock failed")) }

// errBareSentinel and errStackedSentinel stand in for a package-level var declared each way.
// Both are package level, so errStackedSentinel's frames really are init's, which is the point.
var errBareSentinel = errors.New("bare sentinel")
var errStackedSentinel = buildStackedSentinel()

// noinline pins the frame the stacked sentinel records. Left to the compiler, the
// plain build inlines this into the package's synthesized init and the race build
// does not, and a test that names either frame is asserting an inlining decision.
//
//go:noinline
func buildStackedSentinel() error { return New("stacked sentinel") }

func raiseBareSentinel() error    { return WithStack(errBareSentinel) }
func raiseStackedSentinel() error { return WithStack(errStackedSentinel) }

func branchA() error { return New("branch a") }
func branchB() error { return New("branch b") }

// errorfOverBare is the case with no stack anywhere below the outer constructor, so the outer one
// is the one that captures. Named rather than inline because a closure's frame is reported as
// "TestX.funcN", which pins the position of the literal in the file instead of the rule.
func errorfOverBare() error { return Errorf("outer: %w", errors.New("bare")) }

// detail stands in for the wire-meaning types (customerrors.ErrorDetail and friends) that the
// tree matches on.
type detail struct{ code string }

func (d *detail) Error() string { return d.code }

// ---- helpers over the internals ---------------------------------------------------------------

// constructorNames are the functions of this package that must never appear in a captured stack:
// the frames belong to the caller, not to the machinery that recorded them.
var constructorNames = map[string]bool{
	"New": true, "Errorf": true, "Wrap": true, "Wrapf": true,
	"WithStack": true, "Join": true, "stack": true, "callers": true,
}

// stackOwners returns every withStack in the tree that carries frames, walking the same order
// owner does but without stopping at the first. Exactly one is the invariant this package sells.
func stackOwners(err error) []*withStack {
	var found []*withStack
	var walk func(error)
	walk = func(e error) {
		for e != nil {
			if ws, ok := e.(*withStack); ok && ws.pcs != nil {
				found = append(found, ws)
			}
			switch u := e.(type) {
			case interface{ Unwrap() error }:
				e = u.Unwrap()
			case interface{ Unwrap() []error }:
				for _, child := range u.Unwrap() {
					walk(child)
				}
				return
			default:
				return
			}
		}
	}
	walk(err)
	return found
}

// frameNames returns the short function name of each frame of ws, "originNew" rather than
// "github.com/leodip/goiabada/core/errs.originNew".
func frameNames(ws *withStack) []string {
	var names []string
	frames := runtime.CallersFrames(ws.pcs)
	for {
		f, more := frames.Next()
		names = append(names, shortFuncName(f.Function))
		if !more {
			break
		}
	}
	return names
}

func shortFuncName(full string) string {
	if i := strings.LastIndex(full, "/"); i >= 0 {
		full = full[i+1:]
	}
	if i := strings.Index(full, "."); i >= 0 {
		full = full[i+1:]
	}
	return full
}

// firstFrame is the deepest recorded frame of the tree's single owner, which is the function that
// called the constructor that captured.
func firstFrame(t *testing.T, err error) string {
	t.Helper()
	owners := stackOwners(err)
	require.Len(t, owners, 1, "expected exactly one stack owner in the tree")
	names := frameNames(owners[0])
	require.NotEmpty(t, names)
	return names[0]
}

// firstFrameOfOwner reads the frame the printed tree attributes itself to, which under a join of
// two separately built branches is not the same question as "the tree's only owner".
func firstFrameOfOwner(t *testing.T, err error) string {
	t.Helper()
	ws := owner(err)
	require.NotNil(t, ws)
	names := frameNames(ws)
	require.NotEmpty(t, names)
	return names[0]
}

// plusV is %+v with the message stripped, so what is left is the frame block alone. The message
// may itself hold newlines under a join, which is why this trims rather than splitting on the
// first newline.
func plusV(err error) string {
	return strings.TrimPrefix(fmt.Sprintf("%+v", err), err.Error())
}

// ---- the chain --------------------------------------------------------------------------------

func TestChain_MessageTextIsIdenticalToPkgErrors(t *testing.T) {
	err := WithStack(service())

	// The exact string github.com/pkg/errors' Wrap produced for the same three layers. Five
	// existing tests in the tree assert on Wrap-shaped text; this is what keeps them true.
	assert.Equal(t,
		"unable to load the user: unable to query database: sql: connection is already closed",
		err.Error())
	assert.Equal(t, err.Error(), fmt.Sprintf("%v", err), "%%v prints the message only")
	assert.Equal(t, err.Error(), fmt.Sprintf("%s", err), "%%s prints the message only")
}

func TestChain_CarriesExactlyOneStackAndItIsTheOrigin(t *testing.T) {
	err := WithStack(service())

	owners := stackOwners(err)
	require.Len(t, owners, 1,
		"pkg/errors captured a stack at every call; the whole point of this package is that it does not")

	names := frameNames(owners[0])
	assert.Equal(t, "dataLayer", names[0], "the deepest layer owns the stack")
	assert.Contains(t, names, "service", "and the layers above it are in the same one")

	for _, name := range names {
		assert.False(t, constructorNames[name],
			"a frame names this package's own %s; the stack belongs to the caller", name)
	}

	out := fmt.Sprintf("%+v", err)
	require.True(t, strings.HasPrefix(out, err.Error()), "%%+v opens with the message")
	assert.Less(t, strings.Index(out, "dataLayer"), strings.Index(out, "service"),
		"frames print deepest first, which is pkg/errors' layout")
	assert.Equal(t, 1, strings.Count(out, ".dataLayer\n"), "one stack, printed once")
}

func TestChain_ErrorsIsTraversesEveryWrapper(t *testing.T) {
	assert.True(t, errors.Is(WithStack(service()), sql.ErrConnDone),
		"Wrap, then Wrap, then WithStack, and the sentinel is still reachable")
}

func TestChain_ErrorsAsFindsATypedErrorABareAssertionMisses(t *testing.T) {
	wrapped := Wrap(&detail{code: "invalid_grant"}, "validating")

	var d *detail
	require.True(t, errors.As(wrapped, &d))
	assert.Equal(t, "invalid_grant", d.code)

	_, bare := wrapped.(*detail)
	assert.False(t, bare,
		"the bare assertion the tree uses at 55 sites today is what decision 6 retires")
}

func TestNilIn_NilOut(t *testing.T) {
	// Call sites that return Wrap(err, ...) unconditionally rely on this.
	assert.Nil(t, Wrap(nil, "x"))
	assert.Nil(t, Wrapf(nil, "x %d", 1))
	assert.Nil(t, WithStack(nil))
	assert.Nil(t, Join(nil, nil))
	assert.Nil(t, Join())
}

func TestNew_AndErrorf_Messages(t *testing.T) {
	assert.Equal(t, "plain", New("plain").Error())
	assert.Equal(t, "reading x: 7", Errorf("reading %s: %d", "x", 7).Error())
	assert.Equal(t, "reading x: sql: no rows in result set",
		Wrapf(sql.ErrNoRows, "reading %s", "x").Error())
}

func TestErrorf_WithVerbWKeepsTheChain(t *testing.T) {
	assert.True(t, errors.Is(Errorf("ctx: %w", sql.ErrNoRows), sql.ErrNoRows))
}

func TestWithStack_KeepsSentinelIdentity(t *testing.T) {
	sentinel := errors.New("sentinel")
	stacked := WithStack(sentinel)

	assert.True(t, errors.Is(stacked, sentinel))
	assert.Equal(t, "sentinel", stacked.Error())
	assert.Same(t, stacked, WithStack(stacked), "already stacked, so WithStack is the identity")
}

// Why a package-level sentinel keeps stdlib errors.New, stated as behaviour rather than as the
// lint's prose. A sentinel built with New already carries a stack, so WithStack at the site that
// raises it is the identity and records nothing: the frames stay the ones captured wherever the
// sentinel was constructed, which for a package-level var is init.
//
// This is not hypothetical. #279's core sweep moved four sentinels onto New, and
// signing_key_rotator.go then raised the same one from two distinct compare-and-set failures with
// an identical stack, so a log could not tell them apart. Both rows are here because it is the
// contrast that carries the rule; the lint's package-level check is what keeps it (#279 decision 5).
func TestWithStack_OnlyRecordsTheRaisingSiteForABareSentinel(t *testing.T) {
	t.Run("a stdlib sentinel records where it was raised", func(t *testing.T) {
		err := raiseBareSentinel()

		owners := stackOwners(err)
		require.Len(t, owners, 1)
		assert.Equal(t, "raiseBareSentinel", frameNames(owners[0])[0])
	})

	t.Run("a sentinel built through New records where it was built", func(t *testing.T) {
		err := raiseStackedSentinel()

		owners := stackOwners(err)
		require.Len(t, owners, 1)
		// The trace was captured when the package initialised, so it starts at the builder
		// and runs down the initializing goroutine; the raising site appears nowhere in it.
		// That is the masquerade in one frame.
		assert.Equal(t, "buildStackedSentinel", frameNames(owners[0])[0],
			"WithStack is the identity here, so the raising site is nowhere in the trace")
		assert.NotContains(t, frameNames(owners[0]), "raiseStackedSentinel")
	})
}

// ---- the caller row: one per export ------------------------------------------------------------

func TestEveryConstructor_CapturesItsCallerAndNotItself(t *testing.T) {
	rows := []struct {
		name   string
		origin func() error
	}{
		{"New", originNew},
		{"Errorf", originErrorf},
		{"Wrap", originWrap},
		{"Wrapf", originWrapf},
		{"WithStack", originWithStack},
		{"Join", originJoin},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			err := row.origin()

			owners := stackOwners(err)
			require.Len(t, owners, 1)
			names := frameNames(owners[0])

			assert.Equal(t, "origin"+row.name, names[0],
				"the first frame is the constructor's caller")
			for _, name := range names {
				assert.False(t, constructorNames[name],
					"frame %q is inside this package; the skip is off by one", name)
			}
		})
	}
}

// ---- the inherited-stack rows ------------------------------------------------------------------
//
// Each of these puts something over an error that is already stacked. The tree must print the
// origin's frames, keep its message, keep every errors.Is match, and never emit a synthetic ":0"
// frame from a wrapper that owns none.

func TestInheritedStack_TheOriginKeepsTheOnlyStack(t *testing.T) {
	rows := []struct {
		name    string
		build   func() error
		message string
	}{
		{
			name:    "Errorf with %w over a stacked error",
			build:   func() error { return Errorf("load failed: %w", dataLayer()) },
			message: "load failed: unable to query database: sql: connection is already closed",
		},
		{
			name:    "WithStack over a stdlib wrapper hiding a stacked error",
			build:   func() error { return WithStack(fmt.Errorf("load failed: %w", dataLayer())) },
			message: "load failed: unable to query database: sql: connection is already closed",
		},
		{
			name:    "WithStack over errors.Join(stacked, bare)",
			build:   func() error { return WithStack(errors.Join(dataLayer(), errors.New("cleanup failed"))) },
			message: "unable to query database: sql: connection is already closed\ncleanup failed",
		},
		{
			name:    "Wrap over errors.Join(stacked, bare)",
			build:   func() error { return Wrap(errors.Join(dataLayer(), errors.New("cleanup failed")), "migration") },
			message: "migration: unable to query database: sql: connection is already closed\ncleanup failed",
		},
		{
			name:    "Errorf with two %w, the first stacked",
			build:   func() error { return Errorf("apply failed: %w; %w", dataLayer(), errors.New("dirty marker")) },
			message: "apply failed: unable to query database: sql: connection is already closed; dirty marker",
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			err := row.build()

			assert.Equal(t, row.message, err.Error())
			assert.Equal(t, "dataLayer", firstFrame(t, err),
				"the wrapper prints the origin's frames, not its own")
			assert.True(t, errors.Is(err, sql.ErrConnDone), "the chain still unwraps")

			frames := plusV(err)
			assert.NotContains(t, frames, ":0",
				"a wrapper that owns no frames must print none, never a synthetic frame")
			assert.Contains(t, frames, "dataLayer")
		})
	}
}

func TestInheritedStack_JoinedBranchesAreStillMatchable(t *testing.T) {
	wrapped := Wrap(errors.Join(dataLayer(), errors.New("cleanup failed")), "migration")
	assert.True(t, errors.Is(wrapped, sql.ErrConnDone), "the left branch of a wrapped join")

	both := Join(Wrap(&detail{code: "invalid_grant"}, "validating"), dataLayer())
	var d *detail
	assert.True(t, errors.As(both, &d), "errors.As reaches a typed error in the left branch")
	assert.True(t, errors.Is(both, sql.ErrConnDone), "and errors.Is the sentinel in the right one")
}

// ---- the ownership row -------------------------------------------------------------------------

func TestJoin_TheLeftmostStackedBranchOwnsTheTreesOneStack(t *testing.T) {
	joined := Join(branchA(), branchB())

	owners := stackOwners(joined)
	require.Len(t, owners, 2, "each branch was constructed separately, so each carries frames")

	out := plusV(joined)
	assert.Contains(t, out, "branchA", "the leftmost stacked branch is the one printed")
	assert.NotContains(t, out, "branchB",
		"one stack per log line, however many failures were joined into it")
	assert.Equal(t, "branchA", firstFrameOfOwner(t, joined))
	assert.Equal(t, "branch a\nbranch b", joined.Error())
}

func TestJoin_OfBareErrorsIsStackedAtItsOrigin(t *testing.T) {
	ours := originJoin()
	assert.Equal(t, "originJoin", firstFrame(t, ours),
		"errs.Join records where the failures were joined")
	assert.Equal(t, "close failed\nunlock failed", ours.Error())

	// The contrast, and the reason Join is exported at all: a stdlib join reaches the writer with
	// no frames, so the writer's WithStack records the writer as the origin.
	theirs := WithStack(errors.Join(errors.New("close failed"), errors.New("unlock failed")))
	assert.Equal(t, "TestJoin_OfBareErrorsIsStackedAtItsOrigin", firstFrame(t, theirs))
}

// ---- the frame-count row -----------------------------------------------------------------------

func TestOneStackUnderEveryPairOfConstructors(t *testing.T) {
	origins := []struct {
		name string
		fn   func() error
	}{
		{"New", originNew},
		{"Errorf", originErrorf},
		{"Wrap", originWrap},
		{"Wrapf", originWrapf},
		{"WithStack", originWithStack},
		{"Join", originJoin},
	}
	outers := []struct {
		name string
		fn   func(error) error
	}{
		{"Wrap", func(e error) error { return Wrap(e, "outer") }},
		{"Wrapf", func(e error) error { return Wrapf(e, "outer %d", 1) }},
		{"ErrorfW", func(e error) error { return Errorf("outer: %w", e) }},
		{"WithStack", WithStack},
		{"Join", func(e error) error { return Join(e, errors.New("bare")) }},
		{"ErrorfTwoW", func(e error) error { return Errorf("outer: %w; %w", e, errors.New("bare")) }},
	}

	for _, origin := range origins {
		for _, outer := range outers {
			t.Run(origin.name+">"+outer.name, func(t *testing.T) {
				err := outer.fn(origin.fn())

				owners := stackOwners(err)
				require.Len(t, owners, 1,
					"the wrapper captured a second stack; %%+v would print the same failure twice")
				assert.Equal(t, "origin"+origin.name, frameNames(owners[0])[0],
					"and the one stack is the innermost constructor's caller")
			})
		}
	}

	// The other half of the rule: an outer constructor over a tree with no stack anywhere is the
	// one that captures, and it captures at its own caller.
	t.Run("ErrorfW over an unstacked inner", func(t *testing.T) {
		assert.Equal(t, "errorfOverBare", firstFrame(t, errorfOverBare()))
	})
}

// ---- what slog prints ----------------------------------------------------------------------------
//
// Decision 3 is that this package has no LogValue, so slog's own formatting decides: the default
// handler, which is the one both servers run, renders an error attribute with %+v and therefore
// carries the stack, and a JSON handler renders Error() and therefore carries the message. Both
// halves are asserted, because the decision's whole content is that neither was overridden.

func TestSlog_DefaultHandlerPrintsTheStackInTheErrorAttribute(t *testing.T) {
	var buf bytes.Buffer
	// slog's default handler forwards to the log package, so this is where its output is
	// captured. Restored on the way out; nothing here calls slog.SetDefault.
	previousFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(previousFlags)
	})

	slog.Error("database error", "error", WithStack(service()))

	out := buf.String()
	assert.Contains(t, out, "unable to load the user: unable to query database")
	assert.Contains(t, out, "dataLayer", "the stack travels in the error attribute")
	assert.Equal(t, 1, strings.Count(out, ".dataLayer"), "and it travels exactly once")
}

func TestSlog_JSONHandlerPrintsTheMessageOnly(t *testing.T) {
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Error("database error", "error", WithStack(service()))

	out := buf.String()
	assert.Contains(t, out, `"error":"unable to load the user: unable to query database: sql: connection is already closed"`)
	assert.NotContains(t, out, "dataLayer",
		"a JSON handler renders Error(), which is slog's convention and the moment to revisit")
}
