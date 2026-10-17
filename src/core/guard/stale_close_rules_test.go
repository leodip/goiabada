package guard

// The rule table AssertNoStaleDeferredBodyCloses enforces, over fixture trees written by
// writeGoFile.
//
// The four shapes a response body close can take: the stale closure over a variable a later
// statement of the same function assigns, the fixed shape that hands the closure its own value,
// the direct defer that binds its receiver when it runs, and the shadow -- a redeclaration of
// the same name in a nested block, which declares a new variable the closure never reads and is
// the one finding of difference between this walk and the scan in #591. Beside them, the three
// other ways a statement reaches the variable after the defer has run -- the next iteration of a
// loop around it, a range clause assigning with `=`, and a nested closure -- and the two units a
// function literal makes. A file that does not parse is excluded from the walk, as it is for
// every other guard.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// staleChainSource is the shape #591 measured: two closures registered before the reassignments
// that stale them, and one after the last, which is clean. The defer on line 10 is staled by the
// assignment on line 11, the defer on line 12 by the assignment on line 13, and the defer on line
// 14 has no assignment after it.
const staleChainSource = `package ceremony

import "net/http"

func Walk(c *http.Client, url, url2 string) {
	resp, err := c.Get(url)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(c, url2)
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(c, url2)
	defer func() { _ = resp.Body.Close() }()
}
`

// fixedSource hands each closure its own value, the shape bfbaedd8 fixed the one instance the
// review of #582 found, so the reassignment on the line after the defer stales nothing.
const fixedSource = `package fixed

import "net/http"

func Walk(c *http.Client, url, url2 string) {
	resp, err := c.Get(url)
	if err != nil {
		return
	}
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	resp = loadPage(c, url2)
}
`

// directSource defers the method value itself, which binds its receiver when the defer statement
// runs, so the reassignment after it does not reach the close.
const directSource = `package direct

import "net/http"

func Walk(c *http.Client, url, url2 string) {
	resp, err := c.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	resp = loadPage(c, url2)
}
`

// shadowSource redeclares the name inside the loop body, a new variable in a new scope, which is
// what the object identity of the reassignment excludes: the closure reads the outer variable,
// and no statement assigns that one after the defer. This is the shape the scan in #591 counted
// at api_client_administrative_scopes_test.go:259 and this walk does not.
const shadowSource = `package shadow

import "net/http"

func Walk(c *http.Client, url string, n int) {
	resp, err := c.Get(url)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	for i := 0; i < n; i++ {
		resp, err := c.Get(url)
		_ = resp
		_ = err
	}
}
`

// loopSource registers a closure on every iteration over a variable declared outside the loop.
// The assignment on line 9 comes before the defer on line 13 in the source, but the next
// iteration runs it after, so every response but the last is left unclosed.
const loopSource = `package loop

import "net/http"

func Walk(c *http.Client, urls []string) {
	var resp *http.Response
	var err error
	for _, u := range urls {
		resp, err = c.Get(u)
		if err != nil {
			return
		}
		defer func() { _ = resp.Body.Close() }()
	}
}
`

// forLoopSource is loopSource's counted retry loop: the assignment on line 9 is the for
// statement's body, and its next iteration runs it after the defer on line 13.
const forLoopSource = `package forloop

import "net/http"

func Walk(c *http.Client, url string, limit int) {
	var resp *http.Response
	var err error
	for attempt := 0; attempt < limit; attempt++ {
		resp, err = c.Get(url)
		if err != nil {
			return
		}
		defer func() { _ = resp.Body.Close() }()
	}
}
`

// cleanupLocalSource declares its response inside the deferred literal, which closes the one
// response it made and captures nothing: the declaration on line 7 is the literal's own, not a
// reassignment of a variable it closes over.
const cleanupLocalSource = `package cleanuplocal

import "net/http"

func Walk(c *http.Client, url string) {
	defer func() {
		resp, err := c.Get(url)
		if err != nil {
			return
		}
		_ = resp.Body.Close()
	}()
}
`

// loopDefineSource is the clean twin of loopSource: the `:=` inside the body declares a new
// variable on each iteration, so each closure reads its own.
const loopDefineSource = `package loopdefine

import "net/http"

func Walk(c *http.Client, urls []string) {
	for _, u := range urls {
		resp, err := c.Get(u)
		if err != nil {
			return
		}
		defer func() { _ = resp.Body.Close() }()
	}
}
`

// rangeAssignSource reassigns the variable through a range clause with `=`, on line 11, after the
// defer on line 10: a range clause is an assignment no *ast.AssignStmt spells.
const rangeAssignSource = `package rangeassign

import "net/http"

func Walk(c *http.Client, url string, resps []*http.Response) {
	resp, err := c.Get(url)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	for _, resp = range resps {
	}
}
`

// closureSource reassigns the outer variable inside a subtest's callback, on line 16, which runs
// before the test returns and so before the defer on line 14 does.
const closureSource = `package closure

import (
	"net/http"
	"testing"
)

func TestWalk(t *testing.T) {
	c := &http.Client{}
	resp, err := c.Get("a")
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	t.Run("next", func(t *testing.T) {
		resp, err = c.Get("b")
	})
}
`

// closureUnitSource holds the stale chain inside a subtest's callback, a function unit of its
// own: the defer on line 15 is staled by the assignment on line 16, and is reported once, from
// the callback's unit and not again from the enclosing function's.
const closureUnitSource = `package closureunit

import (
	"net/http"
	"testing"
)

func TestWalk(t *testing.T) {
	c := &http.Client{}
	t.Run("chain", func(t *testing.T) {
		resp, err := c.Get("a")
		if err != nil {
			return
		}
		defer func() { _ = resp.Body.Close() }()
		resp = loadPage(c, "b")
	})
}
`

// closureThenOuterSource defers inside a subtest's callback, which runs when the callback
// returns, before the enclosing function reassigns the variable after it: the callback's unit
// borrows no statement of the enclosing one.
const closureThenOuterSource = `package closurethenouter

import (
	"net/http"
	"testing"
)

func TestWalk(t *testing.T) {
	c := &http.Client{}
	resp, err := c.Get("a")
	if err != nil {
		return
	}
	t.Run("close", func(t *testing.T) {
		defer func() { _ = resp.Body.Close() }()
	})
	resp = loadPage(c, "b")
}
`

// staleCloseTree writes every shape together, plus one file that does not parse.
func staleCloseTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeGoFile(t, root, "integration/stale_chain_test.go", staleChainSource)
	writeGoFile(t, root, "integration/fixed_test.go", fixedSource)
	writeGoFile(t, root, "integration/direct_test.go", directSource)
	writeGoFile(t, root, "integration/shadow_test.go", shadowSource)
	writeGoFile(t, root, "integration/loop_test.go", loopSource)
	writeGoFile(t, root, "integration/for_loop_test.go", forLoopSource)
	writeGoFile(t, root, "integration/cleanup_local_test.go", cleanupLocalSource)
	writeGoFile(t, root, "integration/loop_define_test.go", loopDefineSource)
	writeGoFile(t, root, "integration/range_assign_test.go", rangeAssignSource)
	writeGoFile(t, root, "integration/closure_test.go", closureSource)
	writeGoFile(t, root, "integration/closure_unit_test.go", closureUnitSource)
	writeGoFile(t, root, "integration/closure_then_outer_test.go", closureThenOuterSource)
	writeGoFile(t, root, "integration/broken.go", unparseableSource)
	return root
}

// TestStaleClose_TheRuleTable covers what the walk does with each of the shapes a deferred
// response body close can take. The unparseable file is neither a finding nor a file the walk
// reached a verdict on, so a tree of nothing but broken files reads as an empty walk rather than
// a clean one.
func TestStaleClose_TheRuleTable(t *testing.T) {
	root := staleCloseTree(t)

	stale, files, err := findStaleDeferredBodyCloses(root)
	require.NoError(t, err)

	assert.Equal(t, 12, files, "the twelve parseable fixtures, and not the broken one")
	assert.Equal(t, []staleClose{
		{file: "integration/closure_test.go", line: 14, variable: "resp", reassignedAt: 16},
		{file: "integration/closure_unit_test.go", line: 15, variable: "resp", reassignedAt: 16},
		{file: "integration/for_loop_test.go", line: 13, variable: "resp", reassignedAt: 9},
		{file: "integration/loop_test.go", line: 13, variable: "resp", reassignedAt: 9},
		{file: "integration/range_assign_test.go", line: 10, variable: "resp", reassignedAt: 11},
		{file: "integration/stale_chain_test.go", line: 10, variable: "resp", reassignedAt: 11},
		{file: "integration/stale_chain_test.go", line: 12, variable: "resp", reassignedAt: 13},
	}, stale, "each stale defer once, and not the defer after the last reassignment, the per-iteration "+
		"`:=`, the callback's defer the enclosing function reassigns after, or the cleanup's own response")
}

// TestStaleClose_ACleanTreeReportsNothing is the other direction, and it is what keeps the case
// above from passing for the wrong reason: a tree of the fixed, the direct, the shadow, the
// per-iteration `:=`, the callback-unit and the cleanup-local shapes reaches files and reports
// nothing.
func TestStaleClose_ACleanTreeReportsNothing(t *testing.T) {
	root := t.TempDir()
	writeGoFile(t, root, "integration/fixed_test.go", fixedSource)
	writeGoFile(t, root, "integration/direct_test.go", directSource)
	writeGoFile(t, root, "integration/shadow_test.go", shadowSource)
	writeGoFile(t, root, "integration/loop_define_test.go", loopDefineSource)
	writeGoFile(t, root, "integration/closure_then_outer_test.go", closureThenOuterSource)
	writeGoFile(t, root, "integration/cleanup_local_test.go", cleanupLocalSource)

	stale, files, err := findStaleDeferredBodyCloses(root)
	require.NoError(t, err)

	assert.Equal(t, 6, files)
	assert.Empty(t, stale)

	report := Run(func(r Reporter) { assertNoStaleDeferredBodyCloses(r, root) })
	assert.False(t, report.Failed(), "a clean tree failed the guard: %s", report.Text())
}

// TestStaleClose_AStaleTreeFails drives the reporting half, which until this harness landed was
// reached only by the real callers, and so never observed failing.
func TestStaleClose_AStaleTreeFails(t *testing.T) {
	root := t.TempDir()
	writeGoFile(t, root, "integration/stale_chain_test.go", staleChainSource)

	report := Run(func(r Reporter) { assertNoStaleDeferredBodyCloses(r, root) })

	require.True(t, report.Failed())
	assert.False(t, report.Stopped, "a stale defer is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "integration/stale_chain_test.go:10")
	assert.Contains(t, report.Text(), "is reassigned at line 11")
	assert.Contains(t, report.Text(), "defer func(r *http.Response) { _ = r.Body.Close() }(resp)")
}

// TestStaleClose_AnEmptyTreeStopsTheGuard covers the walk that reached nothing, the one way a
// guard like this fails silently in the direction that matters: a tree with nothing to read
// would otherwise pass vacuously, and the reader would never learn the walk was broken.
func TestStaleClose_AnEmptyTreeStopsTheGuard(t *testing.T) {
	root := t.TempDir()

	report := Run(func(r Reporter) { assertNoStaleDeferredBodyCloses(r, root) })

	require.True(t, report.Stopped, "an empty tree must stop the guard, not pass it")
	assert.Contains(t, report.Fatal, "walked no Go files under")
}
