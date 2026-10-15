package guard

// The rule table AssertNoStaleDeferredBodyCloses enforces, over fixture trees written by
// writeGoFile.
//
// The four shapes a response body close can take: the stale closure over a variable a later
// statement of the same function assigns, the fixed shape that hands the closure its own value,
// the direct defer that binds its receiver when it runs, and the shadow -- a redeclaration of
// the same name in a nested block, which declares a new variable the closure never reads and is
// the one finding of difference between this walk and the scan in #591. A file that does not
// parse is excluded from the walk, as it is for every other guard.

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

// staleCloseTree writes the four shapes together, plus one file that does not parse.
func staleCloseTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeGoFile(t, root, "integration/stale_chain_test.go", staleChainSource)
	writeGoFile(t, root, "integration/fixed_test.go", fixedSource)
	writeGoFile(t, root, "integration/direct_test.go", directSource)
	writeGoFile(t, root, "integration/shadow_test.go", shadowSource)
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

	assert.Equal(t, 4, files, "the four parseable fixtures, and not the broken one")
	require.Len(t, stale, 2, "the two defers before a reassignment, and not the one after the last")
	assert.Equal(t, staleClose{
		file:         "integration/stale_chain_test.go",
		line:         10,
		variable:     "resp",
		reassignedAt: 11,
	}, stale[0])
	assert.Equal(t, staleClose{
		file:         "integration/stale_chain_test.go",
		line:         12,
		variable:     "resp",
		reassignedAt: 13,
	}, stale[1])
}

// TestStaleClose_ACleanTreeReportsNothing is the other direction, and it is what keeps the case
// above from passing for the wrong reason: a tree of the fixed, the direct and the shadow shapes
// reaches files and reports nothing.
func TestStaleClose_ACleanTreeReportsNothing(t *testing.T) {
	root := t.TempDir()
	writeGoFile(t, root, "integration/fixed_test.go", fixedSource)
	writeGoFile(t, root, "integration/direct_test.go", directSource)
	writeGoFile(t, root, "integration/shadow_test.go", shadowSource)

	stale, files, err := findStaleDeferredBodyCloses(root)
	require.NoError(t, err)

	assert.Equal(t, 3, files)
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
