package testutil

// Seam 9 of #433: the rule AssertContextValuesThroughAccessors enforces, over fixture modules
// written into a temp tree and walked through the same functions the real caller uses.
//
// The real caller walks a clean tree -- #433 left no raw read outside internal/reqctx but the
// rate limiter's exempted one -- so it passes identically whether the rule still fires or has
// quietly stopped resolving anything. Every fixture below is a shape the auth server had, or one
// that would make the walk answer by spelling rather than by type.

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const contextFixtureAccessor = `package reqctx

import "context"

type key int

const settingsKey key = iota

func WithSettings(ctx context.Context, s string) context.Context {
	return context.WithValue(ctx, settingsKey, s)
}

func SettingsFrom(ctx context.Context) (string, bool) {
	s, ok := ctx.Value(settingsKey).(string)
	return s, ok
}
`

// contextFixtureLimiter is the rate limiter's shape: a private key written and read in one file,
// the read through r.Context(), which resolves only because net/http is read from source.
const contextFixtureLimiter = `package limiter

import (
	"context"
	"net/http"
)

type reservationKey struct{}

func Reserve(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), reservationKey{}, 1))
}

func Reservation(r *http.Request) (int, bool) {
	n, ok := r.Context().Value(reservationKey{}).(int)
	return n, ok
}
`

// contextFixtureClean holds everything that spells Value and is not a context read: a zero-argument
// Value on a database/sql type, a one-argument Value on a type of its own package, and the
// accessors' own names. None of them is a site.
const contextFixtureClean = `package handlers

import (
	"context"
	"database/sql"

	"example.com/mod/reqctx"
)

type table struct{}

func (table) Value(k string) string { return k }

func Clean(ctx context.Context) string {
	var n sql.NullString
	_, _ = n.Value()
	ctx = reqctx.WithSettings(ctx, "s")
	s, _ := reqctx.SettingsFrom(ctx)
	return table{}.Value(s)
}
`

// contextFixtureCleanTest is a test file reading a raw value, which the rule does not walk.
const contextFixtureCleanTest = `package handlers

import (
	"context"
	"testing"
)

func TestClean(t *testing.T) {
	_ = context.WithValue(context.Background(), "subject", "x").Value("subject")
}
`

// contextFixtureRaw carries every refused shape, one per line, each marked so the table can name it.
const contextFixtureRaw = `package handlers

import (
	"context"
	stdctx "context"
	"net/http"

	"example.com/mod/other"
)

type wrapped struct {
	context.Context
}

func Raw(ctx context.Context, r *http.Request) {
	_ = ctx.Value("subject") // site:plain-read
	_ = context.WithValue(ctx, "subject", "x") // site:plain-write
	_ = stdctx.WithValue(ctx, "k", 1) // site:aliased-write
	_ = r.Context().Value("k") // site:request-read
	_ = wrapped{ctx}.Value("k") // site:embedded-read
	read := ctx.Value // site:method-value
	_ = read
	_ = other.Make().Value("k") // site:unresolved
}
`

// contextFixtureOther is a package the importer stubs, so a value of its type is unresolvable.
const contextFixtureOther = `package other

import "context"

func Make() context.Context { return context.Background() }
`

// contextFixtureModule writes the passing tree: an accessor package, an exempted file and a
// package that only looks like it reads a context.
func contextFixtureModule(t *testing.T, root string) {
	t.Helper()

	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")
	writeFixture(t, root, "mod/reqctx/reqctx.go", contextFixtureAccessor)
	writeFixture(t, root, "mod/limiter/limiter.go", contextFixtureLimiter)
	writeFixture(t, root, "mod/handlers/clean.go", contextFixtureClean)
	writeFixture(t, root, "mod/handlers/clean_test.go", contextFixtureCleanTest)
}

var contextFixtureExemptions = []ContextValueExemption{
	{File: "limiter/limiter.go", Reason: "the reservation key is private to the limiter"},
}

// lineOf finds the line of src carrying the marker comment, so a table row names a line without
// hard-coding a number the fixture's next edit would silently shift.
func lineOf(t *testing.T, src, marker string) int {
	t.Helper()
	for i, line := range strings.Split(src, "\n") {
		if strings.HasSuffix(line, "// site:"+marker) {
			return i + 1
		}
	}
	t.Fatalf("no line marked %s", marker)
	return 0
}

func contextFindingNames(findings []contextValueFinding) []string {
	names := make([]string, 0, len(findings))
	for _, f := range findings {
		names = append(names, f.file+":"+strconv.Itoa(f.line)+" "+f.what)
	}
	return names
}

func TestContextValues_ThePassingTreeReportsNothing(t *testing.T) {
	root := t.TempDir()
	contextFixtureModule(t, root)

	walk, err := findContextValueSites(root, "mod", "reqctx", contextFixtureExemptions)
	require.NoError(t, err)

	assert.Empty(t, walk.findings)
	assert.Empty(t, walk.blocked)
	assert.Empty(t, walk.problems)
	// The accessor's write and read, and the limiter's write and read. The test file's two are
	// not walked, and nothing in clean.go is a site.
	assert.Equal(t, 4, walk.sites)
}

func TestContextValues_TheRuleTable(t *testing.T) {
	root := t.TempDir()
	contextFixtureModule(t, root)
	writeFixture(t, root, "mod/handlers/raw.go", contextFixtureRaw)
	writeFixture(t, root, "mod/other/other.go", contextFixtureOther)

	walk, err := findContextValueSites(root, "mod", "reqctx", contextFixtureExemptions)
	require.NoError(t, err)

	at := func(marker string) string {
		return "handlers/raw.go:" + strconv.Itoa(lineOf(t, contextFixtureRaw, marker))
	}
	assert.Equal(t, []string{
		at("plain-read") + " a context Value read",
		at("plain-write") + " context.WithValue",
		at("aliased-write") + " context.WithValue",
		at("request-read") + " a context Value read",
		at("embedded-read") + " a context Value read",
		at("method-value") + " a context Value read",
	}, contextFindingNames(walk.findings))

	require.Len(t, walk.blocked, 1)
	assert.Equal(t, "handlers/raw.go", walk.blocked[0].file)
	assert.Equal(t, lineOf(t, contextFixtureRaw, "unresolved"), walk.blocked[0].line)
	assert.Contains(t, walk.blocked[0].why, "cannot resolve")

	assert.Empty(t, walk.problems)
}

// Without its exemption the limiter's two sites are findings like any other: the exemption is
// what admits them, not anything about the shape.
func TestContextValues_AnUnexemptedPrivateKeyIsRefused(t *testing.T) {
	root := t.TempDir()
	contextFixtureModule(t, root)

	walk, err := findContextValueSites(root, "mod", "reqctx", nil)
	require.NoError(t, err)

	assert.Equal(t, []string{
		"limiter/limiter.go:11 context.WithValue",
		"limiter/limiter.go:15 a context Value read",
	}, contextFindingNames(walk.findings))
}

func TestContextValues_ExemptionsAndTheAccessorAreHeldBothWays(t *testing.T) {
	root := t.TempDir()
	contextFixtureModule(t, root)

	walk, err := findContextValueSites(root, "mod", "handlers", []ContextValueExemption{
		{File: "limiter/limiter.go", Reason: "  "},
		{File: "handlers/clean.go", Reason: "stale: nothing raw in it"},
	})
	require.NoError(t, err)

	assert.Equal(t, []string{
		"accessor package handlers holds no context value read or write, so it is not where " +
			"this module's accessors are",
		"exemption handlers/clean.go names a file holding no context value read or write; " +
			"remove the exemption",
		"exemption limiter/limiter.go carries no reason; say why this file may hold a raw " +
			"context value, or remove it",
	}, walk.problems)
	// Naming the wrong accessor also turns the real one's reads into findings.
	assert.Equal(t, []string{
		"reqctx/reqctx.go:10 context.WithValue",
		"reqctx/reqctx.go:14 a context Value read",
	}, contextFindingNames(walk.findings))
}

func TestContextValues_TheReportingHalfFailsOnARawRead(t *testing.T) {
	root := t.TempDir()
	contextFixtureModule(t, root)
	writeFixture(t, root, "mod/handlers/raw.go", contextFixtureRaw)
	writeFixture(t, root, "mod/other/other.go", contextFixtureOther)

	report := RunGuard(func(r Reporter) {
		assertContextValuesThroughAccessors(r, root, "mod", "reqctx", contextFixtureExemptions)
	})

	assert.True(t, report.Failed())
	assert.False(t, report.Stopped)
	assert.Contains(t, report.Text(), "6 raw context value read(s) or write(s) outside reqctx")
	assert.Contains(t, report.Text(),
		"handlers/raw.go:"+strconv.Itoa(lineOf(t, contextFixtureRaw, "plain-read"))+": a context Value read")
	assert.Contains(t, report.Text(),
		"handlers/raw.go:"+strconv.Itoa(lineOf(t, contextFixtureRaw, "unresolved"))+": a Value call")
}

func TestContextValues_TheReportingHalfReportsExemptionProblems(t *testing.T) {
	root := t.TempDir()
	contextFixtureModule(t, root)

	report := RunGuard(func(r Reporter) {
		assertContextValuesThroughAccessors(r, root, "mod", "reqctx", []ContextValueExemption{
			{File: "limiter/limiter.go", Reason: ""},
		})
	})

	assert.True(t, report.Failed())
	assert.Contains(t, report.Text(), "exemption limiter/limiter.go carries no reason")
}

func TestContextValues_TheReportingHalfPassesTheCleanTree(t *testing.T) {
	root := t.TempDir()
	contextFixtureModule(t, root)

	report := RunGuard(func(r Reporter) {
		assertContextValuesThroughAccessors(r, root, "mod", "reqctx", contextFixtureExemptions)
	})

	assert.False(t, report.Failed(), report.Text())
}

func TestContextValues_AWalkThatReachedNothingIsFatal(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")
	writeFixture(t, root, "mod/handlers/clean.go", contextFixtureClean)
	writeFixture(t, root, "mod/reqctx/reqctx.go", "package reqctx\n\nfunc SettingsFrom() {}\n")

	report := RunGuard(func(r Reporter) {
		assertContextValuesThroughAccessors(r, root, "mod", "reqctx", nil)
	})

	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "walked no context.WithValue or context Value call under mod")
}

func TestContextValues_AModuleWithNoGoModIsFatal(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "mod/reqctx/reqctx.go", contextFixtureAccessor)

	report := RunGuard(func(r Reporter) {
		assertContextValuesThroughAccessors(r, root, "mod", "reqctx", nil)
	})

	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "walking")
}
