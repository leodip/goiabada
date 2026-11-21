package guard

// Seam 9 of #433: the rule AssertContextValuesThroughAccessors enforces, over fixture modules
// written into a temp tree and walked through the same functions the real caller uses.
//
// The real caller walks a clean tree -- #439 moved the rate limiter's credential reservation, the
// last raw read #433 left outside internal/reqctx, in behind it -- so it passes identically
// whether the rule still fires or has quietly stopped resolving anything. Every fixture below is a
// shape the auth server had, or one that would make the walk answer by spelling rather than by
// type. Each tree is a module the go command loads, and compiles: the guard reads it through
// pkgload, where a package that does not compile is fatal (#420).

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
// the read through r.Context(), whose type comes from net/http.
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
	_ = other.Make().Value("k") // site:other-package-read
}
`

// contextFixtureOther returns a context from another package of the module. A hand-written
// importer that stubbed it could not tell what its Value call read; the type checker can.
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
	assert.Empty(t, walk.problems)
	// The accessor's write and read, and the limiter's write and read, each counted once however
	// many of the builds read select its file. The test file's two are not walked, and nothing in
	// clean.go is a site.
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
		at("other-package-read") + " a context Value read",
	}, contextFindingNames(walk.findings))

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

	report := Run(func(r Reporter) {
		assertContextValuesThroughAccessors(r, root, "mod", "reqctx", contextFixtureExemptions)
	})

	assert.True(t, report.Failed())
	assert.False(t, report.Stopped)
	assert.Contains(t, report.Text(), "7 raw context value read(s) or write(s) outside reqctx")
	assert.Contains(t, report.Text(),
		"handlers/raw.go:"+strconv.Itoa(lineOf(t, contextFixtureRaw, "plain-read"))+": a context Value read")
	assert.Contains(t, report.Text(),
		"handlers/raw.go:"+strconv.Itoa(lineOf(t, contextFixtureRaw, "other-package-read"))+": a context Value read")
}

func TestContextValues_TheReportingHalfReportsExemptionProblems(t *testing.T) {
	root := t.TempDir()
	contextFixtureModule(t, root)

	report := Run(func(r Reporter) {
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

	report := Run(func(r Reporter) {
		assertContextValuesThroughAccessors(r, root, "mod", "reqctx", contextFixtureExemptions)
	})

	assert.False(t, report.Failed(), report.Text())
}

// contextFixtureSiteless is an accessor package renamed away from the context: the names
// clean.go calls, and no site.
const contextFixtureSiteless = `package reqctx

import "context"

func WithSettings(ctx context.Context, s string) context.Context { return ctx }

func SettingsFrom(ctx context.Context) (string, bool) { return "", false }
`

// contextFixtureWindows is a production file only the Windows release build selects: the test
// machine's default build and the other four release builds leave it out.
const contextFixtureWindows = `//go:build windows

package handlers

import "context"

func OnWindows(ctx context.Context) any {
	return ctx.Value("k") // site:windows-read
}
`

// contextFixtureReleaseOnly is a production file only a build with the production tag selects,
// which every release build sets and the default build does not.
const contextFixtureReleaseOnly = `//go:build production

package handlers

import "context"

func InRelease(ctx context.Context) context.Context {
	return context.WithValue(ctx, "k", 1) // site:release-write
}
`

// contextFixtureDevelopmentOnly is a production file no release build selects, as the admin
// console's handler test support is: only the default build reads it.
const contextFixtureDevelopmentOnly = `//go:build !production

package handlers

import "context"

func InDevelopment(ctx context.Context) any {
	return ctx.Value("k") // site:development-read
}
`

// A raw read in a file only one of the builds selects is still a raw read in shipped code, or in
// code the development server runs, so the walk reads every release build and the default build
// and merges what they find (#420 decision 11).
func TestContextValues_AFileOnlyOneBuildSelectsIsRead(t *testing.T) {
	for _, tc := range []struct {
		name, file, src, marker, what string
	}{
		{"another platform's release build", "handlers/platform.go", contextFixtureWindows,
			"windows-read", "a context Value read"},
		{"the production tag", "handlers/release.go", contextFixtureReleaseOnly,
			"release-write", "context.WithValue"},
		{"the default build only", "handlers/development.go", contextFixtureDevelopmentOnly,
			"development-read", "a context Value read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			contextFixtureModule(t, root)
			writeFixture(t, root, "mod/"+tc.file, tc.src)

			walk, err := findContextValueSites(root, "mod", "reqctx", contextFixtureExemptions)
			require.NoError(t, err)

			assert.Equal(t, []string{
				tc.file + ":" + strconv.Itoa(lineOf(t, tc.src, tc.marker)) + " " + tc.what,
			}, contextFindingNames(walk.findings))
			assert.Equal(t, 5, walk.sites)
		})
	}
}

// A package that does not compile cannot be read whole, and a raw read in it would pass unseen,
// so the walk stops and names it (#420 decision 3).
func TestContextValues_APackageThatDoesNotCompileIsFatal(t *testing.T) {
	root := t.TempDir()
	contextFixtureModule(t, root)
	writeFixture(t, root, "mod/broken/broken.go", "package broken\n\nfunc Broken() int { return \"x\" }\n")

	report := Run(func(r Reporter) {
		assertContextValuesThroughAccessors(r, root, "mod", "reqctx", contextFixtureExemptions)
	})

	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "example.com/mod/broken")
	assert.Contains(t, report.Fatal, "does not load or type-check")
}

func TestContextValues_AWalkThatReachedNothingIsFatal(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")
	writeFixture(t, root, "mod/handlers/clean.go", contextFixtureClean)
	writeFixture(t, root, "mod/reqctx/reqctx.go", contextFixtureSiteless)

	report := Run(func(r Reporter) {
		assertContextValuesThroughAccessors(r, root, "mod", "reqctx", nil)
	})

	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "walked no context.WithValue or context Value call under mod")
}

func TestContextValues_AModuleWithNoGoModIsFatal(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "mod/reqctx/reqctx.go", contextFixtureAccessor)

	report := Run(func(r Reporter) {
		assertContextValuesThroughAccessors(r, root, "mod", "reqctx", nil)
	})

	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "walking")
}
