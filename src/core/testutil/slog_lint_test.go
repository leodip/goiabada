package testutil

// The rule table AssertSlogConvention enforces, over fixture source text written into a temp tree
// and walked through the same function the real caller uses.
//
// The synthetic half exists because the real half cannot fail informatively. A guard that has
// quietly stopped matching anything passes on a clean tree exactly as it passes on a correct one,
// and the tree is clean by construction, so the only thing left holding a rule would be a test
// that never proves it can fire (#320).

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureTree is a source root inside a temp directory, with the golangci-lint configuration one
// level above it exactly where AssertSlogConvention looks for the real one.
type fixtureTree struct {
	t        *testing.T
	root     string
	golangci string
}

func newFixtureTree(t *testing.T) fixtureTree {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "src")
	require.NoError(t, os.MkdirAll(root, 0o755))
	return fixtureTree{t: t, root: root, golangci: filepath.Join(dir, golangciConfigName)}
}

func (f fixtureTree) write(rel, src string) {
	f.t.Helper()
	path := filepath.Join(f.root, filepath.FromSlash(rel))
	require.NoError(f.t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(f.t, os.WriteFile(path, []byte(src), 0o644))
}

func (f fixtureTree) writeGolangci(src string) {
	f.t.Helper()
	require.NoError(f.t, os.WriteFile(f.golangci, []byte(src), 0o644))
}

// golangciWithForwarders is a configuration whose custom-funcs are exactly the forwarders in
// slogSpreadSites, in the shape the real file uses. args-pos is 2 for every entry because rule 4
// compares names only; the real file's offsets are the header's accepted residual risk.
func golangciWithForwarders() string {
	var b strings.Builder
	b.WriteString("linters:\n  settings:\n    sloglint:\n      context: scope\n      custom-funcs:\n")
	for _, site := range slogSpreadSites {
		if site.forwarder == "" {
			continue
		}
		b.WriteString("        - name: " + site.forwarder + "\n          msg-pos: -1\n          args-pos: 2\n")
	}
	b.WriteString("  exclusions:\n    rules:\n      - path: _test\\.go\n")
	return b.String()
}

// found renders one violation as the rule table states it: file, line and the finding, without
// the fix text, which is advice rather than a claim the table needs to pin.
func found(v slogViolation) string {
	return v.file + ":" + strconv.Itoa(v.line) + " " + v.what
}

func TestSlogConvention_TheRuleTable(t *testing.T) {
	tree := newFixtureTree(t)
	tree.writeGolangci(golangciWithForwarders())

	// ---- rule 1: no component prefix, no "failed to", no "error " -------------------------------

	tree.write("core/caught/openers.go", `package caught

import (
	"context"
	"log/slog"
)

func openers(ctx context.Context) {
	slog.Info("logout: session ended")
	slog.Error("failed to load the client")
	slog.Error("error loading the client")
	slog.InfoContext(ctx, "failed to read the shape at index one")
	slog.Log(ctx, slog.LevelInfo, "TokenParser: the shape at index two")
	slog.LogAttrs(ctx, slog.LevelWarn, "error at index two as well")
}
`)
	// A constant passes sloglint's static-msg and is never read by its msg-style, so a constant is
	// how an opener would get past every guard; a concatenation and a variable are the same shape
	// one step further out. sloglint refuses the last two as well, and the overlap is deliberate.
	tree.write("core/caught/nonliteral.go", `package caught

import "log/slog"

const message = "Component: failed to load the client"

func nonliteral(name string) {
	slog.Error(message)
	slog.Warn("client " + name + " is disabled")
	slog.Info(name)
}
`)
	// Near misses: a colon later in the message, a colon after a token with a space in it, the
	// verb the convention chose, and a word that merely begins with "error".
	tree.write("core/passed/openers.go", `package passed

import "log/slog"

func openers() {
	slog.Info("the token's audience: none")
	slog.Info("client x: consent required")
	slog.Warn("unable to load the client")
	slog.Info("errors were found in the request")
	slog.Info("WARNING is not a prefix without the colon")
}
`)

	// ---- rule 2: handler ownership --------------------------------------------------------------

	tree.write("core/caught/installs.go", `package caught

import (
	"log/slog"
	"os"
)

func installs() {
	slog.SetDefault(slog.Default())
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	_ = logger
	_ = slog.With("component", "x")
	build := slog.New
	_ = build
}
`)
	tree.write("core/caught/aliased.go", `package caught

import (
	l "log/slog"
	"os"
)

func aliased() { _ = l.New(l.NewTextHandler(os.Stderr, nil)) }
`)
	tree.write("core/caught/dot.go", `package caught

import . "log/slog"

func dot() { Info("nothing here resolves") }
`)
	// The owners: the handler's package, a main, schemadump, and the one file in core/testutil.
	tree.write("core/logging/handler.go", `package logging

import "log/slog"

func Install() { slog.SetDefault(slog.New(slog.Default().Handler())) }
`)
	tree.write("authserver/cmd/goiabada-authserver/main.go", `package main

import "log/slog"

func main() { slog.SetDefault(slog.Default()) }
`)
	tree.write("core/cmd/schemadump/main.go", `package main

import "log/slog"

func main() { slog.SetDefault(slog.Default()) }
`)
	tree.write("core/testutil/slog_capture.go", `package testutil

import "log/slog"

func Capture() { _ = slog.New(slog.Default().Handler()) }
`)
	// The same call one file over in the same package is not admitted: the allowlist names the
	// file, not the package.
	tree.write("core/testutil/other.go", `package testutil

import "log/slog"

func Other() { _ = slog.New(slog.Default().Handler()) }
`)

	// ---- rule 3: a run spread into a record or a forwarder ----------------------------------------

	tree.write("core/caught/spreads.go", `package caught

import (
	"context"
	"log/slog"
)

func spreadRecord(ctx context.Context, attrs []any) {
	slog.InfoContext(ctx, "a run this rule cannot read", attrs...)
}

func spreadFromClosure(ctx context.Context, attrs []any) {
	emit := func() { slog.WarnContext(ctx, "the enclosing top-level function is what is listed", attrs...) }
	emit()
}

// A builder's name outside the scope that lists it is any other function.
func reportTrip(ctx context.Context, attrs []any) {
	slog.WarnContext(ctx, "rate limit reached", attrs...)
}
`)
	tree.write("authserver/internal/handlers/apihandlers/caught.go", `package apihandlers

import "net/http"

func writeInternalServerError(w http.ResponseWriter, r *http.Request, err error, attrs ...any) {}

func bare(w http.ResponseWriter, r *http.Request, err error, attrs []any) {
	writeInternalServerError(w, r, err, attrs...)
}
`)
	tree.write("authserver/internal/handlers/caught.go", `package handlers

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/apiresponse"
)

func rejectIdTokenHint(ctx context.Context, gate string, args ...any) {}

func qualified(w http.ResponseWriter, r *http.Request, err error, attrs []any) {
	apiresponse.WriteInternalServerError(w, r, err, attrs...)
}

func bareReject(ctx context.Context, attrs []any) {
	rejectIdTokenHint(ctx, "aud", attrs...)
}
`)
	// The forwarders themselves, spreading their own run and each other's, and the two builders.
	tree.write("authserver/internal/apiresponse/apiresponse.go", `package apiresponse

import (
	"log/slog"
	"net/http"
)

func WriteInternalServerError(w http.ResponseWriter, r *http.Request, err error, attrs ...any) {
	LogInternalServerError(r, err, attrs...)
}

func LogInternalServerError(r *http.Request, err error, attrs ...any) string {
	record := append([]any{"error", err}, attrs...)
	slog.ErrorContext(r.Context(), "internal server error", record...)
	return ""
}
`)
	tree.write("core/middleware/builders.go", `package middleware

import (
	"context"
	"log/slog"
	"net/http"
)

type limiter struct{}

func (m *limiter) reportTrip(ctx context.Context, keyField, key string) {
	attrs := []any{"limiter", "login"}
	if keyField != "" {
		attrs = append(attrs, keyField, key)
	}
	slog.WarnContext(ctx, "rate limit reached", attrs...)
}

func MiddlewareRequestLogger() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attributes := []any{"method", r.Method}
			slog.InfoContext(r.Context(), "http request", attributes...)
		})
	}
}
`)
	// A same-named bare function in a package outside the forwarder's scope is not the forwarder,
	// and a spread into it is nothing this rule reads: the only record it could reach is in its own
	// body, where rule 3 looks anyway.
	tree.write("core/passed/same_name.go", `package passed

import "net/http"

func writeInternalServerError(w http.ResponseWriter, r *http.Request, err error, attrs ...any) {}

func caller(w http.ResponseWriter, r *http.Request, err error, attrs []any) {
	writeInternalServerError(w, r, err, attrs...)
}
`)
	// Literal keys at the call, which is the shape the rule sends a spread to.
	tree.write("core/passed/literal_keys.go", `package passed

import (
	"context"
	"log/slog"
)

func literal(ctx context.Context, id int64) {
	slog.InfoContext(ctx, "client loaded", "client_id", id, slog.Int64("user_id", 1))
}
`)

	// ---- exemptions -----------------------------------------------------------------------------

	tree.write("core/caught/exempt_test.go", `package caught

import "log/slog"

func inTest() { slog.SetDefault(slog.New(slog.Default().Handler())); slog.Info("failed to x") }
`)
	tree.write("core/mocks/exempt.go", `package mocks

import "log/slog"

func inMock() { slog.SetDefault(slog.Default()); slog.Info("failed to x") }
`)
	tree.write("core/caught/exempt_tagged.go", `//go:build !production

package caught

import "log/slog"

func tagged() { slog.SetDefault(slog.Default()); slog.Info("failed to x") }
`)

	violations, files, err := findSlogViolations(tree.root, tree.golangci, nil)
	require.NoError(t, err)
	assert.Equal(t, 18, files, "every non-exempt fixture is walked")

	got := make([]string, 0, len(violations))
	for _, v := range violations {
		got = append(got, found(v))
	}
	want := []string{
		// rule 1
		"core/caught/openers.go:9 message carries a component prefix",
		`core/caught/openers.go:10 message opens with "failed to"`,
		`core/caught/openers.go:11 message opens with "error "`,
		`core/caught/openers.go:12 message opens with "failed to"`,
		"core/caught/openers.go:13 message carries a component prefix",
		`core/caught/openers.go:14 message opens with "error "`,
		"core/caught/nonliteral.go:8 message is not a string literal",
		"core/caught/nonliteral.go:9 message is not a string literal",
		"core/caught/nonliteral.go:10 message is not a string literal",
		// rule 2
		"core/caught/installs.go:9 slog.SetDefault outside the files that own the handler",
		"core/caught/installs.go:9 slog.Default outside the files that own the handler",
		"core/caught/installs.go:10 slog.New outside the files that own the handler",
		"core/caught/installs.go:12 slog.With outside the files that own the handler",
		"core/caught/installs.go:13 slog.New outside the files that own the handler",
		"core/caught/aliased.go:8 slog.New outside the files that own the handler",
		`core/caught/dot.go:3 dot import of "log/slog"`,
		"core/testutil/other.go:5 slog.Default outside the files that own the handler",
		"core/testutil/other.go:5 slog.New outside the files that own the handler",
		// rule 3
		"core/caught/spreads.go:9 a run spread into a record outside slogSpreadSites",
		"core/caught/spreads.go:13 a run spread into a record outside slogSpreadSites",
		"core/caught/spreads.go:19 a run spread into a record outside slogSpreadSites",
		"authserver/internal/handlers/apihandlers/caught.go:8 a run spread into writeInternalServerError outside slogSpreadSites",
		"authserver/internal/handlers/caught.go:13 a run spread into WriteInternalServerError outside slogSpreadSites",
		"authserver/internal/handlers/caught.go:17 a run spread into rejectIdTokenHint outside slogSpreadSites",
	}
	sort.Strings(want)
	sort.Strings(got)
	assert.Equal(t, want, got)
}

// TestSlogConvention_TheForwarderTable is rule 4: the forwarders in slogSpreadSites and the
// custom-funcs in .golangci.yml are one set, read from the file the way the real caller reads it.
func TestSlogConvention_TheForwarderTable(t *testing.T) {
	clean := `package clean

import "log/slog"

func clean() { slog.Info("nothing to report") }
`
	forwarders := []string{}
	for _, site := range slogSpreadSites {
		if site.forwarder != "" {
			forwarders = append(forwarders, site.forwarder)
		}
	}
	require.NotEmpty(t, forwarders, "the table names at least one forwarder, or rule 4 tests nothing")

	t.Run("the same set passes", func(t *testing.T) {
		tree := newFixtureTree(t)
		tree.write("core/clean/clean.go", clean)
		tree.writeGolangci(golangciWithForwarders())
		violations, _, err := findSlogViolations(tree.root, tree.golangci, nil)
		require.NoError(t, err)
		assert.Empty(t, violations)
	})

	t.Run("a forwarder missing from custom-funcs", func(t *testing.T) {
		tree := newFixtureTree(t)
		tree.write("core/clean/clean.go", clean)
		cfg := golangciWithForwarders()
		missing := forwarders[len(forwarders)-1]
		cfg = strings.Replace(cfg, "        - name: "+missing+"\n          msg-pos: -1\n          args-pos: 2\n", "", 1)
		require.NotContains(t, cfg, missing)
		tree.writeGolangci(cfg)
		violations, _, err := findSlogViolations(tree.root, tree.golangci, nil)
		require.NoError(t, err)
		require.Len(t, violations, 1)
		assert.Equal(t, golangciConfigName+":5 "+missing+" is a forwarder in slogSpreadSites but not a custom-func", found(violations[0]))
	})

	t.Run("a custom-func missing from the table", func(t *testing.T) {
		tree := newFixtureTree(t)
		tree.write("core/clean/clean.go", clean)
		cfg := golangciWithForwarders()
		cfg = strings.Replace(cfg, "      custom-funcs:\n",
			"      custom-funcs:\n        - name: example.com/pkg.Unlisted\n          msg-pos: -1\n          args-pos: 1\n", 1)
		tree.writeGolangci(cfg)
		violations, _, err := findSlogViolations(tree.root, tree.golangci, nil)
		require.NoError(t, err)
		require.Len(t, violations, 1)
		assert.Equal(t, golangciConfigName+":6 example.com/pkg.Unlisted is a custom-func but not a forwarder in slogSpreadSites", found(violations[0]))
	})

	t.Run("an entry outside the custom-funcs block is not read as one", func(t *testing.T) {
		tree := newFixtureTree(t)
		tree.write("core/clean/clean.go", clean)
		// The exclusions list that follows custom-funcs at a shallower indent carries a `- path:`
		// entry; a `- name:` there would belong to something else and must not count.
		cfg := golangciWithForwarders() + "        linters: [sloglint]\n      - name: example.com/pkg.NotAForwarder\n"
		tree.writeGolangci(cfg)
		violations, _, err := findSlogViolations(tree.root, tree.golangci, nil)
		require.NoError(t, err)
		assert.Empty(t, violations)
	})

	t.Run("no custom-funcs key at all", func(t *testing.T) {
		tree := newFixtureTree(t)
		tree.write("core/clean/clean.go", clean)
		tree.writeGolangci("linters:\n  settings:\n    sloglint:\n      context: scope\n")
		violations, _, err := findSlogViolations(tree.root, tree.golangci, nil)
		require.NoError(t, err)
		require.Len(t, violations, 1)
		assert.Equal(t, golangciConfigName+":0 no custom-funcs under sloglint", found(violations[0]))
	})

	t.Run("no configuration file", func(t *testing.T) {
		tree := newFixtureTree(t)
		tree.write("core/clean/clean.go", clean)
		violations, _, err := findSlogViolations(tree.root, tree.golangci, nil)
		require.NoError(t, err)
		require.Len(t, violations, 1)
		assert.Equal(t, golangciConfigName+":0 no golangci-lint configuration beside the source root", found(violations[0]))
	})
}

// TestSlogConvention_TheTreeItself is the real half: the whole source root, through the same
// entry point the authserver and adminconsole tiers call.
func TestSlogConvention_TheTreeItself(t *testing.T) {
	AssertSlogConvention(t)
}

// TestSlogConvention_EverySpreadSiteExists holds the table to the tree: a listed function that no
// longer exists at its scope is an admission nothing uses, and the first function to take its name
// there would inherit it.
func TestSlogConvention_EverySpreadSiteExists(t *testing.T) {
	root := SourceRoot(t)
	for _, site := range slogSpreadSites {
		t.Run(site.scope+"/"+site.name, func(t *testing.T) {
			matches, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(site.scope), "*.go"))
			require.NoError(t, err)
			declared := 0
			for _, path := range matches {
				if strings.HasSuffix(path, "_test.go") {
					continue
				}
				src, err := os.ReadFile(path)
				require.NoError(t, err)
				declared += strings.Count(string(src), ") "+site.name+"(") + strings.Count(string(src), "func "+site.name+"(")
			}
			assert.Equal(t, 1, declared, "declared exactly once in its scope")
		})
	}
}
