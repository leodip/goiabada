package testutil

// Seam 2: the rule table AssertArchitecture enforces, over fixture trees written into a temp
// directory and read through the same graph builder the real caller uses.
//
// The synthetic half exists because the real half cannot fail informatively. The tree satisfies
// ARCHITECTURE.md today by construction — the tables were written from it — so the real test passes
// whether the rules match anything or not, which is the way a guard like this dies: quietly, still
// green. Every rule below therefore gets a fixture that must be caught and, where the rule is
// deliberately lenient, a fixture that must survive it (#279 sets out the same reasoning for the
// error-construction lint).

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/internal/refgraph"
)

// ---- fixture helpers -----------------------------------------------------------------------

// writeTree lays out a miniature four-module repository. The module paths are deliberately not the
// real ones: everything the guard knows about module identity it reads from these go.mod files, so
// a fixture that passed only because a path was hard-coded somewhere would fail here.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	all := map[string]string{
		"core/go.mod":               "module example.test/core\n",
		"authserver/go.mod":         "module example.test/authserver\n",
		"adminconsole/go.mod":       "module example.test/adminconsole\n",
		"cmd/goiabada-setup/go.mod": "module example.test/setup\n",
	}
	for rel, src := range files {
		all[rel] = src
	}
	for rel, src := range all {
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	}
	return root
}

// pkg writes a package whose only content is its imports.
func pkg(name string, imports ...string) string {
	var b strings.Builder
	b.WriteString("package " + name + "\n")
	for _, i := range imports {
		b.WriteString("\nimport _ \"" + i + "\"\n")
	}
	return b.String()
}

// ownerRows builds the ownership table from "<package> <owner> <issue>" triples.
func ownerRows(rows ...string) []ownerRow {
	out := make([]ownerRow, 0, len(rows))
	for i, r := range rows {
		f := strings.Fields(r)
		out = append(out, ownerRow{pkg: f[0], owner: f[1], issue: f[2], line: i + 1})
	}
	return out
}

// exceptionRows builds the exception table from "<from> <to> <issue>" triples.
func exceptionRows(rows ...string) []exceptionRow {
	out := make([]exceptionRow, 0, len(rows))
	for i, r := range rows {
		f := strings.Fields(r)
		out = append(out, exceptionRow{from: f[0], to: f[1], issue: f[2], line: i + 1})
	}
	return out
}

// foreignRows builds the foreign-module table from "<module> <yes|no> <issue>" triples.
func foreignRows(rows ...string) []foreignRow {
	out := make([]foreignRow, 0, len(rows))
	for i, r := range rows {
		f := strings.Fields(r)
		out = append(out, foreignRow{module: f[0], reachable: f[1] == "yes", clearedBy: f[2], line: i + 1})
	}
	return out
}

// testFrameworkRows builds the test-framework table from package paths, numbered from line 1.
func testFrameworkRows(pkgs ...string) []testFrameworkRow {
	out := make([]testFrameworkRow, 0, len(pkgs))
	for i, p := range pkgs {
		out = append(out, testFrameworkRow{pkg: p, line: i + 1})
	}
	return out
}

// The three shipped mains, as directories relative to the source root. Spelled out here rather
// than read from shippedMains, so that a list edited in the guard is not also edited in its tests.
const (
	authserverMain   = "authserver/cmd/goiabada-authserver"
	adminconsoleMain = "adminconsole/cmd/goiabada-adminconsole"
	setupMain        = "cmd/goiabada-setup"
)

// withShippedMains adds an empty main package at each of the three shipped mains the fixture did
// not write itself. The reporting half is fatal on a tree holding none of them, so every fixture
// driving it past that point carries them.
func withShippedMains(files map[string]string) map[string]string {
	out := map[string]string{
		authserverMain + "/main.go":   pkg("main"),
		adminconsoleMain + "/main.go": pkg("main"),
		setupMain + "/main.go":        pkg("main"),
	}
	for rel, src := range files {
		out[rel] = src
	}
	return out
}

// check runs the whole pipeline over a fixture tree and returns the findings, sorted the way
// AssertArchitecture sorts them.
//
// Every package the ownership table names is given an empty file if the fixture did not write one,
// so that a test about one rule is not also a test about table completeness. The tests that are
// about completeness use checkTree, which writes exactly what it is given.
func check(t *testing.T, files map[string]string, tables architectureTables) []string {
	t.Helper()

	stubbed := map[string]string{}
	for rel, src := range files {
		stubbed[rel] = src
	}
	for _, row := range tables.owners {
		if !strings.HasPrefix(row.pkg, "core/") {
			continue
		}
		written := false
		for rel := range files {
			if strings.HasPrefix(rel, row.pkg+"/") {
				written = true
				break
			}
		}
		if !written {
			name := strings.ReplaceAll(strings.TrimPrefix(row.pkg, "core/"), "-", "")
			stubbed[row.pkg+"/stub.go"] = pkg(name)
		}
	}
	return checkTree(t, stubbed, tables)
}

// checkTree runs the pipeline over exactly the files given, with nothing filled in.
func checkTree(t *testing.T, files map[string]string, tables architectureTables) []string {
	t.Helper()

	graph, err := refgraph.BuildImportGraph(writeTree(t, files))
	require.NoError(t, err)
	findings := checkArchitecture(tables, graph, nil)
	sort.Strings(findings)
	return findings
}

// assertFindings asserts the exact number of findings and that each one contains its fragment, in
// the order the fragments are given.
func assertFindings(t *testing.T, got []string, fragments ...string) {
	t.Helper()

	if !assert.Len(t, got, len(fragments), "findings:\n\t%s", strings.Join(got, "\n\t")) {
		return
	}
	for i, want := range fragments {
		assert.Contains(t, got[i], want)
	}
}

// ---- rule 1: module direction --------------------------------------------------------------

func TestArchitecture_ModuleDirection(t *testing.T) {
	tables := architectureTables{owners: ownerRows("core/errs kernel -")}

	t.Run("core may not import a process", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/errs/errs.go": pkg("errs", "example.test/authserver/internal/handlers"),
		}, tables)
		assertFindings(t, findings, "module direction: example.test/core/errs (production) imports example.test/authserver/internal/handlers; core may not import authserver")
	})

	t.Run("the two processes may not import each other", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/errs/errs.go":            pkg("errs"),
			"adminconsole/internal/a/a.go": pkg("a", "example.test/authserver/internal/b"),
			"authserver/internal/b/b.go":   pkg("b"),
		}, tables)
		assertFindings(t, findings, "adminconsole may not import authserver")
	})

	// Rule 1 is the one rule that reads test files: a test importing across a forbidden edge still
	// proves the two modules are coupled, and it still has to compile.
	t.Run("a test file is checked too", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/errs/errs.go":                 pkg("errs"),
			"adminconsole/internal/a/a.go":      pkg("a"),
			"adminconsole/internal/a/a_test.go": pkg("a", "example.test/authserver/internal/b"),
			"authserver/internal/b/b.go":        pkg("b"),
		}, tables)
		assertFindings(t, findings, "(test) imports example.test/authserver/internal/b")
	})

	t.Run("every module may import core, including the setup wizard", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/errs/errs.go":            pkg("errs"),
			"authserver/internal/a/a.go":   pkg("a", "example.test/core/errs"),
			"adminconsole/internal/b/b.go": pkg("b", "example.test/core/errs"),
			"cmd/goiabada-setup/main.go":   pkg("main", "example.test/core/errs"),
		}, tables)
		assert.Empty(t, findings)
	})
}

// ---- rule 2: kernel purity -----------------------------------------------------------------

func TestArchitecture_KernelPurity(t *testing.T) {
	t.Run("a kernel package may not import an authserver-owned package", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/i18n/i18n.go":     pkg("i18n", "example.test/core/models"),
			"core/models/models.go": pkg("models"),
		}, architectureTables{owners: ownerRows("core/i18n kernel -", "core/models authserver #359")})
		assertFindings(t, findings, "kernel purity: core/i18n imports core/models, and ARCHITECTURE.md lists no exception")
	})

	t.Run("a kernel package may not import a package already marked for deletion", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/i18n/i18n.go":   pkg("i18n", "example.test/core/audit"),
			"core/audit/audit.go": pkg("audit"),
		}, architectureTables{owners: ownerRows("core/i18n kernel -", "core/audit delete #333")})
		// The dead-package rule fires as well: a package with an importer is not dead.
		assertFindings(t, findings,
			"dead package: ARCHITECTURE.md:2 records core/audit as delete",
			"kernel purity: core/i18n imports core/audit")
	})

	// The leniency that makes the table usable mid-epic: a split package has no edge rule until the
	// issue that splits it lands, because at package granularity there is nothing yet to check.
	t.Run("a split package is not a target", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/i18n/i18n.go":   pkg("i18n", "example.test/core/oauth"),
			"core/oauth/oauth.go": pkg("oauth"),
		}, architectureTables{owners: ownerRows("core/i18n kernel -", "core/oauth split #338")})
		assert.Empty(t, findings)
	})

	t.Run("kernel to kernel is the point of the kernel", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/i18n/i18n.go": pkg("i18n", "example.test/core/errs"),
			"core/errs/errs.go": pkg("errs"),
		}, architectureTables{owners: ownerRows("core/i18n kernel -", "core/errs kernel -")})
		assert.Empty(t, findings)
	})

	// Rules 2 and 3 read production files only. A test may import a mock or a fixture from
	// anywhere; holding test code to the production graph would make this very package unusable
	// from the tiers that call the guard.
	t.Run("a test file is not held to the production graph", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/i18n/i18n.go":      pkg("i18n"),
			"core/i18n/i18n_test.go": pkg("i18n", "example.test/core/models"),
			"core/models/models.go":  pkg("models"),
		}, architectureTables{owners: ownerRows("core/i18n kernel -", "core/models authserver #359")})
		assert.Empty(t, findings)
	})

	t.Run("a package importing its own subpackage is not an edge", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/i18n/i18n.go":              pkg("i18n", "example.test/core/i18n/catalogs"),
			"core/i18n/catalogs/catalogs.go": pkg("catalogs"),
		}, architectureTables{owners: ownerRows("core/i18n kernel -")})
		assert.Empty(t, findings)
	})
}

// ---- rule 3: process isolation -------------------------------------------------------------

func TestArchitecture_ProcessIsolation(t *testing.T) {
	tables := architectureTables{owners: ownerRows(
		"core/user authserver #346",
		"core/uithemes adminconsole #348",
		"core/oauth split #338",
		"core/errs kernel -",
	)}

	t.Run("the admin console may not import an authserver-owned package", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/user/user.go":            pkg("user"),
			"adminconsole/internal/a/a.go": pkg("a", "example.test/core/user"),
		}, tables)
		assertFindings(t, findings, "process isolation: adminconsole/internal/a imports core/user")
	})

	t.Run("the auth server may not import an adminconsole-owned package", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/uithemes/uithemes.go":  pkg("uithemes"),
			"authserver/internal/a/a.go": pkg("a", "example.test/core/uithemes"),
		}, tables)
		assertFindings(t, findings, "process isolation: authserver/internal/a imports core/uithemes")
	})

	// The wizard ships as a standalone binary, so a package it pulls in is a package a user
	// downloads. It may import the kernel and nothing else.
	t.Run("the setup wizard may import neither process", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/user/user.go":          pkg("user"),
			"core/errs/errs.go":          pkg("errs"),
			"cmd/goiabada-setup/main.go": pkg("main", "example.test/core/user", "example.test/core/errs"),
		}, tables)
		assertFindings(t, findings, "process isolation: cmd/goiabada-setup imports core/user")
	})

	t.Run("a split package is not a target", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/oauth/oauth.go":          pkg("oauth"),
			"adminconsole/internal/a/a.go": pkg("a", "example.test/core/oauth"),
		}, tables)
		assert.Empty(t, findings)
	})

	t.Run("a test file is not held to the production graph", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/user/user.go":                 pkg("user"),
			"adminconsole/internal/a/a.go":      pkg("a"),
			"adminconsole/internal/a/a_test.go": pkg("a", "example.test/core/user"),
		}, tables)
		assert.Empty(t, findings)
	})
}

// ---- rule 4: dead package ------------------------------------------------------------------

func TestArchitecture_DeadPackage(t *testing.T) {
	tables := architectureTables{owners: ownerRows("core/audit delete #333", "core/errs kernel -")}

	t.Run("a delete row with no importer is what dead means", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/audit/mocks/mock.go": pkg("mocks"),
			"core/errs/errs.go":        pkg("errs"),
		}, tables)
		assert.Empty(t, findings)
	})

	t.Run("a production importer disproves the row", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/audit/mocks/mock.go":   pkg("mocks"),
			"authserver/internal/a/a.go": pkg("a", "example.test/core/audit/mocks"),
		}, tables)
		assertFindings(t, findings, "dead package: ARCHITECTURE.md:1 records core/audit as delete, but example.test/authserver/internal/a imports example.test/core/audit/mocks (production)")
	})

	// A test importer counts. A mocks package kept alive by one test is exactly the shape #333 is
	// deleting, and it would be invisible to a production-only rule.
	t.Run("a test importer disproves the row too", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/audit/mocks/mock.go":        pkg("mocks"),
			"authserver/internal/a/a.go":      pkg("a"),
			"authserver/internal/a/a_test.go": pkg("a", "example.test/core/audit/mocks"),
		}, tables)
		assertFindings(t, findings, "imports example.test/core/audit/mocks (test)")
	})
}

// ---- rule 5: foreign closure ---------------------------------------------------------------

func TestArchitecture_ForeignClosure(t *testing.T) {
	tables := func(rows ...string) architectureTables {
		return architectureTables{
			owners:  ownerRows("core/oauth split #338", "core/data authserver #359"),
			foreign: foreignRows(rows...),
		}
	}

	// The headline the epic exists to remove, in miniature: the admin console imports no driver,
	// and compiles one anyway because a core package three hops away does.
	reaching := map[string]string{
		"core/oauth/oauth.go":          pkg("oauth", "example.test/core/data"),
		"core/data/data.go":            pkg("data", "modernc.org/sqlite"),
		"adminconsole/internal/a/a.go": pkg("a", "example.test/core/oauth"),
	}

	t.Run("a module declared unreachable that is reachable is a regression", func(t *testing.T) {
		findings := check(t, reaching, tables("modernc.org/sqlite no -"))
		assertFindings(t, findings, "foreign closure: ARCHITECTURE.md:1 records modernc.org/sqlite as unreachable from the admin console, but example.test/core/data imports it")
	})

	t.Run("a module declared reachable that is reachable is the burn-down state", func(t *testing.T) {
		findings := check(t, reaching, tables("modernc.org/sqlite yes #359"))
		assert.Empty(t, findings)
	})

	// The half that makes the table shrink. When the edge goes, the row has to go with it, or the
	// list would only ever grow.
	t.Run("a module declared reachable that is no longer reachable is a row to delete", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/oauth/oauth.go":          pkg("oauth"),
			"core/data/data.go":            pkg("data", "modernc.org/sqlite"),
			"adminconsole/internal/a/a.go": pkg("a", "example.test/core/oauth"),
		}, tables("modernc.org/sqlite yes #359"))
		assertFindings(t, findings, "nothing reaches it any more; delete the row (#359)")
	})

	t.Run("a row names the module, and a package under it matches", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/oauth/oauth.go":          pkg("oauth", "example.test/core/data"),
			"core/data/data.go":            pkg("data", "github.com/jackc/pgx/v5/stdlib"),
			"adminconsole/internal/a/a.go": pkg("a", "example.test/core/oauth"),
		}, tables("github.com/jackc/pgx/v5 no -"))
		assertFindings(t, findings, "records github.com/jackc/pgx/v5 as unreachable")
	})

	t.Run("the standard library is not a foreign module", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/oauth/oauth.go":          pkg("oauth", "database/sql", "net/http"),
			"core/data/data.go":            pkg("data"),
			"adminconsole/internal/a/a.go": pkg("a", "example.test/core/oauth"),
		}, tables("database/sql no -"))
		assert.Empty(t, findings)
	})

	// The closure is production-only because it is about what lands in a shipped binary, and the
	// admin console's tests are not shipped.
	t.Run("a test-only dependency is not in the binary", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/oauth/oauth.go":               pkg("oauth"),
			"core/data/data.go":                 pkg("data"),
			"adminconsole/internal/a/a.go":      pkg("a"),
			"adminconsole/internal/a/a_test.go": pkg("a", "modernc.org/sqlite"),
		}, tables("modernc.org/sqlite no -"))
		assert.Empty(t, findings)
	})

	t.Run("the auth server's own dependencies are not the admin console's", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/oauth/oauth.go":        pkg("oauth"),
			"core/data/data.go":          pkg("data"),
			"authserver/internal/a/a.go": pkg("a", "modernc.org/sqlite"),
		}, tables("modernc.org/sqlite no -"))
		assert.Empty(t, findings)
	})
}

// ---- rule 9: test code ---------------------------------------------------------------------

func TestArchitecture_TestCode(t *testing.T) {
	tables := architectureTables{
		owners:         ownerRows("core/testutil kernel -"),
		testFrameworks: testFrameworkRows("testing", "net/http/httptest", "github.com/stretchr/testify"),
	}

	// The defect rule 9 exists for (#331): a production import of a test helper links the helper,
	// and the framework behind it, into a binary nobody tests.
	t.Run("a shipped main reaching the frameworks through first-party packages is reported with the path", func(t *testing.T) {
		findings := check(t, map[string]string{
			authserverMain + "/main.go":       pkg("main", "example.test/authserver/internal/a"),
			"authserver/internal/a/a.go":      pkg("a", "example.test/core/testutil"),
			"core/testutil/testutil.go":       pkg("testutil", "testing", "github.com/stretchr/testify/require", "github.com/stretchr/testify/assert"),
			"authserver/internal/a/a_test.go": pkg("a"),
		}, tables)
		assert.Equal(t, []string{
			"test code: authserver/cmd/goiabada-authserver links github.com/stretchr/testify/assert, which ARCHITECTURE.md:3 refuses in a shipped binary: authserver/cmd/goiabada-authserver -> authserver/internal/a -> core/testutil -> github.com/stretchr/testify/assert",
			"test code: authserver/cmd/goiabada-authserver links testing, which ARCHITECTURE.md:1 refuses in a shipped binary: authserver/cmd/goiabada-authserver -> authserver/internal/a -> core/testutil -> testing",
		}, findings)
	})

	t.Run("each of the three shipped mains is walked", func(t *testing.T) {
		findings := check(t, map[string]string{
			authserverMain + "/main.go":   pkg("main", "example.test/core/testutil"),
			adminconsoleMain + "/main.go": pkg("main", "example.test/core/testutil"),
			setupMain + "/main.go":        pkg("main", "example.test/core/testutil"),
			"core/testutil/testutil.go":   pkg("testutil", "testing"),
		}, tables)
		assertFindings(t, findings,
			"test code: adminconsole/cmd/goiabada-adminconsole links testing",
			"test code: authserver/cmd/goiabada-authserver links testing",
			"test code: cmd/goiabada-setup links testing")
	})

	t.Run("a row refuses the packages under it: testing's subpackages", func(t *testing.T) {
		findings := check(t, map[string]string{
			adminconsoleMain + "/main.go":  pkg("main", "example.test/adminconsole/internal/b"),
			"adminconsole/internal/b/b.go": pkg("b", "testing/fstest"),
		}, tables)
		assertFindings(t, findings,
			"test code: adminconsole/cmd/goiabada-adminconsole links testing/fstest, which ARCHITECTURE.md:1 refuses in a shipped binary: adminconsole/cmd/goiabada-adminconsole -> adminconsole/internal/b -> testing/fstest")
	})

	t.Run("a refused package imported by the main itself", func(t *testing.T) {
		findings := check(t, map[string]string{
			setupMain + "/main.go": pkg("main", "net/http/httptest"),
		}, tables)
		assertFindings(t, findings,
			"test code: cmd/goiabada-setup links net/http/httptest, which ARCHITECTURE.md:2 refuses in a shipped binary: cmd/goiabada-setup -> net/http/httptest")
	})

	// A row is a path and the packages under it, never a spelling: testingx is no more testing
	// than github.com/stretchr/testifyx is testify.
	t.Run("a path that merely begins with a row's spelling is not refused", func(t *testing.T) {
		findings := check(t, map[string]string{
			authserverMain + "/main.go": pkg("main", "testingx", "github.com/stretchr/testifyx", "net/http/httptestx"),
		}, tables)
		assert.Empty(t, findings)
	})

	t.Run("the path reported is the shortest", func(t *testing.T) {
		findings := check(t, map[string]string{
			authserverMain + "/main.go":  pkg("main", "example.test/authserver/internal/a", "example.test/authserver/internal/b"),
			"authserver/internal/a/a.go": pkg("a", "example.test/authserver/internal/c"),
			"authserver/internal/c/c.go": pkg("c", "example.test/core/testutil"),
			"authserver/internal/b/b.go": pkg("b", "example.test/core/testutil"),
			"core/testutil/testutil.go":  pkg("testutil", "testing"),
		}, tables)
		assertFindings(t, findings,
			": authserver/cmd/goiabada-authserver -> authserver/internal/b -> core/testutil -> testing")
	})

	// The same tree with the long route sorted last, so a walk that happened to pop its newest
	// package first would report it here.
	t.Run("the path reported is the shortest whichever route sorts first", func(t *testing.T) {
		findings := check(t, map[string]string{
			authserverMain + "/main.go":  pkg("main", "example.test/authserver/internal/a", "example.test/authserver/internal/b"),
			"authserver/internal/a/a.go": pkg("a", "example.test/core/testutil"),
			"authserver/internal/b/b.go": pkg("b", "example.test/authserver/internal/c"),
			"authserver/internal/c/c.go": pkg("c", "example.test/core/testutil"),
			"core/testutil/testutil.go":  pkg("testutil", "testing"),
		}, tables)
		assertFindings(t, findings,
			": authserver/cmd/goiabada-authserver -> authserver/internal/a -> core/testutil -> testing")
	})

	// The passing direction. Tests may import whatever they need, a helper nothing shipped reaches
	// is not in a binary, and a main that is not released ships nothing.
	t.Run("test files, unreached packages and unshipped mains may import the frameworks", func(t *testing.T) {
		findings := check(t, map[string]string{
			authserverMain + "/main.go":          pkg("main", "example.test/authserver/internal/a"),
			authserverMain + "/main_test.go":     pkg("main", "testing", "net/http/httptest"),
			"authserver/internal/a/a.go":         pkg("a"),
			"authserver/internal/a/a_test.go":    pkg("a", "example.test/core/testutil", "github.com/stretchr/testify/mock"),
			"core/testutil/testutil.go":          pkg("testutil", "testing", "github.com/stretchr/testify/assert"),
			"authserver/cmd/schemadump/main.go":  pkg("main", "example.test/core/testutil"),
			adminconsoleMain + "/main.go":        pkg("main"),
			adminconsoleMain + "/helper_test.go": pkg("main", "github.com/stretchr/testify/require"),
		}, tables)
		assert.Empty(t, findings)
	})

	// Every generated mock carries this constraint, so a production import of one breaks the
	// release build rather than linking it; the graph reads the tree the way that build does.
	t.Run("a file excluded from production builds is not in the binary", func(t *testing.T) {
		findings := check(t, map[string]string{
			authserverMain + "/main.go":      pkg("main", "example.test/authserver/internal/mocks"),
			"authserver/internal/mocks/m.go": "//go:build !production\n\n" + pkg("mocks", "github.com/stretchr/testify/mock"),
		}, tables)
		assert.Empty(t, findings)
	})

	// The walk crosses the edge of the four modules through the imports the go command reports for
	// the packages beyond it (#331, review R1-2).
	t.Run("a framework behind a third-party package is reported with the path through it", func(t *testing.T) {
		files := map[string]string{
			authserverMain + "/main.go":  pkg("main", "example.test/authserver/internal/a"),
			"authserver/internal/a/a.go": pkg("a", "example.net/helper"),
			"core/testutil/testutil.go":  pkg("testutil"),
		}
		external := map[string][]string{
			"example.net/helper":       {"example.net/helper/inner", "fmt"},
			"example.net/helper/inner": {"github.com/stretchr/testify/require"},
		}
		stopped := check(t, files, tables)
		assert.Empty(t, stopped, "without the go command's edges the walk stops at the edge of the four modules")

		graph, err := refgraph.BuildImportGraph(writeTree(t, withShippedMains(files)))
		require.NoError(t, err)
		findings := checkArchitecture(tables, graph, external)
		assert.Equal(t, []string{
			"test code: authserver/cmd/goiabada-authserver links github.com/stretchr/testify/require, which ARCHITECTURE.md:3 refuses in a shipped binary: authserver/cmd/goiabada-authserver -> authserver/internal/a -> example.net/helper -> example.net/helper/inner -> github.com/stretchr/testify/require",
		}, findings)
	})

	t.Run("a refused package is reported once per row and main, however many packages import it", func(t *testing.T) {
		findings := check(t, map[string]string{
			authserverMain + "/main.go":  pkg("main", "example.test/authserver/internal/a", "example.test/authserver/internal/b"),
			"authserver/internal/a/a.go": pkg("a", "testing"),
			"authserver/internal/b/b.go": pkg("b", "testing", "testing/quick"),
		}, tables)
		assertFindings(t, findings, "authserver/cmd/goiabada-authserver -> authserver/internal/a -> testing")
	})
}

// ---- rule 6: table hygiene -----------------------------------------------------------------

func TestArchitecture_TableHygiene(t *testing.T) {
	tree := map[string]string{
		"core/errs/errs.go":   pkg("errs"),
		"core/models/m.go":    pkg("models"),
		"core/locales/l.json": "",
	}

	// Completeness is what makes adding a core package a decision rather than a default: the tier
	// goes red until somebody says where the new package belongs.
	t.Run("a core package with no row", func(t *testing.T) {
		findings := checkTree(t, tree, architectureTables{owners: ownerRows("core/errs kernel -")})
		assertFindings(t, findings, "ARCHITECTURE.md holds no ownership row for core/models")
	})

	t.Run("a row for a package that is not there", func(t *testing.T) {
		findings := checkTree(t, tree, architectureTables{owners: ownerRows(
			"core/errs kernel -", "core/models authserver #359", "core/ghost authserver #360")})
		assertFindings(t, findings, "records ownership for core/ghost, which holds no production Go file")
	})

	// A directory of data files is not a package and owes no row.
	t.Run("a directory with no Go file owes no row", func(t *testing.T) {
		findings := checkTree(t, tree, architectureTables{owners: ownerRows(
			"core/errs kernel -", "core/models authserver #359")})
		assert.Empty(t, findings)
	})

	t.Run("two rows for one package", func(t *testing.T) {
		findings := checkTree(t, tree, architectureTables{owners: ownerRows(
			"core/errs kernel -", "core/models authserver #359", "core/models split #350")})
		assertFindings(t, findings, "gives core/models a second ownership row; the first is at line 2")
	})

	t.Run("a kernel package that names an issue", func(t *testing.T) {
		findings := checkTree(t, tree, architectureTables{owners: ownerRows(
			"core/errs kernel #123", "core/models authserver #359")})
		assertFindings(t, findings, "gives kernel package core/errs the issue #123; a package that is not moving has no issue")
	})

	// A move with no issue is the thing the epic is trying not to accumulate: an intention with
	// nobody responsible for it.
	t.Run("a moving package that names no issue", func(t *testing.T) {
		findings := checkTree(t, tree, architectureTables{owners: ownerRows(
			"core/errs kernel -", "core/models authserver -")})
		assertFindings(t, findings, "says core/models becomes authserver but names \"-\" where an issue like #332 belongs")
	})

	t.Run("an owner that is not one of the five", func(t *testing.T) {
		findings := checkTree(t, tree, architectureTables{owners: ownerRows(
			"core/errs kernel -", "core/models maybe #359")})
		assertFindings(t, findings, "gives core/models the owner \"maybe\", which is none of kernel, authserver, adminconsole, split, delete")
	})

	t.Run("a reachable foreign module that names no clearing issue", func(t *testing.T) {
		findings := checkTree(t, map[string]string{
			"core/errs/errs.go":            pkg("errs", "modernc.org/sqlite"),
			"core/models/m.go":             pkg("models"),
			"adminconsole/internal/a/a.go": pkg("a", "example.test/core/errs"),
		}, architectureTables{
			owners:  ownerRows("core/errs kernel -", "core/models authserver #359"),
			foreign: foreignRows("modernc.org/sqlite yes -"),
		})
		assertFindings(t, findings, "is reachable from the admin console but names \"-\" where the issue that clears it belongs")
	})

	t.Run("a test framework listed twice", func(t *testing.T) {
		findings := checkTree(t, tree, architectureTables{
			owners:         ownerRows("core/errs kernel -", "core/models authserver #359"),
			testFrameworks: testFrameworkRows("testing", "net/http/httptest", "testing"),
		})
		assertFindings(t, findings, "table hygiene: ARCHITECTURE.md:3 lists the test framework testing twice; the first is at line 1")
	})
}

// ---- rule 6: exception reconciliation ------------------------------------------------------

func TestArchitecture_Exceptions(t *testing.T) {
	tree := map[string]string{
		"core/i18n/i18n.go":     pkg("i18n", "example.test/core/models"),
		"core/models/models.go": pkg("models"),
	}
	owners := ownerRows("core/i18n kernel -", "core/models authserver #359")

	t.Run("a listed exception silences the violation it names", func(t *testing.T) {
		findings := check(t, tree, architectureTables{
			owners:     owners,
			exceptions: exceptionRows("core/i18n core/models #337"),
		})
		assert.Empty(t, findings)
	})

	// An exception is scoped to the exact edge, not to the package at either end. Granting
	// core/i18n one dependency must not grant it every dependency.
	t.Run("an exception covers one edge and no other", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/i18n/i18n.go":     pkg("i18n", "example.test/core/models", "example.test/core/user"),
			"core/models/models.go": pkg("models"),
			"core/user/user.go":     pkg("user"),
		}, architectureTables{
			owners:     append(owners, ownerRows("core/user authserver #346")...),
			exceptions: exceptionRows("core/i18n core/models #337"),
		})
		assertFindings(t, findings, "kernel purity: core/i18n imports core/user")
	})

	// The burn-down half. #335 already instructs its implementer to remove the exact exception rows
	// this issue grants; this is what happens when that is forgotten.
	t.Run("an exception for an edge that no longer exists", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/i18n/i18n.go":     pkg("i18n"),
			"core/models/models.go": pkg("models"),
		}, architectureTables{
			owners:     owners,
			exceptions: exceptionRows("core/i18n core/models #337"),
		})
		assertFindings(t, findings, "lists core/i18n -> core/models as a temporary exception, but that edge no longer exists; delete the row (#337)")
	})

	t.Run("an exception that names no issue is a waiver", func(t *testing.T) {
		findings := check(t, tree, architectureTables{
			owners:     owners,
			exceptions: exceptionRows("core/i18n core/models -"),
		})
		assertFindings(t, findings, "a temporary dependency with no issue is a waiver")
	})

	t.Run("the same exception listed twice", func(t *testing.T) {
		findings := check(t, tree, architectureTables{
			owners:     owners,
			exceptions: exceptionRows("core/i18n core/models #337", "core/i18n core/models #350"),
		})
		assertFindings(t, findings, "lists the exception core/i18n -> core/models twice")
	})

	// Guidance point 4 of #332 asks for exact package edges, and this is what that buys: granting
	// one package a dependency must not grant it to the package next door, or a second consumer
	// could appear with nothing going red and the row count would stop measuring the work left.
	t.Run("an exception names the importing package, not its module", func(t *testing.T) {
		tree := map[string]string{
			"core/user/user.go":            pkg("user"),
			"adminconsole/internal/a/a.go": pkg("a", "example.test/core/user"),
			"adminconsole/internal/b/b.go": pkg("b", "example.test/core/user"),
		}
		owners := ownerRows("core/user authserver #346")

		findings := check(t, tree, architectureTables{
			owners:     owners,
			exceptions: exceptionRows("adminconsole/internal/a core/user #346"),
		})
		assertFindings(t, findings, "process isolation: adminconsole/internal/b imports core/user")

		findings = check(t, tree, architectureTables{
			owners: owners,
			exceptions: exceptionRows(
				"adminconsole/internal/a core/user #346",
				"adminconsole/internal/b core/user #346"),
		})
		assert.Empty(t, findings)
	})

	// A module name in the from column is no longer a grant at all: it matches no edge, so it reads
	// as a stale row and says so.
	t.Run("a module name in the from column grants nothing", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/user/user.go":            pkg("user"),
			"adminconsole/internal/a/a.go": pkg("a", "example.test/core/user"),
		}, architectureTables{
			owners:     ownerRows("core/user authserver #346"),
			exceptions: exceptionRows("adminconsole core/user #346"),
		})
		assertFindings(t, findings,
			"process isolation: adminconsole/internal/a imports core/user",
			"lists adminconsole -> core/user as a temporary exception, but that edge no longer exists")
	})
}

// ---- the import graph itself ---------------------------------------------------------------

func TestArchitecture_ImportsAreReadFromTheAst(t *testing.T) {
	owners := ownerRows("core/i18n kernel -", "core/models authserver #359")

	// Reading the AST rather than the text is what lets the guard be exact in both directions.
	t.Run("an import path in a comment or a string is not an edge", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/i18n/i18n.go": `package i18n

// This package used to import "example.test/core/models" and no longer does.
const doc = "example.test/core/models"
`,
			"core/models/models.go": pkg("models"),
		}, architectureTables{owners: owners})
		assert.Empty(t, findings)
	})

	t.Run("an aliased import is still an edge", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/i18n/i18n.go": `package i18n

import m "example.test/core/models"

var _ = m.X
`,
			"core/models/models.go": pkg("models"),
		}, architectureTables{owners: owners})
		assertFindings(t, findings, "kernel purity: core/i18n imports core/models")
	})

	// A file excluded from every production build is not part of the production graph, which is the
	// same judgement the error-construction lint makes about the same comment.
	t.Run("a file excluded from production builds is not in the production graph", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/i18n/i18n.go": `//go:build !production

package i18n

import _ "example.test/core/models"
`,
			"core/models/models.go": pkg("models"),
		}, architectureTables{owners: owners})
		assert.Empty(t, findings)
	})

	t.Run("a file that does not parse is the build tier's problem, not this one", func(t *testing.T) {
		findings := check(t, map[string]string{
			"core/i18n/i18n.go":     "package i18n\n\nthis is not Go\n",
			"core/models/models.go": pkg("models"),
		}, architectureTables{owners: owners})
		assert.Empty(t, findings)
	})
}

// ---- the document parser -------------------------------------------------------------------

func TestArchitecture_DocParsing(t *testing.T) {
	doc := `# Architecture

Prose that mentions | pipes | and must not be read as a row.

### Package ownership

| package | owner | moves in |
|---|---|---|
| ` + "`core/api`" + ` | kernel | — |
| ` + "`core/models`" + ` | authserver | #359 |

More prose.

### Temporary exceptions

| from | to | issue |
|---|---|---|
| ` + "`core/api`" + ` | ` + "`core/models`" + ` | #350 |

### Foreign modules

| module | why | reachable today | cleared by |
|---|---|---|---|
| ` + "`modernc.org/sqlite`" + ` | SQLite driver | yes | #359 |
| ` + "`github.com/pquerna/otp`" + ` | TOTP | no | — |

### Test frameworks

| package | what it is |
|---|---|
| ` + "`testing`" + ` | the standard test framework |
| ` + "`github.com/stretchr/testify`" + ` | assertions and mocks |

### Built-in identifiers ownership

| symbol | justification | issue |
|---|---|---|
| ` + "`Version`" + ` | kernel | — |
| ` + "`ManageUsersPermissionIdentifier`" + ` | moving | #359 |
`

	tables, findings := parseArchitectureDoc(doc)
	assert.Empty(t, findings)

	assert.Equal(t, []ownerRow{
		{pkg: "core/api", owner: "kernel", issue: "—", line: 9},
		{pkg: "core/models", owner: "authserver", issue: "#359", line: 10},
	}, tables.owners)
	assert.Equal(t, []exceptionRow{
		{from: "core/api", to: "core/models", issue: "#350", line: 18},
	}, tables.exceptions)
	assert.Equal(t, []foreignRow{
		{module: "modernc.org/sqlite", reachable: true, clearedBy: "#359", line: 24},
		{module: "github.com/pquerna/otp", reachable: false, clearedBy: "—", line: 25},
	}, tables.foreign)
	assert.Equal(t, []testFrameworkRow{
		{pkg: "testing", line: 31},
		{pkg: "github.com/stretchr/testify", line: 32},
	}, tables.testFrameworks)
	assert.Equal(t, []builtinRow{
		{symbol: "Version", justification: "kernel", issue: "—", line: 38},
		{symbol: "ManageUsersPermissionIdentifier", justification: "moving", issue: "#359", line: 39},
	}, tables.builtin)
}

func TestArchitecture_DocParsingRejects(t *testing.T) {
	t.Run("a missing table", func(t *testing.T) {
		_, findings := parseArchitectureDoc("# Architecture\n")
		require.Len(t, findings, 5)
		assert.Contains(t, findings[0], `has no "### Package ownership" table`)
		assert.Contains(t, findings[3], `has no "### Test frameworks" table`)
		assert.Contains(t, findings[4], `has no "### Built-in identifiers ownership" table`)
	})

	t.Run("a test-framework row with the wrong number of cells", func(t *testing.T) {
		_, findings := parseArchitectureDoc("### Test frameworks\n\n| a | b |\n|---|---|\n| testing | x | y |\n")
		assert.Contains(t, findings, "ARCHITECTURE.md:5: a test-framework row needs 2 cells, found 3")
	})

	// An empty table refuses nothing, so rule 9 would pass every tree. The exception table may be
	// empty because an empty burn-down list is the goal; this one being empty is the guard gone.
	t.Run("a test-framework table with no rows", func(t *testing.T) {
		_, findings := parseArchitectureDoc("### Test frameworks\n\n| a | b |\n|---|---|\n")
		assert.Contains(t, findings, `ARCHITECTURE.md has an empty "### Test frameworks" table, so rule 9 refuses nothing`)
	})

	t.Run("a row with the wrong number of cells", func(t *testing.T) {
		_, findings := parseArchitectureDoc("### Package ownership\n\n| a | b | c |\n|---|---|---|\n| core/api | kernel |\n\n### Temporary exceptions\n\n| a | b | c |\n|---|---|---|\n\n### Foreign modules\n\n| a | b | c | d |\n|---|---|---|---|\n")
		require.NotEmpty(t, findings)
		assert.Contains(t, findings[0], "an ownership row needs 3 cells, found 2")
	})

	t.Run("a reachability cell that is neither yes nor no", func(t *testing.T) {
		_, findings := parseArchitectureDoc("### Package ownership\n\n| a | b | c |\n|---|---|---|\n\n### Temporary exceptions\n\n| a | b | c |\n|---|---|---|\n\n### Foreign modules\n\n| a | b | c | d |\n|---|---|---|---|\n| mod | why | maybe | #1 |\n")
		require.NotEmpty(t, findings)
		assert.Contains(t, findings[0], `row's reachability is "maybe", which is neither yes nor no`)
	})
}

func TestArchitecture_NoIssueSpellings(t *testing.T) {
	// The document writes an em dash. A hyphen and an empty cell mean the same thing to a reader,
	// and refusing them would make the guard a finding about typography rather than about the tree.
	for _, cell := range []string{"—", "–", "-", "", "  "} {
		assert.True(t, noIssue(cell), "%q", cell)
	}
	for _, cell := range []string{"#332", "later", "TODO"} {
		assert.False(t, noIssue(cell), "%q", cell)
	}
}

// ---- the real tree -------------------------------------------------------------------------

// TestArchitecture_TheRealTreeIsHeldByItsExceptions proves the guard is connected to this
// repository and not merely to its fixtures. The tree passes today because the tables were written
// from it, so passing proves nothing on its own.
//
// #360 emptied the exception table, which left this test with nothing to drop, so the probe that
// carries the proof is now the other direction of the same coupling — the one that still has
// something to say at zero rows. Adding back the row the epic's last move deleted must be reported
// as a row to delete, against the real import graph. The drop loop stays for whenever a row comes
// back; at zero rows it runs zero times, and the probe above is why that is not a test which passes
// by doing nothing.
func TestArchitecture_TheRealTreeIsHeldByItsExceptions(t *testing.T) {
	root := SourceRoot(t)

	doc, err := os.ReadFile(filepath.Join(filepath.Dir(root), architectureDoc))
	require.NoError(t, err)
	tables, findings := parseArchitectureDoc(string(doc))
	require.Empty(t, findings)

	graph, err := refgraph.BuildImportGraph(root)
	require.NoError(t, err)
	require.Empty(t, checkArchitecture(tables, graph, nil))

	t.Run("an exception listed for an edge that no longer exists", func(t *testing.T) {
		// The exact row #360 deleted when core/testutil/fake and core/uuidutil both moved to
		// authserver/internal. Naming a stale edge rather than an invented one keeps the probe
		// honest: this pair was a real violation until the move, so a guard that reported it
		// from the row alone rather than from the graph would look identical here.
		stale := exceptionRow{from: "core/testutil/fake", to: "core/uuidutil", issue: "#360", line: 1}
		kept := architectureTables{owners: tables.owners, foreign: tables.foreign}
		kept.exceptions = append(append(kept.exceptions, tables.exceptions...), stale)

		findings := checkArchitecture(kept, graph, nil)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0], "core/testutil/fake -> core/uuidutil")
		assert.Contains(t, findings[0], "that edge no longer exists")
	})

	for _, dropped := range tables.exceptions {
		t.Run(dropped.from+" -> "+dropped.to, func(t *testing.T) {
			kept := architectureTables{owners: tables.owners, foreign: tables.foreign}
			for _, row := range tables.exceptions {
				if row != dropped {
					kept.exceptions = append(kept.exceptions, row)
				}
			}
			findings := checkArchitecture(kept, graph, nil)
			require.Len(t, findings, 1)
			assert.Contains(t, findings[0], dropped.from+" imports "+dropped.to)
		})
	}
}

// TestArchitecture_TheRealTreeReachesEveryForeignModuleItDeclares does the same for the foreign
// table: flipping a declared reachability must produce a finding, in both directions.
func TestArchitecture_TheRealTreeReachesEveryForeignModuleItDeclares(t *testing.T) {
	root := SourceRoot(t)

	doc, err := os.ReadFile(filepath.Join(filepath.Dir(root), architectureDoc))
	require.NoError(t, err)
	tables, _ := parseArchitectureDoc(string(doc))
	require.NotEmpty(t, tables.foreign)

	graph, err := refgraph.BuildImportGraph(root)
	require.NoError(t, err)

	for i, row := range tables.foreign {
		t.Run(row.module, func(t *testing.T) {
			flipped := architectureTables{owners: tables.owners, exceptions: tables.exceptions}
			flipped.foreign = append(flipped.foreign, tables.foreign...)
			flipped.foreign[i].reachable = !row.reachable
			if flipped.foreign[i].reachable {
				flipped.foreign[i].clearedBy = "#360"
			}

			findings := checkArchitecture(flipped, graph, nil)
			require.Len(t, findings, 1)
			assert.Contains(t, findings[0], row.module)
		})
	}
}

// TestArchitecture_TheRealShippedMainsAreWalked connects rule 9 to this repository. The real tree
// passes it, and would pass it just as well if the walk reached nothing, so the probe adds a row
// for a package every shipped binary certainly links and expects one finding per binary: fmt, which
// first-party code imports, and internal/abi, which no first-party code can import, so it is
// reached only through the standard library's own edges, the ones the go command supplies.
func TestArchitecture_TheRealShippedMainsAreWalked(t *testing.T) {
	root := SourceRoot(t)

	doc, err := os.ReadFile(filepath.Join(filepath.Dir(root), architectureDoc))
	require.NoError(t, err)
	tables, findings := parseArchitectureDoc(string(doc))
	require.Empty(t, findings)

	pkgs := make([]string, 0, len(tables.testFrameworks))
	for _, row := range tables.testFrameworks {
		pkgs = append(pkgs, row.pkg)
	}
	assert.Equal(t, []string{"testing", "net/http/httptest", "github.com/stretchr/testify"}, pkgs,
		"rule 9 refuses testing, net/http/httptest and testify, and nothing else (#331)")

	graph, err := refgraph.BuildImportGraph(root)
	require.NoError(t, err)

	probed := architectureTables{owners: tables.owners, foreign: tables.foreign, exceptions: tables.exceptions}
	probed.testFrameworks = append(append(probed.testFrameworks, tables.testFrameworks...),
		testFrameworkRow{pkg: "fmt", line: 1}, testFrameworkRow{pkg: "internal/abi", line: 2})

	external, loadFindings, err := compiledClosure(root, graph)
	require.NoError(t, err)
	require.Empty(t, loadFindings)

	findings = checkArchitecture(probed, graph, external)
	sort.Strings(findings)
	assertFindings(t, findings,
		"test code: adminconsole/cmd/goiabada-adminconsole links fmt",
		"test code: adminconsole/cmd/goiabada-adminconsole links internal/abi",
		"test code: authserver/cmd/goiabada-authserver links fmt",
		"test code: authserver/cmd/goiabada-authserver links internal/abi",
		"test code: cmd/goiabada-setup links fmt",
		"test code: cmd/goiabada-setup links internal/abi")
}

// ---- seam 3: the reporting half -------------------------------------------------------------
//
// Everything above runs checkArchitecture and asserts on the findings it returned. The lines that
// read ARCHITECTURE.md off disk, refuse an empty graph and turn each finding into a failure were
// reached only by the two server tiers, which walk a tree that satisfies the document by
// construction.

// architectureFixture writes a miniature repository in the real one's shape: the four modules under
// a src/ source root, and ARCHITECTURE.md one level above it, which is where the guard looks rather
// than anywhere it is told. It returns the source root, as SourceRoot would.
func architectureFixture(t *testing.T, doc string, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	root := filepath.Join(dir, "src")
	all := map[string]string{
		"core/go.mod":               "module example.test/core\n",
		"authserver/go.mod":         "module example.test/authserver\n",
		"adminconsole/go.mod":       "module example.test/adminconsole\n",
		"cmd/goiabada-setup/go.mod": "module example.test/setup\n",
	}
	for rel, src := range files {
		all[rel] = src
	}
	for rel, src := range all {
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, architectureDoc), []byte(doc), 0o644))
	return root
}

// architectureDocWith renders a document carrying the five headings the parser needs, with the
// ownership, test-framework and built-in identifiers tables populated. The other two are left as a header
// and a separator, which is what an empty table looks like to refgraph.TableUnder.
//
// The two ownership rows and the one built-in identifiers row it always writes are the baseline rule
// 7 needs: the guard is fatal on a tree declaring no built-in identifier or referencing none, so every fixture
// driving the reporting half carries builtinBaselineFiles alongside its own.
func architectureDocWith(ownership ...string) string {
	var b strings.Builder
	b.WriteString("# Architecture\n\nProse that mentions | pipes | and is not a row.\n\n")
	b.WriteString("### Package ownership\n\n| package | owner | moves in |\n|---|---|---|\n")
	b.WriteString("| `core/builtin` | kernel | — |\n")
	b.WriteString("| `core/errs` | kernel | — |\n")
	for _, row := range ownership {
		b.WriteString(row + "\n")
	}
	b.WriteString("\n### Temporary exceptions\n\n| from | to | issue |\n|---|---|---|\n")
	b.WriteString("\n### Foreign modules\n\n| module | why | reachable today | cleared by |\n|---|---|---|---|\n")
	b.WriteString("\n### Test frameworks\n\n| package | what it is |\n|---|---|\n")
	b.WriteString("| `testing` | the standard test framework |\n")
	b.WriteString("| `github.com/stretchr/testify` | assertions and mocks |\n")
	b.WriteString("\n### Built-in identifiers ownership\n\n| symbol | justification | issue |\n|---|---|---|\n")
	b.WriteString("| `Shared` | kernel | — |\n")
	return b.String()
}

// TestArchitecture_TheGuardPassesATreeItsTablesDescribe is the clean direction, and it is what keeps
// every case below from passing for the wrong reason.
func TestArchitecture_TheGuardPassesATreeItsTablesDescribe(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), withShippedMains(withBuiltinBaseline(map[string]string{
		"core/api/api.go": pkg("api"),
	})))

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	assert.False(t, report.Failed(), "a tree its tables describe failed the guard: %s", report.Text())
}

// TestArchitecture_TheGuardFailsOnAPackageTheTableDoesNotName drives the reporting half over the
// rule that makes the document a burn-down list rather than a wish: a new top-level core package
// fails the tier until the table says where it belongs.
func TestArchitecture_TheGuardFailsOnAPackageTheTableDoesNotName(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), withShippedMains(withBuiltinBaseline(map[string]string{
		"core/api/api.go":      pkg("api"),
		"core/newcomer/new.go": pkg("newcomer"),
	})))

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Failed(), "an unowned core package passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "core/newcomer")
	assert.Contains(t, report.Text(), "every top-level core package needs one")
}

// TestArchitecture_TheGuardFailsOnAForbiddenModuleEdge is the rule with no exceptions, and the one
// a reader is likeliest to meet: core depends on neither process.
func TestArchitecture_TheGuardFailsOnAForbiddenModuleEdge(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), withShippedMains(withBuiltinBaseline(map[string]string{
		"core/api/api.go": pkg("api", "example.test/authserver/internal/handlers"),
	})))

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Failed(), "a core to authserver edge passed the guard")
	assert.Contains(t, report.Text(), "core/api")
	assert.Contains(t, report.Text(), "authserver/internal/handlers")
}

// TestArchitecture_TheGuardFailsOnAStaleExceptionRow is the direction that makes the tables a
// burn-down list: an exception left standing for an edge that no longer exists is as much a failure
// as an edge the tables do not allow, which is what forces the issue removing an edge to remove its
// row with it (#332).
func TestArchitecture_TheGuardFailsOnAStaleExceptionRow(t *testing.T) {
	doc := architectureDocWith("| `core/api` | kernel | — |", "| `core/models` | authserver | #359 |")
	doc = strings.Replace(doc,
		"### Temporary exceptions\n\n| from | to | issue |\n|---|---|---|\n",
		"### Temporary exceptions\n\n| from | to | issue |\n|---|---|---|\n| `core/api` | `core/models` | #350 |\n",
		1)
	root := architectureFixture(t, doc, withShippedMains(withBuiltinBaseline(map[string]string{
		"core/api/api.go":       pkg("api"),
		"core/models/models.go": pkg("models"),
	})))

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Failed(), "an exception for an edge nothing carries passed the guard")
	assert.Contains(t, report.Text(), "core/api")
	assert.Contains(t, report.Text(), "core/models")
}

// TestArchitecture_TheGuardFailsOnTestCodeInAShippedBinary is rule 9 through the path the three
// module tiers take: a shipped main reaching testify through a first-party helper.
func TestArchitecture_TheGuardFailsOnTestCodeInAShippedBinary(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |", "| `core/testutil` | kernel | — |"), withShippedMains(withBuiltinBaseline(map[string]string{
		"core/api/api.go":             pkg("api"),
		adminconsoleMain + "/main.go": pkg("main", "example.test/core/testutil"),
		"core/testutil/testutil.go":   pkg("testutil", "github.com/stretchr/testify/mock"),
	})))

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Failed(), "a shipped main linking testify passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "adminconsole/cmd/goiabada-adminconsole -> core/testutil -> github.com/stretchr/testify/mock")
}

// TestArchitecture_TheGuardFailsOnTestCodeBehindAThirdPartyModule is rule 9 through the reporting
// half with the go command in the loop: the shipped auth server imports a third-party module, here
// a local directory the auth server's go.mod replaces it with, whose own production code imports
// testing. The source graph never reads that module, so only the go command's listing can show the
// edge (#331, review R1-2).
func TestArchitecture_TheGuardFailsOnTestCodeBehindAThirdPartyModule(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), withShippedMains(withBuiltinBaseline(map[string]string{
		"core/api/api.go": pkg("api"),
		"authserver/go.mod": "module example.test/authserver\n\ngo 1.21\n\n" +
			"require example.net/helper v0.0.0\n\nreplace example.net/helper => ../../helper\n",
		authserverMain + "/main.go":     pkg("main", "example.net/helper"),
		"../helper/go.mod":              "module example.net/helper\n\ngo 1.21\n",
		"../helper/helper.go":           pkg("helper", "example.net/helper/inner"),
		"../helper/inner/inner.go":      pkg("inner", "testing"),
		"../helper/inner/inner_test.go": pkg("inner"),
	})))

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Failed(), "a shipped main linking testing through a third-party module passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	require.Len(t, report.Errors, 1, "findings:\n\t%s", strings.Join(report.Errors, "\n\t"))
	assert.Contains(t, report.Errors[0], "test code: authserver/cmd/goiabada-authserver links testing, which ARCHITECTURE.md:")
	assert.Contains(t, report.Errors[0], " refuses in a shipped binary: authserver/cmd/goiabada-authserver -> example.net/helper -> example.net/helper/inner -> testing")
}

// TestArchitecture_TheGuardReportsAPackageTheGoCommandCannotLoad is the compiled walk that reached
// nothing: a dependency the go command cannot load lists no imports, so it must be a finding rather
// than a package that silently imports nothing.
func TestArchitecture_TheGuardReportsAPackageTheGoCommandCannotLoad(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), withShippedMains(withBuiltinBaseline(map[string]string{
		"core/api/api.go":           pkg("api"),
		authserverMain + "/main.go": pkg("main", "example.net/missing"),
	})))

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Failed(), "a dependency the go command cannot load passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "test code: the go command cannot load example.net/missing for authserver/cmd/goiabada-authserver on linux/amd64, so rule 9 cannot see what it imports")
}

// TestArchitecture_TheGuardIsFatalWithNoShippedMain is rule 9's walk that reached nothing. Every
// tree satisfies "no shipped main links a test framework" when no shipped main is found, so a
// rename of all three, or a source root resolved somewhere else, would otherwise read as a clean
// tree.
func TestArchitecture_TheGuardIsFatalWithNoShippedMain(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), withBuiltinBaseline(map[string]string{
		"core/api/api.go":                   pkg("api"),
		"authserver/cmd/schemadump/main.go": pkg("main"),
	}))

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Stopped, "a tree with no shipped main must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "found none of the shipped mains authserver/cmd/goiabada-authserver, adminconsole/cmd/goiabada-adminconsole, cmd/goiabada-setup under")
}

// TestArchitecture_TheGuardFailsWithOneShippedMainMissing is the same failure one binary at a time:
// a renamed main would leave rule 9 walking two binaries of three with nothing going red.
func TestArchitecture_TheGuardFailsWithOneShippedMainMissing(t *testing.T) {
	files := withShippedMains(withBuiltinBaseline(map[string]string{
		"core/api/api.go": pkg("api"),
	}))
	delete(files, setupMain+"/main.go")
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), files)

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Failed(), "a missing shipped main passed the guard")
	assert.False(t, report.Stopped, "two mains are still walked, so this is a finding, not a stop")
	assert.Contains(t, report.Text(), "test code: the shipped main cmd/goiabada-setup holds no production Go file, so rule 9 walks nothing for it")
	assert.NotContains(t, report.Text(), "authserver/cmd/goiabada-authserver holds")
}

// TestArchitecture_TheGuardIsFatalWithNoArchitectureDoc pins the first of this guard's two seams.
// It reads its rules from a file rather than from code, so the document being renamed or moved is
// the way it stops having any rules at all.
func TestArchitecture_TheGuardIsFatalWithNoArchitectureDoc(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), map[string]string{
		"core/api/api.go": pkg("api"),
	})
	require.NoError(t, os.Remove(filepath.Join(filepath.Dir(root), architectureDoc)))

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Stopped, "a missing ARCHITECTURE.md must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "reading ARCHITECTURE.md")
}

// TestArchitecture_TheGuardIsFatalOnAnEmptyGraph pins the second. A graph holding no production
// package satisfies every rule below it, so a root that resolved somewhere with no Go in it would
// otherwise read as a tree in perfect order.
func TestArchitecture_TheGuardIsFatalOnAnEmptyGraph(t *testing.T) {
	// The four go.mod files and nothing else: the graph builder reads them to resolve import paths,
	// so a tree without them fails earlier and for a different reason. What is being pinned here is
	// the tree that resolves and holds no package.
	root := architectureFixture(t, architectureDocWith(), nil)

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Stopped, "an empty graph must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "found no production Go packages under")
}

// TestArchitecture_TheGuardIsFatalWithAModuleMissing is the shape that reaches the graph builder
// first. Requiring all four go.mod files is what lets the builder resolve an import path to a
// module at all, so one missing is reported as the read that failed rather than as a tree holding
// no packages.
func TestArchitecture_TheGuardIsFatalWithAModuleMissing(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), map[string]string{
		"core/api/api.go": pkg("api"),
	})
	require.NoError(t, os.Remove(filepath.Join(root, "adminconsole", "go.mod")))

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "reading the import graph under")
	assert.Contains(t, report.Fatal, "adminconsole/go.mod")
}
