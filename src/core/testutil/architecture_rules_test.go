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

	graph, err := buildImportGraph(writeTree(t, files))
	require.NoError(t, err)
	findings := checkArchitecture(tables, graph)
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

	t.Run("module identity is read from go.mod", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"core/go.mod":       "module example.test/renamed-core\n",
			"core/errs/errs.go": pkg("errs"),
		})
		graph, err := buildImportGraph(root)
		require.NoError(t, err)
		assert.Equal(t, "example.test/renamed-core", graph.modules["core"])
		assert.Equal(t, "core/errs", graph.topCorePackage("example.test/renamed-core/errs"))
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
}

func TestArchitecture_DocParsingRejects(t *testing.T) {
	t.Run("a missing table", func(t *testing.T) {
		_, findings := parseArchitectureDoc("# Architecture\n")
		assert.Len(t, findings, 3)
		assert.Contains(t, findings[0], `has no "### Package ownership" table`)
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
// from it, so passing proves nothing on its own; removing one exception must make it fail, and the
// finding must name the edge that exception was covering.
func TestArchitecture_TheRealTreeIsHeldByItsExceptions(t *testing.T) {
	root := SourceRoot(t)

	doc, err := os.ReadFile(filepath.Join(filepath.Dir(root), architectureDoc))
	require.NoError(t, err)
	tables, findings := parseArchitectureDoc(string(doc))
	require.Empty(t, findings)
	require.NotEmpty(t, tables.exceptions)

	graph, err := buildImportGraph(root)
	require.NoError(t, err)
	require.Empty(t, checkArchitecture(tables, graph))

	for _, dropped := range tables.exceptions {
		t.Run(dropped.from+" -> "+dropped.to, func(t *testing.T) {
			kept := architectureTables{owners: tables.owners, foreign: tables.foreign}
			for _, row := range tables.exceptions {
				if row != dropped {
					kept.exceptions = append(kept.exceptions, row)
				}
			}
			findings := checkArchitecture(kept, graph)
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

	graph, err := buildImportGraph(root)
	require.NoError(t, err)

	for i, row := range tables.foreign {
		t.Run(row.module, func(t *testing.T) {
			flipped := architectureTables{owners: tables.owners, exceptions: tables.exceptions}
			flipped.foreign = append(flipped.foreign, tables.foreign...)
			flipped.foreign[i].reachable = !row.reachable
			if flipped.foreign[i].reachable {
				flipped.foreign[i].clearedBy = "#360"
			}

			findings := checkArchitecture(flipped, graph)
			require.Len(t, findings, 1)
			assert.Contains(t, findings[0], row.module)
		})
	}
}
