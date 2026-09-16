package testutil

// Seam: the rule table checkErrorCodeDoc enforces, over a fixture catalog and a fixture
// error_codes.md written into a temp tree and read through the same functions the real caller uses,
// plus the real pair as the case that must pass.
//
// The synthetic half exists for the reason agentdocs_test.go's does: the real pair is correct by
// construction once this lands, so a guard that had quietly stopped matching anything would pass
// exactly as a working one does, and nothing would be holding the rule. The reporting half is
// driven through RunGuard for the reason guard.go gives: a defect in the five lines that report
// disables the guard across every module with nothing going red (#333, #344 decision 9).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixture catalog. page.title is here to pin that a key outside the validator./handler.
// families is not owned by the document: it has no row below and that is not a finding.
var fakeErrorCatalogLines = []string{
	`"validator.email.required" = "Please enter an email address."`,
	`"validator.email.too_long" = "The email address cannot exceed a maximum length of {{.max}} characters."`,
	`"handler.login.auth_failed" = "Authentication failed."`,
	`"page.title" = "Goiabada"`,
}

// The fixture document, in the real one's shape: a heading, prose, then a table whose header and
// separator rows must not be read as codes.
var fakeErrorDocLines = []string{
	"# Error code taxonomy",
	"",
	"Companion to `error_codes.go`.",
	"",
	"## Email validator",
	"",
	"| Code | Args | English message |",
	"|---|---|---|",
	"| `validator.email.required` | (none) | Please enter an email address. |",
	"| `validator.email.too_long` | `max` (int) | The email address cannot exceed a maximum length of {{.max}} characters. |",
	"",
	"## Login handler",
	"",
	"| Code | Args | English message |",
	"|---|---|---|",
	"| `handler.login.auth_failed` | (none) | Authentication failed. |",
}

// writeErrorCodeDocFixture lays out the two files at the paths checkErrorCodeDoc resolves from a
// source root, and returns that root. Passing "" for either file leaves it absent, which is how the
// unreadable cases are built.
func writeErrorCodeDocFixture(t *testing.T, catalog, doc string) string {
	t.Helper()

	root := t.TempDir()
	catalogDir := filepath.Join(root, "core", "i18n", "catalogs")
	require.NoError(t, os.MkdirAll(catalogDir, 0o755))

	if catalog != "" {
		require.NoError(t, os.WriteFile(filepath.Join(catalogDir, "active.en.toml"), []byte(catalog), 0o600))
	}
	if doc != "" {
		require.NoError(t, os.WriteFile(filepath.Join(root, "core", "i18n", "error_codes.md"), []byte(doc), 0o600))
	}
	return root
}

func fakeErrorCatalog() string { return strings.Join(fakeErrorCatalogLines, "\n") + "\n" }
func fakeErrorDoc() string     { return strings.Join(fakeErrorDocLines, "\n") + "\n" }

// docWithout returns the fixture document with the one line holding substr removed.
func docWithout(t *testing.T, substr string) string {
	t.Helper()

	var kept []string
	var dropped int
	for _, line := range fakeErrorDocLines {
		if strings.Contains(line, substr) {
			dropped++
			continue
		}
		kept = append(kept, line)
	}
	require.Equal(t, 1, dropped, "the fixture must hold exactly one line containing %q", substr)
	return strings.Join(kept, "\n") + "\n"
}

// A tree the guard must accept. Without this every case below would pass against a guard that
// reported everything.
func TestCheckErrorCodeDoc_AcceptsADocumentThatMatchesTheCatalog(t *testing.T) {
	root := writeErrorCodeDocFixture(t, fakeErrorCatalog(), fakeErrorDoc())

	findings, err := checkErrorCodeDoc(root)

	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCheckErrorCodeDoc_MissingRow(t *testing.T) {
	root := writeErrorCodeDocFixture(t, fakeErrorCatalog(), docWithout(t, "validator.email.too_long"))

	findings, err := checkErrorCodeDoc(root)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "validator.email.too_long", findings[0].Code)
	assert.Contains(t, findings[0].Reason, "no row for it")
	// The finding carries the sentence to add, so the fix does not need a second lookup.
	assert.Contains(t, findings[0].Reason, "{{.max}}")
}

// The drift rule is the reason the document is checked at all: the row exists, the code is right,
// and the sentence describes something the software does not say.
func TestCheckErrorCodeDoc_DriftedMessage(t *testing.T) {
	doc := strings.Replace(fakeErrorDoc(),
		"| `handler.login.auth_failed` | (none) | Authentication failed. |",
		"| `handler.login.auth_failed` | (none) | Authentication succeeded. |", 1)
	root := writeErrorCodeDocFixture(t, fakeErrorCatalog(), doc)

	findings, err := checkErrorCodeDoc(root)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "handler.login.auth_failed", findings[0].Code)
	assert.Contains(t, findings[0].Reason, "Authentication succeeded.")
	assert.Contains(t, findings[0].Reason, "Authentication failed.")
}

// A placeholder rendered in the document but raw in the catalog is drift, not a formatting choice:
// both sides carry the template, so a row reading "60 characters" hides which limit the code uses.
func TestCheckErrorCodeDoc_ARenderedPlaceholderIsDrift(t *testing.T) {
	doc := strings.Replace(fakeErrorDoc(), "{{.max}}", "60", 1)
	root := writeErrorCodeDocFixture(t, fakeErrorCatalog(), doc)

	findings, err := checkErrorCodeDoc(root)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "validator.email.too_long", findings[0].Code)
}

func TestCheckErrorCodeDoc_DuplicateRow(t *testing.T) {
	doc := fakeErrorDoc() + "| `validator.email.required` | (none) | Please enter an email address. |\n"
	root := writeErrorCodeDocFixture(t, fakeErrorCatalog(), doc)

	findings, err := checkErrorCodeDoc(root)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "validator.email.required", findings[0].Code)
	assert.Contains(t, findings[0].Reason, "2 rows")
}

func TestCheckErrorCodeDoc_RowNamingAKeyTheCatalogDoesNotHave(t *testing.T) {
	doc := fakeErrorDoc() + "| `validator.email.renamed_away` | (none) | Please enter an email address. |\n"
	root := writeErrorCodeDocFixture(t, fakeErrorCatalog(), doc)

	findings, err := checkErrorCodeDoc(root)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "validator.email.renamed_away", findings[0].Code)
	assert.Contains(t, findings[0].Reason, "does not declare")
}

// A key outside the two families needs no row, and a document that gives it one is still held to
// the catalog's sentence. Both halves of that are worth pinning: the first is what keeps the
// document from growing into a translation memory, the second is what stops a row being parked
// under a prefix nobody checks.
func TestCheckErrorCodeDoc_KeysOutsideTheOwnedFamilies(t *testing.T) {
	t.Run("no row is needed", func(t *testing.T) {
		root := writeErrorCodeDocFixture(t, fakeErrorCatalog(), fakeErrorDoc())

		findings, err := checkErrorCodeDoc(root)

		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("a row that exists is still held to the catalog", func(t *testing.T) {
		doc := fakeErrorDoc() + "| `page.title` | (none) | Goiabada Authentication |\n"
		root := writeErrorCodeDocFixture(t, fakeErrorCatalog(), doc)

		findings, err := checkErrorCodeDoc(root)

		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "page.title", findings[0].Code)
	})
}

// The three ways the comparison can be meaningless. Each is an error from the finder rather than a
// finding, because every per-code check would otherwise pass vacuously.
func TestCheckErrorCodeDoc_MeaninglessComparisonsAreErrors(t *testing.T) {
	t.Run("the document is absent", func(t *testing.T) {
		root := writeErrorCodeDocFixture(t, fakeErrorCatalog(), "")

		_, err := checkErrorCodeDoc(root)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "error_codes.md")
	})

	t.Run("the catalog is absent", func(t *testing.T) {
		root := writeErrorCodeDocFixture(t, "", fakeErrorDoc())

		_, err := checkErrorCodeDoc(root)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "active.en.toml")
	})

	t.Run("the document holds no code rows", func(t *testing.T) {
		root := writeErrorCodeDocFixture(t, fakeErrorCatalog(), "# Error code taxonomy\n\nNothing yet.\n")

		_, err := checkErrorCodeDoc(root)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "no code rows")
	})

	t.Run("the catalog holds no owned keys", func(t *testing.T) {
		root := writeErrorCodeDocFixture(t, `"page.title" = "Goiabada"`+"\n", fakeErrorDoc())

		_, err := checkErrorCodeDoc(root)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "no validator. or handler. keys")
	})

	t.Run("a row whose message holds an unescaped pipe", func(t *testing.T) {
		doc := fakeErrorDoc() + "| `handler.login.account_disabled` | (none) | Disabled | see the admin |\n"
		root := writeErrorCodeDocFixture(t, fakeErrorCatalog(), doc)

		_, err := checkErrorCodeDoc(root)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "cells rather than 3")
	})
}

// The reporting half, driven the way the real caller drives it. Findings must reach Errorf, and a
// comparison that cannot be made must stop the test rather than report a clean pass.
func TestAssertErrorCodeDoc_ReportingHalf(t *testing.T) {
	t.Run("findings reach Errorf", func(t *testing.T) {
		root := writeErrorCodeDocFixture(t, fakeErrorCatalog(), docWithout(t, "validator.email.too_long"))

		report := RunGuard(func(r Reporter) { assertErrorCodeDoc(r, root) })

		assert.True(t, report.Failed())
		assert.False(t, report.Stopped, "a missing row is a finding, not a reason to stop")
		assert.Len(t, report.Errors, 1)
		assert.Contains(t, report.Text(), "validator.email.too_long")
	})

	t.Run("a walk that reached nothing is fatal", func(t *testing.T) {
		root := writeErrorCodeDocFixture(t, fakeErrorCatalog(), "")

		report := RunGuard(func(r Reporter) { assertErrorCodeDoc(r, root) })

		assert.True(t, report.Stopped, "an unreadable document must stop the test, not pass it")
		assert.Contains(t, report.Fatal, "error_codes.md")
	})

	t.Run("a matching pair says nothing", func(t *testing.T) {
		root := writeErrorCodeDocFixture(t, fakeErrorCatalog(), fakeErrorDoc())

		report := RunGuard(func(r Reporter) { assertErrorCodeDoc(r, root) })

		assert.False(t, report.Failed())
	})
}

// The real pair, read through the real root resolution. This is the case the module tiers run, and
// it is here as well so a failure names the rule rather than only the tier.
func TestCheckErrorCodeDoc_TheCommittedDocumentMatchesTheCatalog(t *testing.T) {
	findings, err := checkErrorCodeDoc(SourceRoot(t))

	require.NoError(t, err)
	assert.Empty(t, findings, "src/core/i18n/error_codes.md has drifted from catalogs/active.en.toml")
}
