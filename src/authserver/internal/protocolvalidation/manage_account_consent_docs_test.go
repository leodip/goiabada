package protocolvalidation

// The refresh refusals for authserver:manage-account, held to the refresh token grant that answers
// them (#509 decision 3).
//
// A refresh renewing authserver:manage-account for a client other than the admin console's is
// refused with invalid_grant while the user's stored consent does not cover it, whatever the
// client's Consent required says. The token endpoint's reference quotes the two answers, and the
// refresh tokens page and the troubleshooting page say when a refresh is checked against the
// consent. Before #509 both said only a client requiring consent and an offline token were, so an
// integrator whose consent-off client is refused would find no reason there.
//
// It reads files and nothing else.

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/docsreader"
	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/oauth"
)

// The sections, relative to the repository root.
var (
	refreshGrantSection   = refreshDocSection{"site/src/content/docs/reference/endpoints/token.mdx", "## Refresh token grant"}
	refreshChecksSection  = refreshDocSection{"site/src/content/docs/concepts/refresh-tokens.mdx", "## What a refresh checks"}
	refreshReasonsSection = refreshDocSection{"site/src/content/docs/troubleshooting/this-refresh-token-has-been-revoked.mdx", "## Other reasons a refresh fails"}
)

// refreshDocSection is one section of a page: the page, and its heading line as written.
type refreshDocSection struct{ page, heading string }

const refreshManageAccountScope = builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier

// manageAccountRefreshRefusals is what the refresh token grant answers a consent-off client renewing
// authserver:manage-account, with no stored consent and with one leaving it out, read from the
// validator over the stored-grant harness.
func manageAccountRefreshRefusals(t *testing.T) []string {
	t.Helper()
	var descriptions []string
	for _, consentScope := range []string{"", "openid"} {
		grant := storedGrant{scope: "openid " + refreshManageAccountScope, readsConsent: true, consentScope: consentScope}
		validator, _, settings, input := newStoredGrantRefresh(t, grant, "", true)

		_, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		var detail *oauth.ErrorDetail
		require.ErrorAs(t, err, &detail, "the refresh of %q with consent %q is not refused", grant.scope, consentScope)
		require.Equal(t, "invalid_grant", detail.Code())
		descriptions = append(descriptions, detail.Description())
	}
	return descriptions
}

// The token endpoint's refresh section quotes both answers and names the scope; the refresh tokens
// page names the scope among what a refresh checks; and the troubleshooting page has a row for each
// answer saying a manage-account refresh is checked.
func TestManageAccountRefreshDocs_ThePagesGiveTheRefusals(t *testing.T) {
	refusals := manageAccountRefreshRefusals(t)
	root := filepath.Dir(guard.SourceRoot(t))
	scope := "`" + refreshManageAccountScope + "`"

	guard.AssertSectionSays(t, root, refreshGrantSection.page, refreshGrantSection.heading,
		append([]string{scope}, refusals...), nil)
	guard.AssertSectionSays(t, root, refreshChecksSection.page, refreshChecksSection.heading,
		[]string{scope, "admin console"}, nil)
	assertRefreshReasonRows(t, root, refreshReasonsSection, refusals, scope)
}

func TestManageAccountRefreshDocs_APageMissingAnAnswerFails(t *testing.T) {
	root := t.TempDir()
	writeRefreshDocFixture(t, root, "site/revoked.mdx", "## Other reasons\n\n| `error_description` | Why |\n|---|---|\n"+
		"| \"No consent.\" | The user withdrew their consent. |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertRefreshReasonRows(r, root, refreshDocSection{"site/revoked.mdx", "## Other reasons"},
			[]string{"No consent.", "Not consented."}, "`authserver:manage-account`")
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/revoked.mdx: ## Other reasons row 1, \"No consent.\", does not name `authserver:manage-account` in its Why",
		"site/revoked.mdx: ## Other reasons has no row for \"Not consented.\"",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestManageAccountRefreshDocs_APageGivingTheAnswersPasses(t *testing.T) {
	root := t.TempDir()
	writeRefreshDocFixture(t, root, "site/revoked.mdx", "## Other reasons\n\n| `error_description` | Why |\n|---|---|\n"+
		"| \"No consent.\" | Checked for `authserver:manage-account` too. |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertRefreshReasonRows(r, root, refreshDocSection{"site/revoked.mdx", "## Other reasons"},
			[]string{"No consent."}, "`authserver:manage-account`")
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a page giving the answers was refused: %+v", report)
	}
}

// A row in a fenced example is not a row of the section's table, so it answers for no description.
func TestManageAccountRefreshDocs_ARowInAFencedExampleIsNoRow(t *testing.T) {
	root := t.TempDir()
	writeRefreshDocFixture(t, root, "site/revoked.mdx", "## Other reasons\n\n| `error_description` | Why |\n|---|---|\n"+
		"| \"No consent.\" | Checked for `authserver:manage-account` too. |\n\n"+
		"```md\n| \"Not consented.\" | Checked for `authserver:manage-account` too. |\n```\n")

	report := guard.Run(func(r guard.Reporter) {
		assertRefreshReasonRows(r, root, refreshDocSection{"site/revoked.mdx", "## Other reasons"},
			[]string{"No consent.", "Not consented."}, "`authserver:manage-account`")
	})

	want := []string{"site/revoked.mdx: ## Other reasons has no row for \"Not consented.\""}
	if report.Stopped || !slices.Equal(report.Errors, want) {
		t.Errorf("failures %+v, want exactly %q", report, want)
	}
}

func TestManageAccountRefreshDocs_AMissingSectionStops(t *testing.T) {
	root := t.TempDir()
	writeRefreshDocFixture(t, root, "site/revoked.mdx", "## Other reasons a refresh fails\n\n| `error_description` | Why |\n|---|---|\n")

	report := guard.Run(func(r guard.Reporter) {
		assertRefreshReasonRows(r, root, refreshDocSection{"site/revoked.mdx", "## Other reasons"},
			[]string{"No consent."}, "`authserver:manage-account`")
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Other reasons") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

// assertRefreshReasonRows is the reporting half of the table check: one failure per description with
// no row whose first cell quotes it, and per such row whose last cell does not hold text; a stop for a
// section not found.
func assertRefreshReasonRows(r guard.Reporter, root string, section refreshDocSection, descriptions []string, text string) {
	r.Helper()
	body, err := docsreader.Section(root, section.page, section.heading)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	rows := docsreader.Rows(body)
	for _, description := range descriptions {
		found := false
		for i, row := range rows {
			if row[0] != `"`+description+`"` {
				continue
			}
			found = true
			if !strings.Contains(row[len(row)-1], text) {
				r.Errorf("%s: %s row %d, %q, does not name %s in its Why", section.page, section.heading, i+1, description, text)
			}
		}
		if !found {
			r.Errorf("%s: %s has no row for %q", section.page, section.heading, description)
		}
	}
}

func writeRefreshDocFixture(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}
