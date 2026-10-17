package authflow

// The pages that say when the consent screen is owed for authserver:manage-account, held to the code
// that owes it (#509).
//
// A client other than the admin console's gets authserver:manage-account only once the user's
// stored consent covers it, whatever its Consent required says. The Clients page's consent section
// says so beside its table, and the silent checks on prompt name the condition beside the two
// consent_required answers, which a client with Consent required off now gets too. An integrator
// reading either page and finding only Consent required and offline_access there would not expect
// the screen, or the refusal, that the code gives them.
//
// The guard drives decideSilentAuthentication and reads the site through core/docsreader, so it
// lives here with the decision and needs no HTTP harness (#584).
//
// It reads files and nothing else.

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/guard"
)

// The Clients page's consent section names the scope the table's column is about, and the one client
// its Yes leaves out, which no row can show.
func TestConceptDocs_TheConsentSectionSaysWhoIsAskedForManageAccount(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), consentScreenSection.page, consentScreenSection.heading,
		[]string{"`" + consentManageAccountScope + "`", "admin console's own client"}, nil)
}

// manageAccountSilentRefusals is what decideSilentAuthentication answers a prompt=none request from a
// client with Consent required off, other than the admin console's, whose scope holds
// authserver:manage-account: with no stored consent, and with one leaving manage-account out. It
// fails when the code answers either with no refusal, or refuses the admin console's client, since
// the page's sentences would then describe nothing.
func manageAccountSilentRefusals(t *testing.T) []silentRefusal {
	t.Helper()
	scope := func(s string) *string { return &s }
	world := silentWorld{
		valid:            true,
		subject:          "sub-1",
		target:           record.AcrLevel1,
		sessionAcr:       record.AcrLevel1,
		effectiveScope:   "openid " + consentManageAccountScope,
		clientIdentifier: "my-app",
	}

	var refusals []silentRefusal
	for _, consentScope := range []*string{nil, scope("openid")} {
		world.consentScope = consentScope
		answer, _ := driveSilentAuthentication(t, world)
		if answer.ErrorCode == "" {
			t.Fatalf("decideSilentAuthentication refuses nothing for %+v", world)
		}
		refusals = append(refusals, silentRefusal{answer.ErrorCode, answer.ErrorDescription})
	}

	world.consentScope = nil
	world.clientIdentifier = builtin.AdminConsoleClientIdentifier
	if answer, _ := driveSilentAuthentication(t, world); answer.ErrorCode != "" {
		t.Fatalf("decideSilentAuthentication refuses the admin console's client with %s %q",
			answer.ErrorCode, answer.ErrorDescription)
	}
	return refusals
}

// Each answer prompt=none gives a consent-off client asking for authserver:manage-account without a
// covering consent has its row in the silent checks table, and that row's check names the scope.
func TestConceptDocs_TheSilentConsentChecksNameManageAccount(t *testing.T) {
	assertSilentChecksName(t, filepath.Dir(guard.SourceRoot(t)), silentChecksSection,
		manageAccountSilentRefusals(t), consentManageAccountScope)
}

func TestConceptDocs_ASilentCheckNotNamingTheScopeFails(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/prompt.mdx", "## The silent checks\n\n"+silentChecksFixtureHeader+
		"| The user has consented, when the client requires it | `consent_required` | \"User consent is required\" |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSilentChecksName(r, root, conceptSection{"site/prompt.mdx", "## The silent checks"}, []silentRefusal{
			{"consent_required", "User consent is required"},
			{"consent_required", "Additional consent is required"},
		}, "authserver:manage-account")
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/prompt.mdx: ## The silent checks row 1, consent_required \"User consent is required\", does not name authserver:manage-account in its check",
		"site/prompt.mdx: ## The silent checks has no row for consent_required \"Additional consent is required\"",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestConceptDocs_ASilentCheckNamingTheScopePasses(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/prompt.mdx", "## The silent checks\n\n"+silentChecksFixtureHeader+
		"| The browser has a session | `login_required` | \"User authentication is required\" |\n"+
		"| A consent, when the scope holds `authserver:manage-account` | `consent_required` | \"User consent is required\" |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSilentChecksName(r, root, conceptSection{"site/prompt.mdx", "## The silent checks"},
			[]silentRefusal{{"consent_required", "User consent is required"}}, "authserver:manage-account")
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a table naming the scope was refused: %+v", report)
	}
}

func TestConceptDocs_ASilentChecksTableWithoutItsCheckColumnStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/prompt.mdx", "## The silent checks\n\n"+
		"| `error` | `error_description` |\n|---|---|\n| `consent_required` | \"User consent is required\" |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSilentChecksName(r, root, conceptSection{"site/prompt.mdx", "## The silent checks"},
			[]silentRefusal{{"consent_required", "User consent is required"}}, "authserver:manage-account")
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "Check") {
		t.Errorf("a table without its check column did not stop the check naming it: %+v", report)
	}
}

const silentChecksFixtureHeader = "| Check | `error` | `error_description` |\n|---|---|---|\n"

// assertSilentChecksName is the reporting half of the check that the silent checks table states a
// condition: one failure per refusal with no row, and per row of a refusal whose check does not hold
// text; a stop for a section, table or column not found.
func assertSilentChecksName(r guard.Reporter, root string, section conceptSection, refusals []silentRefusal, text string) {
	r.Helper()
	columns, err := conceptTableColumns(root, section, "Check", "`error`", "`error_description`")
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, refusal := range refusals {
		found := false
		for i, row := range columns {
			if (silentRefusal{row[1], row[2]}) != refusal {
				continue
			}
			found = true
			if !strings.Contains(row[0], text) {
				r.Errorf("%s: %s row %d, %s %q, does not name %s in its check",
					section.page, section.heading, i+1, refusal.code, refusal.description, text)
			}
		}
		if !found {
			r.Errorf("%s: %s has no row for %s %q", section.page, section.heading, refusal.code, refusal.description)
		}
	}
}
