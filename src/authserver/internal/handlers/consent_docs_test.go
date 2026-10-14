package handlers

// The consent table on Clients, held to the code that decides whether a sign-in shows the consent
// screen (#522).
//
// The screen is decided in two places: /auth/completed sends a ceremony to /auth/consent when the
// request has prompt=consent, the client requires consent or the scope has offline_access, or when
// the scope holds authserver:manage-account, the client is not the admin console's and the user's
// stored consent does not cover it (authflow.DecideAfterBinding, #509), and /auth/consent then skips
// the screen when every scope is already consented, unless offline_access or prompt=consent is there
// (consentScreenOwed). The table states the two together, so it is held to both, for every
// combination of its five conditions and of the client being the admin console's or not, which the
// manage-account column folds in.
//
// It reads files and nothing else.

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/authflow"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/guard"
)

const clientsPage = "site/src/content/docs/concepts/clients.mdx"

var consentScreenSection = conceptSection{clientsPage, "## Consent required"}

// The consent table's columns, as the page heads them.
const (
	consentColumnRequired = "**Consent required**"
	consentColumnOffline  = "`offline_access` asked for"
	consentColumnPrompt   = "`prompt=consent`"
	consentColumnAccount  = "`authserver:manage-account` asked for"
	consentColumnApproved = "Stored consent covers what's required"
	consentColumnScreen   = "Consent screen"
)

// consentManageAccountScope is authserver:manage-account as a request spells it.
const consentManageAccountScope = builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier

// consentWorld is one combination of the table's five conditions, and of the client being the admin
// console's or another. The manage-account column reads Yes only for another client asking for it:
// the admin console's asking for it is a No, which is the exemption the section states.
type consentWorld struct {
	consentRequired, offlineAccess, promptConsent, manageAccount, adminConsole, approvedBefore bool
}

func (w consentWorld) String() string {
	onOff := map[bool]string{false: "Off", true: "On"}
	yesNo := map[bool]string{false: "No", true: "Yes"}
	client := map[bool]string{false: "another client", true: "the admin console's client"}
	return fmt.Sprintf("Consent required %s, offline_access %s, prompt=consent %s, manage-account %s by %s, approved before %s",
		onOff[w.consentRequired], yesNo[w.offlineAccess], yesNo[w.promptConsent], yesNo[w.manageAccount],
		client[w.adminConsole], yesNo[w.approvedBefore])
}

// consentWorlds is every combination of the conditions.
func consentWorlds() []consentWorld {
	var worlds []consentWorld
	both := []bool{false, true}
	for _, required := range both {
		for _, offline := range both {
			for _, prompt := range both {
				for _, account := range both {
					for _, adminConsole := range both {
						for _, approved := range both {
							worlds = append(worlds, consentWorld{required, offline, prompt, account, adminConsole, approved})
						}
					}
				}
			}
		}
	}
	return worlds
}

// consentScreenShown is whether a sign-in in world sees the consent screen:
// authflow.DecideAfterBinding's answer for a user holding every scope asked for, given stored consent covering the scopes this
// world requires or none, and, when that is the consent step, consentScreenOwed's for the same
// consent. With Consent required off, manage-account alone is enough even when another requested
// scope was never approved; this partial-consent case keeps the table's approval column honest.
func consentScreenShown(t *testing.T, world consentWorld) bool {
	t.Helper()
	scope := "openid profile"
	if world.offlineAccess {
		scope += " offline_access"
	}
	if world.manageAccount {
		scope += " " + consentManageAccountScope
	}
	clientIdentifier := "my-app"
	if world.adminConsole {
		clientIdentifier = builtin.AdminConsoleClientIdentifier
	}
	var storedConsent *record.UserConsent
	if world.approvedBefore {
		consentedScope := scope
		if world.manageAccount && !world.consentRequired && !world.adminConsole {
			consentedScope = consentManageAccountScope
		}
		storedConsent = &record.UserConsent{Scope: consentedScope}
	}
	facts := authflow.AfterBindingFacts{
		PromptConsent:    world.promptConsent,
		ConsentRequired:  world.consentRequired,
		ClientIdentifier: clientIdentifier,
		EffectiveScope:   &scope,
	}
	answer, need := authflow.DecideAfterBinding(facts)
	if need == authflow.AfterBindingFactConsent {
		facts.ConsentLoaded = true
		facts.Consent = storedConsent
		answer, need = authflow.DecideAfterBinding(facts)
	}
	if need != authflow.AfterBindingFactNone {
		t.Fatalf("%s: DecideAfterBinding still needs fact %d with the effective scope and the consent given", world, need)
	}
	switch answer {
	case authflow.AfterBindingIssue:
		return false
	case authflow.AfterBindingConsent:
	default:
		t.Fatalf("%s: DecideAfterBinding answered %d, neither issuance nor the consent step", world, answer)
	}
	var scopes []ScopeInfo
	for _, s := range strings.Split(scope, " ") {
		scopes = append(scopes, ScopeInfo{Scope: s, AlreadyConsented: storedConsent != nil && storedConsent.HasScope(s)})
	}
	return consentScreenOwed(scopes, scope, world.promptConsent)
}

// consentScreens is consentScreenShown for every world.
func consentScreens(t *testing.T) map[consentWorld]bool {
	t.Helper()
	screens := map[consentWorld]bool{}
	for _, world := range consentWorlds() {
		screens[world] = consentScreenShown(t, world)
	}
	return screens
}

// The consent table on Clients says when a user sees the consent screen, and an administrator
// deciding whether to turn Consent required on reads it there. Every row is what the code decides
// for each combination of conditions it matches, and every combination is matched by a row.
func TestConceptDocs_TheConsentTableIsWhenTheCodeShowsTheScreen(t *testing.T) {
	assertConsentTable(t, filepath.Dir(guard.SourceRoot(t)), consentScreenSection, consentScreens(t))
}

func TestConceptDocs_AConsentTableDisagreeingWithTheCodeFails(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/clients.mdx", "## Consent required\n\n"+consentFixtureHeader+
		"| Off | Either | Either | No | Either | Skipped |\n"+
		"| On | No | No | No | Maybe | Shown |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertConsentTable(r, root, conceptSection{"site/clients.mdx", "## Consent required"}, map[consentWorld]bool{
			{}:                      false,
			{offlineAccess: true}:   true,
			{consentRequired: true}: true,
			{manageAccount: true}:   true,
			{manageAccount: true, adminConsole: true}: false,
		})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/clients.mdx: ## Consent required row 1 says the screen is skipped, the code shows it for Consent required Off, offline_access Yes, prompt=consent No, manage-account No by another client, approved before No",
		`site/clients.mdx: ## Consent required row 2 says "Maybe" under "Stored consent covers what's required", which is not Yes, No or Either`,
		"site/clients.mdx: ## Consent required has no row for Consent required Off, offline_access No, prompt=consent No, manage-account Yes by another client, approved before No",
		"site/clients.mdx: ## Consent required has no row for Consent required On, offline_access No, prompt=consent No, manage-account No by another client, approved before No",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestConceptDocs_AConsentTableAgreeingWithTheCodePasses(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/clients.mdx", "## Consent required\n\n"+consentFixtureHeader+
		"| Off | No | No | No | Either | Skipped |\n"+
		"| Off | No | No | Yes | No | Shown |\n"+
		"| Either | Yes | Either | Either | Either | Shown |\n"+
		"| On | No | No | Either | Either | Shown |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertConsentTable(r, root, conceptSection{"site/clients.mdx", "## Consent required"}, map[consentWorld]bool{
			{}:                     false,
			{approvedBefore: true}: false,
			{manageAccount: true, adminConsole: true}: false,
			{manageAccount: true}:                     true,
			{offlineAccess: true}:                     true,
			{consentRequired: true, offlineAccess: true, approvedBefore: true}: true,
			{consentRequired: true, approvedBefore: true}:                      true,
		})
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a table agreeing with the code was refused: %+v", report)
	}
}

func TestConceptDocs_AConsentTableWithoutItsColumnsStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/clients.mdx", "## Consent required\n\n"+
		"| **Consent required** | `offline_access` asked for | `prompt=consent` | Stored consent covers what's required | Consent screen |\n"+
		"|---|---|---|---|---|\n| On | No | No | No | Shown |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertConsentTable(r, root, conceptSection{"site/clients.mdx", "## Consent required"},
			map[consentWorld]bool{{consentRequired: true}: true})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, consentColumnAccount) {
		t.Errorf("a table without its columns did not stop the check naming them: %+v", report)
	}
}

func TestConceptDocs_AMissingConsentSectionStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/clients.mdx", "## Consent\n\n"+consentFixtureHeader+
		"| On | No | No | No | No | Shown |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertConsentTable(r, root, conceptSection{"site/clients.mdx", "## Consent required"},
			map[consentWorld]bool{{consentRequired: true}: true})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Consent required") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

const consentFixtureHeader = "| **Consent required** | `offline_access` asked for | `prompt=consent` | `authserver:manage-account` asked for | Stored consent covers what's required | Consent screen |\n" +
	"|---|---|---|---|---|---|\n"

// assertConsentTable is the reporting half of the consent table's check: one failure per row whose
// answer differs from the code's for a combination it matches, per cell that is no condition value
// or answer, and per combination no row matches; a stop for a section, table or column not found.
func assertConsentTable(r guard.Reporter, root string, section conceptSection, want map[consentWorld]bool) {
	r.Helper()
	columns, err := conceptTableColumns(root, section, consentColumnRequired, consentColumnOffline,
		consentColumnPrompt, consentColumnAccount, consentColumnApproved, consentColumnScreen)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	conditions := []struct {
		header        string
		no, yes       string
		valueForWorld func(consentWorld) bool
	}{
		{consentColumnRequired, "Off", "On", func(w consentWorld) bool { return w.consentRequired }},
		{consentColumnOffline, "No", "Yes", func(w consentWorld) bool { return w.offlineAccess }},
		{consentColumnPrompt, "No", "Yes", func(w consentWorld) bool { return w.promptConsent }},
		{consentColumnAccount, "No", "Yes", func(w consentWorld) bool { return w.manageAccount && !w.adminConsole }},
		{consentColumnApproved, "No", "Yes", func(w consentWorld) bool { return w.approvedBefore }},
	}
	answers := map[string]bool{"Skipped": false, "Shown": true}
	matched := map[consentWorld]bool{}
	worlds := make([]consentWorld, 0, len(want))
	for world := range want {
		worlds = append(worlds, world)
	}
	slices.SortFunc(worlds, func(a, b consentWorld) int { return strings.Compare(a.String(), b.String()) })

	for i, row := range columns {
		cellsRead := true
		for c, condition := range conditions {
			if cell := row[c]; cell != condition.no && cell != condition.yes && cell != "Either" {
				r.Errorf("%s: %s row %d says %q under %q, which is not %s, %s or Either",
					section.page, section.heading, i+1, cell, condition.header, condition.yes, condition.no)
				cellsRead = false
			}
		}
		screen := row[len(conditions)]
		shown, known := answers[screen]
		if !known {
			r.Errorf("%s: %s row %d says %q under %q, which is not Shown or Skipped",
				section.page, section.heading, i+1, screen, consentColumnScreen)
			cellsRead = false
		}
		if !cellsRead {
			continue
		}
		for _, world := range worlds {
			matches := true
			for c, condition := range conditions {
				if cell := row[c]; cell != "Either" && (cell == condition.yes) != condition.valueForWorld(world) {
					matches = false
				}
			}
			if !matches {
				continue
			}
			matched[world] = true
			if shown != want[world] {
				r.Errorf("%s: %s row %d says the screen is %s, the code %s for %s", section.page, section.heading,
					i+1, strings.ToLower(screen), map[bool]string{false: "skips it", true: "shows it"}[want[world]], world)
			}
		}
	}
	for _, world := range worlds {
		if !matched[world] {
			r.Errorf("%s: %s has no row for %s", section.page, section.heading, world)
		}
	}
}
