package handlers

// The consent table on Clients, held to the code that decides whether a sign-in shows the consent
// screen (#522).
//
// The screen is decided in two places: /auth/completed sends a ceremony to /auth/consent when the
// request has prompt=consent, the client requires consent or the scope has offline_access
// (decideAfterBinding), and /auth/consent then skips the screen when every scope is already
// consented, unless offline_access or prompt=consent is there (consentScreenOwed). The table
// states the two together, so it is held to both, for every combination of its four conditions.
//
// It reads files and nothing else.

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

const clientsPage = "site/src/content/docs/concepts/clients.mdx"

var consentScreenSection = conceptSection{clientsPage, "## Consent required"}

// The consent table's columns, as the page heads them.
const (
	consentColumnRequired = "**Consent required**"
	consentColumnOffline  = "`offline_access` asked for"
	consentColumnPrompt   = "`prompt=consent`"
	consentColumnApproved = "The user approved every scope before"
	consentColumnScreen   = "Consent screen"
)

// consentWorld is one combination of the table's four conditions.
type consentWorld struct {
	consentRequired, offlineAccess, promptConsent, approvedBefore bool
}

func (w consentWorld) String() string {
	onOff := map[bool]string{false: "Off", true: "On"}
	yesNo := map[bool]string{false: "No", true: "Yes"}
	return fmt.Sprintf("Consent required %s, offline_access %s, prompt=consent %s, approved before %s",
		onOff[w.consentRequired], yesNo[w.offlineAccess], yesNo[w.promptConsent], yesNo[w.approvedBefore])
}

// consentWorlds is every combination of the four conditions.
func consentWorlds() []consentWorld {
	var worlds []consentWorld
	for _, required := range []bool{false, true} {
		for _, offline := range []bool{false, true} {
			for _, prompt := range []bool{false, true} {
				for _, approved := range []bool{false, true} {
					worlds = append(worlds, consentWorld{required, offline, prompt, approved})
				}
			}
		}
	}
	return worlds
}

// consentScreenShown is whether a sign-in in world sees the consent screen: decideAfterBinding's
// answer for a user holding every scope asked for, and, when that is the consent step,
// consentScreenOwed's for a stored consent covering every scope or none of them.
func consentScreenShown(t *testing.T, world consentWorld) bool {
	t.Helper()
	scope := "openid profile"
	if world.offlineAccess {
		scope += " offline_access"
	}
	answer, need := decideAfterBinding(afterBindingFacts{
		promptConsent:   world.promptConsent,
		consentRequired: world.consentRequired,
		effectiveScope:  &scope,
	})
	if need != afterBindingFactNone {
		t.Fatalf("%s: decideAfterBinding still needs fact %d with the effective scope given", world, need)
	}
	switch answer {
	case afterBindingIssue:
		return false
	case afterBindingConsent:
	default:
		t.Fatalf("%s: decideAfterBinding answered %d, neither issuance nor the consent step", world, answer)
	}
	var scopes []ScopeInfo
	for _, s := range strings.Split(scope, " ") {
		scopes = append(scopes, ScopeInfo{Scope: s, AlreadyConsented: world.approvedBefore})
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
		"| Off | Either | Either | Either | Skipped |\n"+
		"| On | No | No | Maybe | Shown |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertConsentTable(r, root, conceptSection{"site/clients.mdx", "## Consent required"}, map[consentWorld]bool{
			{false, false, false, false}: false,
			{false, true, false, false}:  true,
			{true, false, false, false}:  true,
		})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/clients.mdx: ## Consent required row 1 says the screen is skipped, the code shows it for Consent required Off, offline_access Yes, prompt=consent No, approved before No",
		`site/clients.mdx: ## Consent required row 2 says "Maybe" under "The user approved every scope before", which is not Yes, No or Either`,
		"site/clients.mdx: ## Consent required has no row for Consent required On, offline_access No, prompt=consent No, approved before No",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestConceptDocs_AConsentTableAgreeingWithTheCodePasses(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/clients.mdx", "## Consent required\n\n"+consentFixtureHeader+
		"| Off | No | No | Either | Skipped |\n"+
		"| Either | Yes | Either | Either | Shown |\n"+
		"| On | No | No | Either | Shown |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertConsentTable(r, root, conceptSection{"site/clients.mdx", "## Consent required"}, map[consentWorld]bool{
			{false, false, false, false}: false,
			{false, false, false, true}:  false,
			{false, true, false, false}:  true,
			{true, true, false, true}:    true,
			{true, false, false, true}:   true,
		})
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a table agreeing with the code was refused: %+v", report)
	}
}

func TestConceptDocs_AConsentTableWithoutItsColumnsStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/clients.mdx", "## Consent required\n\n"+
		"| **Consent required** | Consent screen |\n|---|---|\n| On | Shown |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertConsentTable(r, root, conceptSection{"site/clients.mdx", "## Consent required"},
			map[consentWorld]bool{{true, false, false, false}: true})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, consentColumnOffline) {
		t.Errorf("a table without its columns did not stop the check naming them: %+v", report)
	}
}

func TestConceptDocs_AMissingConsentSectionStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/clients.mdx", "## Consent\n\n"+consentFixtureHeader+
		"| On | No | No | No | Shown |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertConsentTable(r, root, conceptSection{"site/clients.mdx", "## Consent required"},
			map[consentWorld]bool{{true, false, false, false}: true})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Consent required") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

const consentFixtureHeader = "| **Consent required** | `offline_access` asked for | `prompt=consent` | The user approved every scope before | Consent screen |\n" +
	"|---|---|---|---|---|\n"

// assertConsentTable is the reporting half of the consent table's check: one failure per row whose
// answer differs from the code's for a combination it matches, per cell that is no condition value
// or answer, and per combination no row matches; a stop for a section, table or column not found.
func assertConsentTable(r guard.Reporter, root string, section conceptSection, want map[consentWorld]bool) {
	r.Helper()
	columns, err := conceptTableColumns(root, section, consentColumnRequired, consentColumnOffline,
		consentColumnPrompt, consentColumnApproved, consentColumnScreen)
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
		shown, known := answers[row[4]]
		if !known {
			r.Errorf("%s: %s row %d says %q under %q, which is not Shown or Skipped",
				section.page, section.heading, i+1, row[4], consentColumnScreen)
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
					i+1, strings.ToLower(row[4]), map[bool]string{false: "skips it", true: "shows it"}[want[world]], world)
			}
		}
	}
	for _, world := range worlds {
		if !matched[world] {
			r.Errorf("%s: %s has no row for %s", section.page, section.heading, world)
		}
	}
}
