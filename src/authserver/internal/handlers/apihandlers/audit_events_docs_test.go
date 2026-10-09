package apihandlers

// The audit log page's event catalog, held to the audit package's (#519 decision 6).
//
// The audit log page is where an operator reading an entry learns what its event means, and where
// an alert rule is written from. audit.EventTypes is every event the auth server writes, the list
// the viewer's filter is filled from, held in its own package to every declaration. This holds the
// page's tables to that list in both directions: an event the auth server gains without its row
// fails, and so does a row naming an event it no longer writes.
//
// It reads files and nothing else.

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/core/guard"
)

// The sections of the audit log page the checks read.
var (
	auditEventsSection = docSection{auditLogPage, "## Every event"}
	auditAlertSection  = docSection{auditLogPage, "## Events to alert on"}
)

// docAuditEventCell is a table cell holding one backticked snake_case event and nothing else. An
// event may be one word, as logout is.
var docAuditEventCell = regexp.MustCompile("^`([a-z][a-z0-9]*(?:_[a-z0-9]+)*)`$")

func TestAuditLogDocs_TheCatalogIsTheAuditPackages(t *testing.T) {
	assertAuditEventCatalog(t, filepath.Dir(guard.SourceRoot(t)), auditEventsSection, audit.EventTypes())
}

// The events that signal an attack on a credential or a grant are the ones besides the
// administrative model's an operator alerts on: each attests a replay or a guessing run the server
// refused. The administrative events in the same section are held by administrative_docs_test.go
// and administrative_scopes_docs_test.go.
func TestAuditLogDocs_TheAlertSectionNamesTheAttackSignals(t *testing.T) {
	events := make(map[string]bool)
	for _, event := range audit.EventTypes() {
		events[event] = true
	}

	assertDocNames(t, filepath.Dir(guard.SourceRoot(t)), []docNames{{
		section: auditAlertSection,
		pattern: docAuditEvent, kind: "audit event", live: events,
		skipColumn: "Details",
		want: []string{
			audit.EventRefreshTokenReplayDetected, audit.EventAuthCodeReuseDetected,
			audit.EventOTPCodeReplayDetected, audit.EventRateLimitExceeded,
		},
	}})
}

func TestAuditLogDocs_ACatalogDisagreeingWithTheCodeFails(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/audit.mdx", "## Every event\n\n"+
		"### Sign-in\n\n"+
		"| Event | Meaning |\n"+
		"|---|---|\n"+
		"| `auth_failed_pwd` | A password was refused. |\n"+
		"| `retired_event` | Gone from the code. |\n\n"+
		"### Clients\n\n"+
		"| Event | Meaning |\n"+
		"|---|---|\n"+
		"| `auth_failed_pwd` | Listed twice. |\n"+
		"| `created_client` | |\n"+
		"| deleted_client | Not backticked. |\n"+
		"| `logout` | A user signed out. | extra |\n\n"+
		"## Next\n\n| `viewed_client_secret` | Outside the section. |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertAuditEventCatalog(r, root, docSection{"site/audit.mdx", "## Every event"},
			[]string{"auth_failed_pwd", "created_client", "deleted_client", "logout", "viewed_client_secret"})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/audit.mdx: ## Every event lists retired_event, which the auth server does not write",
		"site/audit.mdx: ## Every event lists auth_failed_pwd twice",
		"site/audit.mdx: ## Every event gives created_client no meaning",
		`site/audit.mdx: ## Every event has a row whose event is not one backticked snake_case event: "deleted_client"`,
		`site/audit.mdx: ## Every event has a row of 3 cells, want event and meaning: ["` + "`logout`" + `" "A user signed out." "extra"]`,
		"site/audit.mdx: ## Every event does not list deleted_client",
		"site/audit.mdx: ## Every event does not list logout",
		"site/audit.mdx: ## Every event does not list viewed_client_secret",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestAuditLogDocs_ACatalogMatchingTheCodePasses(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/audit.mdx", "## Every event\n\n"+
		"### Sign-in\n\n"+
		"| Event | Meaning |\n"+
		"|---|---|\n"+
		"| `auth_failed_pwd` | A password was refused. |\n"+
		"| `logout` | A user signed out. |\n\n"+
		"### Clients\n\n"+
		"| Event | Meaning |\n"+
		"|---|---|\n"+
		"| `created_client` | An administrator created a client. |\n\n"+
		"## Next\n\nText.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertAuditEventCatalog(r, root, docSection{"site/audit.mdx", "## Every event"},
			[]string{"auth_failed_pwd", "created_client", "logout"})
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a catalog matching the code failed: %+v", report)
	}
}

func TestAuditLogDocs_AMissingSectionStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/audit.mdx", "## Events\n\n"+
		"| Event | Meaning |\n|---|---|\n| `logout` | A user signed out. |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertAuditEventCatalog(r, root, docSection{"site/audit.mdx", "## Every event"}, []string{"logout"})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Every event") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

func TestAuditLogDocs_ASectionWithNoTableStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/audit.mdx", "## Every event\n\n- `logout`: a user signed out.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertAuditEventCatalog(r, root, docSection{"site/audit.mdx", "## Every event"}, []string{"logout"})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "no table") {
		t.Errorf("a section without its table did not stop the check: %+v", report)
	}
}

// assertAuditEventCatalog is the reporting half of the catalog's check: one failure per finding of
// auditEventCatalogFindings; a stop for a section not found or holding no table, since a check that
// read no row proves nothing.
func assertAuditEventCatalog(r guard.Reporter, root string, section docSection, events []string) {
	r.Helper()
	findings, err := auditEventCatalogFindings(root, section, events)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, finding := range findings {
		r.Errorf("%s", finding)
	}
}

// auditEventCatalogFindings reads every table in section, one row per event with its meaning, and
// returns one finding per row that is not an event the auth server writes, lists an event a second
// time, or gives it no meaning, and then one per event in events with no row. It returns an error,
// and no findings, for a section not found or holding no table.
func auditEventCatalogFindings(root string, section docSection, events []string) ([]string, error) {
	text, err := docSectionText(root, section)
	if err != nil {
		return nil, err
	}
	rows := docEveryTableRows(text)
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: %s holds no table of the audit events", section.page, section.heading)
	}

	where := section.page + ": " + section.heading
	var findings []string
	listed := make(map[string]bool)
	for _, cells := range rows {
		if len(cells) != 2 {
			findings = append(findings, fmt.Sprintf("%s has a row of %d cells, want event and meaning: %q",
				where, len(cells), cells))
			continue
		}
		match := docAuditEventCell.FindStringSubmatch(cells[0])
		if match == nil {
			findings = append(findings, fmt.Sprintf("%s has a row whose event is not one backticked snake_case event: %q",
				where, cells[0]))
			continue
		}
		event := match[1]
		switch {
		case !slices.Contains(events, event):
			findings = append(findings, where+" lists "+event+", which the auth server does not write")
		case listed[event]:
			findings = append(findings, where+" lists "+event+" twice")
		case cells[1] == "":
			findings = append(findings, where+" gives "+event+" no meaning")
		}
		listed[event] = true
	}
	for _, event := range events {
		if !listed[event] {
			findings = append(findings, where+" does not list "+event)
		}
	}
	return findings, nil
}

// docEveryTableRows is the body rows of every Markdown table in text, in order, each trimmed cell
// in order: each table's header row and the delimiter row under it are left out.
func docEveryTableRows(text string) [][]string {
	var rows [][]string
	inTable := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			inTable = false
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if !inTable {
			inTable = true // a table's header row
			continue
		}
		if strings.Trim(strings.Join(cells, ""), "-: ") == "" {
			continue // the delimiter row
		}
		rows = append(rows, cells)
	}
	return rows
}
