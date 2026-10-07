package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// The sections that tell an operator how to turn the metrics listener on and what to read beside
// it. The auth server's tier reads the same sections.
var monitoringDocs = []docSection{
	{"site/src/content/docs/deploy/monitoring.mdx", "## Turning the endpoint on"},
	{"site/src/content/docs/deploy/monitoring.mdx", "## Scraping the endpoint"},
	{"site/src/content/docs/deploy/monitoring.mdx", "## Metrics catalog"},
	{"site/src/content/docs/deploy/monitoring.mdx", "## Suggested alerts"},
	{"site/src/content/docs/deploy/monitoring.mdx", "## What to watch in the logs"},
	{"site/src/content/docs/deploy/kubernetes.mdx", "## Metrics"},
}

// The monitoring docs name only admin console variables this console reads. A misspelt switch is
// ignored, so the listener an operator turned on never starts, the scraper reports the target
// down, and nothing in the console's log says why. Every other GOIABADA_ variable is the auth
// server's tier to check (#400 decision 9).
func TestMonitoringDocs_NameOnlyVariablesTheConsoleReads(t *testing.T) {
	assertDocsNameOnlyReadVariables(t, filepath.Dir(guard.SourceRoot(t)), monitoringDocs, readVariables())
}

func TestMonitoringDocs_AnUnreadVariableFails(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/monitoring.mdx", "## Turning the endpoint on\n\n"+
		"Set GOIABADA_ADMINCONSOLE_METRICS_ENABLE, and GOIABADA_AUTHSERVER_METRICS_ENABLED for the auth server.\n\n"+
		"```bash\nGOIABADA_ADMINCONSOLE_LISTEN_PORT_METRICS=9191 ./goiabada-adminconsole\n```\n\n"+
		"## Next\n\nGOIABADA_ADMINCONSOLE_AFTER_THE_SECTION\n")

	report := guard.Run(func(r guard.Reporter) {
		assertDocsNameOnlyReadVariables(r, root, []docSection{{"site/monitoring.mdx", "## Turning the endpoint on"}},
			map[string]bool{"GOIABADA_ADMINCONSOLE_METRICS_ENABLED": true, "GOIABADA_ADMINCONSOLE_LISTEN_PORT_METRICS": true})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := "site/monitoring.mdx: ## Turning the endpoint on names GOIABADA_ADMINCONSOLE_METRICS_ENABLE, which this console does not read"
	if len(report.Errors) != 1 || report.Errors[0] != want {
		t.Errorf("failures %q, want exactly %q", report.Errors, want)
	}
}

func TestMonitoringDocs_AMissingSectionStops(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/monitoring.mdx", "## Turning it on\n\nGOIABADA_ADMINCONSOLE_METRICS_ENABLED\n")

	report := guard.Run(func(r guard.Reporter) {
		assertDocsNameOnlyReadVariables(r, root, []docSection{{"site/monitoring.mdx", "## Turning the endpoint on"}},
			map[string]bool{"GOIABADA_ADMINCONSOLE_METRICS_ENABLED": true})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Turning the endpoint on") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

// assertDocsNameOnlyReadVariables is the reporting half: one failure per admin console variable a
// section names that read does not hold, and a stop for a section not found.
func assertDocsNameOnlyReadVariables(r guard.Reporter, root string, sections []docSection, read map[string]bool) {
	r.Helper()
	for _, s := range sections {
		text, err := docSectionText(root, s)
		if err != nil {
			r.Fatalf("%v", err)
			return
		}
		seen := map[string]bool{}
		for _, name := range docVariable.FindAllString(text, -1) {
			if seen[name] || read[name] {
				continue
			}
			seen[name] = true
			r.Errorf("%s: %s names %s, which this console does not read", s.page, s.heading, name)
		}
	}
}
