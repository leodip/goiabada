package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

const (
	monitoringPage        = "site/src/content/docs/deploy/monitoring.mdx"
	logsPage              = "site/src/content/docs/deploy/logs.mdx"
	productionChecklist   = "site/src/content/docs/deploy/production-checklist.mdx"
	metricsNotScrapedPage = "site/src/content/docs/troubleshooting/metrics-are-not-scraped.mdx"
)

// The sections that tell an operator how to turn the metrics listener on, how to scrape it, what to
// alert on and what to read beside it, and the checklist that sends them there. The admin console's
// tier reads the same sections.
var monitoringDocs = []docSection{
	{monitoringPage, "## Turn the metrics on"},
	{monitoringPage, "## Scrape on Kubernetes"},
	{monitoringPage, "## Scrape outside Kubernetes"},
	{monitoringPage, "## Set up alerts"},
	{monitoringPage, "## How it works"},
	{logsPage, ""},
	{productionChecklist, ""},
	{metricsNotScrapedPage, "## Why it happens"},
	{metricsNotScrapedPage, "## Fix it"},
}

// The monitoring docs name only variables this server reads. A misspelt switch is ignored, so the
// listener an operator turned on never starts, the scraper reports the target down, and nothing in
// the server's log says why. The admin console's own variables are its tier to check (#400
// decision 9).
func TestMonitoringDocs_NameOnlyVariablesTheServerReads(t *testing.T) {
	assertDocsNameOnlyReadVariables(t, filepath.Dir(guard.SourceRoot(t)), monitoringDocs, readVariables())
}

func TestMonitoringDocs_AnUnreadVariableFails(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/monitoring.mdx", "## Turn the metrics on\n\n"+
		"Set GOIABADA_AUTHSERVER_METRICS_ENABLE, and GOIABADA_ADMINCONSOLE_METRICS_ENABLED for the console.\n\n"+
		"```bash\nGOIABADA_AUTHSERVER_LISTEN_PORT_METRICS=9190 ./goiabada-authserver\n```\n\n"+
		"## Next\n\nGOIABADA_AFTER_THE_SECTION\n")

	report := guard.Run(func(r guard.Reporter) {
		assertDocsNameOnlyReadVariables(r, root, []docSection{{"site/monitoring.mdx", "## Turn the metrics on"}},
			map[string]bool{"GOIABADA_AUTHSERVER_METRICS_ENABLED": true, "GOIABADA_AUTHSERVER_LISTEN_PORT_METRICS": true})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := "site/monitoring.mdx: ## Turn the metrics on names GOIABADA_AUTHSERVER_METRICS_ENABLE, which this server does not read"
	if len(report.Errors) != 1 || report.Errors[0] != want {
		t.Errorf("failures %q, want exactly %q", report.Errors, want)
	}
}

func TestMonitoringDocs_AMissingSectionStops(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/monitoring.mdx", "## Turning it on\n\nGOIABADA_AUTHSERVER_METRICS_ENABLED\n")

	report := guard.Run(func(r guard.Reporter) {
		assertDocsNameOnlyReadVariables(r, root, []docSection{{"site/monitoring.mdx", "## Turn the metrics on"}},
			map[string]bool{"GOIABADA_AUTHSERVER_METRICS_ENABLED": true})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Turn the metrics on") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

// assertDocsNameOnlyReadVariables is the reporting half: one failure per variable a section names
// that read does not hold, the admin console's own excepted, and a stop for a section not found.
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
			if seen[name] || read[name] || strings.HasPrefix(name, "GOIABADA_ADMINCONSOLE_") {
				continue
			}
			seen[name] = true
			r.Errorf("%s names %s, which this server does not read", s, name)
		}
	}
}
