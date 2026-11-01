package server

// The docs on what each server's HTTP listener does, held to the redirecting listener (#715
// decision 7).
//
// With an https base URL, the HTTP listener serves only with TRUST_PROXY_HEADERS on, and otherwise
// only redirects. The rule has one home, the environment-variables page's Listen addresses section,
// which states the redirect's status and the health check the listener still answers, as the real
// listener answers them. Every other place an operator decides about the listener, its trust or HSTS
// says the listener redirects and links to that home, so a reader who meets a redirect loop or a
// missing page finds the rule.
//
// It reads files, and sends two requests to a redirecting listener on a loopback port.

import (
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/docsreader"
	"github.com/leodip/goiabada/core/guard"
)

// listenerRuleHome is the section holding the HTTP listener's rule.
var listenerRuleHome = docSection{"site/src/content/docs/reference/environment-variables.mdx", "## Listen addresses"}

// listenerRulePlace is a section, or one row of its tables when row names the row's first-cell code
// span, that must say the HTTP listener redirects and link to the rule's home with link.
type listenerRulePlace struct {
	section docSection
	row     string
	link    string
}

const listenerRuleLink = "(/reference/environment-variables/#listen-addresses)"

var listenerRulePlaces = []listenerRulePlace{
	{docSection{"site/src/content/docs/reference/environment-variables.mdx", "## Every variable"}, "GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS", "(#listen-addresses)"},
	{docSection{"site/src/content/docs/reference/environment-variables.mdx", "## Every variable"}, "GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS", "(#listen-addresses)"},
	{docSection{"site/src/content/docs/reference/security.mdx", "## Response headers"}, "Strict-Transport-Security", listenerRuleLink},
	{docSection{"site/src/content/docs/deploy/reverse-proxy.mdx", "## What this setup gives you"}, "", listenerRuleLink},
	{docSection{"site/src/content/docs/deploy/native-binaries.mdx", "## Serve HTTPS without a proxy"}, "", listenerRuleLink},
	{docSection{"site/src/content/docs/deploy/production-checklist.mdx", "## Network"}, "", listenerRuleLink},
}

// The rule's home states the status the redirecting listener answers with and the health check it
// still answers, as a redirecting listener on a loopback port answers them, and names the trust
// setting that tells the two modes apart.
func TestHTTPListenerDocs_TheRulesHomeIsWhatTheListenerAnswers(t *testing.T) {
	addr := serveHTTPListener(t, redirectingServer(t))
	redirect, _ := sendToHTTPListener(t, addr, http.MethodGet, "GET /auth/authorize HTTP/1.1\r\nHost: auth.example.com\r\nConnection: close\r\n\r\n")
	health, _ := sendToHTTPListener(t, addr, http.MethodGet, "GET /health HTTP/1.1\r\nHost: auth.example.com\r\nConnection: close\r\n\r\n")
	if health.StatusCode != http.StatusOK {
		t.Fatalf("the redirecting listener answered GET /health with %d, so the page has no health check to name", health.StatusCode)
	}

	assertListenerRuleHome(t, filepath.Dir(guard.SourceRoot(t)), listenerRuleHome, redirect.StatusCode, "/health")
}

// Every place the rule is met says the listener redirects and links to the rule's home.
func TestHTTPListenerDocs_EveryPlaceLinksToTheRule(t *testing.T) {
	assertListenerRulePlaces(t, filepath.Dir(guard.SourceRoot(t)), listenerRulePlaces)
}

func TestHTTPListenerDocs_AHomeMissingTheListenersAnswersFails(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/env.mdx", "## Listen addresses\n\n"+
		"With `TRUST_PROXY_HEADERS` off, the HTTP listener answers with a `302`, health checks included.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertListenerRuleHome(r, root, docSection{"site/env.mdx", "## Listen addresses"}, http.StatusMovedPermanently, "/health")
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/env.mdx: ## Listen addresses does not name the redirect's status `301`",
		"site/env.mdx: ## Listen addresses does not name `/health`, which the redirecting listener still answers",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestHTTPListenerDocs_AHomeStatingTheListenersAnswersPasses(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/env.mdx", "## Listen addresses\n\n"+
		"With `TRUST_PROXY_HEADERS` off, the HTTP listener answers a `301`, except `GET /health`.\n\n"+
		"## Next\n")

	report := guard.Run(func(r guard.Reporter) {
		assertListenerRuleHome(r, root, docSection{"site/env.mdx", "## Listen addresses"}, http.StatusMovedPermanently, "/health")
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a home stating the listener's answers was refused: %+v", report)
	}
}

func TestHTTPListenerDocs_PlacesNotLinkingToTheRuleFail(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/env.mdx", "## Every variable\n\n"+
		"| Variable | What it does |\n|---|---|\n"+
		"| `GOIABADA_A`<br/>Read by: both | It redirects. See [listen addresses](#listen-addresses). |\n"+
		"| `GOIABADA_B`<br/>Read by: both | It serves. See [listen addresses](#listen-addresses). |\n"+
		"| `GOIABADA_C`<br/>Read by: both | It redirects, with no link. |\n")
	writeDocFixture(t, root, "site/proxy.mdx", "## What you get\n\n- Plain HTTP is redirected. See [Listen addresses](/reference/environment-variables/#listen-addresses).\n")
	writeDocFixture(t, root, "site/checklist.mdx", "## Network\n\n- HTTPS everywhere.\n\n## Next\n\nRedirected: [rule](/reference/environment-variables/#listen-addresses).\n")

	link := "(/reference/environment-variables/#listen-addresses)"
	report := guard.Run(func(r guard.Reporter) {
		assertListenerRulePlaces(r, root, []listenerRulePlace{
			{docSection{"site/env.mdx", "## Every variable"}, "GOIABADA_A", "(#listen-addresses)"},
			{docSection{"site/env.mdx", "## Every variable"}, "GOIABADA_B", "(#listen-addresses)"},
			{docSection{"site/env.mdx", "## Every variable"}, "GOIABADA_C", "(#listen-addresses)"},
			{docSection{"site/env.mdx", "## Every variable"}, "GOIABADA_D", "(#listen-addresses)"},
			{docSection{"site/proxy.mdx", "## What you get"}, "", link},
			{docSection{"site/checklist.mdx", "## Network"}, "", link},
		})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/env.mdx: ## Every variable row GOIABADA_B does not say the HTTP listener redirects",
		"site/env.mdx: ## Every variable row GOIABADA_C does not link to the rule with (#listen-addresses)",
		"site/env.mdx: ## Every variable has no row for GOIABADA_D",
		"site/checklist.mdx: ## Network does not say the HTTP listener redirects",
		"site/checklist.mdx: ## Network does not link to the rule with " + link,
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestHTTPListenerDocs_AMissingPlaceStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/proxy.mdx", "## Something else\n\nRedirects. [rule](/reference/environment-variables/#listen-addresses)\n")

	report := guard.Run(func(r guard.Reporter) {
		assertListenerRulePlaces(r, root, []listenerRulePlace{
			{docSection{"site/proxy.mdx", "## What you get"}, "", "(/reference/environment-variables/#listen-addresses)"},
		})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## What you get") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

// assertListenerRuleHome is the reporting half of the home's check: one failure per answer of the
// listener the section does not name at the end of a code span, as in `301` or `GET /health`, and
// one when it does not name the trust setting; a stop for a section not found.
func assertListenerRuleHome(r guard.Reporter, root string, home docSection, redirectStatus int, healthPath string) {
	r.Helper()
	text, err := docsreader.Section(root, home.page, home.heading)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	if status := "`" + strconv.Itoa(redirectStatus) + "`"; !strings.Contains(text, status) {
		r.Errorf("%s: %s does not name the redirect's status %s", home.page, home.heading, status)
	}
	if !strings.Contains(text, healthPath+"`") {
		r.Errorf("%s: %s does not name `%s`, which the redirecting listener still answers", home.page, home.heading, healthPath)
	}
	if !strings.Contains(text, "TRUST_PROXY_HEADERS") {
		r.Errorf("%s: %s does not name TRUST_PROXY_HEADERS, which decides whether the listener serves", home.page, home.heading)
	}
}

// assertListenerRulePlaces is the reporting half of the places' check. A place's text is its
// section, or its row when it names one, the row whose first cell's first code span is that name.
// One failure per place whose text does not say "redirect" or lacks its link, and per row not
// found; a stop for a section not found.
func assertListenerRulePlaces(r guard.Reporter, root string, places []listenerRulePlace) {
	r.Helper()
	for _, place := range places {
		text, err := docsreader.Section(root, place.section.page, place.section.heading)
		if err != nil {
			r.Fatalf("%v", err)
			return
		}
		where := place.section.page + ": " + place.section.heading
		if place.row != "" {
			row, found := listenerRuleRow(text, place.row)
			if !found {
				r.Errorf("%s has no row for %s", where, place.row)
				continue
			}
			text, where = row, where+" row "+place.row
		}
		if !strings.Contains(strings.ToLower(text), "redirect") {
			r.Errorf("%s does not say the HTTP listener redirects", where)
		}
		if !strings.Contains(text, place.link) {
			r.Errorf("%s does not link to the rule with %s", where, place.link)
		}
	}
}

// listenerRuleRow answers the cells, joined, of the row whose first cell's first code span is name.
func listenerRuleRow(text, name string) (string, bool) {
	for _, row := range docsreader.Rows(text) {
		_, span, ok := strings.Cut(row[0], "`")
		if !ok {
			continue
		}
		if span, _, _ = strings.Cut(span, "`"); span == name {
			return strings.Join(row, " | "), true
		}
	}
	return "", false
}
