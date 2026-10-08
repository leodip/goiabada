package handlers

// The Security page, held to the code that does what it says (#522).
//
// The page lists every header both servers add to every answer, with its value, because an operator
// checking a deployment, or a proxy in front of it replacing one, needs the exact values. They are
// what httpmw.SecurityHeaders writes, so the page's table is held to the headers that middleware sets
// on an https deployment, in both directions and value for value. The CSRF exemptions on the same
// page are this server's policy, unexported in internal/server, and are held there.
//
// It reads files, and runs the middleware over a recorder.

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/httpmw"
)

const securityPage = "site/src/content/docs/reference/security.mdx"

var securityHeadersSection = conceptSection{securityPage, "### Response headers"}

// securityHeaders is every header httpmw.SecurityHeaders sets on an https deployment's answers, with
// its value. Over http it leaves out Strict-Transport-Security, which the page says in the row.
func securityHeaders(t *testing.T) map[string]string {
	t.Helper()
	rr := httptest.NewRecorder()
	httpmw.SecurityHeaders(true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	headers := make(map[string]string)
	for name, values := range rr.Header() {
		headers[name] = strings.Join(values, ", ")
	}
	if len(headers) == 0 {
		t.Fatal("the middleware set no header, so there is nothing to hold the page to")
	}
	return headers
}

// The response headers table on Security has one row per header the servers add, with its value,
// and none for a header they never add.
func TestSecurityDocs_TheHeadersTableIsWhatTheMiddlewareSets(t *testing.T) {
	assertValueTable(t, filepath.Dir(guard.SourceRoot(t)), securityHeadersSection, "Header", "Value",
		securityHeaders(t), "the middleware")
}

func TestSecurityDocs_AHeadersTableDisagreeingWithTheMiddlewareFails(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/security.mdx", "### Response headers\n\n"+
		"| Header | Value |\n|---|---|\n"+
		"| `Referrer-Policy` | `no-referrer` |\n"+
		"| `X-XSS-Protection` | `1` |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertValueTable(r, root, conceptSection{"site/security.mdx", "### Response headers"}, "Header", "Value",
			map[string]string{"Referrer-Policy": "same-origin", "X-Frame-Options": "DENY"}, "the middleware")
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/security.mdx: ### Response headers row 1 gives Referrer-Policy as no-referrer, where the middleware has same-origin",
		"site/security.mdx: ### Response headers row 2 names X-XSS-Protection, which the middleware never has",
		"site/security.mdx: ### Response headers has no row for X-Frame-Options",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}
