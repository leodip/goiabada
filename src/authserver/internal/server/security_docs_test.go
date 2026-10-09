package server

// The Security page's table of the endpoints the CSRF origin check leaves out, held to this server's
// policy (#522).
//
// The table is where an operator or a reviewer learns which endpoints another site may POST to, and
// why each is safe to. The paths are csrfPolicy's, every exact path, prefix and conditional entry,
// so the table is held to them in both directions: a path the policy exempts with no row fails, and
// so does a row naming one it does not. A path is matched as the policy writes it, a prefix with its
// trailing slash, so a row cannot turn an exact path into a subtree or back.

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/httpmw"
)

var csrfExemptionsSection = docSection{"site/src/content/docs/reference/security.mdx", "## Cross-site request forgery"}

// csrfExemptPaths is every path the policy names, exact, prefix and conditional alike, sorted.
func csrfExemptPaths(policy httpmw.CSRFPolicy) []string {
	paths := slices.Concat(policy.ExactPaths, policy.Prefixes)
	for path := range policy.Conditional {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	return paths
}

// The exemptions table on Security has one row per path the auth server's CSRF policy exempts, and
// none for a path it does not.
func TestSecurityDocs_TheCSRFTableIsThePolicysPaths(t *testing.T) {
	assertCSRFExemptionTable(t, filepath.Dir(guard.SourceRoot(t)), csrfExemptionsSection, csrfExemptPaths(csrfPolicy()))
}

func TestSecurityDocs_ACSRFTableDisagreeingWithThePolicyFails(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/security.mdx", "## Cross-site request forgery\n\n"+
		"| Path | Why |\n|---|---|\n"+
		"| `/auth/token` | A client secret or a code |\n"+
		"| `/api` | Bearer tokens |\n"+
		"| `/auth/token` | Twice |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertCSRFExemptionTable(r, root, docSection{"site/security.mdx", "## Cross-site request forgery"},
			[]string{"/api/", "/auth/token"})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/security.mdx: ## Cross-site request forgery row 2 names /api, which the policy does not exempt",
		"site/security.mdx: ## Cross-site request forgery row 3 names /auth/token, which an earlier row already does",
		"site/security.mdx: ## Cross-site request forgery has no row for /api/",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestSecurityDocs_ACSRFTableAgreeingWithThePolicyPasses(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/security.mdx", "## Cross-site request forgery\n\n"+
		"| Path | Why |\n|---|---|\n"+
		"| `/api/` and everything under it | Bearer tokens |\n"+
		"| `/auth/token` | A client secret or a code |\n\n"+
		"## Next\n\n| Path | Why |\n|---|---|\n| `/other` | Another table |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertCSRFExemptionTable(r, root, docSection{"site/security.mdx", "## Cross-site request forgery"},
			[]string{"/api/", "/auth/token"})
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a table agreeing with the policy was refused: %+v", report)
	}
}

func TestSecurityDocs_AMissingCSRFSectionStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/security.mdx", "## CSRF\n\n| Path | Why |\n|---|---|\n| `/auth/token` | A secret |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertCSRFExemptionTable(r, root, docSection{"site/security.mdx", "## Cross-site request forgery"},
			[]string{"/auth/token"})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Cross-site request forgery") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

func TestSecurityDocs_ACSRFSectionWithNoTableStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/security.mdx", "## Cross-site request forgery\n\n- `/auth/token` is exempt.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertCSRFExemptionTable(r, root, docSection{"site/security.mdx", "## Cross-site request forgery"},
			[]string{"/auth/token"})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "no table") {
		t.Errorf("a section without its table did not stop the check: %+v", report)
	}
}

func TestSecurityDocs_NoExemptPathsStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/security.mdx", "## Cross-site request forgery\n\n"+
		"| Path | Why |\n|---|---|\n| `/auth/token` | A secret |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertCSRFExemptionTable(r, root, docSection{"site/security.mdx", "## Cross-site request forgery"}, nil)
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "no path") {
		t.Errorf("a check handed no paths did not stop: %+v", report)
	}
}

// assertCSRFExemptionTable is the reporting half of the exemptions check. A row's path is the first
// code span in its first cell, so a row may say more about a prefix around it. One failure per row
// naming a path the policy does not exempt or one an earlier row named, and per exempt path with no
// row; a stop for a section or table not found, and for no paths to hold it to.
func assertCSRFExemptionTable(r guard.Reporter, root string, section docSection, paths []string) {
	r.Helper()
	if len(paths) == 0 {
		r.Fatalf("no path to hold %s: %s to: the policy exempts nothing", section.page, section.heading)
		return
	}
	text, err := docSectionText(root, section)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	rows := docTableRows(text)
	if len(rows) == 0 {
		r.Fatalf("%s: %s has no table", section.page, section.heading)
		return
	}
	named := make(map[string]bool)
	for i, row := range rows {
		path := row[0]
		if _, span, ok := strings.Cut(path, "`"); ok {
			path, _, _ = strings.Cut(span, "`")
		}
		switch {
		case named[path]:
			r.Errorf("%s: %s row %d names %s, which an earlier row already does", section.page, section.heading, i+1, path)
		case !slices.Contains(paths, path):
			r.Errorf("%s: %s row %d names %s, which the policy does not exempt", section.page, section.heading, i+1, path)
		}
		named[path] = true
	}
	for _, path := range paths {
		if !named[path] {
			r.Errorf("%s: %s has no row for %s", section.page, section.heading, path)
		}
	}
}
