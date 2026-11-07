package handlers

// The pages where an operator makes a choice the Personal data page's rules are about, each held
// to a link to the section that holds the rule (#745 decision 5).
//
// The Personal data page is the one home of what a deployment stores and shares and of what stays
// the operator's to decide about cookie consent. A reader choosing Always under Closing the
// browser, turning Turnstile on, editing the templates, publishing a privacy notice or checking a
// deployment before it goes live doesn't look there, so each of those sections links to it. A
// place that loses its link fails, and so does a link to a section the page no longer has.
//
// It reads files.

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/docsreader"
	"github.com/leodip/goiabada/core/guard"
)

// personalDataTarget is a section of the Personal data page and the link that reaches it from
// another page.
type personalDataTarget struct {
	heading string
	link    string
}

var (
	personalDataPageItself    = personalDataTarget{"", "(/deploy/personal-data/)"}
	personalDataYoursToDecide = personalDataTarget{"### What's yours to decide", "(/deploy/personal-data/#whats-yours-to-decide)"}
)

// personalDataLinkPlace is a section, or the row of its tables whose first cell is row, that must
// link to target. A next steps card links with its href, so its link is written as one.
type personalDataLinkPlace struct {
	section conceptSection
	row     string
	target  personalDataTarget
	link    string
}

var personalDataLinkPlaces = []personalDataLinkPlace{
	{conceptSection{"site/src/content/docs/deploy/production-checklist.mdx", "## Personal data"}, "", personalDataPageItself, ""},
	{conceptSection{"site/src/content/docs/concepts/sessions.mdx", "## Closing the browser"}, "**Always**", personalDataYoursToDecide, ""},
	{conceptSection{"site/src/content/docs/guides/require-a-turnstile-challenge.mdx", "## What it costs"}, "", personalDataYoursToDecide, ""},
	{conceptSection{"site/src/content/docs/guides/customize-and-translate-the-pages.mdx", "## Change the templates"}, "", personalDataYoursToDecide, ""},
	{conceptSection{"site/src/content/docs/guides/publish-legal-documents.mdx", "## Next steps"}, "", personalDataPageItself, `href="/deploy/personal-data/"`},
	{conceptSection{"site/src/content/docs/about/privacy.mdx", "## Goiabada servers run by others"}, "", personalDataPageItself, ""},
}

func TestPersonalDataLinks_EveryDecisionPointLinksToTheGuide(t *testing.T) {
	assertPersonalDataLinks(t, filepath.Dir(guard.SourceRoot(t)), personalDataPage, personalDataLinkPlaces)
}

func TestPersonalDataLinks_PlacesMissingTheirLinkFail(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/data.mdx", "# Data\n\n## Cookies\n\n### What's yours to decide\n\n- Always.\n")
	writeConceptFixture(t, root, "site/sessions.mdx", "## Closing the browser\n\n"+
		"| Setting | The cookie |\n|---|---|\n"+
		"| **Let each user choose** | See [it](/deploy/personal-data/#whats-yours-to-decide). |\n"+
		"| **Always** | Lasts as long as the session. |\n\n"+
		"## Next\n")
	writeConceptFixture(t, root, "site/checklist.mdx", "## Personal data\n\n- [ ] Write a notice.\n\n"+
		"## After it's live\n\n- [ ] See [Personal data](/deploy/personal-data/).\n")
	writeConceptFixture(t, root, "site/legal.mdx", "## Next steps\n\n"+
		`<LinkCard title="Audit log" href="/concepts/audit-log/" />`+"\n")

	report := guard.Run(func(r guard.Reporter) {
		assertPersonalDataLinks(r, root, "site/data.mdx", []personalDataLinkPlace{
			{conceptSection{"site/sessions.mdx", "## Closing the browser"}, "**Always**", personalDataYoursToDecide, ""},
			{conceptSection{"site/sessions.mdx", "## Closing the browser"}, "**Never**", personalDataYoursToDecide, ""},
			{conceptSection{"site/checklist.mdx", "## Personal data"}, "", personalDataPageItself, ""},
			{conceptSection{"site/legal.mdx", "## Next steps"}, "", personalDataPageItself, `href="/deploy/personal-data/"`},
		})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/sessions.mdx: ## Closing the browser row **Always** does not link to the Personal data page with (/deploy/personal-data/#whats-yours-to-decide)",
		"site/sessions.mdx: ## Closing the browser has no row for **Never**",
		"site/checklist.mdx: ## Personal data does not link to the Personal data page with (/deploy/personal-data/)",
		`site/legal.mdx: ## Next steps does not link to the Personal data page with href="/deploy/personal-data/"`,
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestPersonalDataLinks_PlacesWithTheirLinkPass(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/data.mdx", "# Data\n\n## Cookies\n\n### What's yours to decide\n\n- Always.\n")
	writeConceptFixture(t, root, "site/sessions.mdx", "## Closing the browser\n\n"+
		"| Setting | The cookie |\n|---|---|\n"+
		"| **Always** | Lasts. See [Personal data](/deploy/personal-data/#whats-yours-to-decide). |\n")
	writeConceptFixture(t, root, "site/legal.mdx", "## Next steps\n\n"+
		`<LinkCard title="Personal data" href="/deploy/personal-data/" />`+"\n")

	report := guard.Run(func(r guard.Reporter) {
		assertPersonalDataLinks(r, root, "site/data.mdx", []personalDataLinkPlace{
			{conceptSection{"site/sessions.mdx", "## Closing the browser"}, "**Always**", personalDataYoursToDecide, ""},
			{conceptSection{"site/legal.mdx", "## Next steps"}, "", personalDataPageItself, `href="/deploy/personal-data/"`},
		})
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("places linking to the guide were refused: %+v", report)
	}
}

func TestPersonalDataLinks_ALinkToASectionThePageLacksFails(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/data.mdx", "# Data\n\n## Cookies\n\n### Yours to choose\n\n- Always.\n")
	writeConceptFixture(t, root, "site/turnstile.mdx", "## What it costs\n\n"+
		"- Cloudflare. See [Personal data](/deploy/personal-data/#whats-yours-to-decide).\n")

	report := guard.Run(func(r guard.Reporter) {
		assertPersonalDataLinks(r, root, "site/data.mdx", []personalDataLinkPlace{
			{conceptSection{"site/turnstile.mdx", "## What it costs"}, "", personalDataYoursToDecide, ""},
		})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "### What's yours to decide") {
		t.Errorf("a link to a section the page lacks did not stop the check naming it: %+v", report)
	}
}

func TestPersonalDataLinks_AMissingPlaceStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/data.mdx", "# Data\n")
	writeConceptFixture(t, root, "site/privacy.mdx", "## Something else\n\nSee [Personal data](/deploy/personal-data/).\n")

	report := guard.Run(func(r guard.Reporter) {
		assertPersonalDataLinks(r, root, "site/data.mdx", []personalDataLinkPlace{
			{conceptSection{"site/privacy.mdx", "## Goiabada servers run by others"}, "", personalDataPageItself, ""},
		})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Goiabada servers run by others") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

// assertPersonalDataLinks is the reporting half of the check. A place's text is its section, or its
// row when it names one, the row whose first cell is that name. One failure per place whose text
// lacks its link, the target's link unless the place writes it otherwise, and per row not found; a
// stop for a section not found, on the place's page or on the guide.
func assertPersonalDataLinks(r guard.Reporter, root, guide string, places []personalDataLinkPlace) {
	r.Helper()
	for _, place := range places {
		if _, err := docsreader.Section(root, guide, place.target.heading); err != nil {
			r.Fatalf("%v", err)
			return
		}
		text, err := docsreader.Section(root, place.section.page, place.section.heading)
		if err != nil {
			r.Fatalf("%v", err)
			return
		}
		where := place.section.page + ": " + place.section.heading
		if place.row != "" {
			row, found := personalDataLinkRow(text, place.row)
			if !found {
				r.Errorf("%s has no row for %s", where, place.row)
				continue
			}
			text, where = row, where+" row "+place.row
		}
		link := place.target.link
		if place.link != "" {
			link = place.link
		}
		if !strings.Contains(text, link) {
			r.Errorf("%s does not link to the Personal data page with %s", where, link)
		}
	}
}

// personalDataLinkRow answers the cells, joined, of the row whose first cell is name.
func personalDataLinkRow(text, name string) (string, bool) {
	for _, row := range docsreader.Rows(text) {
		if row[0] == name {
			return strings.Join(row, " | "), true
		}
	}
	return "", false
}
