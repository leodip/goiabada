package apihandlers

// A brand's footer links and support contact as the docs describe them, held to the code (#814).
//
// The customize guide is where an administrator learns what a brand's footer holds before filling
// it in: the editor's sections and fields by their labels, each value's limits, where the footer is
// drawn, and the admin API's four members. The glossary, the audit log, the Clients page and the
// publish-legal-documents guide each say their part and link to the guide rather than repeat it.
// Every limit is written out here, so a guide and a rule that drift apart fail here or in the
// handler tests that hold the code to the same values.
//
// It reads files and the English catalog, and nothing else.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/core/docsreader"
	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/i18n"
)

const (
	// brandFooterHead is the customize guide's section on a brand's footer links and support contact.
	brandFooterHead = "## Footer links and support contact"
	// brandFooterAPIHead is its subsection on the admin API's members.
	brandFooterAPIHead = "### The footer through the Admin API"
	// footerLinksLink is the guide's subsection on footer links, which the other pages link to.
	footerLinksLink = "/guides/customize-and-translate-the-pages/#footer-links"
	// brandFooterLink is the guide's whole section, which the other pages link to.
	brandFooterLink = "/guides/customize-and-translate-the-pages/#footer-links-and-support-contact"

	auditLogDocsPage    = "site/src/content/docs/concepts/audit-log.mdx"
	legalDocumentsGuide = "site/src/content/docs/guides/publish-legal-documents.mdx"
)

// The guide's section names the editor's two sections and every field by the labels the editor
// gives them, the footer's built-in words, and each value's limits (#814 decisions 1, 4, 5 and 11):
// three links, a 40-character label, a 256-character https: URL, the account address's 254
// characters and a phone number's + and 15 digits.
func TestBrandFooterDocs_TheGuideNamesTheEditorsFieldsAndLimits(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, brandFooterHead,
		[]string{
			brandLabel("brand.footer_links.title"),
			"**" + i18n.T(context.Background(), "adminconsole.admin_branding.brand.footer_links.link", map[string]any{"number": 1}) + "**",
			brandLabel("brand.footer_links.label"),
			brandLabel("brand.footer_links.url"),
			brandLabel("brand.footer_links.languages"),
			brandLabel("brand.support.title"),
			brandLabel("brand.support.email"),
			brandLabel("brand.support.url"),
			brandLabel("brand.support.phone"),
			`"` + english("common.footer.need_help") + `"`,
			`"` + english("common.footer.support_page") + `"`,
			"up to three links",
			"up to 40 characters",
			"up to 256 characters",
			"`https:`",
			"user name or password",
			"`<` or `>`",
			"up to 254 characters",
			"up to 15 digits",
			"spaces, hyphens, dots and parentheses",
		}, nil)
	if brandFooterLinksMax != 3 || brandFooterLabelMaxLength != 40 || brandURLMaxLength != 256 ||
		accountvalidation.MaxEmailLength != 254 {
		t.Errorf("the guide states 3 links, a 40-character label, a 256-character URL and a 254-character address, "+
			"but the code's limits are %d, %d, %d and %d",
			brandFooterLinksMax, brandFooterLabelMaxLength, brandURLMaxLength, accountvalidation.MaxEmailLength)
	}
}

// The guide says where the footer is drawn and how (#814 decisions 2, 3, 5, 6 and 7): under the
// card on every auth server page and the console's end-user pages, at the foot of an Account page,
// never on an admin page, on a panel over a background image, each link in a new tab, with no
// fallback to the default brand's, and the advice to fill in a label for each language the users
// read, since a fallback label is in no language a page can declare.
func TestBrandFooterDocs_TheGuideSaysWhereAndHowTheFooterIsDrawn(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, brandFooterHead,
		[]string{
			"under the card",
			"**" + english("adminconsole.menu.account") + "**",
			"admin pages draw no footer",
			"on a panel",
			"#background-image",
			"new tab",
			"default brand's",
			"each language your users read",
			"in the language the page is written in",
		},
		[]string{"falls back to the default brand"})
}

// The guide's admin API subsection names the four members, a link's three, what an update does with
// a member left out, and the refusal's error_field with a pointer counted from 0 (#814 decisions 9
// and 10).
func TestBrandFooterDocs_TheGuideGivesTheAPIsMembers(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, brandFooterAPIHead,
		[]string{
			"`footerLinks`",
			"`supportEmail`",
			"`supportUrl`",
			"`supportPhone`",
			"`url`",
			"`label`",
			"`labels`",
			`"pt-BR"`,
			"(/reference/api/admin/operations/updatebrand/)",
			"`null`",
			"`error_field`",
			"`/footerLinks/1/url`",
			"counted from 0",
		}, nil)
}

// The brand-the-pages step points at the footer's section, and the templates step tells an operator
// keeping their own layouts to keep the footer, or the pages lose it.
func TestBrandFooterDocs_TheGuidesStepsMentionTheFooter(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	guard.AssertSectionSays(t, root, customizeGuidePage, "## Brand the pages",
		[]string{"#footer-links-and-support-contact"}, nil)
	guard.AssertSectionSays(t, root, customizeGuidePage, "## Change the templates",
		[]string{"footer"}, nil)
}

// The glossary's brand holds its footer links and support contact, and points at the guide for them.
func TestBrandFooterDocs_TheGlossarysBrandHoldsTheFooter(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), glossaryPage, "### Brand",
		[]string{"footer links", "support contact", brandFooterLink}, nil)
}

// The Clients page's console client says its end-user pages draw the footer and its admin pages
// none (#814 decision 7).
func TestBrandFooterDocs_TheConsolesClientSaysWhereItsFooterIsDrawn(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), clientsPage, "## The admin console's client",
		[]string{"footer", brandFooterLink}, nil)
}

// auditEventRow is the cells of the audit log's event row naming event, or nil.
func auditEventRow(t *testing.T, heading, event string) []string {
	t.Helper()
	text, err := docsreader.Section(filepath.Dir(guard.SourceRoot(t)), auditLogDocsPage, heading)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range docsreader.Rows(text) {
		if len(row) > 0 && row[0] == "`"+event+"`" {
			return row
		}
	}
	return nil
}

// The audit log's two brand writes say they record the support contact and each footer link's URL
// (#814 decision 9), so an auditor knows to look there for a link added under a sign-in card.
func TestBrandFooterDocs_TheAuditLogsBrandEventsNameTheFooter(t *testing.T) {
	for _, event := range []string{audit.EventCreatedBrand, audit.EventUpdatedBrand} {
		row := auditEventRow(t, "### Brands", event)
		if row == nil {
			t.Errorf("%s: ### Brands has no row for `%s`", auditLogDocsPage, event)
			continue
		}
		joined := strings.Join(row, " | ")
		for _, want := range []string{"support contact", "footer links' URLs"} {
			if !strings.Contains(joined, want) {
				t.Errorf("%s: the row for `%s` does not say %q: %s", auditLogDocsPage, event, want, joined)
			}
		}
	}
}

// The publish-legal-documents guide says a document's public page can be a brand's footer link, the
// one way a document reaches the footer (#814, Assumed: the footer holds the brand's links alone).
func TestBrandFooterDocs_ALegalDocumentCanBeAFooterLink(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), legalDocumentsGuide, "## The public page",
		[]string{"[footer link](" + footerLinksLink + ")"}, nil)
}
