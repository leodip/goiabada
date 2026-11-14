package apihandlers

// The email templates as Customize and translate the pages describes them, held to the code (#818).
//
// The guide is where an administrator learns, before rewording an email, where the editor is, the
// format a body is written in, which placeholders each email offers and which its body cannot do
// without, what becomes of an edit a later release makes invalid, and the Admin API's operations
// and scopes. Each email's placeholders are its built-in definition's, its name the console's, the
// limits the record's, and the labels the console's English catalog: a guide offering a placeholder
// an email refuses, or leaving out one it requires, sends the reader to a refusal with nothing
// going red. The glossary names the term, and the pages that once sent a reader to the guide's
// "Email bodies" section, or said a mounted email template could load an image, must not again.
//
// It reads files, the built-in email definitions and the English catalog, and nothing else.

import (
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/docsreader"
	"github.com/leodip/goiabada/core/guard"
)

const (
	// emailTemplatesHead is the customize guide's section on email templates, and emailTemplatesLink
	// the anchor the guide's other sections and the glossary link to.
	emailTemplatesHead = "## Email templates"
	emailTemplatesLink = "/guides/customize-and-translate-the-pages/#email-templates"

	emailFormatHead          = "### The body's format"
	placeholdersHead         = "### Placeholders"
	emailPlaceholdersHead    = "### Each email's placeholders"
	invalidEditHead          = "### When an upgrade breaks an edit"
	emailTemplatesAPIHead    = "### Email templates through the Admin API"
	personalDataPage         = "site/src/content/docs/deploy/personal-data.mdx"
	emailTemplateGlossary    = "### Email template"
	emailTemplateConsoleRoot = "adminconsole.email_templates.editor."
)

// editorLabel is a label of the email template editor, bold, as a page quotes it.
func editorLabel(key string) string {
	return "**" + english(emailTemplateConsoleRoot+key) + "**"
}

// written is a placeholder as an administrator writes it, in a code span.
func written(name string) string {
	return "`{{" + name + "}}`"
}

// The section's steps name the editor where the console puts it, Admin, Email, its tab, by the
// console's labels, and each field, the placeholder buttons, the preview, the test send, the save
// and the reset by theirs (#818 decision 14). It says the six languages are edited one at a time,
// that a field left alone follows later releases (decision 7), that edits are not per brand, that a
// language an operator added gets English, and that the mounted templates change only the frame.
func TestEmailTemplateDocs_TheGuideSaysWhereTheEditorIsAndWhatItDoes(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, emailTemplatesHead,
		[]string{
			"**" + english("adminconsole.menu.admin") + "**, **" + english("adminconsole.admin_menu.settings_email") + "**",
			"**" + english("adminconsole.email_tabs.templates") + "**",
			editorLabel("field_subject"),
			editorLabel("field_button_label"),
			editorLabel("field_body"),
			editorLabel("required"),
			editorLabel("preview_title"),
			editorLabel("preview_brand"),
			"**" + english("adminconsole.email_tabs.send_test") + "**",
			editorLabel("save_button"),
			editorLabel("reset_button"),
			"six built-in languages",
			"follows the built-in text when you upgrade",
			"every brand",
			"in English",
			"`layouts/email_layout.html`",
			"#branded-emails",
			"#change-the-templates",
		}, nil)
}

// The format names the Markdown set a body takes and what is shown as typed (#818 decision 2): the
// web, mail and phone addresses a link may lead to, and that a javascript: one loses its address.
// The limits are the record's (decision 7).
func TestEmailTemplateDocs_TheFormatSaysWhatABodyTakesAndTheLimits(t *testing.T) {
	limit := func(n int) string {
		s := strconv.Itoa(n)
		if n >= 10_000 {
			s = s[:len(s)-3] + "," + s[len(s)-3:]
		}
		return "up to " + s + " characters"
	}
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, emailFormatHead,
		[]string{
			"`**bold**`",
			"`*italic*`",
			"`[link text](https://example.com)`",
			"`-`",
			"`1.`",
			"A blank line starts a paragraph, and a single line break is kept",
			"`https:`, `http:`, `mailto:` or `tel:`",
			"`javascript:`",
			"shown as you typed it",
			"no image is loaded",
			"brand's color",
			"one line",
			"The subject is " + limit(record.EmailTemplateSubjectMaxLength),
			"the button label " + limit(record.EmailTemplateButtonLabelMaxLength),
			"the body " + limit(record.EmailTemplateBodyMaxLength),
		}, nil)
}

// Placeholders lists every placeholder some email offers, once, each with what it writes, and says
// how one is written and escaped and the rules a save holds a text to (#818 decisions 3, 15 and 17).
func TestEmailTemplateDocs_PlaceholdersDescribesEachPlaceholderAndItsRules(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	guard.AssertSectionSays(t, root, customizeGuidePage, placeholdersHead,
		[]string{
			"`{{ name }}`",
			"`\\{{`",
			"as text",
			"the address the email is sent to",
			"`[Reset your password]({{link}})`",
			"a line of its own",
			"in the body only",
			"something to read besides the button",
			"**" + english("adminconsole.admin_settings.general.field.app_name") + "**",
		}, nil)

	var offered []string
	for _, email := range emailtemplate.BuiltIns() {
		for _, p := range email.Placeholders {
			if !slices.Contains(offered, written(p.Name)) {
				offered = append(offered, written(p.Name))
			}
		}
	}
	documented := placeholderColumn(t, root, placeholdersHead, "Placeholder")
	slices.Sort(offered)
	slices.Sort(documented)
	if !slices.Equal(documented, offered) {
		t.Errorf("%s: %s lists the placeholders %q, but the emails offer %q", customizeGuidePage, placeholdersHead, documented, offered)
	}
}

// Each email's placeholders gives every email a row: its name as the console's list shows it, its
// identifier, the placeholders its definition offers in the order the editor's buttons show them,
// and the ones its body requires, so none is offered that a save refuses and none required that the
// guide leaves out (#818 decisions 3 and 6).
func TestEmailTemplateDocs_EachEmailsRowListsItsPlaceholders(t *testing.T) {
	text, err := docsreader.Section(filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, emailPlaceholdersHead)
	if err != nil {
		t.Fatal(err)
	}
	tables := docsreader.Tables(text)
	if len(tables) != 1 {
		t.Fatalf("%s: %s holds %d tables, want 1", customizeGuidePage, emailPlaceholdersHead, len(tables))
	}
	rows, err := tables[0].Columns("Email", "Identifier", "Placeholders", "Required")
	if err != nil {
		t.Fatal(err)
	}
	byIdentifier := map[string][]string{}
	for _, row := range rows {
		byIdentifier[row[1]] = row
	}

	emails := emailtemplate.BuiltIns()
	if len(rows) != len(emails) {
		t.Errorf("%s: %s has %d rows, want one for each of the %d emails", customizeGuidePage, emailPlaceholdersHead, len(rows), len(emails))
	}
	for _, email := range emails {
		row, ok := byIdentifier["`"+email.ID+"`"]
		if !ok {
			t.Errorf("%s: %s has no row for `%s`", customizeGuidePage, emailPlaceholdersHead, email.ID)
			continue
		}
		var offers, required []string
		for _, p := range email.Placeholders {
			offers = append(offers, written(p.Name))
			if p.Required {
				required = append(required, written(p.Name))
			}
		}
		want := []string{
			english("adminconsole.email_templates.email." + email.ID + ".name"),
			"`" + email.ID + "`",
			strings.Join(offers, ", "),
			"None",
		}
		if len(required) > 0 {
			want[3] = strings.Join(required, ", ")
		}
		if !slices.Equal(row, want) {
			t.Errorf("%s: %s's row for `%s` reads %q, want %q", customizeGuidePage, emailPlaceholdersHead, email.ID, row, want)
		}
	}
}

// An edit a release makes invalid is kept, its email sent in that language with the whole built-in
// text, the console marks it by its labels, and the server logs it (#818 decision 8).
func TestEmailTemplateDocs_TheGuideSaysWhatBecomesOfAnInvalidEdit(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, invalidEditHead,
		[]string{
			editorLabel("needs_attention"),
			"never deleted",
			"built-in text",
			"all of it",
			editorLabel("reset_button"),
			"logs a warning",
			"when it starts",
		}, nil)
}

// The Admin API's section names each operation by its route, linked to its reference page, the
// languages a path takes, a language's three statuses, the scopes each operation takes (#818
// decisions 9 and 10), and the audit events the writes leave (decision 13).
func TestEmailTemplateDocs_TheAPISectionNamesEachOperationAndItsScopes(t *testing.T) {
	present := []string{
		"[`GET /api/v1/admin/email-templates`](/reference/api/admin/operations/getemailtemplates/)",
		"[`GET /api/v1/admin/email-templates/{email}`](/reference/api/admin/operations/getemailtemplate/)",
		"[`PUT /api/v1/admin/email-templates/{email}/{language}`](/reference/api/admin/operations/saveemailtemplate/)",
		"[`DELETE /api/v1/admin/email-templates/{email}/{language}`](/reference/api/admin/operations/resetemailtemplate/)",
		"[`POST /api/v1/admin/email-templates/{email}/{language}/preview`](/reference/api/admin/operations/previewemailtemplate/)",
		"[`POST /api/v1/admin/email-templates/{email}/{language}/send-test`](/reference/api/admin/operations/sendemailtemplatetest/)",
		"`default`", "`edited`", "`invalid`",
		"`authserver:admin-read`", "`authserver:manage-settings`", "`authserver:manage`",
		"`" + audit.EventUpdatedEmailTemplate + "`",
		"`" + audit.EventResetEmailTemplate + "`",
		"`" + audit.EventSentTestEmail + "`",
		"/concepts/audit-log/",
		"`buttonLabel`",
	}
	for _, lang := range emailtemplate.Languages {
		present = append(present, "`"+lang+"`")
	}
	root := filepath.Dir(guard.SourceRoot(t))
	guard.AssertSectionSays(t, root, customizeGuidePage, emailTemplatesAPIHead, present, nil)

	// Each operation's row gives its own scopes (decision 9): a read or a preview takes any scope
	// that reads settings, and a write or a test send takes authserver:manage alone, which the
	// section's prose naming every scope somewhere would not show.
	const readsSettings = "`authserver:admin-read`, `authserver:manage-settings` or `authserver:manage`"
	const manageOnly = "`authserver:manage`"
	want := map[string]string{
		"GET /api/v1/admin/email-templates":                               readsSettings,
		"GET /api/v1/admin/email-templates/{email}":                       readsSettings,
		"PUT /api/v1/admin/email-templates/{email}/{language}":            manageOnly,
		"DELETE /api/v1/admin/email-templates/{email}/{language}":         manageOnly,
		"POST /api/v1/admin/email-templates/{email}/{language}/preview":   readsSettings,
		"POST /api/v1/admin/email-templates/{email}/{language}/send-test": manageOnly,
	}
	text, err := docsreader.Section(root, customizeGuidePage, emailTemplatesAPIHead)
	if err != nil {
		t.Fatal(err)
	}
	tables := docsreader.Tables(text)
	if len(tables) != 1 {
		t.Fatalf("%s: %s holds %d tables, want 1", customizeGuidePage, emailTemplatesAPIHead, len(tables))
	}
	rows, err := tables[0].Columns("Route", "Scope")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, row := range rows {
		route := strings.TrimPrefix(row[0], "[`")
		if i := strings.Index(route, "`]"); i >= 0 {
			route = route[:i]
		}
		got[route] = row[1]
	}
	for route, scopes := range want {
		if got[route] != scopes {
			t.Errorf("%s: %s gives %s the scopes %q, want %q", customizeGuidePage, emailTemplatesAPIHead, route, got[route], scopes)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%s: %s lists %d operations, want %d", customizeGuidePage, emailTemplatesAPIHead, len(got), len(want))
	}
}

// The guide's sections that meet emails link the new section, and none links the section it
// replaced; the glossary defines the term and links it; the personal data page does not say an
// email template can load an image, which the format refuses (#818 decision 2).
func TestEmailTemplateDocs_TheOtherSectionsAndTheGlossaryLinkIt(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	for _, heading := range []string{"## Add a language", "## Change a few words", "## Catalogs"} {
		guard.AssertSectionSays(t, root, customizeGuidePage, heading, []string{"(#email-templates)"}, nil)
	}
	guard.AssertSectionSays(t, root, customizeGuidePage, "", nil, []string{"## Email bodies", "#email-bodies"})
	guard.AssertSectionSays(t, root, glossaryPage, emailTemplateGlossary,
		[]string{"subject", "body", "button label", "six built-in languages", "**Admin**, **Email**", emailTemplatesLink}, nil)
	guard.AssertSectionSays(t, root, personalDataPage, "", []string{"email layout"}, []string{"An email template can embed"})
}

// placeholderColumn answers the cells of column in the one table under heading.
func placeholderColumn(t *testing.T, root, heading, column string) []string {
	t.Helper()
	text, err := docsreader.Section(root, customizeGuidePage, heading)
	if err != nil {
		t.Fatal(err)
	}
	tables := docsreader.Tables(text)
	if len(tables) != 1 {
		t.Fatalf("%s: %s holds %d tables, want 1", customizeGuidePage, heading, len(tables))
	}
	rows, err := tables[0].Columns(column)
	if err != nil {
		t.Fatal(err)
	}
	cells := make([]string, len(rows))
	for i, row := range rows {
		cells[i] = row[0]
	}
	return cells
}
