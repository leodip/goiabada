package i18n

// The documentation of a user's page language, held to the console's own labels (#631).
//
// Customize and translate the pages says how each page's language is chosen. A user's page
// language, chosen under Account, Profile, comes before every source a request carries: a
// ui_locales, then the browser's Accept-Language, then English. Language and region no longer
// steers the console, which once read it from the ID token's locale claim, and an email follows it
// only for a user on Automatic. The authorize and sign-out pages' ui_locales rows say the page
// language wins over them, and the Scopes page says the locale claim is the Language and region the
// user picked, not the language of Goiabada's own pages. The labels each page quotes are the English
// catalog's, so a page naming a field the console does not show fails.
//
// It reads files and nothing else.

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/docsreader"
	"github.com/leodip/goiabada/core/guard"
)

// The pages, relative to the repository root, and the guide's anchor the others link to.
const (
	authorizePage       = "site/src/content/docs/reference/endpoints/authorize.mdx"
	logoutPage          = "site/src/content/docs/reference/endpoints/logout.mdx"
	scopesPage          = "site/src/content/docs/concepts/scopes.mdx"
	languageChosenLink  = "/guides/customize-and-translate-the-pages/#how-the-language-is-chosen"
	languageChosenTitle = "## How the language is chosen"
)

// bold is a console label as a page quotes it, in the English the console shows.
func bold(key string) string {
	return "**" + T(context.Background(), key) + "**"
}

// The guide puts the page language first, names Automatic as what skips it, and keeps ui_locales
// ahead of the browser. It says emails fall back to Language and region, and no longer says the
// console reads that from the ID token.
func TestPageLanguageDocs_TheGuideSaysThePageLanguageComesFirst(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	pageLanguage := bold("adminconsole.account.profile.field.page_language")
	guard.AssertSectionSays(t, root, customizeGuide, languageChosenTitle,
		[]string{
			pageLanguage,
			bold("adminconsole.account.profile.page_language_automatic"),
			bold("adminconsole.account.profile.field.locale"),
			"**" + T(context.Background(), "adminconsole.account_menu.profile") + "**",
			"`ui_locales`",
			"`Accept-Language`",
			"password",
			"email",
		},
		[]string{"`locale` claim", "refreshes the user's tokens", "the user's own choice comes first: the **Language and region**"})
	assertSaysInOrder(t, root, customizeGuide, languageChosenTitle, pageLanguage, "`ui_locales`", "`Accept-Language`")
}

// The guide's step on where users choose the language names the page language.
func TestPageLanguageDocs_AddingALanguageSaysWhereUsersChooseIt(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuide, "## Add a language",
		[]string{bold("adminconsole.account.profile.field.page_language"), "`ui_locales`", "(#how-the-language-is-chosen)"}, nil)
}

// The authorize and sign-out pages' ui_locales rows say a user's page language wins over them.
func TestPageLanguageDocs_TheUILocalesRowsSayThePageLanguageWins(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	assertParameterRowSays(t, root, authorizePage, "## Parameters", "`ui_locales`", "page language", languageChosenLink)
	assertParameterRowSays(t, root, logoutPage, "## The request", "`ui_locales`", "page language", languageChosenLink)
}

// The Scopes page says the locale claim is the Language and region the user picked, not "the
// language the user chose", which would read as the page language.
func TestPageLanguageDocs_TheScopesPageSaysLocaleIsTheLanguageAndRegion(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), scopesPage, "## OpenID Connect scopes and their claims",
		[]string{bold("adminconsole.account.profile.field.locale"), "page language"},
		[]string{"`locale` is the language the user chose."})
}

func TestPageLanguageDocs_ARowNotSayingTheTextFails(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/authorize.mdx", "## Parameters\n\n"+
		"| Parameter | Required | |\n|---|---|---|\n"+
		"| `ui_locales` | No | The languages for the sign-in pages |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertParameterRowSays(r, root, "site/authorize.mdx", "## Parameters", "`ui_locales`", "page language")
	})

	want := []string{"site/authorize.mdx: the `ui_locales` row under ## Parameters does not say \"page language\""}
	if report.Stopped || !slices.Equal(report.Errors, want) {
		t.Errorf("failures %+v\nwant %q", report, want)
	}
}

func TestPageLanguageDocs_ARowSayingTheTextPasses(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/authorize.mdx", "## Parameters\n\n"+
		"| Parameter | Required | |\n|---|---|---|\n"+
		"| `state` | No | Any value |\n"+
		"| `ui_locales` | No | The languages. A user's page language wins over it. |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertParameterRowSays(r, root, "site/authorize.mdx", "## Parameters", "`ui_locales`", "page language")
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a row saying the text was refused: %+v", report)
	}
}

func TestPageLanguageDocs_AMissingRowStops(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/authorize.mdx", "## Parameters\n\n"+
		"| Parameter | Required | |\n|---|---|---|\n"+
		"| `state` | No | Any value, such as page language |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertParameterRowSays(r, root, "site/authorize.mdx", "## Parameters", "`ui_locales`", "page language")
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "`ui_locales`") {
		t.Errorf("a section with no such row did not stop the check naming it: %+v", report)
	}
}

func TestPageLanguageDocs_TextsOutOfOrderFail(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/translate.mdx", "## How the language is chosen\n\n"+
		"1. The `ui_locales` parameter.\n2. The user's **Page language**.\n3. The browser's `Accept-Language`.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSaysInOrder(r, root, "site/translate.mdx", "## How the language is chosen", "**Page language**", "`ui_locales`", "`Accept-Language`")
	})

	want := []string{"site/translate.mdx: ## How the language is chosen names \"`ui_locales`\" before \"**Page language**\""}
	if report.Stopped || !slices.Equal(report.Errors, want) {
		t.Errorf("failures %+v\nwant %q", report, want)
	}
}

func TestPageLanguageDocs_TextsInOrderPass(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/translate.mdx", "## How the language is chosen\n\n"+
		"1. The user's **Page language**.\n2. The `ui_locales` parameter.\n3. The browser's `Accept-Language`, after `ui_locales`.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSaysInOrder(r, root, "site/translate.mdx", "## How the language is chosen", "**Page language**", "`ui_locales`", "`Accept-Language`")
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("texts in order were refused: %+v", report)
	}
}

// assertParameterRowSays holds the table row under heading whose first cell is parameter to saying
// each text: one failure per text the row's cells do not hold, and a stop for a section with no such
// row, so a renamed parameter cannot pass as one that was read.
func assertParameterRowSays(r guard.Reporter, root, page, heading, parameter string, texts ...string) {
	r.Helper()
	section, err := docsreader.Section(root, page, heading)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, row := range docsreader.Rows(section) {
		if len(row) == 0 || row[0] != parameter {
			continue
		}
		cells := strings.Join(row, " | ")
		for _, text := range texts {
			if !strings.Contains(cells, text) {
				r.Errorf("%s: the %s row under %s does not say %q", page, parameter, heading, text)
			}
		}
		return
	}
	r.Fatalf("%s: %s has no %s row, so this check read nothing", page, heading, parameter)
}

// assertSaysInOrder holds a section to first naming each text after the one before it: one failure
// per text whose first mention comes before its predecessor's, and one per text it does not name.
func assertSaysInOrder(r guard.Reporter, root, page, heading string, texts ...string) {
	r.Helper()
	section, err := docsreader.Section(root, page, heading)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	previous := -1
	for i, text := range texts {
		at := strings.Index(section, text)
		switch {
		case at < 0:
			r.Errorf("%s: %s does not say %q", page, heading, text)
			continue
		case at < previous:
			r.Errorf("%s: %s names %q before %q", page, heading, text, texts[i-1])
		}
		previous = at
	}
}
