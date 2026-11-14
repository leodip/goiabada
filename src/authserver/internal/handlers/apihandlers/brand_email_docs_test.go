package apihandlers

// An email's brand as Customize and translate the pages describes it, held to the code (#817).
//
// The guide is where an administrator learns, before setting up a brand, what its emails take from
// it and which brand each email is drawn in: the kit's fields and choices an email draws, by the
// labels the brand editor gives them, what never reaches an email, the one appearance it is drawn
// in, the three origins an email's brand follows, and that safe mode reaches emails as it reaches
// pages. A guide naming a field the editor does not have, or promising an email follows the
// reader's mode, misleads with nothing going red.
//
// It reads files and the English catalog, and nothing else.

import (
	"path/filepath"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

const (
	// brandedEmailsHead is the customize guide's section on what an email takes from a brand and
	// which brand it takes.
	brandedEmailsHead = "## Branded emails"
	// brandedEmailsLink is that section, which the guide's first steps and the glossary link to.
	brandedEmailsLink = "/guides/customize-and-translate-the-pages/#branded-emails"
)

// The section names what an email draws of the kit by the editor's labels (#817 decisions 2 and 4):
// the logo and the dark logo, the switch hiding the app name, the corners and the font, an uploaded
// font drawn in System UI, the appearances and which palette each is drawn in, and the footer by
// its section. It says what never reaches an email, and that an email does not follow the reader's
// light or dark mode.
func TestBrandEmailDocs_TheGuideSaysWhatAnEmailTakesFromItsBrand(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, brandedEmailsHead,
		[]string{
			brandLabel("brand.field.logo"),
			brandLabel("brand.field.dark_logo"),
			brandLabel("brand.field.hide_app_name"),
			brandLabel("brand.field.corners"),
			brandLabel("brand.field.font"),
			brandLabel("font.uploaded") + " is drawn in " + brandLabel("font.system_ui"),
			brandLabel("brand.field.appearance") + " is " + brandLabel("appearance.dark") + " is drawn in its dark colors",
			brandLabel("appearance.light") + " and " + brandLabel("appearance.auto") + " brands are drawn in their light colors",
			"#logo-and-app-name",
			"#footer-links-and-support-contact",
			"background image, the favicon and the custom CSS never reach an email",
			"doesn't follow the reader's light or dark mode",
			"plain text",
		},
		[]string{"WebP", "prefers-color-scheme"})
}

// The section says an email takes the brand of the page it was sent from, and which brand each
// origin gives (#817 decision 1): a sign-in's client's, the access token's client's for the
// Account pages and the Account API, the admin console's own client's among them, and the default
// brand for an administrator's action, a client with none, and the forgot password page opened
// outside a sign-in.
func TestBrandEmailDocs_TheGuideSaysWhichBrandAnEmailTakes(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, brandedEmailsHead,
		[]string{
			"the brand of the page it was sent from",
			"The pages of a sign-in to your app",
			"The client's brand",
			"The **" + english("adminconsole.menu.account") + "** pages, or the Account API",
			"The brand of the client the access token was issued to",
			"the admin console's own client's brand",
			"An administrator's action",
			"The default brand",
			"**" + english("adminconsole.email_tabs.send_test") + "**",
			"A client with no brand of its own gives the default brand",
			"outside a sign-in",
			"/concepts/clients/#brand",
		}, nil)
}

// Safe mode says it reaches emails (#817 decision 6): one sent from a sign-in in safe mode, and
// every email while the operator's switch is on, with the console's own safe mode leaving the
// emails of its Account pages alone, since the Account API follows the switch alone.
func TestBrandEmailDocs_SafeModeSaysItReachesEmails(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, "## Safe mode",
		[]string{
			"An email follows safe mode too",
			"sent from the pages of a sign-in in safe mode",
			"every email while `GOIABADA_AUTHSERVER_BRAND_SAFE_MODE` is on",
			"The admin console's safe mode doesn't change the emails its **" + english("adminconsole.menu.account") + "** pages send",
			brandedEmailsLink[len("/guides/customize-and-translate-the-pages/"):],
		}, nil)
}

// The guide's first steps and the glossary's brand point at the section, so an administrator
// setting up a brand learns its emails are drawn in it.
func TestBrandEmailDocs_TheStepsAndTheGlossaryLinkTheSection(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	guard.AssertSectionSays(t, root, customizeGuidePage, "## Brand the pages",
		[]string{"#branded-emails"}, nil)
	guard.AssertSectionSays(t, root, glossaryPage, "### Brand",
		[]string{"emails", brandedEmailsLink}, nil)
}
