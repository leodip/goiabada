package apihandlers

// The brands as Customize and translate the pages describes them, held to the code (#810), and a
// client's brand as the Clients page, the glossary and the Logout reference describe it (#812).
//
// The guide is where an operator learns which looks there are before choosing one: the themes, by
// the names the console's Branding pages give them and in the order those pages list them, the three
// appearances, the brand a new install starts on, and the console's labels a step names. Each is a
// fact the code owns, the presets, the seed and the catalogs, and a guide naming a theme the editor
// does not offer, or leaving one out, misleads with nothing going red. The Clients page is where an
// administrator learns how to give a client its brand, by the console's labels and the admin API's
// operation, and the pages that once said every page is drawn in the default brand must not say so
// again.
//
// It reads files and the English catalog, and nothing else.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/i18n"
)

const (
	customizeGuidePage = "site/src/content/docs/guides/customize-and-translate-the-pages.mdx"
	glossaryPage       = "site/src/content/docs/concepts/glossary.mdx"
	logoutPage         = "site/src/content/docs/reference/endpoints/logout.mdx"

	// clientBrandLink is the Clients page's section on a client's brand, which the other pages
	// link to rather than repeat.
	clientBrandLink = "/concepts/clients/#brand"
)

// english is a message's English text, as the console's pages show it.
func english(key string) string {
	return i18n.T(context.Background(), key)
}

// themeName is a built-in theme's English name, as the brand editor labels its option.
func themeName(key string) string {
	return english("adminconsole.admin_branding.theme." + strings.ReplaceAll(key, "-", "_"))
}

// boldList is names in bold, as prose lists them: "**a**, **b** and **c**".
func boldList(names []string) string {
	bold := make([]string, len(names))
	for i, name := range names {
		bold[i] = "**" + name + "**"
	}
	if len(bold) < 2 {
		return strings.Join(bold, "")
	}
	return strings.Join(bold[:len(bold)-1], ", ") + " and " + bold[len(bold)-1]
}

// The step that opens the Branding pages names them by the console's menu label.
func TestBrandDocs_TheStepOpensBranding(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, "## Brand the pages",
		[]string{
			"**Admin**, **" + english("adminconsole.admin_menu.settings_branding") + "**",
			"**" + english("adminconsole.admin_branding.list.default_tag") + "**",
			"**" + english("adminconsole.admin_branding.brand.field.appearance") + "**",
			"**" + english("adminconsole.admin_branding.brand.field.theme") + "**",
			"**" + english("adminconsole.admin_clients.settings.field.brand") + "**",
			"**" + english("adminconsole.client_tabs.settings") + "**",
			clientBrandLink,
		},
		[]string{
			"**Theme** and choose a **Color theme**",
			"The sign-in pages and the admin console are drawn in the default brand",
		})
}

// The themes are every built-in one, in the order the editor lists them, by the names it gives
// them; the appearances are the editor's three; and a new install's brand is the seeded one.
func TestBrandDocs_TheThemesAppearancesAndSeededBrandAreTheCodes(t *testing.T) {
	var themes []string
	for _, preset := range brandthemes.All() {
		themes = append(themes, themeName(preset.Key))
	}

	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, "## Brands and themes",
		[]string{
			"one of eight built-in themes: " + boldList(themes) + ".",
			"**" + english("adminconsole.admin_branding.appearance.auto") + "**",
			"**" + english("adminconsole.admin_branding.appearance.light") + "**",
			"**" + english("adminconsole.admin_branding.appearance.dark") + "**",
			"one brand, **" + record.SeededBrandName + "**, on **" +
				english("adminconsole.admin_branding.appearance."+string(record.BrandAppearanceAuto)) + "** and **" +
				themeName(record.BrandThemeBlueberry) + "**",
			"**" + english("adminconsole.admin_branding.list.new_button") + "**",
			"**" + english("adminconsole.admin_branding.brand.make_default_button") + "**",
			"**" + english("adminconsole.admin_branding.list.col_clients") + "**",
			clientBrandLink,
		},
		[]string{
			"no page is drawn in it until it's the default",
			"every page of the auth server and the admin console is drawn in it",
		})
	if len(themes) != 8 {
		t.Errorf("the guide says eight built-in themes, but there are %d", len(themes))
	}
}

// defaultBrandOption is the first option of a client's Brand select as a page quotes it, "**Default
// brand (", up to where the console names the current default.
func defaultBrandOption() string {
	label, _, _ := strings.Cut(english("adminconsole.admin_clients.settings.field.brand_default"), " (")
	return "**" + label + " ("
}

// The Clients page says where a client's brand is chosen, by the labels of the Settings tab, what
// the first option does, which pages it draws, that a self-registered client starts on the default,
// and how the admin API sets it and the audit log records it.
func TestBrandDocs_TheClientsPageSaysHowABrandIsAssigned(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	guard.AssertSectionSays(t, root, clientsPage, "## Brand",
		[]string{
			"**" + english("adminconsole.admin_clients.settings.field.brand") + "**",
			"**" + english("adminconsole.admin_clients.settings.screens_legend") + "**",
			"**" + english("adminconsole.client_tabs.settings") + "**",
			defaultBrandOption(),
			"[`PUT /api/v1/admin/clients/{id}/brand`](/reference/api/admin/operations/updateclientbrand/)",
			"`brandId`",
			"`null`",
			"`" + audit.EventUpdatedClientBrand + "`",
			"id_token_hint",
			"`client_id`",
			"form_post",
			"[registers itself](#self-registered-clients) starts on the default brand",
		}, nil)
	guard.AssertSectionSays(t, root, clientsPage, "## Settings a new client starts with",
		[]string{"on the default brand"}, nil)
}

// The Clients page says the admin console is drawn in its own client's brand.
func TestBrandDocs_TheConsolesClientDrawsTheConsole(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), clientsPage, "## The admin console's client",
		[]string{"[brand](#brand)", "every page of the admin console"}, nil)
}

// The glossary's brand is one a client can be given, and points at the Clients page for it.
func TestBrandDocs_TheGlossarySaysAClientHasABrand(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), glossaryPage, "### Brand",
		[]string{clientBrandLink, "admin console's own client"},
		[]string{"every page is drawn in it"})
}

// The Logout reference says which brand a sign-out's pages take: a confirmed hint's client, or
// without a hint the client client_id names, and the default for a hint it can't confirm.
func TestBrandDocs_TheLogoutReferenceSaysWhichBrandItsPagesTake(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), logoutPage, "## Whether the user is asked",
		[]string{"[brand](" + clientBrandLink + ")", "`client_id`", "default brand"}, nil)
}
