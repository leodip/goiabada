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
// again. A brand's kit (#813) is held the same way: the guide's section on it names the editor's
// fields by their labels, each kind's limits and the admin API's two steps, and the Clients page,
// the glossary, the Security page and the scopes page say where the kit is drawn, the font's
// cross-origin grant and the scopes its files take.
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
	"github.com/leodip/goiabada/core/brandkit"
	"github.com/leodip/goiabada/core/docsreader"
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

	// brandKitLink is the customize guide's section on a brand's kit (#813), which the other pages
	// link to rather than repeat.
	brandKitLink = "/guides/customize-and-translate-the-pages/#the-brand-kit"
	brandKitHead = "## The brand kit"

	securityReferencePage = "site/src/content/docs/reference/security.mdx"
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
			"#the-brand-kit",
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

// The Clients page says the admin console is drawn in its own client's brand: its end-user pages
// in the whole brand, its admin pages in the brand's colors and logo alone (#813 decision 9).
func TestBrandDocs_TheConsolesClientDrawsTheConsole(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), clientsPage, "## The admin console's client",
		[]string{
			"[brand](#brand)",
			"**" + english("adminconsole.menu.account") + "**",
			"colors and logo",
			"font, corners and icons",
			brandKitLink,
		},
		[]string{"every page of the admin console is drawn in it"})
}

// The glossary's brand is one a client can be given, holds the kit, and points at the Clients page
// for it.
func TestBrandDocs_TheGlossarySaysAClientHasABrand(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), glossaryPage, "### Brand",
		[]string{clientBrandLink, "admin console's own client", "logo", "favicon", "background image", "font", "corners",
			"colors and logo"},
		[]string{"every page is drawn in it"})
}

// The Logout reference says which brand a sign-out's pages take: a confirmed hint's client, or
// without a hint the client client_id names, and the default for a hint it can't confirm.
func TestBrandDocs_TheLogoutReferenceSaysWhichBrandItsPagesTake(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), logoutPage, "## Whether the user is asked",
		[]string{"[brand](" + clientBrandLink + ")", "`client_id`", "default brand"}, nil)
}

// brandLabel is a brand editor's field label or option, in English and in bold, as the guide names it.
func brandLabel(key string) string {
	return "**" + english("adminconsole.admin_branding."+key) + "**"
}

// The kit's section names every field and choice of the editor by the label the editor gives it, the
// six system families and the uploaded font in the editor's order, and the buttons an upload field
// has (#813). A guide naming a field the editor does not have, or a family it does not offer,
// misleads an administrator looking for it.
func TestBrandDocs_TheKitNamesTheEditorsFieldsAndChoices(t *testing.T) {
	var families []string
	for _, key := range []string{"system_ui", "humanist", "geometric", "serif", "neo_grotesque", "rounded"} {
		families = append(families, english("adminconsole.admin_branding.font."+key))
	}
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, brandKitHead,
		[]string{
			brandLabel("brand.field.logo"),
			brandLabel("brand.field.dark_logo"),
			brandLabel("brand.field.hide_app_name"),
			brandLabel("brand.field.favicon"),
			brandLabel("brand.field.background_fit"),
			brandLabel("background_fit.cover"),
			brandLabel("background_fit.contain"),
			brandLabel("background_fit.tile"),
			brandLabel("brand.field.font"),
			"six system families: " + boldList(families) + ".",
			brandLabel("font.uploaded"),
			brandLabel("brand.field.regular_font"),
			brandLabel("brand.field.bold_font"),
			brandLabel("brand.field.corners"),
			brandLabel("corners.square") + ", " + brandLabel("corners.rounded") + " or " + brandLabel("corners.pill"),
			brandLabel("asset.upload"),
			brandLabel("asset.remove"),
		}, nil)
}

// kitRow is the row of the kit's limits table whose first cell names label in bold, or nil.
func kitRow(rows [][]string, label string) []string {
	for _, row := range rows {
		if len(row) > 0 && strings.Contains(row[0], "**"+label+"**") {
			return row
		}
	}
	return nil
}

// The kit's limits table holds each kind of file to the limits #813 decision 3 fixes: its types,
// its pixel bounds and its size. The values are written out, so a guide and a rule that drift
// apart fail here or in the upload tests that hold the code to the same values.
func TestBrandDocs_TheKitStatesEachKindsLimits(t *testing.T) {
	text, err := docsreader.Section(filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, brandKitHead)
	if err != nil {
		t.Fatal(err)
	}
	rows := docsreader.Rows(text)
	for _, want := range []struct {
		label string
		cells []string
	}{
		{english("adminconsole.admin_branding.brand.field.logo"), []string{"PNG, JPEG or WebP", "10 to 512 pixels", "1 MiB"}},
		{english("adminconsole.admin_branding.brand.field.dark_logo"), []string{"PNG, JPEG or WebP", "10 to 512 pixels", "1 MiB"}},
		{english("adminconsole.admin_branding.brand.field.favicon"), []string{"PNG", "square", "48 to 512 pixels", "1 MiB"}},
		{english("adminconsole.admin_branding.brand.field.background_fit"), []string{"PNG, JPEG or WebP", "10 to 3840 pixels", "2 MiB"}},
		{english("adminconsole.admin_branding.brand.field.regular_font"), []string{"WOFF2", "2 MiB"}},
		{english("adminconsole.admin_branding.brand.field.bold_font"), []string{"WOFF2", "2 MiB"}},
	} {
		row := kitRow(rows, want.label)
		if row == nil {
			t.Errorf("%s: %s has no limits row for **%s**", customizeGuidePage, brandKitHead, want.label)
			continue
		}
		joined := strings.Join(row, " | ")
		for _, cell := range want.cells {
			if !strings.Contains(joined, cell) {
				t.Errorf("%s: %s's row for **%s** does not say %q: %s", customizeGuidePage, brandKitHead, want.label, cell, joined)
			}
		}
	}
	if brandkit.LogoMaxBytes != 1<<20 || brandkit.FaviconMaxBytes != 1<<20 ||
		brandkit.BackgroundMaxBytes != 2<<20 || brandkit.FontMaxBytes != 2<<20 {
		t.Errorf("the guide states 1 MiB for a logo and a favicon and 2 MiB for a background and a font, but brandkit's limits differ")
	}
}

// The kit's section gives the admin API's two steps, an upload per kind then the brand's write
// naming the asset by its id, and says an asset never saved in a brand is deleted (#813 decision 1).
// It says where the kit is drawn, how the uploaded font's two files split the weights (decision 7),
// and which devices draw Rounded as an ordinary sans.
func TestBrandDocs_TheKitSaysTheAPIsTwoStepsAndWhereItIsDrawn(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), customizeGuidePage, brandKitHead,
		[]string{
			"[`POST /api/v1/admin/brand-assets/logo`](/reference/api/admin/operations/uploadbrandlogo/)",
			"(/reference/api/admin/operations/uploadbrandfavicon/)",
			"(/reference/api/admin/operations/uploadbrandbackground/)",
			"(/reference/api/admin/operations/uploadbrandfont/)",
			"(/reference/api/admin/operations/createbrand/)",
			"(/reference/api/admin/operations/updatebrand/)",
			"`file`",
			`"logo": {"id": 42}`,
			"a day",
			"up to 500",
			"Windows and Android",
			"/concepts/clients/#the-admin-consoles-client",
			"`" + audit.EventUploadedBrandAsset + "`",
		}, nil)
}

// The Security page's list of what answers a cross-origin call names the one grant a brand's font
// file carries, the admin console's origin, and no longer says nothing else answers one (#813
// decision 8).
func TestBrandDocs_TheSecurityPageNamesTheFontGrant(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), securityReferencePage, "## The network",
		[]string{"`/brand-assets/{id}`", "font", "`GOIABADA_ADMINCONSOLE_BASEURL`", "no credentials"},
		[]string{"public, and nothing else answers a cross-origin call"})
}

// The scopes page puts a brand's uploaded files in the settings domain, beside brands, as the
// routes do: the uploads behind the settings write scopes, the read behind the settings read ones.
func TestBrandDocs_TheScopesPagePutsBrandFilesInSettings(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	guard.AssertSectionSays(t, root, apiScopesPage, "## The domains",
		[]string{"brands and their uploaded files"}, nil)
	guard.AssertSectionSays(t, root, apiScopesPage, "## The Admin API scopes",
		[]string{"brands and their uploaded files"}, nil)
}
