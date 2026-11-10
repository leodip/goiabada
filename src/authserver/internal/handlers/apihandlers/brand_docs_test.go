package apihandlers

// The brands as Customize and translate the pages describes them, held to the code (#810).
//
// The guide is where an operator learns which looks there are before choosing one: the themes, by
// the names the console's Branding pages give them and in the order those pages list them, the three
// appearances, the brand a new install starts on, and the console's labels a step names. Each is a
// fact the code owns, the presets, the seed and the catalogs, and a guide naming a theme the editor
// does not offer, or leaving one out, misleads with nothing going red.
//
// It reads files and the English catalog, and nothing else.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/i18n"
)

const customizeGuidePage = "site/src/content/docs/guides/customize-and-translate-the-pages.mdx"

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
		},
		[]string{"**Theme** and choose a **Color theme**"})
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
		}, nil)
	if len(themes) != 8 {
		t.Errorf("the guide says eight built-in themes, but there are %d", len(themes))
	}
}
