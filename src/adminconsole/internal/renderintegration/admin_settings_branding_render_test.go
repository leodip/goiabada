package renderintegration

import (
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Branding pages (#810), drawn through the real renderer in pt-BR: the list marks the default
// and offers no deletion of it, the form draws appearance and theme as option cards whose swatches
// take the colors the auth server listed, each refusal is marked on the field it is about, and the
// delete page of the default says it cannot be deleted.

// Palettes that are no theme's real colors, so a swatch drawn from anything but the bind cannot
// pass. Each value names its theme, mode and token.
func testPalette(prefix string) map[string]string {
	return map[string]string{
		"canvas": "#" + prefix + "001", "surface": "#" + prefix + "002", "line": "#" + prefix + "003",
		"ink": "#" + prefix + "004", "ink-muted": "#" + prefix + "005", "brand": "#" + prefix + "006",
	}
}

var renderThemes = []adminsettingshandlers.BrandThemeOption{
	{Key: "blueberry", Name: "Mirtilo", Light: testPalette("aa0"), Dark: testPalette("ab0")},
	{Key: "plum", Name: "Ameixa", Light: testPalette("ba0"), Dark: testPalette("bb0")},
}

func TestRender_AdminSettingsBrandingListMarksTheDefault(t *testing.T) {
	out := renderMenuPageAt(t, "/admin/settings/branding", "/admin_settings_branding.html", map[string]interface{}{
		"brands": []adminsettingshandlers.BrandRow{
			{BrandResponse: api.BrandResponse{Id: 4, Name: "<b>Autumn</b>", Appearance: "dark", Theme: "plum"},
				AppearanceName: "Escuro", ThemeName: "Ameixa"},
			{BrandResponse: api.BrandResponse{Id: 5, Name: "Default", Appearance: "auto", Theme: "blueberry", IsDefault: true},
				AppearanceName: "Automático", ThemeName: "Mirtilo"},
		},
	})

	// The sidebar's Branding entry, under Settings, is the page the administrator is on.
	assert.Contains(t, out, `<a class="nav-link" href="/admin/settings/branding" aria-current="page">`)
	assert.NotContains(t, out, "/admin/settings/ui-theme")

	assert.Contains(t, out, `href="/admin/settings/branding/new"`)
	assert.Contains(t, out, `<a class="text-link" href="/admin/settings/branding/4/edit">&lt;b&gt;Autumn&lt;/b&gt;</a>`)
	assert.Contains(t, out, `<a class="text-link" href="/admin/settings/branding/5/edit">Default</a>`)
	assert.NotContains(t, out, "<b>Autumn</b>", "a brand's name is text")
	assert.Contains(t, out, ">Escuro</td>")
	assert.Contains(t, out, ">Ameixa</td>")

	// The default is marked, once, and is the one brand with no Delete.
	assert.Equal(t, 1, strings.Count(out, `<span class="tag tag-note ml-1">Padrão</span>`))
	assert.Regexp(t, `branding/5/edit">Default</a>\s*<span class="tag tag-note ml-1">Padrão</span>`, out)
	assert.Contains(t, out, `href="/admin/settings/branding/4/delete"`)
	assert.NotContains(t, out, `href="/admin/settings/branding/5/delete"`)
}

// radioTag is the whole <input> of the radio with the id named.
func radioTag(t *testing.T, out, id string) string {
	t.Helper()
	tag := regexp.MustCompile(`<input type="radio" id="` + regexp.QuoteMeta(id) + `"[^>]*>`).FindString(out)
	require.NotEmpty(t, tag, "no radio %s", id)
	return tag
}

func TestRender_AdminSettingsBrandingFormDrawsTheSwatchesFromThePalettes(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
		"isNew":           false,
		"storedBrand":     api.BrandResponse{Id: 4, Name: "Autumn", Appearance: "dark", Theme: "plum"},
		"brand":           adminsettingshandlers.BrandForm{Name: "Autumn", Appearance: "dark", Theme: "plum"},
		"brandThemes":     renderThemes,
		"appearanceTheme": renderThemes[1],
	})

	assert.Contains(t, out, `<h1 class="page-title">Autumn</h1>`)
	assert.Contains(t, out, `value="Autumn"`)

	// Appearance and theme are option cards, the stored ones checked.
	assert.Contains(t, radioTag(t, out, "appearance-dark"), " checked")
	assert.NotContains(t, radioTag(t, out, "appearance-auto"), " checked")
	assert.NotContains(t, radioTag(t, out, "appearance-light"), " checked")
	assert.Contains(t, radioTag(t, out, "theme-plum"), `name="theme" value="plum" checked`)
	assert.NotContains(t, radioTag(t, out, "theme-blueberry"), " checked")
	assert.Contains(t, out, `<span class="choice-label" id="theme-name-plum">Ameixa</span>`)
	assert.Contains(t, out, `<span class="choice-label" id="appearance-name-auto">Automático</span>`)

	// Each theme card shows its light and its dark palette, the line as the card's border; every
	// value comes from the bind.
	for _, theme := range renderThemes {
		for _, palette := range []map[string]string{theme.Light, theme.Dark} {
			for token, value := range palette {
				assert.Regexp(t, `(fill|stroke)="`+value+`"`, out, "%s's %s", theme.Key, token)
			}
		}
	}
	// The appearance cards are drawn in the form's theme: Plum's light alone on Light, its dark on
	// Dark, and both on Automatic; Blueberry's colors appear only on Blueberry's own card.
	assert.Equal(t, 1+2, strings.Count(out, `fill="#ba0001"`), "Plum's light canvas: its card, Light and Automatic")
	assert.Equal(t, 1+2, strings.Count(out, `fill="#bb0001"`), "Plum's dark canvas: its card, Dark and Automatic")
	assert.Equal(t, 1, strings.Count(out, `fill="#aa0001"`))
	assert.NotContains(t, out, "theme-swatch-light", "no swatch keeps hand-written colors")

	// A brand that is not the default can be made the default, asked first.
	assert.Contains(t, out, `action="/admin/settings/branding/4/make-default" data-confirm-dialog="makeDefault"`)
	assert.Contains(t, out, `id="makeDefault_modalDialog"`)
	assert.Contains(t, out, "Nenhuma página é exibida nesta marca.")
}

func TestRender_AdminSettingsBrandingFormOfTheDefaultOffersNoMakeDefault(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
		"isNew":             false,
		"storedBrand":       api.BrandResponse{Id: 5, Name: "Default", Appearance: "auto", Theme: "blueberry", IsDefault: true},
		"brand":             adminsettingshandlers.BrandForm{Name: "Default", Appearance: "auto", Theme: "blueberry"},
		"brandThemes":       renderThemes,
		"appearanceTheme":   renderThemes[0],
		"savedSuccessfully": true,
	})

	assert.NotContains(t, out, "make-default")
	assert.NotContains(t, out, "makeDefault_modalDialog")
	assert.Contains(t, out, `<span class="tag tag-note">Padrão</span>`)
	assert.Contains(t, out, "Esta é a marca padrão")
	assert.Contains(t, out, `<div class="notice notice-positive" role="status">`)
	assert.Contains(t, out, "Marca salva.")
	assert.Contains(t, radioTag(t, out, "appearance-auto"), " checked")
}

func TestRender_AdminSettingsBrandingNewForm(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
		"isNew":           true,
		"brand":           adminsettingshandlers.BrandForm{Appearance: "auto", Theme: "blueberry"},
		"brandThemes":     renderThemes,
		"appearanceTheme": renderThemes[0],
	})

	assert.Contains(t, out, `<h1 class="page-title">Nova marca</h1>`)
	assert.Contains(t, out, ">Criar marca</button>")
	assert.NotContains(t, out, "make-default")
	assert.Regexp(t, `<input class="control" id="name"[^>]* autofocus>`, out, "a new brand starts at its name")
	assert.Contains(t, radioTag(t, out, "theme-blueberry"), " checked")
}

// Each refusal is marked on the field it is about: the name input for the name's four, the
// appearance cards and the theme cards for theirs, the group described by the notice and its first
// card focused.
func TestRender_AdminSettingsBrandingFormMarksTheRefusedField(t *testing.T) {
	render := func(errorField string) string {
		return renderMenuPage(t, "/admin_settings_branding_brand.html", map[string]interface{}{
			"isNew":           true,
			"brand":           adminsettingshandlers.BrandForm{Name: "Spring", Appearance: "auto", Theme: "plum"},
			"brandThemes":     renderThemes,
			"appearanceTheme": renderThemes[1],
			"error":           "Não.",
			"errorField":      errorField,
		})
	}

	out := render("name")
	assert.Contains(t, out, `<div class="notice notice-danger" role="alert" id="brand-error">`)
	assert.Regexp(t, `<input class="control" id="name"[^>]* aria-describedby="brand-error nameHint" aria-invalid="true" autofocus>`, out)
	assert.NotContains(t, out, `<fieldset aria-describedby="brand-error">`)
	for _, id := range []string{"appearance-auto", "theme-plum"} {
		assert.NotContains(t, radioTag(t, out, id), "aria-invalid")
	}

	out = render("appearance")
	assert.NotRegexp(t, `id="name"[^>]*aria-invalid`, out)
	assert.Equal(t, 1, strings.Count(out, `<fieldset aria-describedby="brand-error">`))
	for _, id := range []string{"appearance-auto", "appearance-light", "appearance-dark"} {
		assert.Contains(t, radioTag(t, out, id), `aria-invalid="true"`)
	}
	assert.Contains(t, radioTag(t, out, "appearance-auto"), "autofocus")
	assert.NotContains(t, radioTag(t, out, "theme-blueberry"), "aria-invalid")

	out = render("theme")
	assert.NotRegexp(t, `id="name"[^>]*aria-invalid`, out)
	assert.Equal(t, 1, strings.Count(out, `<fieldset aria-describedby="brand-error">`))
	for _, id := range []string{"theme-blueberry", "theme-plum"} {
		assert.Contains(t, radioTag(t, out, id), `aria-invalid="true"`)
	}
	assert.Contains(t, radioTag(t, out, "theme-blueberry"), "autofocus", "the first theme takes the focus")
	assert.NotContains(t, radioTag(t, out, "theme-plum"), "autofocus")
	assert.NotContains(t, radioTag(t, out, "appearance-auto"), "aria-invalid")

	// A refusal about no one field marks none, and leaves the focus on the name.
	out = render("")
	assert.NotContains(t, out, `aria-invalid="true"`)
	assert.Regexp(t, `<input class="control" id="name"[^>]* autofocus>`, out)
}

func TestRender_AdminSettingsBrandingDeletePage(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_branding_delete.html", map[string]interface{}{
		"brand": adminsettingshandlers.BrandRow{
			BrandResponse:  api.BrandResponse{Id: 4, Name: "Autumn", Appearance: "dark", Theme: "plum"},
			AppearanceName: "Escuro", ThemeName: "Ameixa"},
	})
	assert.Contains(t, out, "<dd>Autumn</dd>")
	assert.Contains(t, out, "<dd>Escuro</dd>")
	assert.Contains(t, out, "<dd>Ameixa</dd>")
	assert.Contains(t, out, `<input class="control" id="name" type="text" name="name" value=""`)
	assert.Contains(t, out, `<button id="btnDelete" class="button button-danger" type="submit">Excluir marca</button>`)

	// The default cannot be deleted: its page says so, in the auth server's own words, and offers
	// no deletion.
	out = renderMenuPage(t, "/admin_settings_branding_delete.html", map[string]interface{}{
		"brand": adminsettingshandlers.BrandRow{
			BrandResponse:  api.BrandResponse{Id: 5, Name: "Default", Appearance: "auto", Theme: "blueberry", IsDefault: true},
			AppearanceName: "Automático", ThemeName: "Mirtilo"},
	})
	assert.Contains(t, out, `<div class="notice notice-caution">`)
	assert.NotContains(t, out, "btnDelete")
	assert.NotContains(t, out, `name="name"`)
	assert.Contains(t, out, `href="/admin/settings/branding">Voltar às marcas</a>`)
}
