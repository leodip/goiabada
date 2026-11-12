package renderintegration

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/core/api"
)

// The brand editor's Colors section (#815 decisions 7, 8 and 11), drawn through the real renderer:
// the Custom card after the built-in themes, the section shown while it is picked, a row per color
// with a Light and a Dark column, the columns the appearance hides, and a refusal at its field.

// paletteRenderTokens are the 23 color tokens, as ui.css declares them.
var paletteRenderTokens = []string{
	"canvas", "surface", "subtle", "line", "line-strong", "ink", "ink-muted",
	"brand", "brand-strong", "on-brand", "brand-soft",
	"danger", "danger-strong", "on-danger", "danger-soft", "danger-ink",
	"positive-soft", "positive-ink", "caution-soft", "caution-ink", "note-soft", "note-ink",
	"focus",
}

// renderColors is a value for each token no theme has: the prefix and the token's place.
func renderColors(prefix string) map[string]string {
	colors := make(map[string]string, len(paletteRenderTokens))
	for i, token := range paletteRenderTokens {
		colors[token] = fmt.Sprintf("#%s%02d", prefix, i)
	}
	return colors
}

// renderPaletteForm draws brand 8's form in locale, on theme and appearance, its Colors section
// holding palette, refused at errorField when it names one.
func renderPaletteForm(t *testing.T, locale, theme, appearance string, palette adminsettingshandlers.BrandPaletteForm, errorField string) string {
	t.Helper()
	bind := map[string]interface{}{
		"isNew":           false,
		"storedBrand":     api.BrandResponse{Id: 8, Name: "Custom", Appearance: appearance, Theme: theme},
		"brand":           adminsettingshandlers.BrandForm{Name: "Custom", Appearance: appearance, Theme: theme},
		"brandThemes":     renderThemes,
		"appearanceTheme": renderThemes[0],
		"palette":         adminsettingshandlers.NewBrandPaletteView(palette, appearance, errorField),
	}
	if errorField != "" {
		bind["error"] = "Não."
		bind["errorField"] = errorField
	}
	return renderMenuPageIn(t, "/admin_settings_branding_brand.html", bind, locale, true)
}

func basicPalette() adminsettingshandlers.BrandPaletteForm {
	return adminsettingshandlers.BrandPaletteForm{Mode: "basic", StoredMode: "basic", Light: renderColors("e0de"), Dark: renderColors("f0de")}
}

// tagWith is the whole start tag holding attr, which must be in exactly one.
func tagWith(t *testing.T, out, attr string) string {
	t.Helper()
	tags := regexp.MustCompile(`<[a-z]+\b[^>]*`+regexp.QuoteMeta(attr)+`[^>]*>`).FindAllString(out, -1)
	require.Len(t, tags, 1, "one tag with %s", attr)
	return tags[0]
}

func isHidden(tag string) bool {
	return regexp.MustCompile(`\shidden(\s|>|=)`).MatchString(tag)
}

// The Custom card is the ninth theme card, after the built-in ones, checked while the brand is
// custom; its swatch is drawn in the palette's colors. The Colors section is shown while it is picked
// and drawn hidden otherwise, holding its values either way.
func TestRender_AdminSettingsBrandingCustomCardOpensTheColorsSection(t *testing.T) {
	custom := renderPaletteForm(t, "pt-BR", "custom", "auto", basicPalette(), "")

	card := radioTag(t, custom, "theme-custom")
	assert.Contains(t, card, ` name="theme" value="custom"`)
	assert.Contains(t, card, " checked")
	assert.Greater(t, strings.Index(custom, `id="theme-custom"`), strings.Index(custom, `id="theme-plum"`), "after the built-in themes")
	assert.Contains(t, custom, `<span class="choice-label" id="theme-name-custom">Personalizado</span>`)
	assert.NotContains(t, radioTag(t, custom, "theme-plum"), " checked")
	swatch := custom[strings.Index(custom, `id="theme-custom"`):strings.Index(custom, `id="theme-name-custom"`)]
	assert.Contains(t, swatch, `fill="#e0de00" data-fill="canvas"`, "the light swatch is the palette's")
	assert.Contains(t, swatch, `fill="#f0de07" data-fill="brand"`, "the dark swatch is the palette's")
	assert.False(t, isHidden(tagWith(t, custom, `id="brand-palette"`)))
	assert.NotContains(t, custom, `<input type="hidden" name="theme" value="custom">`, "the card is the custom theme's one input")

	plum := renderPaletteForm(t, "pt-BR", "plum", "auto", basicPalette(), "")
	assert.NotContains(t, radioTag(t, plum, "theme-custom"), " checked")
	assert.True(t, isHidden(tagWith(t, plum, `id="brand-palette"`)))
	assert.Contains(t, tagWith(t, plum, `id="palette-light-brand"`), ` value="#e0de07"`, "the values are in the page")
}

// The section says what the check establishes, in decision 11's words.
func TestRender_AdminSettingsBrandingColorsSectionSaysWhatTheCheckEstablishes(t *testing.T) {
	out := renderPaletteForm(t, "en", "custom", "auto", basicPalette(), "")

	assert.Contains(t, out, "Goiabada checks the pairs of colors its pages use for text, boundaries and focus rings "+
		"against the WCAG 2.2 level AA contrast minimums: 4.5:1 for text, 3:1 for boundaries and focus rings. "+
		"Every built-in theme meets them. A custom palette is saved even when a pair is below its minimum, and "+
		"those pairs are listed here.")
	assert.NotContains(t, out, "meets WCAG", "the page never says a palette meets WCAG")
}

// Each color is a row: its plain label, and a color well beside a #rrggbb text field in each
// column. The text field is what the form sends, named by the row and the column, as the well is;
// the well is drawn hidden, since only the script keeps it in step.
func TestRender_AdminSettingsBrandingColorsSectionDrawsARowPerColor(t *testing.T) {
	out := renderPaletteForm(t, "en", "custom", "auto", basicPalette(), "")

	assert.Regexp(t, `<span class="palette-label" id="palette-label-ink-muted">Muted text <code class="palette-token" data-palette-advanced hidden>ink-muted</code></span>`, out)
	assert.Contains(t, out, `id="palette-label-brand-soft">Soft brand background <code`)
	assert.Contains(t, out, `id="palette-head-light" data-palette-column="light">Light</span>`)
	assert.Contains(t, out, `id="palette-head-dark" data-palette-column="dark">Dark</span>`)

	text := tagWith(t, out, `id="palette-dark-ink-muted"`)
	assert.Contains(t, text, `type="text"`)
	assert.Contains(t, text, `name="palette-dark-ink-muted"`)
	assert.Contains(t, text, `value="#f0de06"`)
	assert.Contains(t, out, `<label class="sr-only" for="palette-dark-ink-muted">Muted text, Dark</label>`)
	assert.Contains(t, out, `<label class="sr-only" for="palette-dark-ink-muted-well">Muted text, Dark: color picker</label>`)
	assert.NotContains(t, text, "aria-invalid")

	well := tagWith(t, out, `id="palette-dark-ink-muted-well"`)
	assert.Contains(t, well, `type="color"`)
	assert.Contains(t, well, `value="#f0de06"`)
	assert.NotContains(t, well, "name=", "the well is not sent")
	assert.True(t, isHidden(well))

	for _, token := range paletteRenderTokens {
		for _, mode := range []string{"light", "dark"} {
			assert.Contains(t, out, fmt.Sprintf(`name="palette-%s-%s"`, mode, token))
		}
	}
	assert.True(t, isHidden(tagWith(t, out, `data-palette-copy`)), "Copy colors from needs the script")
}

// Basic shows the four rows of background, card, text and brand color, and Advanced all 23, in
// their groups, with each token's name (decision 7).
func TestRender_AdminSettingsBrandingColorsSectionShowsTheRowsOfItsMode(t *testing.T) {
	basic := renderPaletteForm(t, "en", "custom", "auto", basicPalette(), "")
	advanced := basicPalette()
	advanced.Mode = "advanced"
	all := renderPaletteForm(t, "en", "custom", "auto", advanced, "")

	assert.Contains(t, radioTag(t, basic, "paletteMode-basic"), " checked")
	assert.Contains(t, radioTag(t, all, "paletteMode-advanced"), " checked")
	for _, token := range paletteRenderTokens {
		row := fmt.Sprintf(`data-palette-row="%s"`, token)
		four := token == "canvas" || token == "surface" || token == "ink" || token == "brand"
		assert.Equal(t, !four, isHidden(tagWith(t, basic, row)), "basic: %s", token)
		assert.False(t, isHidden(tagWith(t, all, row)), "advanced: %s", token)
	}
	for _, group := range []string{"Page", "Text", "Brand", "Status"} {
		assert.Regexp(t, `<p class="palette-group-name" id="palette-group-[a-z]+" data-palette-advanced hidden>`+group+`</p>`, basic)
		assert.Regexp(t, `<p class="palette-group-name" id="palette-group-[a-z]+" data-palette-advanced>`+group+`</p>`, all)
	}
	assert.Contains(t, all, `<code class="palette-token" data-palette-advanced>ink-muted</code>`)
}

// Going back to Basic over a palette set in Advanced says the others are worked out at the save.
func TestRender_AdminSettingsBrandingColorsSectionSaysBasicWorksTheOthersOut(t *testing.T) {
	back := basicPalette()
	back.StoredMode = "advanced"
	note := `data-palette-basic-note`

	assert.False(t, isHidden(tagWith(t, renderPaletteForm(t, "en", "custom", "auto", back, ""), note)))
	assert.True(t, isHidden(tagWith(t, renderPaletteForm(t, "en", "custom", "auto", basicPalette(), ""), note)))
	assert.Contains(t, renderPaletteForm(t, "en", "custom", "auto", back, ""),
		"When the brand is saved, the other 19 colors, the status colors included, are worked out from these four")
}

// Under Light the Dark column is hidden, and a line says its colors are kept and not used; under
// Automatic both show and no line does (decision 8).
func TestRender_AdminSettingsBrandingColorsSectionHidesTheColumnTheAppearanceDoesNotDraw(t *testing.T) {
	light := renderPaletteForm(t, "en", "custom", "light", basicPalette(), "")

	assert.True(t, isHidden(tagWith(t, light, `id="palette-head-dark"`)))
	assert.False(t, isHidden(tagWith(t, light, `id="palette-head-light"`)))
	cells := regexp.MustCompile(`<div class="palette-cell" data-palette-column="dark"[^>]*>`).FindAllString(light, -1)
	assert.Len(t, cells, 23)
	for _, cell := range cells {
		assert.True(t, isHidden(cell))
	}
	assert.False(t, isHidden(tagWith(t, light, `data-palette-note="unused-dark"`)))
	assert.Contains(t, light, "The dark colors are kept, and are not used while the appearance is Light.")
	assert.True(t, isHidden(tagWith(t, light, `data-palette-note="unused-light"`)))
	assert.True(t, isHidden(tagWith(t, light, `data-palette-note="invalid-dark"`)))
	assert.Contains(t, tagWith(t, light, `id="palette-dark-brand"`), `value="#f0de07"`, "a hidden column's values are sent unchanged")

	auto := renderPaletteForm(t, "en", "custom", "auto", basicPalette(), "")
	for _, note := range []string{"unused-light", "unused-dark", "invalid-light", "invalid-dark"} {
		assert.True(t, isHidden(tagWith(t, auto, `data-palette-note="`+note+`"`)), note)
	}
}

// A refusal at a field of the column the appearance hides draws that column, with a line saying its
// colors are not drawn but must be valid, and the field marked, described by the notice and its own
// message, and focused, holding what was typed (decision 8's exception).
func TestRender_AdminSettingsBrandingARefusedFieldInAHiddenColumnIsShown(t *testing.T) {
	palette := basicPalette()
	palette.Dark["brand"] = "#12345"

	out := renderPaletteForm(t, "en", "custom", "light", palette, "palette-dark-brand")

	assert.False(t, isHidden(tagWith(t, out, `id="palette-head-dark"`)))
	assert.False(t, isHidden(tagWith(t, out, `data-palette-note="invalid-dark"`)))
	assert.Contains(t, out, "The dark colors are not drawn while the appearance is Light, but each must be a color for the brand to be saved.")
	assert.True(t, isHidden(tagWith(t, out, `data-palette-note="unused-dark"`)))

	field := tagWith(t, out, `id="palette-dark-brand"`)
	assert.Contains(t, field, `value="#12345"`)
	assert.Contains(t, field, `aria-describedby="brand-error palette-dark-brand-error"`)
	assert.Contains(t, field, `aria-invalid="true"`)
	assert.Contains(t, field, "autofocus")
	assert.NotContains(t, tagWith(t, out, `id="name"`), "autofocus")
	assert.Regexp(t, `<p class="field-error" id="palette-dark-brand-error">Enter # and six hexadecimal digits, such as #2456c4.</p>`, out)
	assert.True(t, isHidden(tagWith(t, out, `id="palette-dark-canvas-error"`)), "a color has no message")
}

// A value that is not a color is marked at its field with its message whether or not the save was
// refused there; the notice describes only the refused field.
func TestRender_AdminSettingsBrandingAValueThatIsNoColorIsMarked(t *testing.T) {
	palette := basicPalette()
	palette.Light["ink"] = "navy"

	out := renderPaletteForm(t, "en", "custom", "auto", palette, "name")

	field := tagWith(t, out, `id="palette-light-ink"`)
	assert.Contains(t, field, `aria-describedby="palette-light-ink-error"`)
	assert.Contains(t, field, `aria-invalid="true"`)
	assert.NotContains(t, field, "autofocus")
	assert.False(t, isHidden(tagWith(t, out, `id="palette-light-ink-error"`)))
}

// The mode's refusal is at the Basic and Advanced choice.
func TestRender_AdminSettingsBrandingTheModesRefusalIsAtItsChoice(t *testing.T) {
	palette := basicPalette()
	palette.Mode = "expert"

	out := renderPaletteForm(t, "en", "custom", "auto", palette, "paletteMode")

	assert.Contains(t, radioTag(t, out, "paletteMode-basic"), ` aria-invalid="true" autofocus`)
	assert.Contains(t, radioTag(t, out, "paletteMode-advanced"), ` aria-invalid="true"`)
	assert.NotContains(t, radioTag(t, out, "paletteMode-basic"), " checked")
}

// Copy colors from lists the built-in themes by name.
func TestRender_AdminSettingsBrandingCopyColorsFromListsTheThemes(t *testing.T) {
	out := renderPaletteForm(t, "pt-BR", "custom", "auto", basicPalette(), "")

	assert.Regexp(t, `<select class="control" id="paletteCopyFrom" aria-describedby="paletteCopyHint">\s*<option value="blueberry">Mirtilo</option>\s*<option value="plum">Ameixa</option>\s*</select>`, out)
	assert.Contains(t, out, `<button class="button" type="button" id="paletteCopy">`)
}
