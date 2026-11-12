package renderintegration

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/core/api"
)

// The warnings of a saved brand (#815 decision 9), drawn through the real renderer: the list of
// failing pairs at the foot of the Colors section with its count line, each item with its swatch; the
// saved notice's sentence and link to the list; and the brand list's marker and swatches.

// twoWarnings is a saved brand's list of two failing pairs, as the handler builds it.
func twoWarnings() *adminsettingshandlers.BrandContrastWarnings {
	return &adminsettingshandlers.BrandContrastWarnings{
		CountLine: "2 pairs are below their minimum.",
		Notice:    "2 pairs of its colors are below their contrast minimum.",
		Items: []adminsettingshandlers.BrandContrastWarningItem{
			{Mode: "light", Foreground: "#c0de06", Background: "#c0de10", Text: "Light: Muted text on Soft brand background, 3.91:1. Minimum 4.5:1."},
			{Mode: "dark", Foreground: "#d0de03", Background: "#d0de01", Text: "Dark: Border on Card, 2.1:1. Minimum 3:1."},
		},
	}
}

// renderWarningsForm draws brand 8's form on Custom, with its warnings, saved when saved is true.
func renderWarningsForm(t *testing.T, warnings *adminsettingshandlers.BrandContrastWarnings, saved bool) string {
	t.Helper()
	bind := map[string]interface{}{
		"isNew":             false,
		"storedBrand":       api.BrandResponse{Id: 8, Name: "Custom", Appearance: "auto", Theme: "custom"},
		"brand":             adminsettingshandlers.BrandForm{Name: "Custom", Appearance: "auto", Theme: "custom"},
		"brandThemes":       renderThemes,
		"appearanceTheme":   renderThemes[0],
		"palette":           adminsettingshandlers.NewBrandPaletteView(basicPalette(), "auto", ""),
		"savedSuccessfully": saved,
	}
	if warnings != nil {
		bind["paletteWarnings"] = warnings
	}
	return renderMenuPageIn(t, "/admin_settings_branding_brand.html", bind, "en", true)
}

// warningsRegion is the list's region, from its start tag to the end of the Colors section, whose
// last part it is.
func warningsRegion(t *testing.T, out string) string {
	t.Helper()
	start := strings.Index(out, `id="palette-warnings"`)
	require.GreaterOrEqual(t, start, 0, "the page has the list's region")
	end := strings.Index(out[start:], "</fieldset>")
	require.GreaterOrEqual(t, end, 0)
	return out[start : start+end]
}

// The list is at the foot of the Colors section, after its last color row and inside it: the count
// line, announced as it changes, then an item per pair in order, each its sentence beside a swatch of
// the pair, the background drawn behind the foreground.
func TestRender_AdminSettingsBrandingListsTheFailingPairsAtTheFootOfTheColors(t *testing.T) {
	out := renderWarningsForm(t, twoWarnings(), false)

	region := warningsRegion(t, out)
	assert.Greater(t, strings.Index(out, `id="palette-warnings"`), strings.Index(out, `data-palette-row="note-ink"`), "after the last row")
	assert.Less(t, strings.Index(out, `id="palette-warnings"`), strings.Index(out, `id="logoLabel"`), "inside the Colors section")
	assert.False(t, isHidden(tagWith(t, out, `id="palette-warnings"`)))

	assert.Contains(t, tagWith(t, out, `id="paletteWarningsCount"`), `role="status"`)
	assert.Regexp(t, `id="paletteWarningsCount"[^>]*>2 pairs are below their minimum.</p>`, region)
	items := regexp.MustCompile(`(?s)<li class="palette-warning"[^>]*>.*?</li>`).FindAllString(region, -1)
	require.Len(t, items, 2)
	assert.Contains(t, items[0], "Light: Muted text on Soft brand background, 3.91:1. Minimum 4.5:1.")
	assert.Contains(t, items[1], "Dark: Border on Card, 2.1:1. Minimum 3:1.")
	assert.Regexp(t, `<svg[^>]*class="palette-warning-swatch"[^>]*aria-hidden="true"`, items[0])
	assert.Regexp(t, `fill="#c0de10"[^>]*/>\s*<rect[^>]*fill="#c0de06"`, items[0], "the background, then the foreground on it")
	assert.Regexp(t, `fill="#d0de01"[^>]*/>\s*<rect[^>]*fill="#d0de03"`, items[1])
}

// With no failing pair the count line says every pair meets its minimum, and there is no list.
func TestRender_AdminSettingsBrandingSaysEveryPairMeetsItsMinimum(t *testing.T) {
	out := renderWarningsForm(t, &adminsettingshandlers.BrandContrastWarnings{CountLine: "Every pair meets its minimum."}, false)

	region := warningsRegion(t, out)
	assert.Regexp(t, `id="paletteWarningsCount"[^>]*>Every pair meets its minimum.</p>`, region)
	assert.NotContains(t, region, "<li")
	assert.NotContains(t, region, "<ul")
}

// A form with no saved warnings to list, a new brand's or one refused, holds the region hidden and
// empty, saying nothing about colors it has not checked.
func TestRender_AdminSettingsBrandingHoldsTheListHiddenWithoutWarnings(t *testing.T) {
	out := renderWarningsForm(t, nil, false)

	assert.True(t, isHidden(tagWith(t, out, `id="palette-warnings"`)))
	assert.Regexp(t, `id="paletteWarningsCount"[^>]*></p>`, warningsRegion(t, out))
}

// After a save, the saved notice adds how many pairs fail and links to the list; with none failing,
// or no list, it says only that the brand was saved.
func TestRender_AdminSettingsBrandingSavedNoticeLinksToTheFailingPairs(t *testing.T) {
	out := renderWarningsForm(t, twoWarnings(), true)
	assert.Regexp(t, `<p>Brand saved. 2 pairs of its colors are below their contrast minimum. <a class="text-link" href="#palette-warnings">See the pairs</a></p>`, out)

	passing := renderWarningsForm(t, &adminsettingshandlers.BrandContrastWarnings{CountLine: "Every pair meets its minimum."}, true)
	assert.Contains(t, passing, "<p>Brand saved.</p>")
	assert.Contains(t, renderWarningsForm(t, nil, true), "<p>Brand saved.</p>")

	assert.NotContains(t, renderWarningsForm(t, twoWarnings(), false), "below their contrast minimum. <a", "only after a save")
}

// The brand list marks a brand with failing pairs beside its name, and draws each brand's light and
// dark swatches from its colors in the Theme column; a brand with no colors has no swatch.
func TestRender_AdminSettingsBrandingListMarksFailingPairsAndDrawsTheColors(t *testing.T) {
	colors := &api.BrandColors{Light: testPalette("c10"), Dark: testPalette("d10")}
	out := renderMenuPageAt(t, "/admin/settings/branding", "/admin_settings_branding.html", map[string]interface{}{
		"brands": []adminsettingshandlers.BrandRow{
			{BrandResponse: api.BrandResponse{Id: 8, Name: "Custom", Appearance: "auto", Theme: "custom", Colors: colors},
				AppearanceName: "Automático", ThemeName: "Personalizado", WarningsMarker: "2 pares abaixo do mínimo de contraste"},
			{BrandResponse: api.BrandResponse{Id: 9, Name: "Lost", Appearance: "auto", Theme: "custom"},
				AppearanceName: "Automático", ThemeName: "Personalizado"},
		},
	})

	assert.Regexp(t, `branding/8/edit">Custom</a>\s*<span class="tag tag-caution ml-1">2 pares abaixo do mínimo de contraste</span>`, out)
	assert.Equal(t, 1, strings.Count(out, "tag-caution"), "a brand with none is not marked")

	rows := regexp.MustCompile(`(?s)<tr>.*?</tr>`).FindAllString(out, -1)
	require.Len(t, rows, 3)
	assert.Regexp(t, `<span class="brand-list-swatch" aria-hidden="true"><svg[^>]*><rect width="120" height="64" fill="#c10001"`, rows[1])
	assert.Contains(t, rows[1], `fill="#d10006" data-fill="brand"`, "the dark swatch too")
	assert.Contains(t, rows[1], "Personalizado</span></td>")
	assert.NotContains(t, rows[2], "brand-list-swatch")
	assert.Contains(t, rows[2], "Personalizado</span></td>")
}

// The page hands the live check (#815 decision 6) what its scripts read: the Colors section names the
// console's check route, the region holds the sentence for colors that could not be checked, in the
// page's language, and the Custom card's swatch is marked as the palette being edited.
func TestRender_AdminSettingsBrandingHandsTheLiveCheckItsRouteAndSentence(t *testing.T) {
	out := renderWarningsForm(t, nil, false)

	assert.Contains(t, tagWith(t, out, `id="brand-palette"`), `data-palette-check-url="/admin/settings/branding/palette-check"`)
	assert.Contains(t, tagWith(t, out, `id="palette-warnings"`),
		`data-unchecked="The colors could not be checked. They are checked when the brand is saved."`)
	assert.Regexp(t, `id="theme-custom"(?s).*?<span class="theme-swatch" aria-hidden="true" data-custom-swatch>`, out)
}
