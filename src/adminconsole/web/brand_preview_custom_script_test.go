package web

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The preview of a custom palette (#815 decisions 6 and 7): while Custom is picked, each sample is
// drawn in its mode's colors as the Colors section's fields hold them, each entered color at once as
// it is typed, with no request, since each is a token itself; a basic palette's other 19 fields hold
// the worked-out colors brand-palette.js writes there from the console's answer, telling the page
// with an input event on the section. A value that is not a color is never set on a sample. Editing a
// field switches the preview to that field's mode, so the change is seen, and the Custom card's swatch
// shows the palette being edited.

// customColors is a Colors section whose fields hold colors no theme has, "e1e0" in light and "e1d0"
// in dark.
func customColors() *previewColors {
	return &previewColors{Light: previewPalette("e1e0"), Dark: previewPalette("e1d0")}
}

// customCards are the theme cards with Custom last.
var customCards = []string{"blueberry", "plum", "custom"}

// customPreview is the editor on Custom under appearance, its Colors section holding customColors.
func customPreview(appearance string) previewPage {
	return previewPage{themeCards: customCards, theme: "custom", appearance: appearance, palette: customColors()}
}

// Custom draws each sample in its mode's fields, in lower case, as a built-in theme is drawn, and
// the Appearance cards' swatches in them too.
func TestBrandPreviewJS_CustomIsDrawnInTheColorsSectionsFields(t *testing.T) {
	page := customPreview("auto")
	page.palette.Light["canvas"] = "#ABCDEF"
	looks := runBrandPreview(t, page, load(), lookAt())

	assertSampleDrawn(t, looks[0].Samples["light"], withColor(previewPalette("e1e0"), "canvas", "#abcdef"), "light")
	assertSampleDrawn(t, looks[0].Samples["dark"], previewPalette("e1d0"), "dark")
	assert.Equal(t, []previewSwatch{
		{"canvas": "#abcdef", "surface": "#e1e001", "line": "#e1e003", "ink": "#e1e005", "ink-muted": "#e1e006", "brand": "#e1e007"},
		{"canvas": "#e1d000", "surface": "#e1d001", "line": "#e1d003", "ink": "#e1d005", "ink-muted": "#e1d006", "brand": "#e1d007"},
	}, looks[0].Swatches["appearance"]["auto"])
	assert.Empty(t, looks[0].StyledElsewhere)
}

// Picking Custom draws the palette being edited, and picking a built-in theme again draws that.
func TestBrandPreviewJS_PickingCustomDrawsThePaletteBeingEdited(t *testing.T) {
	page := customPreview("auto")
	page.theme = "plum"
	looks := runBrandPreview(t, page, load(), lookAt(), pick("theme", "custom"), lookAt(), pick("theme", "plum"), lookAt())

	assertSampleDrawn(t, looks[0].Samples["light"], previewPlum.Light, "light")
	assertSampleDrawn(t, looks[1].Samples["light"], previewPalette("e1e0"), "light")
	assertSampleDrawn(t, looks[1].Samples["dark"], previewPalette("e1d0"), "dark")
	assertSampleDrawn(t, looks[2].Samples["light"], previewPlum.Light, "light")
}

// An entered color is drawn at once as it is typed, or picked in its well, with no pause and no
// request: the script has no network to send one on.
func TestBrandPreviewJS_AColorTypedIsDrawnAtOnce(t *testing.T) {
	looks := runBrandPreview(t, customPreview("auto"), load(),
		typeIn("palette-light-brand", "#123456"), lookAt(),
		typeIn("palette-light-brand-well", "#654321"), restoreValue("palette-light-brand", "#654321"), typeIn("palette-light-brand", "#654321"), lookAt())

	assert.Equal(t, "#123456", looks[0].Samples["light"].Style["--color-brand"])
	assertSampleDrawn(t, looks[0].Samples["light"], withColor(previewPalette("e1e0"), "brand", "#123456"), "light")
	assert.Equal(t, "#654321", looks[1].Samples["light"].Style["--color-brand"])
}

// A value that is not # and six hexadecimal digits is never set on a sample: the sample keeps the
// color it was drawn in, and one drawn first with such a value sets nothing for its token.
func TestBrandPreviewJS_AValueThatIsNoColorIsNeverSet(t *testing.T) {
	looks := runBrandPreview(t, customPreview("auto"), load(),
		typeIn("palette-light-brand", "#12"), lookAt(),
		typeIn("palette-light-brand", "red;background:url(x)"), lookAt(),
		typeIn("palette-light-brand", "#12345678"), lookAt())

	for i, look := range looks {
		assert.Equal(t, "#e1e007", look.Samples["light"].Style["--color-brand"], "look %d keeps the color drawn", i)
	}

	page := customPreview("auto")
	page.palette.Dark["focus"] = "blue"
	looks = runBrandPreview(t, page, load(), lookAt())
	assert.NotContains(t, looks[0].Samples["dark"].Style, "--color-focus")
	assert.Equal(t, "#e1d021", looks[0].Samples["dark"].Style["--color-note-ink"])
}

// The worked-out colors brand-palette.js writes in the 19 other fields, with no event of their own,
// are drawn once it tells the page with an input event on the section.
func TestBrandPreviewJS_TheWorkedOutColorsAreDrawnWhenThePageIsTold(t *testing.T) {
	looks := runBrandPreview(t, customPreview("auto"), load(),
		restoreValue("palette-light-focus", "#abcdef"), restoreValue("palette-dark-subtle", "#0a0b0c"), lookAt(),
		previewStep{Do: "input", Name: "brand-palette"}, lookAt())

	assert.Equal(t, "#e1e022", looks[0].Samples["light"].Style["--color-focus"], "not yet told")
	assert.Equal(t, "#abcdef", looks[1].Samples["light"].Style["--color-focus"])
	assert.Equal(t, "#0a0b0c", looks[1].Samples["dark"].Style["--color-subtle"])
}

// Editing a field switches the preview to that field's mode under Automatic, so the change is seen,
// whether it is typed or picked in its well; under Light or Dark the appearance decides the one
// sample, and a field of the other column, shown while it holds a value that is not a color, changes
// nothing.
func TestBrandPreviewJS_ThePreviewFollowsTheEditedFieldsMode(t *testing.T) {
	looks := runBrandPreview(t, customPreview("auto"), load(), lookAt(),
		typeIn("palette-dark-ink", "#eeeeee"), lookAt(),
		typeIn("palette-light-ink-well", "#111111"), lookAt(),
		pick("brandPreviewMode", "dark"), typeIn("palette-light-canvas", "#fafafa"), lookAt())

	assert.Equal(t, "light", looks[0].PreviewMode)
	assert.Equal(t, "dark", looks[1].PreviewMode)
	assert.False(t, looks[1].Samples["dark"].Hidden)
	assert.True(t, looks[1].Samples["light"].Hidden)
	assert.Equal(t, "#eeeeee", looks[1].Samples["dark"].Style["--color-ink"])
	assert.Equal(t, "light", looks[2].PreviewMode, "a well too")
	assert.False(t, looks[2].Samples["light"].Hidden)
	assert.Equal(t, "light", looks[3].PreviewMode)
	assert.False(t, looks[3].Samples["light"].Hidden)

	looks = runBrandPreview(t, customPreview("light"), load(), typeIn("palette-dark-ink", "#12"), typeIn("palette-dark-ink", "#121212"), lookAt())
	assert.Equal(t, "light", looks[0].PreviewMode)
	assert.False(t, looks[0].Samples["light"].Hidden)
	assert.True(t, looks[0].Samples["dark"].Hidden)

	// A field outside the Colors section changes no mode.
	looks = runBrandPreview(t, customPreview("auto"), load(), pick("brandPreviewMode", "dark"), typeIn("supportEmail", "help@example.com"), lookAt())
	assert.Equal(t, "dark", looks[0].PreviewMode)
}

// The Custom card's swatch shows the palette being edited, as it is typed, whichever theme is picked;
// the built-in theme cards keep their own.
func TestBrandPreviewJS_TheCustomCardsSwatchShowsThePaletteBeingEdited(t *testing.T) {
	page := customPreview("auto")
	page.theme = "plum"
	looks := runBrandPreview(t, page, load(), typeIn("palette-dark-brand", "#ff00aa"), lookAt())

	assert.Equal(t, []previewSwatch{
		{"canvas": "#e1e000", "surface": "#e1e001", "line": "#e1e003", "ink": "#e1e005", "ink-muted": "#e1e006", "brand": "#e1e007"},
		{"canvas": "#e1d000", "surface": "#e1d001", "line": "#e1d003", "ink": "#e1d005", "ink-muted": "#e1d006", "brand": "#ff00aa"},
	}, looks[0].Swatches["theme"]["custom"])
	stale := previewSwatch{"canvas": "#5e7a1e", "surface": "#5e7a1e", "line": "#5e7a1e", "ink": "#5e7a1e", "ink-muted": "#5e7a1e", "brand": "#5e7a1e"}
	assert.Equal(t, []previewSwatch{stale, stale}, looks[0].Swatches["theme"]["plum"])
}
