package adminsettingshandlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	handlersmocks "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
)

// The live preview's route (#815 decision 6): the brand editor's script posts the Colors section as
// the form holds it, and the route answers the 23 colors of each mode the palette would be drawn in,
// a basic palette's worked out by the same core code the save uses, and its failing pairs, of the
// modes the appearance draws, as the editor lists them. It changes nothing and asks the admin API
// nothing. The expected colors and ratios are the probe's vectors, computed in JavaScript before any
// Go existed (core/palette/testdata/vectors.json): "a mid-gray brand color" and "a dark mode with a
// pale brand color", with Blueberry's status colors for each one's direction.

// midGray is the probe's mid-gray light palette: its four entered colors, then all 23 worked out.
var (
	midGrayFour = map[string]string{"canvas": "#f4f4f4", "surface": "#ffffff", "ink": "#222222", "brand": "#777777"}
	midGray     = map[string]string{
		"canvas": "#f4f4f4", "surface": "#ffffff", "subtle": "#eeedeb", "line": "#dcdad4", "line-strong": "#7d796c",
		"ink": "#222222", "ink-muted": "#605e5a", "brand": "#777777", "brand-strong": "#606060", "on-brand": "#ffffff",
		"brand-soft": "#ececec", "focus": "#777777",
		"danger": "#b42318", "danger-strong": "#8f1c13", "on-danger": "#ffffff", "danger-soft": "#fdeceb",
		"danger-ink": "#8f1c13", "positive-soft": "#e3f3e8", "positive-ink": "#17612f",
		"caution-soft": "#fdf2d6", "caution-ink": "#6b4400", "note-soft": "#e6edfb", "note-ink": "#1d4796",
	}
	paleBrandFour = map[string]string{"canvas": "#000000", "surface": "#111111", "ink": "#ffffff", "brand": "#ffe8a3"}
	paleBrand     = map[string]string{
		"canvas": "#000000", "surface": "#111111", "subtle": "#1a1a18", "line": "#2b2a26", "line-strong": "#7d796c",
		"ink": "#ffffff", "ink-muted": "#bfbeb9", "brand": "#ffe8a3", "brand-strong": "#fffffe", "on-brand": "#211a02",
		"brand-soft": "#271f06", "focus": "#ffe8a3",
		"danger": "#ff8f85", "danger-strong": "#ffb0a8", "on-danger": "#330b07", "danger-soft": "#3a1714",
		"danger-ink": "#ffb4ab", "positive-soft": "#11291a", "positive-ink": "#8fd6a5",
		"caution-soft": "#2e2410", "caution-ink": "#f0c96a", "note-soft": "#142340", "note-ink": "#a8c7ff",
	}
)

// midGrayWarnings are the mid-gray palette's six failing pairs, in the shared list's order, as the
// editor lists them in mode, each with the two colors its swatch is drawn in.
func midGrayWarnings(mode, modeName string) []any {
	item := func(foreground, background, text string) map[string]any {
		return map[string]any{"mode": mode, "foreground": foreground, "background": background, "text": modeName + ": " + text}
	}
	return []any{
		item("#777777", "#f4f4f4", "Brand color on Background, 4.07:1. Minimum 4.5:1."),
		item("#777777", "#ffffff", "Brand color on Card, 4.47:1. Minimum 4.5:1."),
		item("#ffffff", "#777777", "Text on brand color on Brand color, 4.47:1. Minimum 4.5:1."),
		item("#777777", "#eeedeb", "Brand color on Subtle background, 3.82:1. Minimum 4.5:1."),
		item("#777777", "#e6edfb", "Brand color on Soft note background, 3.81:1. Minimum 4.5:1."),
		item("#777777", "#fdf2d6", "Brand color on Soft caution background, 4.01:1. Minimum 4.5:1."),
	}
}

const sixPairsBelow = "6 pairs are below their minimum. Text and boundaries drawn in them do not meet WCAG 2.2 level AA contrast."

// paletteCheckForm is what the script posts: the mode, the appearance, and each color of light and
// dark in the field the save reads it from.
func paletteCheckForm(mode, appearance string, light, dark map[string]string) url.Values {
	form := url.Values{"paletteMode": {mode}, "appearance": {appearance}}
	for token, value := range light {
		form.Set(paletteFieldId("light", token), value)
	}
	for token, value := range dark {
		form.Set(paletteFieldId("dark", token), value)
	}
	return form
}

// checkPalette posts form to the route and answers what it encoded.
func checkPalette(t *testing.T, form url.Values) map[string]any {
	t.Helper()
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.ExpectEncodeJSON(httpHelper).Once()
	HandleBrandPaletteCheckPost(httpHelper).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/settings/branding/palette-check", handlertest.WithAccessToken(),
			handlertest.WithForm(form)))
	return handlertest.Encoded(t, httpHelper)
}

// refusedPalette posts form to the route and answers its refusal.
func refusedPalette(t *testing.T, form url.Values) (code, description string, status int) {
	t.Helper()
	httpHelper := handlersmocks.NewHttpHelper(t)
	httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Return().Once()
	HandleBrandPaletteCheckPost(httpHelper).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/settings/branding/palette-check", handlertest.WithAccessToken(),
			handlertest.WithForm(form)))
	refused := jsonErrorOf(t, httpHelper)
	return refused.Code(), refused.Description(), refused.HTTPStatus()
}

// asAny is a color map as a JSON answer decodes it.
func asAny(colors map[string]string) map[string]any {
	out := map[string]any{}
	for token, value := range colors {
		out[token] = value
	}
	return out
}

// upper is a color map with every value in upper case, as a person may type it.
func upper(colors map[string]string) map[string]string {
	out := map[string]string{}
	for token, value := range colors {
		out[token] = strings.ToUpper(value)
	}
	return out
}

// A basic palette is worked out from its four colors of each mode, as the save works it out, and
// answered whole with the pairs that fail under Automatic, which draws both modes: light first, and
// here the dark mode has none.
func TestHandleBrandPaletteCheckPost_WorksOutABasicPaletteAndListsItsFailingPairs(t *testing.T) {
	answer := checkPalette(t, paletteCheckForm("basic", "auto", midGrayFour, paleBrandFour))

	assert.Equal(t, map[string]any{
		"light":     asAny(midGray),
		"dark":      asAny(paleBrand),
		"countLine": sixPairsBelow,
		"warnings":  midGrayWarnings("light", "Light"),
	}, answer)
}

// Basic reads the four colors alone: what the other 19 fields hold, a value that is not a color
// among them, is neither read nor answered, as the save sends only the four.
func TestHandleBrandPaletteCheckPost_BasicReadsTheFourAlone(t *testing.T) {
	light := upper(midGrayFour)
	light["ink-muted"] = "not a color"
	light["line"] = "#000000"

	answer := checkPalette(t, paletteCheckForm("basic", "auto", light, paleBrandFour))

	assert.Equal(t, asAny(midGray), answer["light"], "the entered colors answered in lower case, the others worked out")
}

// The pairs listed are the modes the appearance draws: Light checks the light mode alone, Dark the
// dark one, and an appearance the console does not know both, as Automatic. The colors of both modes
// are answered whatever the appearance, since both columns are kept.
func TestHandleBrandPaletteCheckPost_ListsThePairsOfTheModesTheAppearanceDraws(t *testing.T) {
	// The mid-gray colors typed in the Dark column take the same status colors, by their direction.
	form := func(appearance string) url.Values {
		return paletteCheckForm("basic", appearance, paleBrandFour, midGrayFour)
	}

	light := checkPalette(t, form("light"))
	assert.Equal(t, "Every pair meets its minimum.", light["countLine"])
	assert.Equal(t, []any{}, light["warnings"])
	assert.Equal(t, asAny(midGray), light["dark"], "the dark colors are answered, though not checked")

	for _, appearance := range []string{"dark", "auto", "sepia"} {
		answer := checkPalette(t, form(appearance))
		assert.Equal(t, sixPairsBelow, answer["countLine"], appearance)
		assert.Equal(t, midGrayWarnings("dark", "Dark"), answer["warnings"], appearance)
	}
}

// An advanced palette is answered as sent, in lower case, and nothing in it is worked out again: a
// color set by hand away from the worked-out one stays.
func TestHandleBrandPaletteCheckPost_AnswersAnAdvancedPaletteAsSent(t *testing.T) {
	light := upper(midGray)
	light["line-strong"] = "#7D796D"

	answer := checkPalette(t, paletteCheckForm("advanced", "auto", light, paleBrand))

	wanted := asAny(midGray)
	wanted["line-strong"] = "#7d796d"
	assert.Equal(t, wanted, answer["light"])
	assert.Equal(t, asAny(paleBrand), answer["dark"])
	assert.Equal(t, sixPairsBelow, answer["countLine"])
	assert.Equal(t, midGrayWarnings("light", "Light"), answer["warnings"])
}

// A value that is not # and six hexadecimal digits is refused as the save refuses it, naming its mode
// and color, light before dark, and the first in the tokens' order; an empty field is not a color.
func TestHandleBrandPaletteCheckPost_RefusesAValueThatIsNotAColor(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mode        string
		light, dark map[string]string
		description string
	}{
		{"three digits in basic", "basic", midGrayFour, with(paleBrandFour, "brand", "#abc"),
			"The palette's dark brand color must be # and six hexadecimal digits, such as #2456c4."},
		{"a name in each mode, light first", "basic", with(midGrayFour, "ink", "navy"), with(paleBrandFour, "canvas", "black"),
			"The palette's light ink color must be # and six hexadecimal digits, such as #2456c4."},
		{"no # in advanced", "advanced", with(midGray, "note-soft", "e6edfb"), paleBrand,
			"The palette's light note-soft color must be # and six hexadecimal digits, such as #2456c4."},
		{"eight digits in advanced", "advanced", midGray, with(paleBrand, "focus", "#ffe8a3ff"),
			"The palette's dark focus color must be # and six hexadecimal digits, such as #2456c4."},
		{"an empty field", "advanced", midGray, with(paleBrand, "on-danger", ""),
			"The palette's dark on-danger color must be # and six hexadecimal digits, such as #2456c4."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, description, status := refusedPalette(t, paletteCheckForm(tc.mode, "auto", tc.light, tc.dark))
			assert.Equal(t, "handler.brand.palette_color_invalid", code)
			assert.Equal(t, tc.description, description)
			assert.Equal(t, http.StatusBadRequest, status)
		})
	}
}

// A mode that is neither basic nor advanced is refused as the save refuses it.
func TestHandleBrandPaletteCheckPost_RefusesAModeItDoesNotKnow(t *testing.T) {
	for _, mode := range []string{"", "expert"} {
		code, description, status := refusedPalette(t, paletteCheckForm(mode, "auto", midGray, paleBrand))
		assert.Equal(t, "handler.brand.palette_mode_invalid", code, mode)
		assert.Equal(t, "The palette's mode must be basic or advanced.", description, mode)
		assert.Equal(t, http.StatusBadRequest, status, mode)
	}
}

// with is colors with token set to value.
func with(colors map[string]string, token, value string) map[string]string {
	out := map[string]string{}
	for t, v := range colors {
		out[t] = v
	}
	out[token] = value
	return out
}
