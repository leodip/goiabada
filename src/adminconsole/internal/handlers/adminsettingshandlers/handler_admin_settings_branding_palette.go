package adminsettingshandlers

import (
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/palette"
)

// The brand editor's Colors section (#815 decisions 7 and 8): the Custom theme card opens it, and it
// holds a field for each of the 23 colors of each mode, in a Light and a Dark column. Basic shows the
// four rows a basic palette is entered with, and Advanced all 23 in four groups. The fields are named
// palette-<mode>-<token>, which is also the id a refusal at /palette/<mode>/<token> marks. Both
// columns are always in the form and always sent, so both modes are stored; a column the appearance
// does not draw is hidden, unless it holds a value that is not a color, or the refused one, which is
// shown for the administrator to correct (decision 8's exception). brand-palette.js keeps the section,
// the rows and the columns in step as the form changes, and keeps each color well beside its text
// field.

// customTheme is the admin API's reserved theme key of a brand drawn in its own custom palette.
const customTheme = "custom"

// The two palette modes the Basic and Advanced choice sends.
const (
	paletteModeBasic    = "basic"
	paletteModeAdvanced = "advanced"
)

// paletteModes are a palette's two modes, the columns' order.
var paletteModes = []string{"light", "dark"}

// brandPaletteGroups are the four groups Advanced shows the 23 colors in, each token once: the page,
// its text, the brand and the status colors.
var brandPaletteGroups = []struct {
	key    string
	tokens []string
}{
	{"page", []string{"canvas", "surface", "subtle", "line", "line-strong"}},
	{"text", []string{"ink", "ink-muted"}},
	{"brand", []string{"brand", "brand-strong", "on-brand", "brand-soft", "focus"}},
	{"status", []string{"danger", "danger-strong", "on-danger", "danger-soft", "danger-ink",
		"positive-soft", "positive-ink", "caution-soft", "caution-ink", "note-soft", "note-ink"}},
}

// paletteWellBlack is what a color well holds while its field holds a value that is not a color: a
// well can only hold a color.
const paletteWellBlack = "#000000"

// BrandPaletteForm is what the Colors section holds. Mode is basic or advanced, or what a refused
// form sent. Light and Dark hold a value for each of the 23 color tokens, by name, as typed.
// StoredMode is the mode of the palette the brand has stored, "" for none. Fresh says the fields hold
// a built-in theme's colors that nothing has changed since, for a brand with no palette, so the first
// pick of Custom replaces them with the theme picked before it (decision 7).
type BrandPaletteForm struct {
	Mode       string
	StoredMode string
	Fresh      bool
	Light      map[string]string
	Dark       map[string]string
}

// BrandPaletteView is the Colors section as the editor draws it: the form, the route its script asks
// for the live check, whether Basic hides the rows other than the four, whether the note on going
// back to Basic shows, the two columns, the four groups of rows, and the colors the Custom card's
// swatch is drawn in.
type BrandPaletteView struct {
	BrandPaletteForm
	CheckURL  string
	Basic     bool
	BasicNote bool
	Columns   []BrandPaletteColumn
	Groups    []BrandPaletteGroup
	Swatch    BrandPaletteSwatch
}

// BrandPaletteColumn is the Light or the Dark column: whether the appearance draws its mode, and
// whether it is shown, which it is while drawn, or while it holds a value that is not a color.
type BrandPaletteColumn struct {
	Mode  string
	Drawn bool
	Shown bool
}

// BrandPaletteGroup is one of the four groups of colors Advanced shows, with its name's message ID.
type BrandPaletteGroup struct {
	Key    string
	NameID string
	Rows   []BrandPaletteRow
}

// BrandPaletteRow is one color's row: its token, its label's message ID, whether it is one of the four
// Basic shows, and its light field and its dark field.
type BrandPaletteRow struct {
	Token   string
	LabelID string
	Basic   bool
	Fields  []BrandPaletteField
}

// BrandPaletteField is one color field: its id, which is its name, its column's mode, the value typed,
// the color its well holds, whether its column is shown, whether it holds a value that is not a color,
// and whether the save was refused at it.
type BrandPaletteField struct {
	Id      string
	Mode    string
	Value   string
	Well    string
	Shown   bool
	Invalid bool
	Refused bool
}

// BrandPaletteSwatch is what the Custom card's swatch is drawn in: the values of each mode that are
// colors, in lower case.
type BrandPaletteSwatch struct {
	Light map[string]string
	Dark  map[string]string
}

// paletteFieldId is the id and the name of the field of token in mode.
func paletteFieldId(mode, token string) string {
	return "palette-" + mode + "-" + token
}

// valuesOf answers the values of a mode of the form.
func (p BrandPaletteForm) valuesOf(mode string) map[string]string {
	if mode == "dark" {
		return p.Dark
	}
	return p.Light
}

// drawnModes reports which modes an appearance draws: Light its light one, Dark its dark one, and
// Automatic, or an appearance the console does not know, both, as the preview reads it.
func drawnModes(appearance string) map[string]bool {
	return map[string]bool{"light": appearance != "dark", "dark": appearance != "light"}
}

// NewBrandPaletteView draws the Colors section for form under appearance, with refusedField the id of
// the field the save was refused at, or none.
func NewBrandPaletteView(form BrandPaletteForm, appearance, refusedField string) BrandPaletteView {
	view := BrandPaletteView{
		BrandPaletteForm: form,
		CheckURL:         brandPaletteCheckPath,
		Basic:            form.Mode != paletteModeAdvanced,
		Swatch:           BrandPaletteSwatch{Light: swatchOf(form.Light), Dark: swatchOf(form.Dark)},
	}
	view.BasicNote = view.Basic && form.StoredMode == paletteModeAdvanced

	drawn := drawnModes(appearance)
	shown := map[string]bool{}
	for _, mode := range paletteModes {
		shown[mode] = drawn[mode]
	}
	basicTokens := palette.BasicTokens()
	for _, group := range brandPaletteGroups {
		g := BrandPaletteGroup{Key: group.key, NameID: "adminconsole.admin_branding.palette.group." + group.key}
		for _, token := range group.tokens {
			row := BrandPaletteRow{Token: token, LabelID: "adminconsole.admin_branding.palette.color." + strings.ReplaceAll(token, "-", "_"),
				Basic: slices.Contains(basicTokens, token)}
			for _, mode := range paletteModes {
				value := form.valuesOf(mode)[token]
				field := BrandPaletteField{Id: paletteFieldId(mode, token), Mode: mode, Value: value, Well: paletteWellBlack,
					Invalid: !palette.IsColor(value)}
				field.Refused = field.Id == refusedField
				if !field.Invalid {
					field.Well = strings.ToLower(value)
				}
				if (row.Basic || !view.Basic) && (field.Invalid || field.Refused) {
					shown[mode] = true
				}
				row.Fields = append(row.Fields, field)
			}
			g.Rows = append(g.Rows, row)
		}
		view.Groups = append(view.Groups, g)
	}
	for _, mode := range paletteModes {
		view.Columns = append(view.Columns, BrandPaletteColumn{Mode: mode, Drawn: drawn[mode], Shown: shown[mode]})
	}
	for _, group := range view.Groups {
		for _, row := range group.Rows {
			for i := range row.Fields {
				row.Fields[i].Shown = shown[row.Fields[i].Mode]
			}
		}
	}
	return view
}

// swatchOf answers the values of a mode that are colors, in lower case.
func swatchOf(values map[string]string) map[string]string {
	colors := map[string]string{}
	for token, value := range values {
		if palette.IsColor(value) {
			colors[token] = strings.ToLower(value)
		}
	}
	return colors
}

// brandPaletteFormFrom reads the Colors section as sent: the mode, each field trimmed, and whether
// the fields still hold untouched theme colors. stored is the brand being saved, nil for a new one,
// whose stored palette's mode the note on going back to Basic reads.
func brandPaletteFormFrom(r *http.Request, stored *api.BrandResponse) BrandPaletteForm {
	form := BrandPaletteForm{
		Mode:  r.PostFormValue("paletteMode"),
		Fresh: r.PostFormValue("paletteFresh") == "true",
		Light: map[string]string{},
		Dark:  map[string]string{},
	}
	if stored != nil && stored.Palette != nil {
		form.StoredMode = stored.Palette.Mode
	}
	for _, mode := range paletteModes {
		for _, token := range palette.Tokens() {
			form.valuesOf(mode)[token] = strings.TrimSpace(r.PostFormValue(paletteFieldId(mode, token)))
		}
	}
	return form
}

// brandPaletteFormOf is the Colors section of a brand drawn as stored, nil for a new one. A custom
// brand's fields hold the 23 colors of each mode it is drawn in, so a basic palette's worked-out ones
// show in Advanced, overlaid with its palette as written. A brand with no palette starts in Basic,
// its fields holding the colors of theme, the theme the form holds, or of the first the auth server
// lists when it lists no such theme, and untouched (decision 7).
func brandPaletteFormOf(brand *api.BrandResponse, themes []api.BrandThemeResponse, theme string) BrandPaletteForm {
	if brand != nil && brand.Palette != nil {
		form := BrandPaletteForm{Mode: brand.Palette.Mode, StoredMode: brand.Palette.Mode, Light: map[string]string{}, Dark: map[string]string{}}
		if brand.Colors != nil {
			maps.Copy(form.Light, brand.Colors.Light)
			maps.Copy(form.Dark, brand.Colors.Dark)
		}
		maps.Copy(form.Light, brand.Palette.Light)
		maps.Copy(form.Dark, brand.Palette.Dark)
		return form
	}
	form := BrandPaletteForm{Mode: paletteModeBasic, Fresh: true, Light: map[string]string{}, Dark: map[string]string{}}
	source := api.BrandThemeResponse{}
	if len(themes) > 0 {
		source = themes[0]
	}
	for _, candidate := range themes {
		if candidate.Key == theme {
			source = candidate
			break
		}
	}
	maps.Copy(form.Light, source.Light)
	maps.Copy(form.Dark, source.Dark)
	return form
}

// request is the palette a save sends with theme: none for a built-in theme, which drops a stored one
// (#815 decision 2), and for custom the form's mode with both modes' colors, the four a basic palette
// is entered with or, in any other mode, all 23, for the admin API to refuse what is not a color, or a
// mode it does not know, at its field.
func (p BrandPaletteForm) request(theme string) *api.BrandPalette {
	if theme != customTheme {
		return nil
	}
	tokens := palette.Tokens()
	if p.Mode == paletteModeBasic {
		tokens = palette.BasicTokens()
	}
	sent := &api.BrandPalette{Mode: p.Mode, Light: map[string]string{}, Dark: map[string]string{}}
	for _, token := range tokens {
		sent.Light[token] = p.Light[token]
		sent.Dark[token] = p.Dark[token]
	}
	return sent
}

// paletteInput answers the id of the Colors section's input tokens point at: "palette-dark-brand" for
// /palette/dark/brand, "paletteMode" for /palette/mode, or "" when they point at no input it draws,
// such as a mode or a token the form has no field for.
func paletteInput(tokens []string) string {
	if len(tokens) < 2 || tokens[0] != "palette" {
		return ""
	}
	if len(tokens) == 2 && tokens[1] == "mode" {
		return "paletteMode"
	}
	if len(tokens) == 3 && slices.Contains(paletteModes, tokens[1]) && slices.Contains(palette.Tokens(), tokens[2]) {
		return paletteFieldId(tokens[1], tokens[2])
	}
	return ""
}
