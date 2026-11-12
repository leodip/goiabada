package apihandlers

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/brandasset"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/palette"
)

// A brand's custom palette in the admin API (#815 decisions 1 and 2): the theme custom with a
// palette member, which holds what was entered, validated before it is written, and worked out into
// the 23 colors of each mode the brand stores. A refusal names the member of the request body it is
// about in the error answer's error_field, such as /palette/light/brand.

// validateBrandPalette holds the palette a create or an update sends with theme to decision 2, and
// answers it as stored, nil for a brand on a built-in theme. A palette is required with the theme
// custom and refused with any other, where left out and null are both none. Its mode is basic or
// advanced. Each of its two modes is checked as validatePaletteColors says, light first, and a basic
// mode's four colors are worked out into all 23 (decision 1); an advanced mode is stored as entered.
// Every color is stored in lower case.
func validateBrandPalette(theme string, sent *api.BrandPalette) (*record.BrandPalette, error) {
	if theme != record.BrandThemeCustom {
		if sent != nil {
			return nil, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandPaletteNotCustom, nil), "palette")
		}
		return nil, nil
	}
	if sent == nil {
		return nil, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandPaletteRequired, nil), "palette")
	}
	mode := record.BrandPaletteMode(sent.Mode)
	if !mode.IsValid() {
		return nil, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandPaletteModeInvalid, nil), "palette", "mode")
	}

	stored := &record.BrandPalette{Mode: mode}
	for _, m := range []struct {
		name   string
		colors map[string]string
		into   *map[string]string
	}{{"light", sent.Light, &stored.Light}, {"dark", sent.Dark, &stored.Dark}} {
		entered, err := validatePaletteColors(m.name, m.colors, mode)
		if err != nil {
			return nil, err
		}
		if mode == record.BrandPaletteModeAdvanced {
			*m.into = entered
			continue
		}
		derived, err := palette.Derive(entered)
		if err != nil {
			return nil, errs.Wrap(err, "unable to work out the palette's "+m.name+" colors")
		}
		*m.into = derived
	}
	return stored, nil
}

// validatePaletteColors holds one mode of a palette, named by modeName, to decision 2 and answers its
// colors in lower case. The mode's colors are required. A name that is no color token is refused,
// and in basic mode so is any of the 19 worked-out ones, each in the order of the names; then every
// color the mode sets, the four in basic mode and the 23 in advanced mode, in the tokens' order, must
// be there and be `#` and six hexadecimal digits.
func validatePaletteColors(modeName string, colors map[string]string, mode record.BrandPaletteMode) (map[string]string, error) {
	if colors == nil {
		return nil, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandPaletteColorsRequired,
			map[string]any{"mode": modeName}), "palette", modeName)
	}
	tokens := palette.Tokens()
	wanted := tokens
	if mode == record.BrandPaletteModeBasic {
		wanted = palette.BasicTokens()
	}
	for _, name := range slices.Sorted(maps.Keys(colors)) {
		args := map[string]any{"mode": modeName, "token": name}
		switch {
		case !slices.Contains(tokens, name):
			return nil, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandPaletteColorUnknown, args), "palette", modeName, name)
		case !slices.Contains(wanted, name):
			return nil, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandPaletteColorNotBasic, args), "palette", modeName, name)
		}
	}
	entered := make(map[string]string, len(wanted))
	for _, name := range wanted {
		args := map[string]any{"mode": modeName, "token": name}
		value, ok := colors[name]
		switch {
		case !ok:
			return nil, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandPaletteColorRequired, args), "palette", modeName, name)
		case !palette.IsColor(value):
			return nil, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandPaletteColorInvalid, args), "palette", modeName, name)
		}
		entered[name] = strings.ToLower(value)
	}
	return entered, nil
}

// brandPaletteAudit adds a custom brand's theme and its palette's mode to the details of a brand
// write's audit event, and never a color (decision 2). A brand on a built-in theme adds nothing.
func brandPaletteAudit(brand *record.Brand, details map[string]interface{}) {
	if brand.Palette == nil {
		return
	}
	details["theme"] = brand.Theme
	details["palette_mode"] = string(brand.Palette.Mode)
}

// brandResponse answers a brand as apimapping.ToBrandResponse does. A brand on the custom theme with
// no palette can only come from a hand edit of the database, or a stored palette that did not parse;
// it is answered with no palette and no colors, and logged (#815 decision 3).
func brandResponse(ctx context.Context, brand *record.Brand, slots brandasset.Slots, baseURL string, isDefault bool,
	clientCount int) api.BrandResponse {
	if brand.Theme == record.BrandThemeCustom && brand.Palette == nil {
		slog.WarnContext(ctx, "brand has the custom theme and no palette", "brand_id", brand.Id)
	}
	return apimapping.ToBrandResponse(brand, slots, baseURL, isDefault, clientCount)
}
