package apimapping

import (
	"maps"

	"github.com/leodip/goiabada/authserver/internal/brandasset"
	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/palette"
)

// ToBrandResponse answers a brand with its kit's choices, its footer links and support contact, and
// its six slots, slots being the assets they name, each answered as ToBrandAssetResponse answers it
// and null for an empty slot; isDefault says whether the settings row points at the brand and
// clientCount how many clients are drawn in it. It answers the brand's custom palette, its colors and
// their contrast warnings as ToBrandPalette, ToBrandColors and ToBrandContrastWarnings do (#815), and
// its custom CSS as stored, "" for none (#816).
func ToBrandResponse(brand *record.Brand, slots brandasset.Slots, baseURL string, isDefault bool, clientCount int) api.BrandResponse {
	slot := func(asset *record.BrandAsset) *api.BrandAssetResponse {
		if asset == nil {
			return nil
		}
		answer := ToBrandAssetResponse(asset, baseURL)
		return &answer
	}
	resp := api.BrandResponse{
		Id:            brand.Id,
		Name:          brand.Name,
		Appearance:    string(brand.Appearance),
		Theme:         brand.Theme,
		Corners:       string(brand.Corners),
		Font:          string(brand.Font),
		BackgroundFit: string(brand.BackgroundFit),
		HideAppName:   brand.HideAppName,
		Logo:          slot(slots.Logo),
		DarkLogo:      slot(slots.DarkLogo),
		Favicon:       slot(slots.Favicon),
		Background:    slot(slots.Background),
		RegularFont:   slot(slots.RegularFont),
		BoldFont:      slot(slots.BoldFont),
		FooterLinks:   ToBrandFooterLinkResponses(brand.FooterLinks),
		SupportEmail:  brand.SupportEmail,
		SupportUrl:    brand.SupportURL,
		SupportPhone:  brand.SupportPhone,
		Palette:       ToBrandPalette(brand),
		CustomCss:     brand.CustomCSS,
		IsDefault:     isDefault,
		ClientCount:   clientCount,
	}
	resp.Colors, resp.ContrastWarnings = ToBrandColors(brand)
	if brand.CreatedAt.Valid {
		createdAt := brand.CreatedAt.Time
		resp.CreatedAt = &createdAt
	}
	if brand.UpdatedAt.Valid {
		updatedAt := brand.UpdatedAt.Time
		resp.UpdatedAt = &updatedAt
	}
	return resp
}

// ToBrandFooterLinkResponses answers a brand's footer links in order, [] for none, each link's
// labels a copy and {} when it has none, so a link read and sent back is the same link (#814
// decision 9).
func ToBrandFooterLinkResponses(links record.BrandFooterLinks) []api.BrandFooterLinkResponse {
	responses := make([]api.BrandFooterLinkResponse, 0, len(links))
	for _, link := range links {
		labels := maps.Clone(link.Labels)
		if labels == nil {
			labels = map[string]string{}
		}
		responses = append(responses, api.BrandFooterLinkResponse{Url: link.URL, Label: link.Label, Labels: labels})
	}
	return responses
}

// ToBrandThemeResponses answers the built-in themes in the order given, each palette a copy.
func ToBrandThemeResponses(presets []brandthemes.Preset) []api.BrandThemeResponse {
	responses := make([]api.BrandThemeResponse, 0, len(presets))
	for _, preset := range presets {
		responses = append(responses, api.BrandThemeResponse{
			Key:   preset.Key,
			Light: maps.Clone(map[string]string(preset.Light)),
			Dark:  maps.Clone(map[string]string(preset.Dark)),
		})
	}
	return responses
}

// ToBrandAssetResponse answers an asset without its bytes, its URL the path it is served at made
// absolute on baseURL.
func ToBrandAssetResponse(asset *record.BrandAsset, baseURL string) api.BrandAssetResponse {
	return api.BrandAssetResponse{
		Id:          asset.Id,
		Kind:        string(asset.Kind),
		Url:         baseURL + brandasset.Path(asset),
		ContentType: asset.ContentType,
		Width:       asset.Width,
		Height:      asset.Height,
	}
}

// ToBrandPalette answers a custom brand's palette as it was written (#815 decision 2): its mode, and
// for each mode the four entered colors in basic mode, the 19 worked out being left out, or all 23 in
// advanced mode. A brand on a built-in theme answers none, whatever is stored.
func ToBrandPalette(brand *record.Brand) *api.BrandPaletteResponse {
	if brand.Theme != record.BrandThemeCustom || brand.Palette == nil {
		return nil
	}
	entered := func(colors map[string]string) map[string]string {
		if brand.Palette.Mode == record.BrandPaletteModeAdvanced {
			return maps.Clone(colors)
		}
		four := map[string]string{}
		for _, token := range palette.BasicTokens() {
			four[token] = colors[token]
		}
		return four
	}
	return &api.BrandPaletteResponse{Mode: string(brand.Palette.Mode), Light: entered(brand.Palette.Light), Dark: entered(brand.Palette.Dark)}
}

// ToBrandColors answers the 23 colors of each mode a brand is drawn in, a custom brand's stored ones
// and a built-in theme's own, and the pairs of them below their minimum in the modes the brand's
// appearance draws, light before dark, each in the shared list's order, [] for none (#815 decisions
// 5 and 8). The ratios are palette.Check's. A brand whose colors cannot be drawn, a custom one with
// no palette or a theme that is none of the built-in ones, answers no colors and no warnings.
func ToBrandColors(brand *record.Brand) (*api.BrandColors, []api.BrandContrastWarning) {
	warnings := []api.BrandContrastWarning{}
	var colors *api.BrandColors
	if brand.Theme == record.BrandThemeCustom {
		if brand.Palette != nil {
			colors = &api.BrandColors{Light: maps.Clone(brand.Palette.Light), Dark: maps.Clone(brand.Palette.Dark)}
		}
	} else if preset, ok := brandthemes.Get(brand.Theme); ok {
		colors = &api.BrandColors{Light: map[string]string(preset.Light), Dark: map[string]string(preset.Dark)}
	}
	if colors == nil {
		return nil, warnings
	}

	modes := []struct {
		name   string
		colors map[string]string
	}{{"light", colors.Light}, {"dark", colors.Dark}}
	for _, mode := range modes {
		if !drawsMode(brand.Appearance, mode.name) {
			continue
		}
		failures, err := palette.Check(mode.colors)
		if err != nil {
			// A stored palette is checked whole when it is written and read, and a built-in
			// theme by its tests, so a mode that cannot be checked is a palette that cannot be
			// drawn.
			return nil, []api.BrandContrastWarning{}
		}
		for _, failure := range failures {
			warnings = append(warnings, api.BrandContrastWarning{Mode: mode.name, Foreground: failure.Foreground,
				Background: failure.Background, Ratio: failure.Ratio, Minimum: failure.Minimum})
		}
	}
	return colors, warnings
}

// drawsMode reports whether a brand of appearance draws its pages in mode, light or dark: a light
// brand draws only light, a dark one only dark, and an automatic one both (#815 decision 8).
func drawsMode(appearance record.BrandAppearance, mode string) bool {
	switch appearance {
	case record.BrandAppearanceLight:
		return mode == "light"
	case record.BrandAppearanceDark:
		return mode == "dark"
	}
	return true
}
