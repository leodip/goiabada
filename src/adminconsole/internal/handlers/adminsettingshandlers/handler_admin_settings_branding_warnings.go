package adminsettingshandlers

import (
	"context"
	"slices"
	"strings"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"golang.org/x/text/number"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/palette"
)

// The warnings of a saved brand (#815 decisions 5, 9 and 11): the pairs of its colors below their
// minimum, as the admin API answers them in contrastWarnings for the modes its appearance draws. The
// editor lists them at the foot of the Colors section under a count line, each with a swatch of the
// pair drawn from the brand's colors; the saved notice says how many there are and links to the list;
// and the brand list marks a brand that has any. They describe the stored colors, so the list is
// drawn for a brand as stored, never for a form holding colors as typed.

// BrandContrastWarnings is the list drawn under a saved custom brand's Colors section: the count
// line, the saved notice's sentence, "" with no failing pair, and an item per failing pair, in the
// admin API's order.
type BrandContrastWarnings struct {
	CountLine string
	Notice    string
	Items     []BrandContrastWarningItem
}

// BrandContrastWarningItem is one failing pair: its mode, the foreground and background colors its
// swatch is drawn in, each "" when the brand's colors hold no color for it, and its sentence.
type BrandContrastWarningItem struct {
	Mode       string
	Foreground string
	Background string
	Text       string
}

// NewBrandContrastWarnings is the list of brand's failing pairs, or nil for a brand with no stored
// palette to list them for: one on a built-in theme, which every pair passes, and a custom one whose
// stored palette cannot be read, which answers no colors (decision 3).
func NewBrandContrastWarnings(ctx context.Context, brand api.BrandResponse) *BrandContrastWarnings {
	if brand.Palette == nil || brand.Colors == nil {
		return nil
	}
	count := len(brand.ContrastWarnings)
	warnings := &BrandContrastWarnings{
		CountLine: countSentence(ctx, "adminconsole.admin_branding.palette.warnings.", count, nil),
	}
	if count > 0 {
		warnings.Notice = oneOrOther(ctx, "adminconsole.admin_branding.brand.saved_warnings.", count)
	}
	for _, w := range brand.ContrastWarnings {
		colors := brand.Colors.Light
		if w.Mode == "dark" {
			colors = brand.Colors.Dark
		}
		warnings.Items = append(warnings.Items, BrandContrastWarningItem{
			Mode:       w.Mode,
			Foreground: swatchColor(colors[w.Foreground]),
			Background: swatchColor(colors[w.Background]),
			Text: i18n.T(ctx, "adminconsole.admin_branding.palette.warning", map[string]any{
				"mode":       nameIn(ctx, brandAppearanceNames, w.Mode),
				"foreground": paletteColorName(ctx, w.Foreground),
				"background": paletteColorName(ctx, w.Background),
				"ratio":      decimal(ctx, w.Ratio),
				"minimum":    decimal(ctx, w.Minimum),
			}),
		})
	}
	return warnings
}

// brandWarningsMarker is what the brand list marks a brand with failing pairs with, saying how many,
// or "" for a brand with none.
func brandWarningsMarker(ctx context.Context, brand api.BrandResponse) string {
	if len(brand.ContrastWarnings) == 0 {
		return ""
	}
	return oneOrOther(ctx, "adminconsole.admin_branding.list.warnings.", len(brand.ContrastWarnings))
}

// oneOrOther is the message under prefix for a count of at least one: its one form for one and its
// other form for more, chosen as countSentence chooses them.
func oneOrOther(ctx context.Context, prefix string, count int) string {
	form := "other"
	if count == 1 {
		form = "one"
	}
	return i18n.T(ctx, prefix+form, map[string]any{"count": count})
}

// paletteColorName is a color token's plain label, as the Colors section's rows name it, or the token
// itself for one the console has no label for, as a newer auth server's could be.
func paletteColorName(ctx context.Context, token string) string {
	if !slices.Contains(palette.Tokens(), token) {
		return token
	}
	return i18n.T(ctx, "adminconsole.admin_branding.palette.color."+strings.ReplaceAll(token, "-", "_"))
}

// swatchColor is value in lower case when it is a color, and "" otherwise, so a swatch is never drawn
// in anything else.
func swatchColor(value string) string {
	if !palette.IsColor(value) {
		return ""
	}
	return strings.ToLower(value)
}

// decimal writes value as the page's language writes a number, with at most the two decimals the
// admin API cuts a ratio to: 4.5 is "4,5" in Portuguese and 3 is "3".
func decimal(ctx context.Context, value float64) string {
	tag, err := language.Parse(i18n.CatalogTag(ctx))
	if err != nil {
		tag = language.English
	}
	return message.NewPrinter(tag).Sprint(number.Decimal(value, number.MaxFractionDigits(2)))
}
