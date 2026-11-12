package adminsettingshandlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/palette"
)

// The live preview's route (#815 decision 6): while a custom palette is edited, brand-palette.js
// posts the Colors section as the form holds it, in the fields a save reads, with the mode and the
// appearance, and the route answers the 23 colors of each mode the palette would be drawn in and its
// failing pairs, worked out and checked by the core code the auth server saves with, so the preview
// shows what the save stores and lists the pairs the save answers. A basic palette's four colors of
// each mode are worked out into all 23 (decision 4); an advanced palette's 23 are answered as sent.
// The pairs are those of the modes the appearance draws (decision 8), each drawn as the editor lists
// a saved brand's, under its count line, in the page's language. The route changes nothing and asks
// the admin API nothing: it sits behind the brand editor's own sign-in and permission. A value that
// is not a color, or a mode that is neither basic nor advanced, is refused as the save refuses it.

// brandPaletteCheckPath is the route the editor's script posts the Colors section to.
const brandPaletteCheckPath = brandingPath + "/palette-check"

// BrandPaletteCheckResponse is the route's answer: the 23 colors of each mode, in lower case, the
// count line of the failing pairs, and an item per pair, as BrandContrastWarnings holds them.
type BrandPaletteCheckResponse struct {
	Light     map[string]string          `json:"light"`
	Dark      map[string]string          `json:"dark"`
	CountLine string                     `json:"countLine"`
	Warnings  []BrandContrastWarningItem `json:"warnings"`
}

// HandleBrandPaletteCheckPost - POST /admin/settings/branding/palette-check: the Colors section's
// fields, paletteMode and appearance, answered with BrandPaletteCheckResponse.
func HandleBrandPaletteCheckPost(httpHelper HttpHelper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		form := brandPaletteFormFrom(r, nil)
		colors, err := form.drawnColors(r.Context())
		if err != nil {
			httpHelper.JSONError(w, r, err)
			return
		}

		drawn := drawnModes(r.PostFormValue("appearance"))
		warnings := []api.BrandContrastWarning{}
		for _, mode := range paletteModes {
			if !drawn[mode] {
				continue
			}
			failures, checkErr := palette.Check(colors.valuesOf(mode))
			if checkErr != nil {
				// Every color was held to being one above, so a mode that cannot be checked is a
				// fault of this code.
				httpHelper.JSONError(w, r, errs.Wrap(checkErr, "unable to check the palette's "+mode+" colors"))
				return
			}
			for _, failure := range failures {
				warnings = append(warnings, api.BrandContrastWarning{Mode: mode, Foreground: failure.Foreground,
					Background: failure.Background, Ratio: failure.Ratio, Minimum: failure.Minimum})
			}
		}

		// The list is drawn as a saved brand's is, from the colors and pairs as an answer of the admin
		// API would carry them.
		listed := NewBrandContrastWarnings(r.Context(), api.BrandResponse{
			Palette:          &api.BrandPaletteResponse{Mode: form.Mode},
			Colors:           &api.BrandColors{Light: colors.Light, Dark: colors.Dark},
			ContrastWarnings: warnings,
		})
		answer := BrandPaletteCheckResponse{Light: colors.Light, Dark: colors.Dark, CountLine: listed.CountLine,
			Warnings: []BrandContrastWarningItem{}}
		answer.Warnings = append(answer.Warnings, listed.Items...)
		httpHelper.EncodeJSON(w, r, answer)
	}
}

// drawnColors answers the 23 colors of each mode the form's palette is drawn in, in lower case: a
// basic palette's worked out from its four colors of each mode, read alone, and an advanced one's as
// typed. A mode that is neither, and a color it reads that is not one, light before dark and each in
// the tokens' order, are refused in the request's language, with the admin API's codes and sentences.
func (p BrandPaletteForm) drawnColors(ctx context.Context) (BrandPaletteForm, error) {
	if p.Mode != paletteModeBasic && p.Mode != paletteModeAdvanced {
		return BrandPaletteForm{}, refusedPaletteCheck(ctx, i18n.ErrCodeBrandPaletteModeInvalid, nil)
	}
	tokens := palette.Tokens()
	if p.Mode == paletteModeBasic {
		tokens = palette.BasicTokens()
	}
	drawn := BrandPaletteForm{Mode: p.Mode, Light: map[string]string{}, Dark: map[string]string{}}
	for _, mode := range paletteModes {
		entered := map[string]string{}
		for _, token := range tokens {
			value := p.valuesOf(mode)[token]
			if !palette.IsColor(value) {
				return BrandPaletteForm{}, refusedPaletteCheck(ctx, i18n.ErrCodeBrandPaletteColorInvalid,
					map[string]any{"mode": mode, "token": token})
			}
			entered[token] = strings.ToLower(value)
		}
		if p.Mode == paletteModeBasic {
			derived, err := palette.Derive(entered)
			if err != nil {
				return BrandPaletteForm{}, errs.Wrap(err, "unable to work out the palette's "+mode+" colors")
			}
			entered = derived
		}
		if mode == "dark" {
			drawn.Dark = entered
		} else {
			drawn.Light = entered
		}
	}
	return drawn, nil
}

// refusedPaletteCheck is the route's refusal of code with args, a 400 in the request's language.
func refusedPaletteCheck(ctx context.Context, code string, args map[string]any) error {
	return oauth.NewErrorDetailWithHTTPStatus(code, i18n.T(ctx, code, args), http.StatusBadRequest)
}
