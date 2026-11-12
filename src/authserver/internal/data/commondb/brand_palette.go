package commondb

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/palette"
)

// checkBrandPaletteWrite refuses a palette parseBrandPalette would refuse, so a write never stores
// what a read cannot use (#815 decision 3). No palette is NULL, and passes.
func checkBrandPaletteWrite(p *record.BrandPalette) error {
	if p == nil {
		return nil
	}
	if err := checkBrandPalette(p); err != nil {
		return errs.Wrap(err, "unable to store the brand's palette")
	}
	return nil
}

// parseBrandPalette reads brands.palette as record.BrandPalette's Value wrote it: one JSON object
// with exactly the members mode, light and dark, the mode basic or advanced, and each of light and
// dark an object holding exactly the 23 color tokens, each a #rrggbb color. Anything else does not
// parse and answers an error with nil, so a reader draws no palette rather than one with a token
// missing or a value that is not a color. A stored value can only be something else after a hand
// edit of the database.
func parseBrandPalette(text string) (*record.BrandPalette, error) {
	decoder := json.NewDecoder(bytes.NewReader([]byte(text)))
	decoder.DisallowUnknownFields()
	var p record.BrandPalette
	if err := decoder.Decode(&p); err != nil {
		return nil, errs.Wrap(err, "the brand's palette is not a JSON palette object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errs.New("the brand's palette has text after its JSON object")
	}
	if err := checkBrandPalette(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// checkBrandPalette holds a palette to the shape a stored palette has: a known mode, and each mode
// exactly the 23 tokens, each a color.
func checkBrandPalette(p *record.BrandPalette) error {
	if !p.Mode.IsValid() {
		return errs.Errorf("the brand's palette mode %q is neither basic nor advanced", p.Mode)
	}
	tokens := palette.Tokens()
	for _, mode := range []struct {
		name   string
		colors map[string]string
	}{{"light", p.Light}, {"dark", p.Dark}} {
		if mode.colors == nil {
			return errs.Errorf("the brand's palette has no %s colors", mode.name)
		}
		for _, token := range tokens {
			value, ok := mode.colors[token]
			if !ok {
				return errs.Errorf("the brand's palette has no %s %s color", mode.name, token)
			}
			if !palette.IsColor(value) {
				return errs.Errorf("the brand's palette's %s %s color, %q, is not a #rrggbb color", mode.name, token, value)
			}
		}
		for token := range mode.colors {
			if !slices.Contains(tokens, token) {
				return errs.Errorf("the brand's palette's %s colors name %q, which is no color token", mode.name, token)
			}
		}
	}
	return nil
}
