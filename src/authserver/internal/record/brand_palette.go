package record

import (
	"database/sql/driver"
	"encoding/json"

	"github.com/leodip/goiabada/core/errs"
)

// BrandPaletteMode is how a custom palette was made (#815 decision 1): from four colors per mode,
// the other 19 worked out at the save, or with all 23 set by hand. It is carried in the stored
// palette as its lower-case wire value, which is also the admin API's.
type BrandPaletteMode string

const (
	// BrandPaletteModeBasic is a palette entered as four colors per mode: canvas, surface, ink and
	// brand. The other 19 are worked out when it is saved, and stored with the four.
	BrandPaletteModeBasic BrandPaletteMode = "basic"
	// BrandPaletteModeAdvanced is a palette whose 23 colors per mode are each set by hand.
	BrandPaletteModeAdvanced BrandPaletteMode = "advanced"
)

// IsValid reports whether m is one of the two modes.
func (m BrandPaletteMode) IsValid() bool {
	return m == BrandPaletteModeBasic || m == BrandPaletteModeAdvanced
}

// BrandPalette is a brand's custom palette as it is stored: how it was made, and the 23 colors of
// each mode the pages are drawn in, by color token name (#815 decisions 1 and 3). Whatever the
// mode, both maps hold every one of the 23 tokens, so what is drawn is exactly what is stored.
//
// It is stored whole as JSON text on brands.palette, {"mode", "light", "dark"}, and NULL for none.
// The engine cannot check the text's shape: the data layer holds a palette to it before a write
// and again on every read, where a stored value that is anything else reads as no palette.
type BrandPalette struct {
	Mode  BrandPaletteMode  `json:"mode"`
	Light map[string]string `json:"light"`
	Dark  map[string]string `json:"dark"`
}

// Value is the palette as brands.palette stores it: its JSON text, and NULL for none. It encodes
// the palette as it is; the data layer holds it to a stored palette's shape before the write.
func (p *BrandPalette) Value() (driver.Value, error) {
	if p == nil {
		return nil, nil
	}
	text, err := json.Marshal(p)
	if err != nil {
		return nil, errs.Wrap(err, "unable to encode the brand's palette")
	}
	return string(text), nil
}
