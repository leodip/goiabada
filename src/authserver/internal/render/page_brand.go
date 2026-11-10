package render

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// DefaultBrandReader is what a page reads its look from: the default brand, the one the settings
// row points at, or nil when the pointer is empty. data.Database satisfies it.
type DefaultBrandReader interface {
	GetDefaultBrand(ctx context.Context, tx *sql.Tx) (*record.Brand, error)
}

// PageBrand is what a page takes from the default brand: the data-theme its html element carries,
// light or dark, or empty for automatic, and the path it links the brand's stylesheet by after
// main.css, or empty for none.
type PageBrand struct {
	DataTheme  string
	Stylesheet string
}

// DefaultPageBrand answers what a page drawn in ctx takes from the default brand brands reads. Both
// layouts and the form_post page are drawn through it, so the three agree.
//
// A page whose brand cannot be read is still drawn, automatic and in main.css's colors, with no
// brand stylesheet (#810): a nil brands, an empty pointer, a failed read, and a stored theme that is
// none of the built-in ones, which names no stylesheet. The last two are faults and are logged; the
// page itself is not one, so it is not refused over them.
func DefaultPageBrand(ctx context.Context, brands DefaultBrandReader) PageBrand {
	if brands == nil {
		return PageBrand{}
	}
	brand, err := brands.GetDefaultBrand(ctx, nil)
	if err != nil {
		slog.ErrorContext(ctx, "unable to read the default brand", "error", err)
		return PageBrand{}
	}
	if brand == nil {
		return PageBrand{}
	}
	stylesheet, err := brandthemes.StylesheetPath(brand.Id, brand.Theme)
	if err != nil {
		slog.ErrorContext(ctx, "unable to link the default brand's stylesheet", "error", err)
		return PageBrand{}
	}

	page := PageBrand{Stylesheet: stylesheet}
	// data-theme is written for light and dark alone, as ui.css reads it: automatic is no attribute,
	// so the device's preference decides.
	if brand.Appearance == record.BrandAppearanceLight || brand.Appearance == record.BrandAppearanceDark {
		page.DataTheme = string(brand.Appearance)
	}
	return page
}
