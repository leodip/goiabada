package render

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/brandasset"
	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
)

// DefaultBrandReader is what a page reads its look from: the default brand, the one the settings
// row points at, or nil when the pointer is empty. data.Database satisfies it.
type DefaultBrandReader interface {
	GetDefaultBrand(ctx context.Context, tx *sql.Tx) (*record.Brand, error)
}

// PageBrandReader is what a page reads its look from: the brand of the client its request names, its
// own or the default, beside the default brand itself, and the assets the brand's slots name, without
// their bytes (#813 decision 2). data.Database satisfies it.
type PageBrandReader interface {
	DefaultBrandReader
	GetClientPageBrand(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Brand, error)
	brandasset.SlotsReader
}

// RequestPageBrand answers what a page drawn in ctx takes from its brand: ClientPageBrand for the
// client ctx names (reqctx.PageClientIdentifier), or for none (#812). Both layouts and the form_post
// page are drawn through it, so the three agree.
func RequestPageBrand(ctx context.Context, brands PageBrandReader) PageBrand {
	return ClientPageBrand(ctx, brands, reqctx.PageClientIdentifier(ctx))
}

// ClientPageBrand answers what a page drawn for the client with clientIdentifier takes from its
// brand: the client's own brand, or the default, and the default brand when clientIdentifier is
// empty or names a client that is not there (#812). The pages a request names a client for are drawn
// through RequestPageBrand, and the public settings answer the admin console's own client's.
//
// A client brand that cannot be read leaves the page as an unreadable default brand does, automatic
// in main.css's colors with no brand stylesheet, and the fault is logged: a page is never refused
// over its look (#810).
func ClientPageBrand(ctx context.Context, brands PageBrandReader, clientIdentifier string) PageBrand {
	if brands == nil || clientIdentifier == "" {
		return DefaultPageBrand(ctx, brands)
	}
	brand, err := brands.GetClientPageBrand(ctx, nil, clientIdentifier)
	if err != nil {
		slog.ErrorContext(ctx, "unable to read the brand of the client a page is drawn for", "error", err)
		return PageBrand{}
	}
	if brand == nil {
		// A client that is not there, or one on the default while the settings row names none.
		return DefaultPageBrand(ctx, brands)
	}
	return pageBrandOf(ctx, brands, brand)
}

// PageBrand is what a page takes from its brand: the data-theme its html element carries,
// light or dark, or empty for automatic, and the path it links the brand's full stylesheet by after
// main.css, or empty for none. ColorsStylesheet is the path of the brand's colors-only stylesheet,
// which no page of the auth server links: the public settings carry it for the admin console's admin
// pages (#813 decision 9). Both are empty, or both are set.
//
// Logo, DarkLogo and Favicon are the paths of the assets the brand's slots name, empty for an empty
// slot; DarkLogo is empty too while there is no Logo, which a write refuses (#813 decision 5).
// HideAppName is whether the app name's text gives way to the logo: the brand's switch, which has no
// effect while there is no logo, so the name never disappears with nothing in its place.
type PageBrand struct {
	DataTheme        string
	Stylesheet       string
	ColorsStylesheet string
	Logo             string
	DarkLogo         string
	Favicon          string
	HideAppName      bool
}

// DefaultPageBrand answers what a page drawn in ctx takes from the default brand brands reads: every
// page that names no client, through ClientPageBrand.
//
// A page whose brand cannot be read is still drawn, automatic and in main.css's colors, with no
// brand stylesheet (#810): a nil brands, an empty pointer, a failed read, and a stored theme that is
// none of the built-in ones, which names no stylesheet. The last two are faults and are logged; the
// page itself is not one, so it is not refused over them.
func DefaultPageBrand(ctx context.Context, brands PageBrandReader) PageBrand {
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
	return pageBrandOf(ctx, brands, brand)
}

// pageBrandOf is what a page drawn in brand takes from it, or nothing when its stored theme is none
// of the built-in ones, which names no stylesheet and is logged.
func pageBrandOf(ctx context.Context, assets brandasset.SlotsReader, brand *record.Brand) PageBrand {
	slots, err := brandasset.ReadSlots(ctx, assets, brand)
	if err != nil {
		slog.ErrorContext(ctx, "unable to read the assets of the brand a page is drawn in", "brand_id", brand.Id, "error", err)
		return PageBrand{}
	}
	stylesheet, err := brandthemes.StylesheetPath(brand, slots)
	if err != nil {
		slog.ErrorContext(ctx, "unable to link the brand's stylesheet", "brand_id", brand.Id, "error", err)
		return PageBrand{}
	}
	colorsStylesheet, err := brandthemes.ColorsStylesheetPath(brand)
	if err != nil {
		slog.ErrorContext(ctx, "unable to link the brand's stylesheet", "brand_id", brand.Id, "error", err)
		return PageBrand{}
	}

	page := PageBrand{Stylesheet: stylesheet, ColorsStylesheet: colorsStylesheet}
	// A dark logo is drawn in place of the logo in dark mode, so it is nothing without one, and the
	// switch hides the name only where a logo takes its place (#813 decision 5).
	if slots.Logo != nil {
		page.Logo = brandasset.Path(slots.Logo)
		if slots.DarkLogo != nil {
			page.DarkLogo = brandasset.Path(slots.DarkLogo)
		}
		page.HideAppName = brand.HideAppName
	}
	if slots.Favicon != nil {
		page.Favicon = brandasset.Path(slots.Favicon)
	}
	// data-theme is written for light and dark alone, as ui.css reads it: automatic is no attribute,
	// so the device's preference decides.
	if brand.Appearance == record.BrandAppearanceLight || brand.Appearance == record.BrandAppearanceDark {
		page.DataTheme = string(brand.Appearance)
	}
	return page
}
