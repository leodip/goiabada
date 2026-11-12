package record

import (
	"database/sql"
)

// BrandAppearance is whether a brand's pages are drawn light, dark or after each visitor's device,
// carried on brands.appearance as its lower-case wire value, which is also the admin API's
// appearance (#810 decision 5).
type BrandAppearance string

const (
	// BrandAppearanceAuto follows each visitor's device between light and dark. It is the seeded
	// brand's appearance on a new deployment, and migration 000089 gives it to an upgraded one
	// whose stored theme was neither light nor dark.
	BrandAppearanceAuto BrandAppearance = "auto"
	// BrandAppearanceLight draws every page light.
	BrandAppearanceLight BrandAppearance = "light"
	// BrandAppearanceDark draws every page dark.
	BrandAppearanceDark BrandAppearance = "dark"
)

// IsValid reports whether a is one of the three appearances.
func (a BrandAppearance) IsValid() bool {
	switch a {
	case BrandAppearanceAuto, BrandAppearanceLight, BrandAppearanceDark:
		return true
	}
	return false
}

// SeededBrandName is the name of the brand a new deployment is seeded with and migration 000089
// creates on an upgraded one, which is the default brand on both.
const SeededBrandName = "Default"

// BrandThemeBlueberry is the key of the built-in Blueberry theme, today's palette, which the seeded
// brand and the brand migration 000089 creates are both drawn in (#810 decision 6).
const BrandThemeBlueberry = "blueberry"

// BrandThemeCustom is the theme key of a brand drawn in its own custom palette, which the brand's
// Palette holds (#815 decision 2). It is reserved: no built-in theme has it, and the admin API's list
// of built-in themes does not name it.
const BrandThemeCustom = "custom"

// BrandNameMaxLength is the bound of a brand's name, in inputvalidation.TextLength's unit. The
// column is as wide.
const BrandNameMaxLength = 60

// BrandCorners is how round a brand's controls and panels are drawn, carried on brands.corners as
// its lower-case wire value (#813).
type BrandCorners string

const (
	// BrandCornersSquare draws no rounding.
	BrandCornersSquare BrandCorners = "square"
	// BrandCornersRounded is today's two radii, which migration 000091 gives every existing brand.
	BrandCornersRounded BrandCorners = "rounded"
	// BrandCornersPill rounds a single-line control fully.
	BrandCornersPill BrandCorners = "pill"
)

// IsValid reports whether c is one of the three corner shapes.
func (c BrandCorners) IsValid() bool {
	switch c {
	case BrandCornersSquare, BrandCornersRounded, BrandCornersPill:
		return true
	}
	return false
}

// BrandFont is the font family a brand's text is drawn in: one of six system families, each a list
// of fonts a visitor's device already has, or the font uploaded to the brand's regular and bold font
// slots. It is carried on brands.font as its lower-case wire value (#813 decision 7).
type BrandFont string

const (
	// BrandFontSystemUI is today's family, which migration 000091 gives every existing brand.
	BrandFontSystemUI     BrandFont = "system-ui"
	BrandFontHumanist     BrandFont = "humanist"
	BrandFontGeometric    BrandFont = "geometric"
	BrandFontSerif        BrandFont = "serif"
	BrandFontNeoGrotesque BrandFont = "neo-grotesque"
	BrandFontRounded      BrandFont = "rounded"
	// BrandFontUploaded draws the font in the brand's regular font slot, and its bold one if set.
	BrandFontUploaded BrandFont = "uploaded"
)

// IsValid reports whether f is one of the six system families or the uploaded font.
func (f BrandFont) IsValid() bool {
	switch f {
	case BrandFontSystemUI, BrandFontHumanist, BrandFontGeometric, BrandFontSerif,
		BrandFontNeoGrotesque, BrandFontRounded, BrandFontUploaded:
		return true
	}
	return false
}

// BrandBackgroundFit is how a brand's background image fills the page behind the card, carried on
// brands.background_fit as its lower-case wire value (#813).
type BrandBackgroundFit string

const (
	// BrandBackgroundFitCover fills the page, cropping the image. Migration 000091 gives it to
	// every existing brand.
	BrandBackgroundFitCover BrandBackgroundFit = "cover"
	// BrandBackgroundFitContain shows the whole image, with the theme's background around it.
	BrandBackgroundFitContain BrandBackgroundFit = "contain"
	// BrandBackgroundFitTile repeats the image at its own size.
	BrandBackgroundFitTile BrandBackgroundFit = "tile"
)

// IsValid reports whether f is one of the three fits.
func (f BrandBackgroundFit) IsValid() bool {
	switch f {
	case BrandBackgroundFitCover, BrandBackgroundFitContain, BrandBackgroundFitTile:
		return true
	}
	return false
}

// Brand is a look an administrator gives the pages: a name, an appearance, one of the built-in
// themes (#810), and its kit: corners, a font, a background fit, whether the app name's text is
// hidden beside a logo, and six slots naming a stored brand asset each (#813); and the footer links
// and the support contact drawn under its card (#814); and a custom palette (#815). One brand is the
// default, the one the settings row's DefaultBrandId points at, and every page is drawn in it; the
// others are stored and editable. Name is unique among brands, compared exactly as every name in
// the schema is.
//
// Each slot is a foreign key to brand_assets with no cascade, NULL for an empty slot: the engine
// refuses a slot naming no asset, and refuses deleting an asset a slot names. A slot holds an
// asset id and never its bytes, so reading a brand for a page loads none. Which kind of asset a
// slot takes is the writer's to hold: the logo and dark logo take a logo, the favicon a favicon, the
// background a background, and the two font slots a font.
type Brand struct {
	Id                 int64              `db:"id" fieldtag:"pk"`
	CreatedAt          sql.NullTime       `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt          sql.NullTime       `db:"updated_at"`
	Name               string             `db:"name"`
	Appearance         BrandAppearance    `db:"appearance"`
	Theme              string             `db:"theme"`
	Corners            BrandCorners       `db:"corners"`
	Font               BrandFont          `db:"font"`
	BackgroundFit      BrandBackgroundFit `db:"background_fit"`
	HideAppName        bool               `db:"hide_app_name"`
	LogoAssetId        sql.NullInt64      `db:"logo_asset_id"`
	DarkLogoAssetId    sql.NullInt64      `db:"dark_logo_asset_id"`
	FaviconAssetId     sql.NullInt64      `db:"favicon_asset_id"`
	BackgroundAssetId  sql.NullInt64      `db:"background_asset_id"`
	RegularFontAssetId sql.NullInt64      `db:"regular_font_asset_id"`
	BoldFontAssetId    sql.NullInt64      `db:"bold_font_asset_id"`
	// SupportEmail, SupportURL and SupportPhone are the brand's support contact, each optional and
	// empty when unset (#814 decision 1). The phone number is stored in E.164, a "+" and digits.
	SupportEmail string `db:"support_email"`
	SupportURL   string `db:"support_url"`
	SupportPhone string `db:"support_phone"`
	// FooterLinks are the links drawn under the brand's card, in order, nil for none. The whole
	// list is one column of JSON text (#814 decision 8).
	FooterLinks BrandFooterLinks `db:"footer_links"`
	// Palette is the brand's custom palette, nil for a brand on a built-in theme. It is stored
	// whole as JSON text on a nullable column, NULL for none (#815 decision 3).
	Palette *BrandPalette `db:"palette"`
}

// NewBrand answers a brand with the given name, appearance and theme, and the kit an existing
// brand was given by migration 000091: rounded corners, the System UI family, a background drawn as
// cover, the app name shown, and every slot empty. It is drawn exactly as a brand was before the
// kit existed.
func NewBrand(name string, appearance BrandAppearance, theme string) Brand {
	return Brand{
		Name:          name,
		Appearance:    appearance,
		Theme:         theme,
		Corners:       BrandCornersRounded,
		Font:          BrandFontSystemUI,
		BackgroundFit: BrandBackgroundFitCover,
	}
}
