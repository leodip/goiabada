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

// BrandNameMaxLength is the bound of a brand's name, in inputvalidation.TextLength's unit. The
// column is as wide.
const BrandNameMaxLength = 60

// Brand is a look an administrator gives the pages: a name, an appearance and one of the built-in
// themes (#810). One brand is the default, the one the settings row's DefaultBrandId points at, and
// every page is drawn in it; the others are stored and editable. Name is unique among brands,
// compared exactly as every name in the schema is.
type Brand struct {
	Id         int64           `db:"id" fieldtag:"pk"`
	CreatedAt  sql.NullTime    `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt  sql.NullTime    `db:"updated_at"`
	Name       string          `db:"name"`
	Appearance BrandAppearance `db:"appearance"`
	Theme      string          `db:"theme"`
}
