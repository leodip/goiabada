package api

import "time"

// BrandResponse is a brand as the admin API answers it (#810 decision 5): a name, an appearance
// (auto, light or dark) and the key of one of the built-in themes. IsDefault marks the one brand
// every page is drawn in.
type BrandResponse struct {
	Id         int64      `json:"id"`
	Name       string     `json:"name"`
	Appearance string     `json:"appearance"`
	Theme      string     `json:"theme"`
	IsDefault  bool       `json:"isDefault"`
	CreatedAt  *time.Time `json:"createdAt"`
	UpdatedAt  *time.Time `json:"updatedAt"`
}

// GetBrandsResponse is every brand, sorted by name.
type GetBrandsResponse struct {
	Brands []BrandResponse `json:"brands"`
}

// CreateBrandRequest creates a brand. The auth server trims the name and refuses an empty one, one
// longer than 60 characters, one with an angle bracket and one another brand holds; an appearance
// or a theme that is missing or unknown is refused too.
type CreateBrandRequest struct {
	Name       string `json:"name"`
	Appearance string `json:"appearance"`
	Theme      string `json:"theme"`
}

type CreateBrandResponse struct {
	Brand BrandResponse `json:"brand"`
}

type GetBrandResponse struct {
	Brand BrandResponse `json:"brand"`
}

// UpdateBrandRequest replaces a brand's three fields, validated as CreateBrandRequest's are.
type UpdateBrandRequest struct {
	Name       string `json:"name"`
	Appearance string `json:"appearance"`
	Theme      string `json:"theme"`
}

type UpdateBrandResponse struct {
	Brand BrandResponse `json:"brand"`
}

// MakeBrandDefaultResponse is the brand that is now the default.
type MakeBrandDefaultResponse struct {
	Brand BrandResponse `json:"brand"`
}

// BrandThemeResponse is one built-in theme: the key a brand stores, and its light and dark palettes,
// each a #rrggbb value for every color token by the token's name.
type BrandThemeResponse struct {
	Key   string            `json:"key"`
	Light map[string]string `json:"light"`
	Dark  map[string]string `json:"dark"`
}

// GetBrandThemesResponse is the built-in themes in display order.
type GetBrandThemesResponse struct {
	BrandThemes []BrandThemeResponse `json:"brandThemes"`
}
