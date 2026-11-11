package api

import "time"

// BrandResponse is a brand as the admin API answers it (#810 decision 5): a name, an appearance
// (auto, light or dark) and the key of one of the built-in themes, and the choices of its kit (#813
// decision 10): its corners (square, rounded or pill), its font (system-ui, humanist, geometric,
// serif, neo-grotesque, rounded or uploaded), its background fit (cover, contain or tile), and
// whether the app name's text is hidden beside a logo. IsDefault marks the brand a client with no
// brand of its own is drawn in. ClientCount is how many clients are drawn in the brand: those given
// it and, for the default brand, those with no brand of their own too, so the counts of all brands
// add up to every client (#812 decision 3).
//
// Logo, DarkLogo, Favicon, Background, RegularFont and BoldFont are the brand's six slots, each the
// stored asset it holds, null when empty. A slot answers the asset's id, which is what a write names
// it by, so a brand read and written back is unchanged (#813 decision 10).
type BrandResponse struct {
	Id            int64               `json:"id"`
	Name          string              `json:"name"`
	Appearance    string              `json:"appearance"`
	Theme         string              `json:"theme"`
	Corners       string              `json:"corners"`
	Font          string              `json:"font"`
	BackgroundFit string              `json:"backgroundFit"`
	HideAppName   bool                `json:"hideAppName"`
	Logo          *BrandAssetResponse `json:"logo"`
	DarkLogo      *BrandAssetResponse `json:"darkLogo"`
	Favicon       *BrandAssetResponse `json:"favicon"`
	Background    *BrandAssetResponse `json:"background"`
	RegularFont   *BrandAssetResponse `json:"regularFont"`
	BoldFont      *BrandAssetResponse `json:"boldFont"`
	IsDefault     bool                `json:"isDefault"`
	ClientCount   int                 `json:"clientCount"`
	CreatedAt     *time.Time          `json:"createdAt"`
	UpdatedAt     *time.Time          `json:"updatedAt"`
}

// BrandAssetRef names a stored brand asset by its id, as a brand's create and update name the asset
// each slot holds. A slot's answer, a BrandAssetResponse, carries the same id, so it can be sent back
// as it was read.
type BrandAssetRef struct {
	Id int64 `json:"id"`
}

// GetBrandsResponse is every brand, sorted by name.
type GetBrandsResponse struct {
	Brands []BrandResponse `json:"brands"`
}

// CreateBrandRequest creates a brand. The auth server trims the name and refuses an empty one, one
// longer than 60 characters, one with an angle bracket and one another brand holds; an appearance,
// a theme, corners, a font or a background fit that is missing or unknown is refused too, so a
// misspelt field is reported rather than taken as a default (#813 decision 10). HideAppName is
// false when absent.
//
// Each of the six slots names, by its id, a stored asset of the slot's kind, uploaded first as a
// brand asset: a logo for Logo and DarkLogo, a favicon, a background, and a font for RegularFont and
// BoldFont. A slot left out or null is empty. One naming no stored asset of its kind is refused at
// that slot, an asset since swept included, and so are a dark logo without a logo, a bold font file
// without a regular one, and the uploaded font without a regular font file (#813 decisions 5, 7 and
// 10).
type CreateBrandRequest struct {
	Name          string         `json:"name"`
	Appearance    string         `json:"appearance"`
	Theme         string         `json:"theme"`
	Corners       string         `json:"corners"`
	Font          string         `json:"font"`
	BackgroundFit string         `json:"backgroundFit"`
	HideAppName   bool           `json:"hideAppName"`
	Logo          *BrandAssetRef `json:"logo"`
	DarkLogo      *BrandAssetRef `json:"darkLogo"`
	Favicon       *BrandAssetRef `json:"favicon"`
	Background    *BrandAssetRef `json:"background"`
	RegularFont   *BrandAssetRef `json:"regularFont"`
	BoldFont      *BrandAssetRef `json:"boldFont"`
}

type CreateBrandResponse struct {
	Brand BrandResponse `json:"brand"`
}

type GetBrandResponse struct {
	Brand BrandResponse `json:"brand"`
}

// UpdateBrandRequest replaces a brand's fields, validated as CreateBrandRequest's are: every field
// is written, so a field left out is refused, or, for HideAppName, false, or, for a slot, empty
// (#813 decision 10).
type UpdateBrandRequest struct {
	Name          string         `json:"name"`
	Appearance    string         `json:"appearance"`
	Theme         string         `json:"theme"`
	Corners       string         `json:"corners"`
	Font          string         `json:"font"`
	BackgroundFit string         `json:"backgroundFit"`
	HideAppName   bool           `json:"hideAppName"`
	Logo          *BrandAssetRef `json:"logo"`
	DarkLogo      *BrandAssetRef `json:"darkLogo"`
	Favicon       *BrandAssetRef `json:"favicon"`
	Background    *BrandAssetRef `json:"background"`
	RegularFont   *BrandAssetRef `json:"regularFont"`
	BoldFont      *BrandAssetRef `json:"boldFont"`
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

// BrandAssetResponse is a stored brand asset as the admin API answers it (#813 decision 10): its id,
// its kind (logo, favicon, background or font), the URL it is served at, which carries its content
// fingerprint, the type it was validated as, and its pixel size, zero for a font. A brand names an
// asset by its id.
type BrandAssetResponse struct {
	Id          int64  `json:"id"`
	Kind        string `json:"kind"`
	Url         string `json:"url"`
	ContentType string `json:"contentType"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
}

// CreateBrandAssetResponse is the asset an upload stored.
type CreateBrandAssetResponse struct {
	BrandAsset BrandAssetResponse `json:"brandAsset"`
}

// GetBrandAssetResponse is one stored asset, read by its id.
type GetBrandAssetResponse struct {
	BrandAsset BrandAssetResponse `json:"brandAsset"`
}
