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
// FooterLinks are the links drawn under the brand's card, in order, [] for none, and SupportEmail,
// SupportUrl and SupportPhone its support contact, each "" when unset, the phone number in E.164: a
// "+" and digits (#814 decisions 1 and 9). The four are always answered.
//
// Logo, DarkLogo, Favicon, Background, RegularFont and BoldFont are the brand's six slots, each the
// stored asset it holds, null when empty. A slot answers the asset's id, which is what a write names
// it by, so a brand read and written back is unchanged (#813 decision 10).
//
// Palette is a brand's custom palette as it was written, null for a brand on a built-in theme, and
// Colors the 23 colors of each mode the brand is drawn in: a custom brand's stored colors, a built-in
// theme's own. ContrastWarnings are the pairs of those colors below their minimum, of the modes the
// appearance draws, [] for none (#815 decisions 2, 5 and 8). Colors and ContrastWarnings are read
// only: a write ignores them. A custom brand whose stored palette cannot be read answers Palette and
// Colors as null and no warnings (#815 decision 3).
type BrandResponse struct {
	Id               int64                     `json:"id"`
	Name             string                    `json:"name"`
	Appearance       string                    `json:"appearance"`
	Theme            string                    `json:"theme"`
	Corners          string                    `json:"corners"`
	Font             string                    `json:"font"`
	BackgroundFit    string                    `json:"backgroundFit"`
	HideAppName      bool                      `json:"hideAppName"`
	Logo             *BrandAssetResponse       `json:"logo"`
	DarkLogo         *BrandAssetResponse       `json:"darkLogo"`
	Favicon          *BrandAssetResponse       `json:"favicon"`
	Background       *BrandAssetResponse       `json:"background"`
	RegularFont      *BrandAssetResponse       `json:"regularFont"`
	BoldFont         *BrandAssetResponse       `json:"boldFont"`
	FooterLinks      []BrandFooterLinkResponse `json:"footerLinks"`
	SupportEmail     string                    `json:"supportEmail"`
	SupportUrl       string                    `json:"supportUrl"`
	SupportPhone     string                    `json:"supportPhone"`
	Palette          *BrandPaletteResponse     `json:"palette"`
	Colors           *BrandColors              `json:"colors"`
	ContrastWarnings []BrandContrastWarning    `json:"contrastWarnings"`
	CustomCss        string                    `json:"customCss"`
	IsDefault        bool                      `json:"isDefault"`
	ClientCount      int                       `json:"clientCount"`
	CreatedAt        *time.Time                `json:"createdAt"`
	UpdatedAt        *time.Time                `json:"updatedAt"`
}

// BrandFooterLinkResponse is one of a brand's footer links as the admin API answers it: the URL it
// opens, the fallback label, and the label of each built-in language that has its own, by language
// tag, {} when none has (#814 decision 9).
type BrandFooterLinkResponse struct {
	Url    string            `json:"url"`
	Label  string            `json:"label"`
	Labels map[string]string `json:"labels"`
}

// BrandFooterLink is one footer link as a brand's create and update name it (#814 decisions 5 and
// 9): an https: URL with a host and no user name or password, at most 256 characters, and a label,
// both required. The label, trimmed, is at most 40 characters, without angle brackets, and is drawn
// in a language the link has no label of its own for. Labels is optional, left out, null or {}, and
// holds a label by the tag of one of the six built-in languages, under the same bounds; a blank one
// is dropped and any other tag is refused. A BrandFooterLinkResponse sent back as it came is the
// same link.
type BrandFooterLink struct {
	Url    string            `json:"url"`
	Label  string            `json:"label"`
	Labels map[string]string `json:"labels"`
}

// BrandPalette is a brand's custom palette as a create and an update write it (#815 decision 2):
// Mode, basic or advanced, and Light and Dark, each a map from a color token's name to a color, `#`
// and six hexadecimal digits in either case. In basic mode each map holds exactly canvas, surface,
// ink and brand, and the other 19 colors are worked out when the brand is saved; in advanced mode
// each holds all 23. Both modes are always sent, whatever the brand's appearance. A
// BrandPaletteResponse sent back as it came is the same palette.
type BrandPalette struct {
	Mode  string            `json:"mode"`
	Light map[string]string `json:"light"`
	Dark  map[string]string `json:"dark"`
}

// BrandPaletteResponse is a brand's custom palette as a brand answers it: as it was written, its
// colors in lower case, the four of each mode in basic mode and the 23 in advanced mode.
type BrandPaletteResponse struct {
	Mode  string            `json:"mode"`
	Light map[string]string `json:"light"`
	Dark  map[string]string `json:"dark"`
}

// BrandColors are the 23 colors of each mode a brand is drawn in, by color token name.
type BrandColors struct {
	Light map[string]string `json:"light"`
	Dark  map[string]string `json:"dark"`
}

// BrandContrastWarning is a pair of a brand's colors below its minimum contrast (#815 decision 5):
// the mode, light or dark, the foreground and background tokens, the ratio cut to two decimals and
// never rounded up, and the minimum, 4.5 for text and 3 for a boundary or the focus ring.
type BrandContrastWarning struct {
	Mode       string  `json:"mode"`
	Foreground string  `json:"foreground"`
	Background string  `json:"background"`
	Ratio      float64 `json:"ratio"`
	Minimum    float64 `json:"minimum"`
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
//
// FooterLinks are at most three, saved in the order sent, each held to BrandFooterLink's rules, and
// a refusal about one names it in the error answer's error_field, a JSON Pointer such as
// /footerLinks/1/url. SupportEmail is an address of the shape and the 254-character bound an
// account's is, SupportUrl a URL held to a footer link's rules, and SupportPhone a number in E.164, a
// "+" and up to 15 digits, the first not zero, which may be written with spaces, hyphens, dots and
// parentheses and is stored without them. Each is trimmed. A member left out or null is no
// links, or an unset contact value, as [] and "" are (#814 decisions 1, 5, 9 and 10).
//
// Theme is a built-in theme's key or custom, the reserved key of a custom palette. Palette is required
// with custom and refused with a built-in theme, where left out and null are both fine, so saving a
// built-in theme drops a stored palette. A refusal about the palette names the member it is about in
// error_field, such as /palette/light/brand (#815 decision 2).
type CreateBrandRequest struct {
	Name          string            `json:"name"`
	Appearance    string            `json:"appearance"`
	Theme         string            `json:"theme"`
	Corners       string            `json:"corners"`
	Font          string            `json:"font"`
	BackgroundFit string            `json:"backgroundFit"`
	HideAppName   bool              `json:"hideAppName"`
	Logo          *BrandAssetRef    `json:"logo"`
	DarkLogo      *BrandAssetRef    `json:"darkLogo"`
	Favicon       *BrandAssetRef    `json:"favicon"`
	Background    *BrandAssetRef    `json:"background"`
	RegularFont   *BrandAssetRef    `json:"regularFont"`
	BoldFont      *BrandAssetRef    `json:"boldFont"`
	FooterLinks   []BrandFooterLink `json:"footerLinks"`
	SupportEmail  string            `json:"supportEmail"`
	SupportUrl    string            `json:"supportUrl"`
	SupportPhone  string            `json:"supportPhone"`
	Palette       *BrandPalette     `json:"palette"`
	CustomCss     string            `json:"customCss"`
}

type CreateBrandResponse struct {
	Brand BrandResponse `json:"brand"`
}

type GetBrandResponse struct {
	Brand BrandResponse `json:"brand"`
}

// UpdateBrandRequest replaces a brand's fields, validated as CreateBrandRequest's are: every field
// is written, so a field left out is refused, or, for HideAppName, false, or, for a slot, empty
// (#813 decision 10), or, for the footer links and the support contact, none (#814 decision 9).
type UpdateBrandRequest struct {
	Name          string            `json:"name"`
	Appearance    string            `json:"appearance"`
	Theme         string            `json:"theme"`
	Corners       string            `json:"corners"`
	Font          string            `json:"font"`
	BackgroundFit string            `json:"backgroundFit"`
	HideAppName   bool              `json:"hideAppName"`
	Logo          *BrandAssetRef    `json:"logo"`
	DarkLogo      *BrandAssetRef    `json:"darkLogo"`
	Favicon       *BrandAssetRef    `json:"favicon"`
	Background    *BrandAssetRef    `json:"background"`
	RegularFont   *BrandAssetRef    `json:"regularFont"`
	BoldFont      *BrandAssetRef    `json:"boldFont"`
	FooterLinks   []BrandFooterLink `json:"footerLinks"`
	SupportEmail  string            `json:"supportEmail"`
	SupportUrl    string            `json:"supportUrl"`
	SupportPhone  string            `json:"supportPhone"`
	Palette       *BrandPalette     `json:"palette"`
	CustomCss     string            `json:"customCss"`
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
