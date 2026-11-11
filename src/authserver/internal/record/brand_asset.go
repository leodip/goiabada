package record

import "time"

// BrandAssetKind is what an uploaded brand asset is for, carried on brand_assets.kind as its
// lower-case wire value (#813 decision 3). Each kind has its own rules: its content types, its pixel
// bounds and its byte limit.
type BrandAssetKind string

const (
	// BrandAssetKindLogo is a brand's logo or dark logo.
	BrandAssetKindLogo BrandAssetKind = "logo"
	// BrandAssetKindFavicon is a brand's favicon.
	BrandAssetKindFavicon BrandAssetKind = "favicon"
	// BrandAssetKindBackground is the image behind a brand's card.
	BrandAssetKindBackground BrandAssetKind = "background"
	// BrandAssetKindFont is a WOFF2 file for a brand's regular or bold font slot.
	BrandAssetKindFont BrandAssetKind = "font"
)

// IsValid reports whether k is one of the four kinds.
func (k BrandAssetKind) IsValid() bool {
	switch k {
	case BrandAssetKindLogo, BrandAssetKindFavicon, BrandAssetKindBackground, BrandAssetKindFont:
		return true
	}
	return false
}

// BrandAsset is one uploaded file of a brand's kit (#813 decision 2): its kind, the content type it
// was validated as, the fingerprint of its bytes, its pixel size (zero for a font) and the bytes. A
// row never changes after the upload, so it has no updated_at and no whole-row UPDATE.
//
// Brands point into the assets through their six slots; nothing on the asset names a brand. An
// asset no slot names is unattached, and the sweep, the only thing that deletes assets, deletes one
// once it is older than its cutoff.
//
// Content is nil on a read that leaves the bytes out, as every read but GetBrandAssetById does.
type BrandAsset struct {
	Id          int64          `db:"id" fieldtag:"pk"`
	CreatedAt   time.Time      `db:"created_at" fieldtag:"dont-update"`
	Kind        BrandAssetKind `db:"kind"`
	ContentType string         `db:"content_type"`
	Fingerprint string         `db:"fingerprint"`
	Width       int            `db:"width"`
	Height      int            `db:"height"`
	Content     []byte         `db:"content"`
}
