// Package brandasset is a brand's kit as stored files (#813 decisions 2 and 3): the rules an upload
// of each kind is held to, the fingerprint of an asset's bytes, and the route and path an asset is
// served at. A logo, a favicon and a background are images, held to imageupload's rules for their
// kinds; a font is a WOFF2 file, told by its signature.
package brandasset

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/imageupload"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/brandkit"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// Route is the route an asset is served at, to anyone, its id in {id}.
const Route = "/brand-assets/{id}"

// FontMaxBytes is the most bytes an uploaded font may hold, fixed as the image kinds' limits are,
// and brandkit's, as theirs are.
const FontMaxBytes = brandkit.FontMaxBytes

// imageRules is the rules of an image kind, and false for the font and any unknown kind.
func imageRules(kind record.BrandAssetKind) (imageupload.Rules, bool) {
	switch kind {
	case record.BrandAssetKindLogo:
		return imageupload.BrandLogo(), true
	case record.BrandAssetKindFavicon:
		return imageupload.BrandFavicon(), true
	case record.BrandAssetKindBackground:
		return imageupload.BrandBackground(), true
	}
	return imageupload.Rules{}, false
}

// MaxBytes is the most bytes an upload of kind may hold, which bounds the read of its body, and 0
// for a kind that is none of the four.
func MaxBytes(kind record.BrandAssetKind) int64 {
	if kind == record.BrandAssetKindFont {
		return FontMaxBytes
	}
	if rules, ok := imageRules(kind); ok {
		return rules.MaxBytes()
	}
	return 0
}

// TooLarge is the refusal of an upload of kind past its byte limit, naming the limit: Validate's
// for a file one byte over it, and the handler's for a body cut at the read's bound (#813
// decision 3).
func TooLarge(kind record.BrandAssetKind) error {
	if kind == record.BrandAssetKindFont {
		return i18n.NewLocalizedError(i18n.ErrCodeFontTooLarge, map[string]any{"max": int64(FontMaxBytes)})
	}
	return i18n.NewLocalizedError(i18n.ErrCodeImageTooLarge, map[string]any{"max": MaxBytes(kind)})
}

// Validate accepts an upload of kind its rules allow, and answers the type it was validated as
// and its pixel size, zero for a font. An image kind is held to imageupload's rules for it; a font
// must be a WOFF2 file of at most FontMaxBytes. A refusal is an *i18n.LocalizedError naming the
// check that failed; a kind that is none of the four is a plain error, the caller's fault.
func Validate(kind record.BrandAssetKind, data []byte) (imageupload.Info, error) {
	if kind == record.BrandAssetKindFont {
		return validateFont(data)
	}
	rules, ok := imageRules(kind)
	if !ok {
		return imageupload.Info{}, errs.Errorf("%q is not a kind of brand asset", kind)
	}
	return imageupload.Validate(data, rules)
}

// woff2Signature is the first four bytes of every WOFF2 file, its header's signature field (W3C
// WOFF File Format 2.0).
var woff2Signature = []byte("wOF2")

// validateFont accepts a WOFF2 file of at most FontMaxBytes, told by its signature: the browser
// reads the rest, and a file it cannot read falls back to the next family in the stack.
func validateFont(data []byte) (imageupload.Info, error) {
	if len(data) > FontMaxBytes {
		return imageupload.Info{}, TooLarge(record.BrandAssetKindFont)
	}
	if len(data) == 0 {
		return imageupload.Info{}, i18n.NewLocalizedError(i18n.ErrCodeFontEmpty, nil)
	}
	if !bytes.HasPrefix(data, woff2Signature) {
		return imageupload.Info{}, i18n.NewLocalizedError(i18n.ErrCodeFontUnsupportedType, nil)
	}
	return imageupload.Info{ContentType: "font/woff2"}, nil
}

// Fingerprint is the fingerprint an asset's URL carries in v: the first twelve hex digits of the
// SHA-256 of its bytes, as a static file's and a brand stylesheet's.
func Fingerprint(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:6])
}

// Path is the path asset is served at: Route with its id, and its fingerprint in v, so the path
// changes whenever the bytes do and a browser may keep it for a year.
func Path(asset *record.BrandAsset) string {
	return strings.Replace(Route, "{id}", strconv.FormatInt(asset.Id, 10), 1) + "?v=" + asset.Fingerprint
}

// Slots are the assets a brand's six slots name, each read without its bytes, and nil for an empty
// slot (#813 decision 2). The logo and dark logo hold a logo, the favicon a favicon, the background a
// background, and the two font slots a font.
type Slots struct {
	Logo        *record.BrandAsset
	DarkLogo    *record.BrandAsset
	Favicon     *record.BrandAsset
	Background  *record.BrandAsset
	RegularFont *record.BrandAsset
	BoldFont    *record.BrandAsset
}

// SlotsReader is what reads a brand's slots: assets by their ids, without their bytes.
// data.Database satisfies it.
type SlotsReader interface {
	GetBrandAssetsByIds(ctx context.Context, tx *sql.Tx, assetIds []int64) ([]record.BrandAsset, error)
}

// SlotIds answers the ids of the assets brand's filled slots name, in slot order, each once.
func SlotIds(brand *record.Brand) []int64 {
	var ids []int64
	for _, slot := range slotsOf(brand) {
		if slot.Valid && !slices.Contains(ids, slot.Int64) {
			ids = append(ids, slot.Int64)
		}
	}
	return ids
}

// slotsOf is brand's six slots in slot order: logo, dark logo, favicon, background, regular font and
// bold font.
func slotsOf(brand *record.Brand) [6]sql.NullInt64 {
	return [6]sql.NullInt64{brand.LogoAssetId, brand.DarkLogoAssetId, brand.FaviconAssetId,
		brand.BackgroundAssetId, brand.RegularFontAssetId, brand.BoldFontAssetId}
}

// SlotsOf answers brand's slots from assets, which may hold others' too: a slot whose asset is not
// among them is left empty.
func SlotsOf(brand *record.Brand, assets []record.BrandAsset) Slots {
	find := func(slot sql.NullInt64) *record.BrandAsset {
		if !slot.Valid {
			return nil
		}
		for i := range assets {
			if assets[i].Id == slot.Int64 {
				asset := assets[i]
				return &asset
			}
		}
		return nil
	}
	return Slots{
		Logo:        find(brand.LogoAssetId),
		DarkLogo:    find(brand.DarkLogoAssetId),
		Favicon:     find(brand.FaviconAssetId),
		Background:  find(brand.BackgroundAssetId),
		RegularFont: find(brand.RegularFontAssetId),
		BoldFont:    find(brand.BoldFontAssetId),
	}
}

// ReadSlots reads the assets brand's slots name, without their bytes, and reads nothing when every
// slot is empty, as a brand nobody has given a file is.
func ReadSlots(ctx context.Context, reader SlotsReader, brand *record.Brand) (Slots, error) {
	ids := SlotIds(brand)
	if len(ids) == 0 {
		return Slots{}, nil
	}
	assets, err := reader.GetBrandAssetsByIds(ctx, nil, ids)
	if err != nil {
		return Slots{}, errs.Wrap(err, "unable to read the assets of the brand's slots")
	}
	return SlotsOf(brand, assets), nil
}
