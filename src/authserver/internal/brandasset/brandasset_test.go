package brandasset

import (
	"bytes"
	"context"
	"database/sql"
	"image"
	"image/png"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/imageupload"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam: the rules each kind of brand asset is held to (#813 decision 3), the fingerprint of an
// asset's bytes and the path it is served at (decision 2).

func testPNG(width, height int) []byte {
	var buf bytes.Buffer
	_ = png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, width, height)))
	return buf.Bytes()
}

// woff2 is a WOFF2 file's signature followed by filler, size bytes in all: the signature is all
// the validator reads.
func woff2(size int) []byte {
	return append([]byte("wOF2"), make([]byte, size-4)...)
}

func TestMaxBytes_EachKindsLimit(t *testing.T) {
	assert.Equal(t, int64(1048576), MaxBytes(record.BrandAssetKindLogo))
	assert.Equal(t, int64(1048576), MaxBytes(record.BrandAssetKindFavicon))
	assert.Equal(t, int64(2097152), MaxBytes(record.BrandAssetKindBackground))
	assert.Equal(t, int64(2097152), MaxBytes(record.BrandAssetKindFont))
	assert.Zero(t, MaxBytes(record.BrandAssetKind("icon")))
}

func TestValidate_AFontIsAWOFF2FileUpTo2MiB(t *testing.T) {
	for _, size := range []int{48, 2097152} {
		info, err := Validate(record.BrandAssetKindFont, woff2(size))

		require.NoError(t, err)
		assert.Equal(t, imageupload.Info{ContentType: "font/woff2"}, info, "a font has no pixel size")
	}
}

func TestValidate_RefusesAFont(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		code    string
		args    map[string]any
		english string
	}{
		{"one byte over 2 MiB", woff2(2097153), i18n.ErrCodeFontTooLarge, map[string]any{"max": int64(2097152)},
			"The font can be at most 2097152 bytes."},
		{"an empty file", []byte{}, i18n.ErrCodeFontEmpty, nil, "The font file is empty."},
		{"a WOFF 1.0 file", append([]byte("wOFF"), make([]byte, 60)...), i18n.ErrCodeFontUnsupportedType, nil,
			"The font type is not supported. The only allowed type is WOFF2."},
		{"a TrueType file", append([]byte{0x00, 0x01, 0x00, 0x00}, make([]byte, 60)...), i18n.ErrCodeFontUnsupportedType, nil,
			"The font type is not supported. The only allowed type is WOFF2."},
		{"an OpenType file", append([]byte("OTTO"), make([]byte, 60)...), i18n.ErrCodeFontUnsupportedType, nil,
			"The font type is not supported. The only allowed type is WOFF2."},
		{"an image", testPNG(20, 20), i18n.ErrCodeFontUnsupportedType, nil,
			"The font type is not supported. The only allowed type is WOFF2."},
		{"the signature cut short", []byte("wOF"), i18n.ErrCodeFontUnsupportedType, nil,
			"The font type is not supported. The only allowed type is WOFF2."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := Validate(record.BrandAssetKindFont, tt.data)

			assert.Equal(t, imageupload.Info{}, info)
			var localized *i18n.LocalizedError
			require.ErrorAs(t, err, &localized)
			assert.Equal(t, tt.code, localized.Code)
			assert.Equal(t, tt.args, localized.Args)
			assert.Equal(t, tt.english, localized.Localize(context.Background()))
		})
	}
}

// An image kind is held to its own rules: what one takes, another may refuse.
func TestValidate_EachImageKindToItsOwnRules(t *testing.T) {
	wide := testPNG(200, 50)

	info, err := Validate(record.BrandAssetKindLogo, wide)
	require.NoError(t, err)
	assert.Equal(t, imageupload.Info{ContentType: "image/png", Width: 200, Height: 50}, info)

	info, err = Validate(record.BrandAssetKindBackground, wide)
	require.NoError(t, err)
	assert.Equal(t, imageupload.Info{ContentType: "image/png", Width: 200, Height: 50}, info)

	_, err = Validate(record.BrandAssetKindFavicon, wide)
	var localized *i18n.LocalizedError
	require.ErrorAs(t, err, &localized)
	assert.Equal(t, i18n.ErrCodeImageNotSquare, localized.Code)

	// A font is not an image, and an image kind does not take one.
	_, err = Validate(record.BrandAssetKindLogo, woff2(64))
	require.ErrorAs(t, err, &localized)
	assert.Equal(t, i18n.ErrCodeImageUnsupportedTypePngJpegWebp, localized.Code)
}

func TestValidate_AnUnknownKindIsAnError(t *testing.T) {
	_, err := Validate(record.BrandAssetKind("icon"), testPNG(20, 20))

	require.Error(t, err)
	var localized *i18n.LocalizedError
	assert.NotErrorAs(t, err, &localized, "an unknown kind is the caller's fault, not a refusal")
}

// The fingerprint is the first twelve hex digits of the bytes' SHA-256, as a static file's and a
// brand stylesheet's: SHA-256("abc") is ba7816bf8f01cfea….
func TestFingerprint_TheFirstTwelveHexDigitsOfTheSHA256(t *testing.T) {
	assert.Equal(t, "ba7816bf8f01", Fingerprint([]byte("abc")))
	assert.Equal(t, "e3b0c44298fc", Fingerprint(nil))
}

func TestPath_NamesTheAssetByIdAndItsFingerprint(t *testing.T) {
	asset := &record.BrandAsset{Id: 7, Fingerprint: "0123456789ab"}

	assert.Equal(t, "/brand-assets/7?v=0123456789ab", Path(asset))
}

// slotsBrand is a brand whose six slots name the assets 11 to 16, in slot order.
func slotsBrand() *record.Brand {
	brand := record.NewBrand("Acme", record.BrandAppearanceAuto, "blueberry")
	for i, slot := range []*sql.NullInt64{&brand.LogoAssetId, &brand.DarkLogoAssetId, &brand.FaviconAssetId,
		&brand.BackgroundAssetId, &brand.RegularFontAssetId, &brand.BoldFontAssetId} {
		*slot = sql.NullInt64{Int64: int64(11 + i), Valid: true}
	}
	return &brand
}

func TestSlotIds_TheFilledSlotsInSlotOrder(t *testing.T) {
	assert.Equal(t, []int64{11, 12, 13, 14, 15, 16}, SlotIds(slotsBrand()))

	brand := slotsBrand()
	brand.LogoAssetId, brand.FaviconAssetId, brand.BoldFontAssetId = sql.NullInt64{}, sql.NullInt64{}, sql.NullInt64{}
	assert.Equal(t, []int64{12, 14, 15}, SlotIds(brand))

	empty := record.NewBrand("Acme", record.BrandAppearanceAuto, "blueberry")
	assert.Empty(t, SlotIds(&empty))

	// An asset two slots name, as the two logo slots may, is read once.
	brand = slotsBrand()
	brand.DarkLogoAssetId = brand.LogoAssetId
	assert.Equal(t, []int64{11, 13, 14, 15, 16}, SlotIds(brand))
}

func TestSlotsOf_EachSlotTakesTheAssetItNames(t *testing.T) {
	assets := []record.BrandAsset{{Id: 16}, {Id: 99}, {Id: 14}, {Id: 13}, {Id: 12}, {Id: 11}, {Id: 15}}

	slots := SlotsOf(slotsBrand(), assets)

	got := []*record.BrandAsset{slots.Logo, slots.DarkLogo, slots.Favicon, slots.Background, slots.RegularFont, slots.BoldFont}
	for i, asset := range got {
		require.NotNil(t, asset, "slot %d", i)
		assert.Equal(t, int64(11+i), asset.Id, "slot %d", i)
	}

	// An empty slot stays empty whatever is read, and so does one whose asset was not.
	brand := slotsBrand()
	brand.FaviconAssetId = sql.NullInt64{}
	slots = SlotsOf(brand, []record.BrandAsset{{Id: 11}, {Id: 13}})
	assert.Equal(t, int64(11), slots.Logo.Id)
	assert.Nil(t, slots.DarkLogo)
	assert.Nil(t, slots.Favicon)
	assert.Nil(t, slots.Background)
}

// assetsStub answers the assets of the ids it is asked for among its own, and records each read and
// the transaction it was made in.
type assetsStub struct {
	assets []record.BrandAsset
	err    error
	asked  [][]int64
	txs    []*sql.Tx
}

func (s *assetsStub) GetBrandAssetsByIds(_ context.Context, tx *sql.Tx, ids []int64) ([]record.BrandAsset, error) {
	s.asked = append(s.asked, ids)
	s.txs = append(s.txs, tx)
	return s.assets, s.err
}

func TestReadSlots_ReadsTheFilledSlotsOnceAndNothingForAnEmptyBrand(t *testing.T) {
	reader := &assetsStub{assets: []record.BrandAsset{{Id: 12, Kind: record.BrandAssetKindLogo, Fingerprint: "abcdefabcdef"}}}
	brand := record.NewBrand("Acme", record.BrandAppearanceAuto, "blueberry")
	brand.DarkLogoAssetId = sql.NullInt64{Int64: 12, Valid: true}
	tx := &sql.Tx{}

	slots, err := ReadSlots(context.Background(), reader, tx, &brand)

	require.NoError(t, err)
	assert.Equal(t, [][]int64{{12}}, reader.asked)
	assert.Same(t, tx, reader.txs[0], "the read is made in the caller's transaction")
	require.NotNil(t, slots.DarkLogo)
	assert.Equal(t, "abcdefabcdef", slots.DarkLogo.Fingerprint)

	empty := record.NewBrand("Acme", record.BrandAppearanceAuto, "blueberry")
	none := &assetsStub{}
	slots, err = ReadSlots(context.Background(), none, nil, &empty)
	require.NoError(t, err)
	assert.Equal(t, Slots{}, slots)
	assert.Empty(t, none.asked, "a brand with every slot empty reads no asset")

	failing := &assetsStub{err: errs.New("connection reset")}
	_, err = ReadSlots(context.Background(), failing, nil, slotsBrand())
	assert.ErrorContains(t, err, "connection reset")
}
