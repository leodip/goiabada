package apihandlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// A brand's six slots in the admin API (#813 decisions 5, 7 and 10): a create and an update name the
// asset each slot holds by its id, each held to its slot's kind, and every brand answer carries each
// filled slot's asset.

// brandBaseURL is the auth server's base URL in these tests, the one an asset's URL is built from.
const brandBaseURL = "https://auth.example.test"

// brandLibrary is every stored asset these tests know, read without its bytes: 11 to 16 fill
// storedKitBrand's slots in slot order, and 21 to 24 are one asset of each kind, attached to none.
var brandLibrary = []record.BrandAsset{
	{Id: 11, Kind: record.BrandAssetKindLogo, ContentType: "image/png", Fingerprint: "11aaaaaaaaaa", Width: 240, Height: 80},
	{Id: 12, Kind: record.BrandAssetKindLogo, ContentType: "image/webp", Fingerprint: "12aaaaaaaaaa", Width: 240, Height: 80},
	{Id: 13, Kind: record.BrandAssetKindFavicon, ContentType: "image/png", Fingerprint: "13aaaaaaaaaa", Width: 64, Height: 64},
	{Id: 14, Kind: record.BrandAssetKindBackground, ContentType: "image/jpeg", Fingerprint: "14aaaaaaaaaa", Width: 1920, Height: 1080},
	{Id: 15, Kind: record.BrandAssetKindFont, ContentType: "font/woff2", Fingerprint: "15aaaaaaaaaa"},
	{Id: 16, Kind: record.BrandAssetKindFont, ContentType: "font/woff2", Fingerprint: "16aaaaaaaaaa"},
	{Id: 21, Kind: record.BrandAssetKindLogo, ContentType: "image/png", Fingerprint: "21aaaaaaaaaa", Width: 100, Height: 100},
	{Id: 22, Kind: record.BrandAssetKindFavicon, ContentType: "image/png", Fingerprint: "22aaaaaaaaaa", Width: 48, Height: 48},
	{Id: 23, Kind: record.BrandAssetKindBackground, ContentType: "image/webp", Fingerprint: "23aaaaaaaaaa", Width: 800, Height: 600},
	{Id: 24, Kind: record.BrandAssetKindFont, ContentType: "font/woff2", Fingerprint: "24aaaaaaaaaa"},
}

// expectBrandAssets has database answer, for any ids, the assets of brandLibrary they name, as the
// data layer answers them: without their bytes, an id naming none left out.
func expectBrandAssets(database *datamocks.Database) *mock.Call {
	return database.On("GetBrandAssetsByIds", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(
		func(_ context.Context, _ *sql.Tx, ids []int64) ([]record.BrandAsset, error) {
			var found []record.BrandAsset
			for _, asset := range brandLibrary {
				if slices.Contains(ids, asset.Id) {
					found = append(found, asset)
				}
			}
			return found, nil
		})
}

// assetAnswer is a slot's answer for the asset of id in brandLibrary: its id, kind, absolute URL with
// its fingerprint, type and pixel size, written out by hand.
func assetAnswer(id int64) map[string]any {
	for _, asset := range brandLibrary {
		if asset.Id == id {
			return map[string]any{
				"id": float64(id), "kind": string(asset.Kind),
				"url":         fmt.Sprintf("https://auth.example.test/brand-assets/%d?v=%s", id, asset.Fingerprint),
				"contentType": asset.ContentType, "width": float64(asset.Width), "height": float64(asset.Height),
			}
		}
	}
	panic(fmt.Sprintf("no asset %d", id))
}

// brandSlotRefusals are the refusals of a write's slots, each at its field: a slot naming no stored
// asset of its kind, an asset since swept being none, and the rules between slots.
var brandSlotRefusals = []struct {
	name string
	edit func(body map[string]any)
	code string
}{
	{"a logo naming no asset", func(b map[string]any) { b["logo"] = map[string]any{"id": 99} }, "handler.brand.logo_asset_invalid"},
	{"a logo naming the id 0", func(b map[string]any) { b["logo"] = map[string]any{"id": 0} }, "handler.brand.logo_asset_invalid"},
	{"a logo with no id", func(b map[string]any) { b["logo"] = map[string]any{} }, "handler.brand.logo_asset_invalid"},
	{"a logo naming a favicon", func(b map[string]any) { b["logo"] = map[string]any{"id": 22} }, "handler.brand.logo_asset_invalid"},
	{"a dark logo naming a background", func(b map[string]any) {
		b["logo"] = map[string]any{"id": 21}
		b["darkLogo"] = map[string]any{"id": 23}
	}, "handler.brand.dark_logo_asset_invalid"},
	{"a dark logo naming no asset", func(b map[string]any) {
		b["logo"] = map[string]any{"id": 21}
		b["darkLogo"] = map[string]any{"id": 98}
	}, "handler.brand.dark_logo_asset_invalid"},
	{"a favicon naming a logo", func(b map[string]any) { b["favicon"] = map[string]any{"id": 21} }, "handler.brand.favicon_asset_invalid"},
	{"a background naming a font", func(b map[string]any) { b["background"] = map[string]any{"id": 24} }, "handler.brand.background_asset_invalid"},
	{"a regular font naming a logo", func(b map[string]any) { b["regularFont"] = map[string]any{"id": 21} }, "handler.brand.regular_font_asset_invalid"},
	{"a bold font naming a background", func(b map[string]any) {
		b["regularFont"] = map[string]any{"id": 24}
		b["boldFont"] = map[string]any{"id": 23}
	}, "handler.brand.bold_font_asset_invalid"},
	// A dark logo is drawn in place of the logo, so it is refused without one (#813 decision 5).
	{"a dark logo without a logo", func(b map[string]any) { b["darkLogo"] = map[string]any{"id": 21} }, "handler.brand.dark_logo_logo_required"},
	{"a dark logo beside a null logo", func(b map[string]any) {
		b["logo"] = nil
		b["darkLogo"] = map[string]any{"id": 21}
	}, "handler.brand.dark_logo_logo_required"},
	// The bold file draws the heavier weights beside the regular one (#813 decision 7).
	{"a bold font without a regular one", func(b map[string]any) { b["boldFont"] = map[string]any{"id": 24} }, "handler.brand.bold_font_regular_required"},
	{"the uploaded font without a font file", func(b map[string]any) { b["font"] = "uploaded" }, "handler.brand.uploaded_font_regular_required"},
}

func TestBrandCreate_SlotRefusals(t *testing.T) {
	for _, c := range brandSlotRefusals {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			expectBrandAssets(database).Maybe()
			body := validBrandBody()
			c.edit(body)

			status, answer := serveBrand(HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
				brandRequest(t, http.MethodPost, body))

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, errorCode(answer))
			database.AssertNotCalled(t, "CreateBrand", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestBrandUpdate_SlotRefusals(t *testing.T) {
	for _, c := range brandSlotRefusals {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(4)).Return(storedKitBrand(), nil).Once()
			expectBrandAssets(database).Maybe()
			body := validBrandBody()
			c.edit(body)

			status, answer := serveBrand(HandleBrandUpdatePut(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
				brandRequest(t, http.MethodPut, body, "id", "4"))

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, errorCode(answer))
			database.AssertNotCalled(t, "UpdateBrand", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A create stores the asset each slot names, and answers each with its id, kind, URL, type and pixel
// size. The uploaded font is taken once a regular font file is named, and a dark logo beside a logo.
func TestBrandCreate_StoresEachSlotAndAnswersItsAsset(t *testing.T) {
	database := datamocks.NewDatabase(t)
	expectBrandAssets(database)
	var stored record.Brand
	database.On("CreateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
		brand := args.Get(2).(*record.Brand)
		stored = *brand
		brand.Id = 7
	}).Return(nil).Once()
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, mock.Anything).Once()
	body := validBrandBody()
	body["font"] = "uploaded"
	body["hideAppName"] = true
	for slot, id := range map[string]int64{"logo": 11, "darkLogo": 12, "favicon": 13, "background": 14, "regularFont": 15, "boldFont": 16} {
		body[slot] = map[string]any{"id": id}
	}

	status, answer := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL), brandRequest(t, http.MethodPost, body))

	require.Equal(t, http.StatusCreated, status, "%v", answer)
	assert.Equal(t, []sql.NullInt64{{Int64: 11, Valid: true}, {Int64: 12, Valid: true}, {Int64: 13, Valid: true},
		{Int64: 14, Valid: true}, {Int64: 15, Valid: true}, {Int64: 16, Valid: true}},
		[]sql.NullInt64{stored.LogoAssetId, stored.DarkLogoAssetId, stored.FaviconAssetId,
			stored.BackgroundAssetId, stored.RegularFontAssetId, stored.BoldFontAssetId})
	assert.Equal(t, record.BrandFontUploaded, stored.Font)
	assert.Equal(t, assetAnswer(11), brandAt(answer, "brand", "logo"))
	assert.Equal(t, assetAnswer(12), brandAt(answer, "brand", "darkLogo"))
	assert.Equal(t, assetAnswer(13), brandAt(answer, "brand", "favicon"))
	assert.Equal(t, assetAnswer(14), brandAt(answer, "brand", "background"))
	assert.Equal(t, assetAnswer(15), brandAt(answer, "brand", "regularFont"))
	assert.Equal(t, assetAnswer(16), brandAt(answer, "brand", "boldFont"))
}

// The two logo slots may name one asset, and so may the two font slots: each is of its slot's kind.
// Font files stay attached while a system family is chosen (#813 decision 7).
func TestBrandCreate_OneAssetMayFillTwoSlotsOfItsKind(t *testing.T) {
	database := datamocks.NewDatabase(t)
	expectBrandAssets(database)
	var stored record.Brand
	database.On("CreateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
		stored = *args.Get(2).(*record.Brand)
	}).Return(nil).Once()
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, mock.Anything).Once()
	body := validBrandBody()
	body["logo"] = map[string]any{"id": 21}
	body["darkLogo"] = map[string]any{"id": 21}
	body["regularFont"] = map[string]any{"id": 24}
	body["boldFont"] = map[string]any{"id": 24}

	status, answer := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL), brandRequest(t, http.MethodPost, body))

	require.Equal(t, http.StatusCreated, status, "%v", answer)
	assert.Equal(t, int64(21), stored.DarkLogoAssetId.Int64)
	assert.Equal(t, int64(24), stored.BoldFontAssetId.Int64)
	assert.Equal(t, record.BrandFont("serif"), stored.Font)
	assert.Equal(t, assetAnswer(21), brandAt(answer, "brand", "darkLogo"))
}

// A read answers each filled slot's asset, and the list reads every brand's assets at once.
func TestBrandReads_AnswerEachFilledSlot(t *testing.T) {
	t.Run("one brand", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(4)).Return(storedKitBrand(), nil).Once()
		expectBrandAssets(database).Once()
		database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
			Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
		database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Once()

		status, body := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "4"))

		require.Equal(t, http.StatusOK, status)
		for slot, id := range map[string]int64{"logo": 11, "darkLogo": 12, "favicon": 13, "background": 14, "regularFont": 15, "boldFont": 16} {
			assert.Equal(t, assetAnswer(id), brandAt(body, "brand", slot), slot)
		}
	})
	t.Run("the list", func(t *testing.T) {
		other := storedBrand(5, "Zest", record.BrandAppearanceLight, "tangerine")
		other.FaviconAssetId = sql.NullInt64{Int64: 22, Valid: true}
		database := datamocks.NewDatabase(t)
		database.On("GetAllBrands", mock.Anything, (*sql.Tx)(nil)).Return([]record.Brand{
			*storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), *storedKitBrand(), *other,
		}, nil).Once()
		expectBrandAssets(database).Once()
		database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
			Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
		database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Once()

		status, body := serveBrand(HandleBrandsGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil))

		require.Equal(t, http.StatusOK, status)
		brands, _ := body["brands"].([]any)
		require.Len(t, brands, 3)
		assert.Equal(t, assetAnswer(11), brandAt(brands[0], "logo"), "Acme")
		assert.Nil(t, brandAt(brands[1], "logo"), "Default")
		assert.Equal(t, assetAnswer(22), brandAt(brands[2], "favicon"), "Zest")
		assert.Nil(t, brandAt(brands[2], "logo"), "Zest")
	})
	t.Run("assets that cannot be read fail the answer", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(4)).Return(storedKitBrand(), nil).Once()
		database.On("GetBrandAssetsByIds", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil, errs.New("connection reset")).Once()
		database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
			Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Maybe()
		database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Maybe()

		status, body := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "4"))

		assert.Equal(t, http.StatusInternalServerError, status)
		assert.Nil(t, body["brand"])
	})
}

// Making a brand with files the default answers its slots, read in the transaction that moves the
// pointer: a read that fails rolls the move back and records nothing, rather than answer an error
// for a default that did change.
func TestBrandMakeDefault_ReadsTheSlotsInItsTransaction(t *testing.T) {
	expectMove := func(database *datamocks.Database) {
		database.On("MakeBrandDefault", mock.Anything, brandTx, int64(4)).Return(int64(1), nil).Once()
		database.On("GetBrandById", mock.Anything, brandTx, int64(4)).Return(storedKitBrand(), nil).Once()
		database.On("GetBrandById", mock.Anything, brandTx, int64(1)).
			Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
	}
	t.Run("the slots answered", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		datamocks.ExpectRunInTransaction(database, brandTx)
		expectMove(database)
		database.On("GetBrandAssetsByIds", mock.Anything, brandTx, []int64{11, 12, 13, 14, 15, 16}).
			Return(brandLibrary[:6], nil).Once()
		database.On("CountClientsPerBrand", mock.Anything, brandTx).Return(map[int64]int{4: 2}, nil).Once()
		auditLogger := handlersmocks.NewAuditLogger(t)
		auditLogger.On("Log", mock.Anything, audit.EventUpdatedDefaultBrand, mock.Anything).Once()

		status, body := serveBrand(HandleBrandMakeDefaultPost(database, auditLogger, brandBaseURL),
			brandRequest(t, http.MethodPost, nil, "id", "4"))

		require.Equal(t, http.StatusOK, status)
		for slot, id := range map[string]int64{"logo": 11, "darkLogo": 12, "favicon": 13, "background": 14, "regularFont": 15, "boldFont": 16} {
			assert.Equal(t, assetAnswer(id), brandAt(body, "brand", slot), slot)
		}
	})
	t.Run("a read that fails rolls the move back", func(t *testing.T) {
		var steps []string
		database := datamocks.NewDatabase(t)
		datamocks.ExpectRunInTransaction(database, brandTx, func(step string) { steps = append(steps, step) })
		expectMove(database)
		database.On("GetBrandAssetsByIds", mock.Anything, brandTx, mock.Anything).Return(nil, errs.New("connection reset")).Once()

		status, body := serveBrand(HandleBrandMakeDefaultPost(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
			brandRequest(t, http.MethodPost, nil, "id", "4"))

		assert.Equal(t, http.StatusInternalServerError, status)
		assert.Nil(t, body["brand"])
		assert.Equal(t, []string{"begin", "rollback"}, steps)
	})
}

// A brand with no slot filled reads no asset: the answers of a brand nobody has given a file cost
// what they did before the kit.
func TestBrandReads_ABrandWithoutFilesReadsNoAsset(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).
		Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Once()
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).Return(nil, nil).Once()
	database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Once()

	status, _ := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "3"))

	assert.Equal(t, http.StatusOK, status)
	database.AssertNotCalled(t, "GetBrandAssetsByIds", mock.Anything, mock.Anything, mock.Anything)
}

// A brand write checks its slots' assets before it writes, and the sweep may delete an old,
// unattached one in between: the engine then refuses the write on the slot's foreign key. That
// write is refused at the slot whose asset is gone, as an id naming no asset is (#813 decision 10),
// and a write that fails while every slot's asset is still stored stays a server error.
func TestBrandWrites_AnAssetSweptBeforeTheWriteIsRefusedAtItsSlot(t *testing.T) {
	foreignKey := errs.New("FOREIGN KEY constraint failed")
	logo := []record.BrandAsset{{Id: 21, Kind: record.BrandAssetKindLogo, ContentType: "image/png", Fingerprint: "21aaaaaaaaaa", Width: 100, Height: 100}}

	tests := []struct {
		name       string
		afterWrite []record.BrandAsset // what a read of the slots' assets answers after the failed write
		readErr    error
		status     int
		code       string
	}{
		{"the logo was swept", nil, nil, http.StatusBadRequest, "handler.brand.logo_asset_invalid"},
		{"the logo is still stored", logo, nil, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR"},
		{"the second read fails", nil, errs.New("connection reset"), http.StatusInternalServerError, "INTERNAL_SERVER_ERROR"},
	}
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		for _, tc := range tests {
			t.Run(method+" "+tc.name, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				database.On("GetBrandAssetsByIds", mock.Anything, (*sql.Tx)(nil), []int64{21}).Return(logo, nil).Once()
				database.On("GetBrandAssetsByIds", mock.Anything, (*sql.Tx)(nil), []int64{21}).Return(tc.afterWrite, tc.readErr).Once()
				body := validBrandBody()
				body["logo"] = map[string]any{"id": 21}

				var handler http.HandlerFunc
				var req *http.Request
				if method == http.MethodPost {
					database.On("CreateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(foreignKey).Once()
					handler = HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t), brandBaseURL)
					req = brandRequest(t, method, body)
				} else {
					database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(4)).Return(storedKitBrand(), nil).Once()
					database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(foreignKey).Once()
					handler = HandleBrandUpdatePut(database, handlersmocks.NewAuditLogger(t), brandBaseURL)
					req = brandRequest(t, method, body, "id", "4")
				}

				status, answer := serveBrand(handler, req)

				assert.Equal(t, tc.status, status, "%v", answer)
				assert.Equal(t, tc.code, errorCode(answer))
			})
		}
	}
}
