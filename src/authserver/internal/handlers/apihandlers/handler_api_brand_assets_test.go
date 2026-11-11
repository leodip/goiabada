package apihandlers

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The admin API's brand assets (#813 decisions 1, 3 and 10): an upload per kind, held to its kind's
// rules and stored unattached, answering its id and URL; and an asset read by its id.

// sha256Fingerprint is the first twelve hex digits of data's SHA-256, worked out here rather than
// through the code under test.
func sha256Fingerprint(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])[:12]
}

func assetJPEG(width, height int) []byte {
	var buf bytes.Buffer
	_ = jpeg.Encode(&buf, image.NewRGBA(image.Rect(0, 0, width, height)), nil)
	return buf.Bytes()
}

func assetGIF(width, height int) []byte {
	var buf bytes.Buffer
	_ = gif.Encode(&buf, image.NewPaletted(image.Rect(0, 0, width, height), []color.Color{color.Black}), nil)
	return buf.Bytes()
}

// assetAPNG is a PNG with an acTL chunk after its IHDR: an animated PNG.
func assetAPNG(width, height int) []byte {
	png := createTestPNG(width, height)
	data := []byte{0, 0, 0, 2, 0, 0, 0, 0}
	var chunk bytes.Buffer
	_ = binary.Write(&chunk, binary.BigEndian, uint32(len(data)))
	chunk.WriteString("acTL")
	chunk.Write(data)
	_ = binary.Write(&chunk, binary.BigEndian, crc32.ChecksumIEEE(append([]byte("acTL"), data...)))
	const afterIHDR = 8 + 25
	return append(append(append([]byte{}, png[:afterIHDR]...), chunk.Bytes()...), png[afterIHDR:]...)
}

// assetAnimatedWebP is a WebP whose VP8X header sets the animation flag.
func assetAnimatedWebP(width, height int) []byte {
	body := append([]byte("WEBPVP8X\x0a\x00\x00\x00"), 0x02, 0, 0, 0,
		byte(width-1), byte((width-1)>>8), byte((width-1)>>16),
		byte(height-1), byte((height-1)>>8), byte((height-1)>>16))
	size := len(body)
	return append(append([]byte("RIFF"), byte(size), byte(size>>8), byte(size>>16), byte(size>>24)), body...)
}

func assetWOFF2(size int) []byte {
	return append([]byte("wOF2"), make([]byte, size-4)...)
}

func paddedAsset(data []byte, size int) []byte {
	return append(append([]byte{}, data...), make([]byte, size-len(data))...)
}

func brandAssetUpload(t *testing.T, kind string, field string, data []byte, sub string) *http.Request {
	t.Helper()
	req, err := createMultipartRequest(http.MethodPost, "/api/v1/admin/brand-assets/"+kind, field, data)
	require.NoError(t, err)
	return setTokenContextWithClaims(req, map[string]interface{}{"scope": "authserver:manage-settings", "sub": sub})
}

func decodeAssetRefusal(t *testing.T, rr *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), rr.Body.String())
	code, _ := body["error_code"].(string)
	description, _ := body["error_description"].(string)
	return code, description
}

func TestBrandAssetPost_StoresEachKindUnattachedAndAnswersItsURL(t *testing.T) {
	tests := []struct {
		kind        record.BrandAssetKind
		data        []byte
		contentType string
		width       int
		height      int
	}{
		{record.BrandAssetKindLogo, createTestPNG(120, 40), "image/png", 120, 40},
		{record.BrandAssetKindFavicon, createTestPNG(64, 64), "image/png", 64, 64},
		{record.BrandAssetKindBackground, assetJPEG(320, 200), "image/jpeg", 320, 200},
		// A background up to 2 MiB, twice a logo's limit, is the background's to take.
		{record.BrandAssetKindBackground, paddedAsset(createTestPNG(100, 100), 2097152), "image/png", 100, 100},
		{record.BrandAssetKindFont, assetWOFF2(4096), "font/woff2", 0, 0},
	}
	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			handler := HandleBrandAssetPost(database, auditLogger, testBaseURL, tt.kind)

			var stored *record.BrandAsset
			database.On("CreateBrandAsset", mock.Anything, (*sql.Tx)(nil), mock.AnythingOfType("*record.BrandAsset")).
				Run(func(args mock.Arguments) {
					stored = args.Get(2).(*record.BrandAsset)
					stored.Id = 41
				}).Return(nil).Once()
			auditLogger.On("Log", mock.Anything, audit.EventUploadedBrandAsset, map[string]interface{}{
				"brand_asset_id": int64(41),
				"kind":           string(tt.kind),
				"logged_in_user": "admin-sub",
			}).Return().Once()

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, brandAssetUpload(t, string(tt.kind), "file", tt.data, "admin-sub"))

			require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
			require.NotNil(t, stored)
			fingerprint := sha256Fingerprint(tt.data)
			assert.Equal(t, record.BrandAsset{
				Id:          41,
				Kind:        tt.kind,
				ContentType: tt.contentType,
				Fingerprint: fingerprint,
				Width:       tt.width,
				Height:      tt.height,
				Content:     tt.data,
			}, *stored)
			assert.JSONEq(t, `{"brandAsset":{"id":41,"kind":"`+string(tt.kind)+`",`+
				`"url":"https://auth.test/brand-assets/41?v=`+fingerprint+`",`+
				`"contentType":"`+tt.contentType+`","width":`+strconv.Itoa(tt.width)+`,"height":`+strconv.Itoa(tt.height)+`}}`,
				rr.Body.String())
		})
	}
}

// Each refusal is answered at the upload, before anything is stored, with the code of the rule it
// broke and a sentence naming the limit (#813 decision 3). datamocks fails the test on any call, so
// nothing reaches the store.
func TestBrandAssetPost_RefusesAFileItsKindDoesNotTake(t *testing.T) {
	tests := []struct {
		name    string
		kind    record.BrandAssetKind
		data    []byte
		code    string
		english string
	}{
		{"a GIF logo", record.BrandAssetKindLogo, assetGIF(50, 50), "validator.image.unsupported_type_png_jpeg_webp",
			"The image type is not supported. Allowed types are PNG, JPEG and WebP."},
		{"an SVG logo", record.BrandAssetKindLogo, []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`),
			"validator.image.unsupported_type_png_jpeg_webp",
			"The image type is not supported. Allowed types are PNG, JPEG and WebP."},
		{"an animated PNG logo", record.BrandAssetKindLogo, assetAPNG(100, 100), "validator.image.animated",
			"Animated images are not allowed. Upload a still image."},
		{"an animated WebP logo", record.BrandAssetKindLogo, assetAnimatedWebP(100, 100), "validator.image.animated",
			"Animated images are not allowed. Upload a still image."},
		{"a logo one byte over 1 MiB", record.BrandAssetKindLogo, paddedAsset(createTestPNG(100, 100), 1048577),
			"validator.image.too_large", "The image can be at most 1048576 bytes."},
		{"a logo one pixel too wide", record.BrandAssetKindLogo, createTestPNG(513, 100),
			"validator.image.dimensions_too_large", "The image can be at most 512x512 pixels."},
		{"a JPEG favicon", record.BrandAssetKindFavicon, assetJPEG(64, 64), "validator.image.unsupported_type_png",
			"The image type is not supported. The only allowed type is PNG."},
		{"a favicon that is not square", record.BrandAssetKindFavicon, createTestPNG(64, 48), "validator.image.not_square",
			"The image must be square. This one is 64x48 pixels."},
		{"a favicon too small", record.BrandAssetKindFavicon, createTestPNG(47, 47), "validator.image.dimensions_too_small",
			"The image must be at least 48x48 pixels."},
		{"an animated PNG favicon", record.BrandAssetKindFavicon, assetAPNG(64, 64), "validator.image.animated",
			"Animated images are not allowed. Upload a still image."},
		{"an animated WebP background", record.BrandAssetKindBackground, assetAnimatedWebP(1920, 1080), "validator.image.animated",
			"Animated images are not allowed. Upload a still image."},
		{"a background one byte over 2 MiB", record.BrandAssetKindBackground, paddedAsset(createTestPNG(100, 100), 2097153),
			"validator.image.too_large", "The image can be at most 2097152 bytes."},
		{"a font that is not WOFF2", record.BrandAssetKindFont, append([]byte("wOFF"), make([]byte, 60)...),
			"validator.font.unsupported_type", "The font type is not supported. The only allowed type is WOFF2."},
		{"a font one byte over 2 MiB", record.BrandAssetKindFont, assetWOFF2(2097153),
			"validator.font.too_large", "The font can be at most 2097152 bytes."},
		{"an image as a font", record.BrandAssetKindFont, createTestPNG(20, 20),
			"validator.font.unsupported_type", "The font type is not supported. The only allowed type is WOFF2."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := HandleBrandAssetPost(datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t), testBaseURL, tt.kind)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, brandAssetUpload(t, string(tt.kind), "file", tt.data, "admin-sub"))

			require.Equal(t, http.StatusBadRequest, rr.Code)
			code, description := decodeAssetRefusal(t, rr)
			assert.Equal(t, tt.code, code)
			assert.Equal(t, tt.english, description)
		})
	}
}

// The file is the multipart field "file": a request without it is refused, and so is a body that is
// not a multipart form.
func TestBrandAssetPost_RefusesARequestWithoutTheFile(t *testing.T) {
	handler := HandleBrandAssetPost(datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t), testBaseURL, record.BrandAssetKindLogo)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, brandAssetUpload(t, "logo", "picture", createTestPNG(100, 100), "admin-sub"))

	require.Equal(t, http.StatusBadRequest, rr.Code)
	code, description := decodeAssetRefusal(t, rr)
	assert.Equal(t, "NO_FILE", code)
	assert.Equal(t, "No file provided", description)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/brand-assets/logo", strings.NewReader(`{"file":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, setTokenContextWithClaims(req, map[string]interface{}{"scope": "authserver:manage-settings", "sub": "admin-sub"}))

	require.Equal(t, http.StatusBadRequest, rr.Code)
	code, _ = decodeAssetRefusal(t, rr)
	assert.Equal(t, "FILE_TOO_LARGE", code)
}

// A body past the kind's limit and its multipart allowance is cut, never read whole, and still
// refused with the kind's limit, as a file one byte over it is (#813 decision 3).
func TestBrandAssetPost_ABodyPastTheReadBoundIsRefusedWithTheKindsLimit(t *testing.T) {
	tests := []struct {
		kind    record.BrandAssetKind
		data    []byte
		code    string
		english string
	}{
		{record.BrandAssetKindLogo, paddedAsset(createTestPNG(100, 100), 1048576+4096),
			"validator.image.too_large", "The image can be at most 1048576 bytes."},
		{record.BrandAssetKindFavicon, paddedAsset(createTestPNG(64, 64), 1048576+4096),
			"validator.image.too_large", "The image can be at most 1048576 bytes."},
		{record.BrandAssetKindBackground, paddedAsset(createTestPNG(100, 100), 2097152+4096),
			"validator.image.too_large", "The image can be at most 2097152 bytes."},
		{record.BrandAssetKindFont, assetWOFF2(2097152 + 4096),
			"validator.font.too_large", "The font can be at most 2097152 bytes."},
	}
	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			handler := HandleBrandAssetPost(datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t), testBaseURL, tt.kind)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, brandAssetUpload(t, string(tt.kind), "file", tt.data, "admin-sub"))

			require.Equal(t, http.StatusBadRequest, rr.Code)
			code, description := decodeAssetRefusal(t, rr)
			assert.Equal(t, tt.code, code)
			assert.Equal(t, tt.english, description)
		})
	}
}

func TestBrandAssetPost_AStoreThatFailsIsA500AndNotAudited(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := HandleBrandAssetPost(database, handlersmocks.NewAuditLogger(t), testBaseURL, record.BrandAssetKindLogo)
	database.On("CreateBrandAsset", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(errors.New("disk full")).Once()

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, brandAssetUpload(t, "logo", "file", createTestPNG(100, 100), "admin-sub"))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestBrandAssetGet_AnswersTheAssetWithoutItsBytes(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetBrandAssetsByIds", mock.Anything, (*sql.Tx)(nil), []int64{9}).Return([]record.BrandAsset{{
		Id: 9, Kind: record.BrandAssetKindFavicon, ContentType: "image/png", Fingerprint: "a1b2c3d4e5f6", Width: 96, Height: 96,
	}}, nil).Once()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/brand-assets/9", nil)
	req.SetPathValue("id", "9")
	rr := httptest.NewRecorder()
	HandleBrandAssetGet(database, testBaseURL).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, `{"brandAsset":{"id":9,"kind":"favicon","url":"https://auth.test/brand-assets/9?v=a1b2c3d4e5f6",`+
		`"contentType":"image/png","width":96,"height":96}}`, rr.Body.String())
}

func TestBrandAssetGet_Refusals(t *testing.T) {
	t.Run("no such asset", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandAssetsByIds", mock.Anything, (*sql.Tx)(nil), []int64{404}).Return(nil, nil).Once()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/brand-assets/404", nil)
		req.SetPathValue("id", "404")
		rr := httptest.NewRecorder()
		HandleBrandAssetGet(database, testBaseURL).ServeHTTP(rr, req)

		require.Equal(t, http.StatusNotFound, rr.Code)
		code, description := decodeAssetRefusal(t, rr)
		assert.Equal(t, "NOT_FOUND", code)
		assert.Equal(t, "Brand asset not found", description)
	})

	for _, id := range []string{"abc", "0", "-3"} {
		t.Run("the id "+id, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/brand-assets/"+id, nil)
			req.SetPathValue("id", id)
			rr := httptest.NewRecorder()
			HandleBrandAssetGet(datamocks.NewDatabase(t), testBaseURL).ServeHTTP(rr, req)

			require.Equal(t, http.StatusBadRequest, rr.Code)
			code, description := decodeAssetRefusal(t, rr)
			assert.Equal(t, "VALIDATION_ERROR", code)
			assert.Equal(t, "Invalid brand asset ID", description)
		})
	}

	t.Run("a read that fails", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandAssetsByIds", mock.Anything, (*sql.Tx)(nil), []int64{9}).Return(nil, errors.New("gone")).Once()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/brand-assets/9", nil)
		req.SetPathValue("id", "9")
		rr := httptest.NewRecorder()
		HandleBrandAssetGet(database, testBaseURL).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}
