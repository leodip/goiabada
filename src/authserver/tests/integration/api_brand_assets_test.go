package integration

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"image"
	"image/jpeg"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Brand assets end to end (#813 decisions 1, 3, 8 and 10): an upload per kind through the admin API,
// past the request-body table's row for its kind, stored unattached and audited; the asset read by
// its id; and the public route answering its bytes to anyone, cached by its fingerprint, with
// nosniff, and a font granted to the admin console's origin alone.

const brandAssetsPath = "/api/v1/admin/brand-assets/"

// uploadBrandAsset sends data as the "file" field of a multipart upload of kind, and answers the
// response and the request id it carried.
func uploadBrandAsset(t *testing.T, accessToken, kind string, data []byte) (*http.Response, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "asset.bin")
	require.NoError(t, err)
	_, err = part.Write(data)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	req, err := http.NewRequest(http.MethodPost, appConfig.AuthServer.BaseURL+brandAssetsPath+kind, &body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+accessToken)
	requestId := "brand-asset-" + fake.LetterN(16)
	req.Header.Set("X-Request-Id", requestId)
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	return resp, requestId
}

type brandAssetAnswer struct {
	Id          int64  `json:"id"`
	Kind        string `json:"kind"`
	Url         string `json:"url"`
	ContentType string `json:"contentType"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
}

func decodeBrandAsset(t *testing.T, resp *http.Response) brandAssetAnswer {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var answer struct {
		BrandAsset brandAssetAnswer `json:"brandAsset"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&answer))
	return answer.BrandAsset
}

func decodeRefusal(t *testing.T, resp *http.Response) (int, string, string) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		ErrorCode        string `json:"error_code"`
		ErrorDescription string `json:"error_description"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return resp.StatusCode, body.ErrorCode, body.ErrorDescription
}

// brandJPEG is a JPEG of width by height pixels.
func brandJPEG(width, height int) []byte {
	var buf bytes.Buffer
	_ = jpeg.Encode(&buf, image.NewRGBA(image.Rect(0, 0, width, height)), nil)
	return buf.Bytes()
}

// brandAPNG is a PNG with an acTL chunk after its IHDR: an animated PNG.
func brandAPNG(width, height int) []byte {
	png := createTestPNGImage(width, height)
	data := []byte{0, 0, 0, 2, 0, 0, 0, 0}
	var chunk bytes.Buffer
	_ = binary.Write(&chunk, binary.BigEndian, uint32(len(data)))
	chunk.WriteString("acTL")
	chunk.Write(data)
	_ = binary.Write(&chunk, binary.BigEndian, crc32.ChecksumIEEE(append([]byte("acTL"), data...)))
	const afterIHDR = 8 + 25
	return append(append(append([]byte{}, png[:afterIHDR]...), chunk.Bytes()...), png[afterIHDR:]...)
}

func brandWOFF2(size int) []byte {
	return append([]byte("wOF2"), make([]byte, size-4)...)
}

func paddedBytes(data []byte, size int) []byte {
	return append(append([]byte{}, data...), make([]byte, size-len(data))...)
}

// consoleOrigin is the admin console's base URL as a browser sends it in Origin: scheme and host,
// the port included, without the path.
func consoleOrigin(t *testing.T) string {
	t.Helper()
	parsed, err := url.Parse(appConfig.AdminConsole.BaseURL)
	require.NoError(t, err)
	return parsed.Scheme + "://" + parsed.Host
}

func TestAPIBrandAssets_EachKindIsStoredReadAndServed(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	base := appConfig.AuthServer.BaseURL

	tests := []struct {
		kind        string
		data        []byte
		contentType string
		width       int
		height      int
	}{
		{"logo", createTestPNGImage(120, 40), "image/png", 120, 40},
		{"favicon", createTestPNGImage(64, 64), "image/png", 64, 64},
		{"background", brandJPEG(640, 360), "image/jpeg", 640, 360},
		// Exactly the background's 2 MiB: over the admin API's 1 MiB body limit, so it reaches the
		// handler only through the background's own row in the request-body table.
		{"background", paddedBytes(createTestPNGImage(100, 100), 2<<20), "image/png", 100, 100},
		{"font", brandWOFF2(2 << 20), "font/woff2", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.kind+" "+tt.contentType, func(t *testing.T) {
			resp, _ := uploadBrandAsset(t, accessToken, tt.kind, tt.data)
			require.Equal(t, http.StatusCreated, resp.StatusCode)
			uploaded := decodeBrandAsset(t, resp)
			require.Positive(t, uploaded.Id)
			id := strconv.FormatInt(uploaded.Id, 10)
			assert.Equal(t, tt.kind, uploaded.Kind)
			assert.Equal(t, tt.contentType, uploaded.ContentType)
			assert.Equal(t, tt.width, uploaded.Width)
			assert.Equal(t, tt.height, uploaded.Height)
			assert.Regexp(t, `^`+regexp.QuoteMeta(base)+`/brand-assets/`+id+`\?v=[0-9a-f]{12}$`, uploaded.Url)

			stored, err := database.GetBrandAssetById(context.Background(), nil, uploaded.Id)
			require.NoError(t, err)
			require.NotNil(t, stored)
			assert.Equal(t, tt.data, stored.Content)

			// The read by id answers what the upload did.
			resp = makeAPIRequest(t, http.MethodGet, base+brandAssetsPath+id, accessToken, nil)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, uploaded, decodeBrandAsset(t, resp))

			// The public route answers anyone, with no cookie.
			status, body, header := getStylesheet(t, createHttpClient(t), uploaded.Url)
			require.Equal(t, http.StatusOK, status)
			assert.Equal(t, string(tt.data), body)
			assert.Equal(t, tt.contentType, header.Get("Content-Type"))
			assert.Equal(t, "nosniff", header.Get("X-Content-Type-Options"))
			assert.Equal(t, "public, max-age=31536000, immutable", header.Get("Cache-Control"))
			assert.Empty(t, header.Values("Set-Cookie"))
			if tt.kind == "font" {
				assert.Equal(t, []string{consoleOrigin(t)}, header.Values("Access-Control-Allow-Origin"))
			} else {
				assert.Empty(t, header.Values("Access-Control-Allow-Origin"))
			}
			assert.Empty(t, header.Values("Access-Control-Allow-Credentials"))

			// Any other fingerprint is the current bytes, kept five minutes.
			status, body, header = getStylesheet(t, createHttpClient(t), base+"/brand-assets/"+id+"?v=000000000000")
			require.Equal(t, http.StatusOK, status)
			assert.Equal(t, string(tt.data), body)
			assert.Equal(t, "public, max-age=300", header.Get("Cache-Control"))
		})
	}
}

func TestAPIBrandAssets_AFileItsKindDoesNotTakeIsRefused(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	tests := []struct {
		name    string
		kind    string
		data    []byte
		code    string
		english string
	}{
		{"an animated PNG logo", "logo", brandAPNG(100, 100), "validator.image.animated",
			"Animated images are not allowed. Upload a still image."},
		{"a logo over 1 MiB", "logo", paddedBytes(createTestPNGImage(100, 100), 1<<20+1), "validator.image.too_large",
			"The image can be at most 1048576 bytes."},
		{"a favicon that is not square", "favicon", createTestPNGImage(64, 48), "validator.image.not_square",
			"The image must be square. This one is 64x48 pixels."},
		{"a JPEG favicon", "favicon", brandJPEG(64, 64), "validator.image.unsupported_type_png",
			"The image type is not supported. The only allowed type is PNG."},
		// One byte past the background's limit is still read whole and refused for its size by the
		// handler, which the row's multipart allowance leaves room for.
		{"a background over 2 MiB", "background", paddedBytes(createTestPNGImage(100, 100), 2<<20+1), "validator.image.too_large",
			"The image can be at most 2097152 bytes."},
		{"a font that is not WOFF2", "font", createTestPNGImage(20, 20), "validator.font.unsupported_type",
			"The font type is not supported. The only allowed type is WOFF2."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, _ := uploadBrandAsset(t, accessToken, tt.kind, tt.data)
			status, code, english := decodeRefusal(t, resp)

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, tt.code, code)
			assert.Equal(t, tt.english, english)
		})
	}
}

func TestAPIBrandAssets_AnUploadIsAudited(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, caller := createAdminClientWithToken(t)

	resp, requestId := uploadBrandAsset(t, accessToken, "favicon", createTestPNGImage(48, 48))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	uploaded := decodeBrandAsset(t, resp)

	assert.Equal(t, []map[string]any{{"brand_asset_id": float64(uploaded.Id), "kind": "favicon",
		"logged_in_user": caller.ClientIdentifier}},
		auditRows(t, accessToken, "uploaded_brand_asset", requestId))

	// A refused upload records nothing.
	resp, requestId = uploadBrandAsset(t, accessToken, "favicon", createTestPNGImage(48, 60))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Empty(t, auditRows(t, accessToken, "uploaded_brand_asset", requestId))
}

func TestAPIBrandAssets_AccessAndMissingAssets(t *testing.T) {
	base := appConfig.AuthServer.BaseURL

	t.Run("an upload needs a token", func(t *testing.T) {
		resp, _ := uploadBrandAsset(t, "", "logo", createTestPNGImage(20, 20))
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("an upload and a read need the settings scopes", func(t *testing.T) {
		token := createClientCredentialsTokenWithoutRouteScope(t)
		resp, _ := uploadBrandAsset(t, token, "logo", createTestPNGImage(20, 20))
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)

		resp = makeAPIRequest(t, http.MethodGet, base+brandAssetsPath+"1", token, nil)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("an asset that does not exist", func(t *testing.T) {
		accessToken, _ := createAdminClientWithToken(t)
		resp := makeAPIRequest(t, http.MethodGet, base+brandAssetsPath+"999999999", accessToken, nil)
		status, code, _ := decodeRefusal(t, resp)
		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, "NOT_FOUND", code)

		publicResp, err := createHttpClient(t).Get(base + "/brand-assets/999999999")
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, publicResp.Body)
		_ = publicResp.Body.Close()
		assert.Equal(t, http.StatusNotFound, publicResp.StatusCode)
	})
}
