package integrationtests

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// createTestClientForLogo creates a client for logo tests
func createTestClientForLogo(t *testing.T) *models.Client {
	t.Helper()
	ident := "test-logo-" + strings.ToLower(gofakeit.LetterN(10))
	client := &models.Client{
		ClientIdentifier: ident,
		Description:      "Test client for logo tests",
		Enabled:          true,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)
	return client
}

// ============================================================================
// Admin Client Logo API Tests
// ============================================================================

func TestAPIClientLogoGet_NoPicture(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createTestClientForLogo(t)

	url := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, client.Id)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.False(t, response["hasLogo"].(bool))
	assert.Nil(t, response["logoUrl"])
}

func TestAPIClientLogoGet_ClientNotFound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, 99999999)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIClientLogoGet_InvalidClientId(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := fmt.Sprintf("%s/api/v1/admin/clients/invalid/logo", config.GetAuthServer().BaseURL)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIClientLogoGet_Unauthorized(t *testing.T) {
	url := fmt.Sprintf("%s/api/v1/admin/clients/1/logo", config.GetAuthServer().BaseURL)

	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIClientLogoGet_InsufficientScope(t *testing.T) {
	client := createTestClientForLogo(t)

	url := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, client.Id)
	tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	resp := makeAPIRequest(t, "GET", url, tok, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestAPIClientLogoPost_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createTestClientForLogo(t)

	url := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, client.Id)
	logoData := createTestPNGImage(100, 100)
	resp := makeMultipartRequest(t, "POST", url, accessToken, "picture", logoData, "logo.png")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))
	assert.Contains(t, response["pictureUrl"].(string), client.ClientIdentifier)

	// Verify the logo was saved
	getResp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = getResp.Body.Close() }()

	var getResponse map[string]interface{}
	err = json.NewDecoder(getResp.Body).Decode(&getResponse)
	assert.NoError(t, err)
	assert.True(t, getResponse["hasLogo"].(bool))
	assert.NotNil(t, getResponse["logoUrl"])
}

func TestAPIClientLogoPost_UpdateExisting(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createTestClientForLogo(t)

	url := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, client.Id)

	// Upload first logo
	logoData1 := createTestPNGImage(100, 100)
	resp1 := makeMultipartRequest(t, "POST", url, accessToken, "picture", logoData1, "logo1.png")
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	// Upload second logo (update)
	logoData2 := createTestPNGImage(200, 200)
	resp2 := makeMultipartRequest(t, "POST", url, accessToken, "picture", logoData2, "logo2.png")
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp2.Body).Decode(&response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))
}

func TestAPIClientLogoPost_ClientNotFound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, 99999999)
	logoData := createTestPNGImage(100, 100)
	resp := makeMultipartRequest(t, "POST", url, accessToken, "picture", logoData, "logo.png")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIClientLogoPost_InvalidImage(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createTestClientForLogo(t)

	url := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, client.Id)
	invalidData := []byte("not a valid image")
	resp := makeMultipartRequest(t, "POST", url, accessToken, "picture", invalidData, "invalid.png")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	errObj := response["error"].(map[string]interface{})
	assert.Equal(t, "INVALID_IMAGE", errObj["code"])
}

func TestAPIClientLogoPost_Unauthorized(t *testing.T) {
	url := fmt.Sprintf("%s/api/v1/admin/clients/1/logo", config.GetAuthServer().BaseURL)
	logoData := createTestPNGImage(100, 100)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormFile("picture", "logo.png")
	_, _ = io.Copy(part, bytes.NewReader(logoData))
	_ = writer.Close()

	req, err := http.NewRequest("POST", url, &body)
	assert.NoError(t, err)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIClientLogoDelete_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createTestClientForLogo(t)

	url := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, client.Id)

	// First upload a logo
	logoData := createTestPNGImage(100, 100)
	uploadResp := makeMultipartRequest(t, "POST", url, accessToken, "picture", logoData, "logo.png")
	defer func() { _ = uploadResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, uploadResp.StatusCode)

	// Verify it exists
	getResp1 := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = getResp1.Body.Close() }()
	var getResponse1 map[string]interface{}
	_ = json.NewDecoder(getResp1.Body).Decode(&getResponse1)
	assert.True(t, getResponse1["hasLogo"].(bool))

	// Delete it
	deleteResp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = deleteResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, deleteResp.StatusCode)

	var deleteResponse map[string]interface{}
	err := json.NewDecoder(deleteResp.Body).Decode(&deleteResponse)
	assert.NoError(t, err)
	assert.True(t, deleteResponse["success"].(bool))

	// Verify it's gone
	getResp2 := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = getResp2.Body.Close() }()
	var getResponse2 map[string]interface{}
	_ = json.NewDecoder(getResp2.Body).Decode(&getResponse2)
	assert.False(t, getResponse2["hasLogo"].(bool))
}

func TestAPIClientLogoDelete_NoPicture(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createTestClientForLogo(t)

	url := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, client.Id)

	// Delete when no logo exists should still succeed
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAPIClientLogoDelete_ClientNotFound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, 99999999)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIClientLogoDelete_Unauthorized(t *testing.T) {
	url := fmt.Sprintf("%s/api/v1/admin/clients/1/logo", config.GetAuthServer().BaseURL)

	req, err := http.NewRequest("DELETE", url, nil)
	assert.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ============================================================================
// Public Client Logo Endpoint Tests
// ============================================================================

func TestClientLogo_PublicEndpoint_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createTestClientForLogo(t)

	// Upload a logo via admin API
	adminUrl := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, client.Id)
	logoData := createTestPNGImage(100, 100)
	uploadResp := makeMultipartRequest(t, "POST", adminUrl, accessToken, "picture", logoData, "logo.png")
	defer func() { _ = uploadResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, uploadResp.StatusCode)

	// Fetch the logo via the public endpoint (no auth required)
	publicUrl := fmt.Sprintf("%s/client/logo/%s", config.GetAuthServer().BaseURL, client.ClientIdentifier)
	httpClient := createHttpClient(t)
	req, err := http.NewRequest("GET", publicUrl, nil)
	assert.NoError(t, err)

	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "image/png", resp.Header.Get("Content-Type"))

	// Verify we got image data back
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.True(t, len(body) > 0)

	// Verify it's a valid PNG (starts with PNG magic bytes)
	assert.True(t, bytes.HasPrefix(body, []byte{0x89, 0x50, 0x4E, 0x47}))
}

func TestClientLogo_PublicEndpoint_NotFound(t *testing.T) {
	publicUrl := fmt.Sprintf("%s/client/logo/nonexistent-client-identifier", config.GetAuthServer().BaseURL)

	httpClient := createHttpClient(t)
	req, err := http.NewRequest("GET", publicUrl, nil)
	assert.NoError(t, err)

	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestClientLogo_PublicEndpoint_ClientHasNoLogo(t *testing.T) {
	client := createTestClientForLogo(t)

	publicUrl := fmt.Sprintf("%s/client/logo/%s", config.GetAuthServer().BaseURL, client.ClientIdentifier)

	httpClient := createHttpClient(t)
	req, err := http.NewRequest("GET", publicUrl, nil)
	assert.NoError(t, err)

	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestClientLogo_PublicEndpoint_CacheHeaders(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createTestClientForLogo(t)

	// Upload a logo
	adminUrl := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, client.Id)
	logoData := createTestPNGImage(100, 100)
	uploadResp := makeMultipartRequest(t, "POST", adminUrl, accessToken, "picture", logoData, "logo.png")
	defer func() { _ = uploadResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, uploadResp.StatusCode)

	// Fetch via public endpoint and check cache headers
	publicUrl := fmt.Sprintf("%s/client/logo/%s", config.GetAuthServer().BaseURL, client.ClientIdentifier)
	httpClient := createHttpClient(t)
	req, err := http.NewRequest("GET", publicUrl, nil)
	assert.NoError(t, err)

	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify Cache-Control header
	cacheControl := resp.Header.Get("Cache-Control")
	assert.Equal(t, "public, max-age=300, must-revalidate", cacheControl)

	// Verify ETag header is set
	etag := resp.Header.Get("ETag")
	assert.NotEmpty(t, etag, "ETag header should be set")
	assert.True(t, strings.HasPrefix(etag, "\"") && strings.HasSuffix(etag, "\""),
		"ETag should be quoted per HTTP spec")
}

func TestClientLogo_PublicEndpoint_ETagConditionalGet(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createTestClientForLogo(t)

	// Upload a logo
	adminUrl := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, client.Id)
	logoData := createTestPNGImage(100, 100)
	uploadResp := makeMultipartRequest(t, "POST", adminUrl, accessToken, "picture", logoData, "logo.png")
	defer func() { _ = uploadResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, uploadResp.StatusCode)

	publicUrl := fmt.Sprintf("%s/client/logo/%s", config.GetAuthServer().BaseURL, client.ClientIdentifier)
	httpClient := createHttpClient(t)

	// First request: get the ETag
	req1, err := http.NewRequest("GET", publicUrl, nil)
	assert.NoError(t, err)
	resp1, err := httpClient.Do(req1)
	assert.NoError(t, err)
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)
	etag := resp1.Header.Get("ETag")
	assert.NotEmpty(t, etag)
	// Consume body
	_, _ = io.ReadAll(resp1.Body)

	// Second request: send If-None-Match with the ETag
	req2, err := http.NewRequest("GET", publicUrl, nil)
	assert.NoError(t, err)
	req2.Header.Set("If-None-Match", etag)
	resp2, err := httpClient.Do(req2)
	assert.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()

	assert.Equal(t, http.StatusNotModified, resp2.StatusCode)

	// Verify no body in 304 response
	body, _ := io.ReadAll(resp2.Body)
	assert.Empty(t, body)
}

func TestClientLogo_PublicEndpoint_ETagChangesAfterUpdate(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createTestClientForLogo(t)

	adminUrl := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, client.Id)
	publicUrl := fmt.Sprintf("%s/client/logo/%s", config.GetAuthServer().BaseURL, client.ClientIdentifier)
	httpClient := createHttpClient(t)

	// Upload first logo and get ETag
	logoData1 := createTestPNGImage(100, 100)
	uploadResp1 := makeMultipartRequest(t, "POST", adminUrl, accessToken, "picture", logoData1, "logo1.png")
	defer func() { _ = uploadResp1.Body.Close() }()
	assert.Equal(t, http.StatusOK, uploadResp1.StatusCode)

	req1, err := http.NewRequest("GET", publicUrl, nil)
	assert.NoError(t, err)
	resp1, err := httpClient.Do(req1)
	assert.NoError(t, err)
	defer func() { _ = resp1.Body.Close() }()
	etag1 := resp1.Header.Get("ETag")
	_, _ = io.ReadAll(resp1.Body)

	// Upload different logo
	logoData2 := createTestPNGImage(200, 200)
	uploadResp2 := makeMultipartRequest(t, "POST", adminUrl, accessToken, "picture", logoData2, "logo2.png")
	defer func() { _ = uploadResp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, uploadResp2.StatusCode)

	// Get new ETag
	req2, err := http.NewRequest("GET", publicUrl, nil)
	assert.NoError(t, err)
	resp2, err := httpClient.Do(req2)
	assert.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	etag2 := resp2.Header.Get("ETag")
	_, _ = io.ReadAll(resp2.Body)

	// ETags should differ because content changed
	assert.NotEqual(t, etag1, etag2, "ETag should change after logo update")

	// Old ETag should not produce 304
	req3, err := http.NewRequest("GET", publicUrl, nil)
	assert.NoError(t, err)
	req3.Header.Set("If-None-Match", etag1)
	resp3, err := httpClient.Do(req3)
	assert.NoError(t, err)
	defer func() { _ = resp3.Body.Close() }()
	_, _ = io.ReadAll(resp3.Body)

	assert.Equal(t, http.StatusOK, resp3.StatusCode, "Old ETag should not match after update")
}

func TestClientLogo_PublicEndpoint_ContentMatchesUpload(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createTestClientForLogo(t)

	// Upload a logo
	adminUrl := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, client.Id)
	logoData := createTestPNGImage(150, 150)
	uploadResp := makeMultipartRequest(t, "POST", adminUrl, accessToken, "picture", logoData, "logo.png")
	defer func() { _ = uploadResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, uploadResp.StatusCode)

	// Fetch via public endpoint
	publicUrl := fmt.Sprintf("%s/client/logo/%s", config.GetAuthServer().BaseURL, client.ClientIdentifier)
	httpClient := createHttpClient(t)
	req, err := http.NewRequest("GET", publicUrl, nil)
	assert.NoError(t, err)

	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	// Verify the content hash matches what we uploaded
	uploadHash := sha256.Sum256(logoData)
	servedHash := sha256.Sum256(body)
	assert.Equal(t, uploadHash, servedHash, "Served logo content should match uploaded content")
}

// ============================================================================
// Full Workflow Test
// ============================================================================

func TestClientLogo_FullWorkflow(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createTestClientForLogo(t)

	adminUrl := fmt.Sprintf("%s/api/v1/admin/clients/%d/logo", config.GetAuthServer().BaseURL, client.Id)
	publicUrl := fmt.Sprintf("%s/client/logo/%s", config.GetAuthServer().BaseURL, client.ClientIdentifier)
	httpClient := createHttpClient(t)

	// 1. Verify no logo initially
	getResp1 := makeAPIRequest(t, "GET", adminUrl, accessToken, nil)
	defer func() { _ = getResp1.Body.Close() }()
	var getResponse1 map[string]interface{}
	_ = json.NewDecoder(getResp1.Body).Decode(&getResponse1)
	assert.False(t, getResponse1["hasLogo"].(bool))

	// 2. Public endpoint returns 404
	pubReq1, _ := http.NewRequest("GET", publicUrl, nil)
	pubResp1, err := httpClient.Do(pubReq1)
	assert.NoError(t, err)
	defer func() { _ = pubResp1.Body.Close() }()
	_, _ = io.ReadAll(pubResp1.Body)
	assert.Equal(t, http.StatusNotFound, pubResp1.StatusCode)

	// 3. Upload a logo
	logoData := createTestPNGImage(150, 150)
	uploadResp := makeMultipartRequest(t, "POST", adminUrl, accessToken, "picture", logoData, "logo.png")
	defer func() { _ = uploadResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, uploadResp.StatusCode)

	var uploadResponse map[string]interface{}
	_ = json.NewDecoder(uploadResp.Body).Decode(&uploadResponse)
	assert.True(t, uploadResponse["success"].(bool))
	assert.Contains(t, uploadResponse["pictureUrl"].(string), client.ClientIdentifier)

	// 4. Verify logo exists via admin API
	getResp2 := makeAPIRequest(t, "GET", adminUrl, accessToken, nil)
	defer func() { _ = getResp2.Body.Close() }()
	var getResponse2 map[string]interface{}
	_ = json.NewDecoder(getResp2.Body).Decode(&getResponse2)
	assert.True(t, getResponse2["hasLogo"].(bool))

	// 5. Fetch the actual logo via public endpoint
	pubReq2, _ := http.NewRequest("GET", publicUrl, nil)
	pubResp2, err := httpClient.Do(pubReq2)
	assert.NoError(t, err)
	defer func() { _ = pubResp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, pubResp2.StatusCode)
	assert.Equal(t, "image/png", pubResp2.Header.Get("Content-Type"))
	body, _ := io.ReadAll(pubResp2.Body)
	assert.True(t, len(body) > 0)

	// 6. Update the logo
	newLogoData := createTestPNGImage(200, 200)
	updateResp := makeMultipartRequest(t, "POST", adminUrl, accessToken, "picture", newLogoData, "new_logo.png")
	defer func() { _ = updateResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, updateResp.StatusCode)

	// 7. Delete the logo
	deleteResp := makeAPIRequest(t, "DELETE", adminUrl, accessToken, nil)
	defer func() { _ = deleteResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, deleteResp.StatusCode)

	// 8. Verify logo no longer exists via admin API
	getResp3 := makeAPIRequest(t, "GET", adminUrl, accessToken, nil)
	defer func() { _ = getResp3.Body.Close() }()
	var getResponse3 map[string]interface{}
	_ = json.NewDecoder(getResp3.Body).Decode(&getResponse3)
	assert.False(t, getResponse3["hasLogo"].(bool))

	// 9. Public endpoint returns 404
	pubReq3, _ := http.NewRequest("GET", publicUrl, nil)
	pubResp3, err := httpClient.Do(pubReq3)
	assert.NoError(t, err)
	defer func() { _ = pubResp3.Body.Close() }()
	_, _ = io.ReadAll(pubResp3.Body)
	assert.Equal(t, http.StatusNotFound, pubResp3.StatusCode)
}
