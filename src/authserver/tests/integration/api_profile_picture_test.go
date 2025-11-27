package integrationtests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// createTestPNGImage creates a valid PNG image with the specified dimensions
func createTestPNGImage(width, height int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 100, G: 150, B: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// makeMultipartRequest creates and sends a multipart form request with a file
func makeMultipartRequest(t *testing.T, method, url, accessToken, fieldName string, fileData []byte, fileName string) *http.Response {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	part, err := writer.CreateFormFile(fieldName, fileName)
	assert.NoError(t, err)
	_, err = io.Copy(part, bytes.NewReader(fileData))
	assert.NoError(t, err)
	_ = writer.Close()

	req, err := http.NewRequest(method, url, &body)
	assert.NoError(t, err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+accessToken)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)

	return resp
}

// createTestUserForProfilePicture creates a user for profile picture tests
func createTestUserForProfilePicture(t *testing.T) *models.User {
	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}

	err = database.CreateUser(nil, user)
	assert.NoError(t, err)
	return user
}

// ============================================================================
// Account Profile Picture Tests (User's own profile picture)
// ============================================================================

func TestAPIAccountProfilePictureGet_Success_NoPicture(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)

	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile-picture"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.False(t, response["hasPicture"].(bool))
	assert.Nil(t, response["pictureUrl"])
}

func TestAPIAccountProfilePictureGet_Unauthorized(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile-picture"

	// No token
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIAccountProfilePictureGet_InsufficientScope(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile-picture"

	// Token with different scope (userinfo instead of manage-account)
	tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	resp := makeAPIRequest(t, "GET", url, tok, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestAPIAccountProfilePicturePost_Success(t *testing.T) {
	accessToken, user := getUserAccessTokenWithAccountScope(t)

	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile-picture"
	pictureData := createTestPNGImage(100, 100)
	resp := makeMultipartRequest(t, "POST", url, accessToken, "picture", pictureData, "picture.png")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))
	assert.Contains(t, response["pictureUrl"].(string), user.Subject.String())

	// Verify the picture was saved
	getResp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = getResp.Body.Close() }()

	var getResponse map[string]interface{}
	err = json.NewDecoder(getResp.Body).Decode(&getResponse)
	assert.NoError(t, err)
	assert.True(t, getResponse["hasPicture"].(bool))
	assert.NotNil(t, getResponse["pictureUrl"])
}

func TestAPIAccountProfilePicturePost_UpdateExisting(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)

	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile-picture"

	// Upload first picture
	pictureData1 := createTestPNGImage(100, 100)
	resp1 := makeMultipartRequest(t, "POST", url, accessToken, "picture", pictureData1, "picture1.png")
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	// Upload second picture (update)
	pictureData2 := createTestPNGImage(200, 200)
	resp2 := makeMultipartRequest(t, "POST", url, accessToken, "picture", pictureData2, "picture2.png")
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp2.Body).Decode(&response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))
}

func TestAPIAccountProfilePicturePost_InvalidImage(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)

	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile-picture"
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

func TestAPIAccountProfilePicturePost_Unauthorized(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile-picture"
	pictureData := createTestPNGImage(100, 100)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormFile("picture", "picture.png")
	_, _ = io.Copy(part, bytes.NewReader(pictureData))
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

func TestAPIAccountProfilePictureDelete_Success(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)

	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile-picture"

	// First upload a picture
	pictureData := createTestPNGImage(100, 100)
	uploadResp := makeMultipartRequest(t, "POST", url, accessToken, "picture", pictureData, "picture.png")
	defer func() { _ = uploadResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, uploadResp.StatusCode)

	// Verify it exists
	getResp1 := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = getResp1.Body.Close() }()
	var getResponse1 map[string]interface{}
	_ = json.NewDecoder(getResp1.Body).Decode(&getResponse1)
	assert.True(t, getResponse1["hasPicture"].(bool))

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
	assert.False(t, getResponse2["hasPicture"].(bool))
}

func TestAPIAccountProfilePictureDelete_NoPicture(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)

	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile-picture"

	// Delete when no picture exists should still succeed
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAPIAccountProfilePictureDelete_Unauthorized(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile-picture"

	req, err := http.NewRequest("DELETE", url, nil)
	assert.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ============================================================================
// Admin User Profile Picture Tests (Admin managing user profile pictures)
// ============================================================================

func TestAPIUserProfilePictureGet_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	user := createTestUserForProfilePicture(t)

	url := fmt.Sprintf("%s/api/v1/admin/users/%d/profile-picture", config.GetAuthServer().BaseURL, user.Id)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.False(t, response["hasPicture"].(bool))
}

func TestAPIUserProfilePictureGet_UserNotFound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := fmt.Sprintf("%s/api/v1/admin/users/%d/profile-picture", config.GetAuthServer().BaseURL, 99999999)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserProfilePictureGet_InvalidUserId(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := fmt.Sprintf("%s/api/v1/admin/users/invalid/profile-picture", config.GetAuthServer().BaseURL)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserProfilePicturePost_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	user := createTestUserForProfilePicture(t)

	url := fmt.Sprintf("%s/api/v1/admin/users/%d/profile-picture", config.GetAuthServer().BaseURL, user.Id)
	pictureData := createTestPNGImage(100, 100)
	resp := makeMultipartRequest(t, "POST", url, accessToken, "picture", pictureData, "picture.png")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))
	assert.Contains(t, response["pictureUrl"].(string), user.Subject.String())

	// Verify the picture was saved
	getResp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = getResp.Body.Close() }()

	var getResponse map[string]interface{}
	err = json.NewDecoder(getResp.Body).Decode(&getResponse)
	assert.NoError(t, err)
	assert.True(t, getResponse["hasPicture"].(bool))
}

func TestAPIUserProfilePicturePost_UserNotFound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := fmt.Sprintf("%s/api/v1/admin/users/%d/profile-picture", config.GetAuthServer().BaseURL, 99999999)
	pictureData := createTestPNGImage(100, 100)
	resp := makeMultipartRequest(t, "POST", url, accessToken, "picture", pictureData, "picture.png")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserProfilePicturePost_InvalidImage(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	user := createTestUserForProfilePicture(t)

	url := fmt.Sprintf("%s/api/v1/admin/users/%d/profile-picture", config.GetAuthServer().BaseURL, user.Id)
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

func TestAPIUserProfilePictureDelete_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	user := createTestUserForProfilePicture(t)

	url := fmt.Sprintf("%s/api/v1/admin/users/%d/profile-picture", config.GetAuthServer().BaseURL, user.Id)

	// First upload a picture
	pictureData := createTestPNGImage(100, 100)
	uploadResp := makeMultipartRequest(t, "POST", url, accessToken, "picture", pictureData, "picture.png")
	defer func() { _ = uploadResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, uploadResp.StatusCode)

	// Delete it
	deleteResp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = deleteResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, deleteResp.StatusCode)

	var deleteResponse map[string]interface{}
	err := json.NewDecoder(deleteResp.Body).Decode(&deleteResponse)
	assert.NoError(t, err)
	assert.True(t, deleteResponse["success"].(bool))

	// Verify it's gone
	getResp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = getResp.Body.Close() }()
	var getResponse map[string]interface{}
	_ = json.NewDecoder(getResp.Body).Decode(&getResponse)
	assert.False(t, getResponse["hasPicture"].(bool))
}

func TestAPIUserProfilePictureDelete_UserNotFound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := fmt.Sprintf("%s/api/v1/admin/users/%d/profile-picture", config.GetAuthServer().BaseURL, 99999999)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// ============================================================================
// Userinfo Picture Endpoint Tests (Public picture retrieval by subject)
// ============================================================================

func TestUserinfoPicture_Success(t *testing.T) {
	// Create a user and upload a profile picture using the account API
	accessToken, user := getUserAccessTokenWithAccountScope(t)

	accountUrl := config.GetAuthServer().BaseURL + "/api/v1/account/profile-picture"
	pictureData := createTestPNGImage(100, 100)
	uploadResp := makeMultipartRequest(t, "POST", accountUrl, accessToken, "picture", pictureData, "picture.png")
	defer func() { _ = uploadResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, uploadResp.StatusCode)

	// Now fetch the picture via the userinfo/picture endpoint (no auth required)
	pictureUrl := fmt.Sprintf("%s/userinfo/picture/%s", config.GetAuthServer().BaseURL, user.Subject.String())
	httpClient := createHttpClient(t)
	req, err := http.NewRequest("GET", pictureUrl, nil)
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

func TestUserinfoPicture_NotFound(t *testing.T) {
	// Use a random UUID that doesn't exist
	randomUUID := uuid.New().String()
	pictureUrl := fmt.Sprintf("%s/userinfo/picture/%s", config.GetAuthServer().BaseURL, randomUUID)

	httpClient := createHttpClient(t)
	req, err := http.NewRequest("GET", pictureUrl, nil)
	assert.NoError(t, err)

	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestUserinfoPicture_InvalidSubject(t *testing.T) {
	pictureUrl := fmt.Sprintf("%s/userinfo/picture/invalid-uuid", config.GetAuthServer().BaseURL)

	httpClient := createHttpClient(t)
	req, err := http.NewRequest("GET", pictureUrl, nil)
	assert.NoError(t, err)

	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Should return 400 Bad Request or 404 Not Found depending on implementation
	assert.True(t, resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound)
}

func TestUserinfoPicture_UserHasNoPicture(t *testing.T) {
	// Create a user without a profile picture
	user := createTestUserForProfilePicture(t)

	pictureUrl := fmt.Sprintf("%s/userinfo/picture/%s", config.GetAuthServer().BaseURL, user.Subject.String())

	httpClient := createHttpClient(t)
	req, err := http.NewRequest("GET", pictureUrl, nil)
	assert.NoError(t, err)

	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestUserinfoPicture_CacheHeaders(t *testing.T) {
	// Create a user and upload a profile picture
	accessToken, user := getUserAccessTokenWithAccountScope(t)

	accountUrl := config.GetAuthServer().BaseURL + "/api/v1/account/profile-picture"
	pictureData := createTestPNGImage(100, 100)
	uploadResp := makeMultipartRequest(t, "POST", accountUrl, accessToken, "picture", pictureData, "picture.png")
	defer func() { _ = uploadResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, uploadResp.StatusCode)

	// Fetch the picture and check cache headers
	pictureUrl := fmt.Sprintf("%s/userinfo/picture/%s", config.GetAuthServer().BaseURL, user.Subject.String())
	httpClient := createHttpClient(t)
	req, err := http.NewRequest("GET", pictureUrl, nil)
	assert.NoError(t, err)

	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify cache control header is set (profile pictures use no-cache for privacy)
	cacheControl := resp.Header.Get("Cache-Control")
	assert.NotEmpty(t, cacheControl, "Cache-Control header should be set")
	assert.True(t, strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "no-cache"),
		"Cache-Control should contain no-store or no-cache directive for privacy")
}

// ============================================================================
// Integration Test: Full workflow
// ============================================================================

func TestProfilePicture_FullWorkflow(t *testing.T) {
	// 1. Create user and get access token
	accessToken, user := getUserAccessTokenWithAccountScope(t)
	accountUrl := config.GetAuthServer().BaseURL + "/api/v1/account/profile-picture"

	// 2. Verify no picture initially
	getResp1 := makeAPIRequest(t, "GET", accountUrl, accessToken, nil)
	defer func() { _ = getResp1.Body.Close() }()
	var getResponse1 map[string]interface{}
	_ = json.NewDecoder(getResp1.Body).Decode(&getResponse1)
	assert.False(t, getResponse1["hasPicture"].(bool))

	// 3. Upload a picture
	pictureData := createTestPNGImage(150, 150)
	uploadResp := makeMultipartRequest(t, "POST", accountUrl, accessToken, "picture", pictureData, "profile.png")
	defer func() { _ = uploadResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, uploadResp.StatusCode)

	// 4. Verify picture exists via account API
	getResp2 := makeAPIRequest(t, "GET", accountUrl, accessToken, nil)
	defer func() { _ = getResp2.Body.Close() }()
	var getResponse2 map[string]interface{}
	_ = json.NewDecoder(getResp2.Body).Decode(&getResponse2)
	assert.True(t, getResponse2["hasPicture"].(bool))

	// 5. Fetch the actual picture via public endpoint
	pictureUrl := fmt.Sprintf("%s/userinfo/picture/%s", config.GetAuthServer().BaseURL, user.Subject.String())
	httpClient := createHttpClient(t)
	pictureResp, err := httpClient.Get(pictureUrl)
	assert.NoError(t, err)
	defer func() { _ = pictureResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, pictureResp.StatusCode)
	assert.Equal(t, "image/png", pictureResp.Header.Get("Content-Type"))

	// 6. Update the picture
	newPictureData := createTestPNGImage(200, 200)
	updateResp := makeMultipartRequest(t, "POST", accountUrl, accessToken, "picture", newPictureData, "new_profile.png")
	defer func() { _ = updateResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, updateResp.StatusCode)

	// 7. Delete the picture
	deleteResp := makeAPIRequest(t, "DELETE", accountUrl, accessToken, nil)
	defer func() { _ = deleteResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, deleteResp.StatusCode)

	// 8. Verify picture no longer exists
	getResp3 := makeAPIRequest(t, "GET", accountUrl, accessToken, nil)
	defer func() { _ = getResp3.Body.Close() }()
	var getResponse3 map[string]interface{}
	_ = json.NewDecoder(getResp3.Body).Decode(&getResponse3)
	assert.False(t, getResponse3["hasPicture"].(bool))

	// 9. Verify public endpoint returns 404
	pictureResp2, err := httpClient.Get(pictureUrl)
	assert.NoError(t, err)
	defer func() { _ = pictureResp2.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, pictureResp2.StatusCode)
}
