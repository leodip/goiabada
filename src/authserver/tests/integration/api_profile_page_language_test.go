package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The page language through the real server and database (#631 decisions 3 and 8): a catalog's tag
// is stored and returned, a profile save that leaves the field out keeps it, "" sets Automatic, and
// a value not in the list is refused with nothing written. Each body is a map, so "left out" is
// literally absent from the JSON an older application sends.

// putPageLanguageProfile sends a profile save with the given body and answers its status, the
// page language it answered with, and its error description on a refusal.
func putPageLanguageProfile(t *testing.T, putURL, accessToken string, body map[string]any) (int, string, string) {
	t.Helper()
	resp := makeAPIRequest(t, "PUT", putURL, accessToken, body)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	if resp.StatusCode != http.StatusOK {
		var refusal api.ErrorResponse
		require.NoError(t, json.Unmarshal(raw, &refusal), string(raw))
		return resp.StatusCode, "", refusal.ErrorDescription
	}
	var updated api.UpdateUserResponse
	require.NoError(t, json.Unmarshal(raw, &updated), string(raw))
	return resp.StatusCode, updated.User.PageLanguage, ""
}

// assertPageLanguageSaves drives one profile route through the four outcomes, reading the row
// after each.
func assertPageLanguageSaves(t *testing.T, putURL, accessToken string, userId int64) {
	t.Helper()
	stored := func() string {
		u, err := database.GetUserById(context.Background(), nil, userId)
		require.NoError(t, err)
		require.NotNil(t, u)
		return u.PageLanguage
	}

	status, answered, _ := putPageLanguageProfile(t, putURL, accessToken,
		map[string]any{"givenName": "Ada", "familyName": "Lovelace", "pageLanguage": "pt-BR"})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "pt-BR", answered, "a catalog's tag is answered")
	assert.Equal(t, "pt-BR", stored(), "and stored")

	status, answered, _ = putPageLanguageProfile(t, putURL, accessToken,
		map[string]any{"givenName": "Grace", "familyName": "Lovelace"})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "pt-BR", answered, "a save that leaves the field out answers the page language it kept")
	assert.Equal(t, "pt-BR", stored(), "a save that leaves the field out keeps the page language")

	status, _, refusal := putPageLanguageProfile(t, putURL, accessToken,
		map[string]any{"givenName": "Ada", "familyName": "Lovelace", "pageLanguage": "ja"})
	assert.Equal(t, http.StatusBadRequest, status, "a language with no catalog is refused")
	assert.Equal(t, "Choose a language from the list.", refusal)
	assert.Equal(t, "pt-BR", stored(), "a refused save writes nothing")

	status, answered, _ = putPageLanguageProfile(t, putURL, accessToken,
		map[string]any{"givenName": "Ada", "familyName": "Lovelace", "pageLanguage": ""})
	require.Equal(t, http.StatusOK, status)
	assert.Empty(t, answered, "empty sets Automatic")
	assert.Empty(t, stored(), "and stores it")
}

func TestAPIAccountProfilePut_PageLanguage(t *testing.T) {
	accessToken, u := getUserAccessTokenWithAccountScope(t)
	profileURL := appConfig.AuthServer.BaseURL + "/api/v1/account/profile"

	assertPageLanguageSaves(t, profileURL, accessToken, u.Id)

	// The account's own read carries it.
	_, _, _ = putPageLanguageProfile(t, profileURL, accessToken,
		map[string]any{"givenName": "Ada", "familyName": "Lovelace", "pageLanguage": "de"})
	resp := makeAPIRequest(t, "GET", profileURL, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got api.GetUserResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "de", got.User.PageLanguage)
}

func TestAPIUserProfilePut_PageLanguage(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@page-language.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, testUser))
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()
	userURL := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10)

	assertPageLanguageSaves(t, userURL+"/profile", accessToken, testUser.Id)

	// The administrator's read and the user search carry it.
	status, _, _ := putPageLanguageProfile(t, userURL+"/profile", accessToken,
		map[string]any{"givenName": "Ada", "familyName": "Lovelace", "pageLanguage": "it"})
	require.Equal(t, http.StatusOK, status)

	getResp := makeAPIRequest(t, "GET", userURL, accessToken, nil)
	defer func() { _ = getResp.Body.Close() }()
	require.Equal(t, http.StatusOK, getResp.StatusCode)
	var got api.GetUserResponse
	require.NoError(t, json.NewDecoder(getResp.Body).Decode(&got))
	assert.Equal(t, "it", got.User.PageLanguage, "the administrator's read")

	searchURL := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/search?query=" + url.QueryEscape(testUser.Email)
	searchResp := makeAPIRequest(t, "GET", searchURL, accessToken, nil)
	defer func() { _ = searchResp.Body.Close() }()
	require.Equal(t, http.StatusOK, searchResp.StatusCode)
	var found api.SearchUsersResponse
	require.NoError(t, json.NewDecoder(searchResp.Body).Decode(&found))
	require.Len(t, found.Users, 1)
	assert.Equal(t, "it", found.Users[0].PageLanguage, "the user search")
}
