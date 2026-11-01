package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIClientUpdatePut_PrivacyPolicyAndTermsOfServiceURLs holds the admin API's settings update and
// client read to a client's own privacy policy and terms of service URLs (#622 decision 12): the
// update stores what it is sent, trimmed, the answer and a later read carry it, and an empty value
// clears it. The client has no redirect URI on either host: URLs an administrator sets are not
// host-checked, as registration's are.
func TestAPIClientUpdatePut_PrivacyPolicyAndTermsOfServiceURLs(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	client := createTestClientUnique(t, true)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	clientURL := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10)
	update := func(privacy, terms string) *api.ClientResponse {
		t.Helper()
		resp := makeAPIRequest(t, "PUT", clientURL, accessToken, api.UpdateClientSettingsRequest{
			ClientIdentifier:  client.ClientIdentifier,
			Description:       client.Description,
			Enabled:           true,
			PrivacyPolicyURL:  privacy,
			TermsOfServiceURL: terms,
		})
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var answer api.UpdateClientResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&answer))
		return &answer.Client
	}
	read := func() *api.ClientResponse {
		t.Helper()
		resp := makeAPIRequest(t, "GET", clientURL, accessToken, nil)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var answer api.GetClientResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&answer))
		return &answer.Client
	}

	answered := update("  https://legal.example.org/privacy  ", "http://legal.example.org/terms?v=3")
	assert.Equal(t, "https://legal.example.org/privacy", answered.PrivacyPolicyURL, "the answer carries the URL trimmed")
	assert.Equal(t, "http://legal.example.org/terms?v=3", answered.TermsOfServiceURL)

	stored, err := database.GetClientById(context.Background(), nil, client.Id)
	require.NoError(t, err)
	assert.Equal(t, "https://legal.example.org/privacy", stored.PrivacyPolicyURL)
	assert.Equal(t, "http://legal.example.org/terms?v=3", stored.TermsOfServiceURL)

	got := read()
	assert.Equal(t, "https://legal.example.org/privacy", got.PrivacyPolicyURL, "the client read carries the privacy policy URL")
	assert.Equal(t, "http://legal.example.org/terms?v=3", got.TermsOfServiceURL, "the client read carries the terms of service URL")

	cleared := update("", "")
	assert.Empty(t, cleared.PrivacyPolicyURL, "an empty value clears the privacy policy URL")
	assert.Empty(t, cleared.TermsOfServiceURL, "an empty value clears the terms of service URL")
	got = read()
	assert.Empty(t, got.PrivacyPolicyURL)
	assert.Empty(t, got.TermsOfServiceURL)
}

// TestAPIClientUpdatePut_PrivacyPolicyAndTermsOfServiceURLValidation refuses what the website URL is
// refused for, each with its own field's message, and stores nothing.
func TestAPIClientUpdatePut_PrivacyPolicyAndTermsOfServiceURLValidation(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	client := createTestClientUnique(t, true)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	clientURL := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10)
	exactly256 := "https://example.com/" + strings.Repeat("a", 236)
	require.Len(t, exactly256, 256)

	cases := []struct {
		name    string
		privacy string
		terms   string
		status  int
		code    string
		message string
	}{
		{"a privacy policy URL of 256 characters", exactly256, "", http.StatusOK, "", ""},
		{"a terms of service URL of 256 characters", "", exactly256, http.StatusOK, "", ""},
		{"a privacy policy URL of 257 characters", exactly256 + "a", "", http.StatusBadRequest,
			"handler.client.privacy_policy_url_too_long", "The privacy policy URL cannot exceed a maximum length of 256 characters."},
		{"a terms of service URL of 257 characters", "", exactly256 + "a", http.StatusBadRequest,
			"handler.client.terms_of_service_url_too_long", "The terms of service URL cannot exceed a maximum length of 256 characters."},
		{"a privacy policy URL that does not parse", "not-a-url", "", http.StatusBadRequest,
			"handler.client.privacy_policy_url_invalid", "Invalid privacy policy URL."},
		{"a terms of service URL that does not parse", "", "not-a-url", http.StatusBadRequest,
			"handler.client.terms_of_service_url_invalid", "Invalid terms of service URL."},
		{"a privacy policy URL on ftp", "ftp://example.com/privacy", "", http.StatusBadRequest,
			"handler.client.privacy_policy_url_scheme_invalid", "Privacy policy URL must use http or https scheme."},
		{"a terms of service URL on javascript", "", "javascript:alert(1)", http.StatusBadRequest,
			"handler.client.terms_of_service_url_scheme_invalid", "Terms of service URL must use http or https scheme."},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := makeAPIRequest(t, "PUT", clientURL, accessToken, api.UpdateClientSettingsRequest{
				ClientIdentifier:  client.ClientIdentifier,
				Description:       client.Description,
				Enabled:           true,
				PrivacyPolicyURL:  tc.privacy,
				TermsOfServiceURL: tc.terms,
			})
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, tc.status, resp.StatusCode)

			stored, err := database.GetClientById(context.Background(), nil, client.Id)
			require.NoError(t, err)
			if tc.status == http.StatusOK {
				assert.Equal(t, tc.privacy, stored.PrivacyPolicyURL)
				assert.Equal(t, tc.terms, stored.TermsOfServiceURL)
				return
			}

			var body map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			assert.Equal(t, tc.code, body["error_code"])
			assert.Equal(t, tc.message, body["error_description"])
			if tc.privacy != "" {
				assert.NotEqual(t, tc.privacy, stored.PrivacyPolicyURL, "a refused privacy policy URL is not stored")
			}
			if tc.terms != "" {
				assert.NotEqual(t, tc.terms, stored.TermsOfServiceURL, "a refused terms of service URL is not stored")
			}
		})
	}
}
