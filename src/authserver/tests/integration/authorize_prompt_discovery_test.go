package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Phase 5: Discovery Document Tests
// =============================================================================

func TestDiscovery_PromptValuesSupported(t *testing.T) {
	httpClient := createHttpClient(t)

	destUrl := appConfig.AuthServer.BaseURL + "/.well-known/openid-configuration"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		t.Fatal(err)
	}

	// Verify prompt_values_supported exists
	promptValues, ok := result["prompt_values_supported"]
	assert.True(t, ok, "prompt_values_supported should be present in discovery document")

	// Verify it's the expected array
	promptValuesArr, ok := promptValues.([]interface{})
	assert.True(t, ok, "prompt_values_supported should be a JSON array")
	assert.Equal(t, 3, len(promptValuesArr), "prompt_values_supported should have 3 values")

	// Verify exact values
	promptStrings := make([]string, len(promptValuesArr))
	for i, v := range promptValuesArr {
		promptStrings[i] = v.(string)
	}

	assert.Contains(t, promptStrings, "none")
	assert.Contains(t, promptStrings, "login")
	assert.Contains(t, promptStrings, "consent")
}

func TestDiscovery_PromptValuesSupportedIsArray(t *testing.T) {
	httpClient := createHttpClient(t)

	destUrl := appConfig.AuthServer.BaseURL + "/.well-known/openid-configuration"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse as raw JSON to verify the type
	body := readResponseBody(t, resp)
	var rawResult map[string]json.RawMessage
	err = json.Unmarshal([]byte(body), &rawResult)
	if err != nil {
		t.Fatal(err)
	}

	promptRaw, ok := rawResult["prompt_values_supported"]
	assert.True(t, ok, "prompt_values_supported should be present")

	// Verify it's a JSON array (starts with '[') not a string (starts with '"')
	rawBytes := []byte(promptRaw)
	assert.True(t, len(rawBytes) > 0, "prompt_values_supported should not be empty")
	assert.Equal(t, byte('['), rawBytes[0], "prompt_values_supported should be a JSON array, not a string")

	// Verify it deserializes as an array of strings
	var promptArr []string
	err = json.Unmarshal(promptRaw, &promptArr)
	assert.NoError(t, err, "prompt_values_supported should deserialize as []string")
	assert.Equal(t, []string{"none", "login", "consent"}, promptArr)
}

// fetchDiscoveryFields reads the served discovery document as raw JSON values by key, so a test
// can tell an absent key from a zero value.
func fetchDiscoveryFields(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	resp, err := createHttpClient(t).Get(appConfig.AuthServer.BaseURL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var fields map[string]json.RawMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&fields))
	return fields
}

// TestDiscovery_ImplementedCapabilities reads the served document end to end. It lists what the
// server implements, whatever the flow switches say (OIDC Discovery 1.0 section 3, RFC 8414
// section 2): every grant and response type with the implicit and password switches both off and
// both on, the two request object parameters written false rather than omitted (an absent
// request_uri_parameter_supported reads as true), public clients' "none", and the
// auth_state_generation claim the server signs (#231, #437).
func TestDiscovery_ImplementedCapabilities(t *testing.T) {
	changeSettings(t, func(settings *record.Settings) {
		settings.ImplicitFlowEnabled = false
		settings.ResourceOwnerPasswordCredentialsEnabled = false
	})
	switchesOff := fetchDiscoveryFields(t)

	changeSettings(t, func(settings *record.Settings) {
		settings.ImplicitFlowEnabled = true
		settings.ResourceOwnerPasswordCredentialsEnabled = true
	})
	switchesOn := fetchDiscoveryFields(t)

	for _, key := range []string{"grant_types_supported", "response_types_supported"} {
		assert.JSONEq(t, string(switchesOff[key]), string(switchesOn[key]), "%s must not depend on a flow switch", key)
	}

	fieldAs := func(key string, target any) {
		t.Helper()
		raw, present := switchesOff[key]
		require.True(t, present, "%s must be present", key)
		require.NoError(t, json.Unmarshal(raw, target), key)
	}

	var grantTypes, responseTypes, responseModes, authMethods, claims []string
	fieldAs("grant_types_supported", &grantTypes)
	fieldAs("response_types_supported", &responseTypes)
	fieldAs("response_modes_supported", &responseModes)
	fieldAs("token_endpoint_auth_methods_supported", &authMethods)
	fieldAs("claims_supported", &claims)

	assert.Equal(t, []string{"authorization_code", "refresh_token", "client_credentials", "password", "implicit"}, grantTypes)
	assert.Equal(t, []string{"code", "token", "id_token", "id_token token"}, responseTypes)
	assert.Equal(t, []string{"query", "fragment", "form_post"}, responseModes)
	assert.Equal(t, []string{"client_secret_post", "client_secret_basic", "none"}, authMethods)
	assert.Contains(t, claims, "auth_state_generation")

	for _, key := range []string{"request_uri_parameter_supported", "request_parameter_supported"} {
		var supported *bool
		fieldAs(key, &supported)
		if assert.NotNil(t, supported, "%s must be a boolean, not null", key) {
			assert.False(t, *supported, key)
		}
	}
}
