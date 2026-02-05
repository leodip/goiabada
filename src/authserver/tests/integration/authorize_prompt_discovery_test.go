package integrationtests

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Phase 5: Discovery Document Tests
// =============================================================================

func TestDiscovery_PromptValuesSupported(t *testing.T) {
	httpClient := createHttpClient(t)

	destUrl := config.GetAuthServer().BaseURL + "/.well-known/openid-configuration"
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

	destUrl := config.GetAuthServer().BaseURL + "/.well-known/openid-configuration"
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
