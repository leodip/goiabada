package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

// GetSettingsKeys calls GET /api/v1/admin/settings/keys
func (c *AuthServerClient) GetSettingsKeys(accessToken string) ([]api.SettingsSigningKeyResponse, error) {
	url := fmt.Sprintf("%s/api/v1/admin/settings/keys", c.baseURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var out api.GetSettingsKeysResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out.Keys, nil
}

// RotateSettingsKeys calls POST /api/v1/admin/settings/keys/rotate
func (c *AuthServerClient) RotateSettingsKeys(accessToken string) error {
	url := fmt.Sprintf("%s/api/v1/admin/settings/keys/rotate", c.baseURL)
	// empty JSON body
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte("{}")))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return parseAPIError(resp, body)
	}
	return nil
}

// DeleteSettingsKey calls DELETE /api/v1/admin/settings/keys/{id}
func (c *AuthServerClient) DeleteSettingsKey(accessToken string, id int64) error {
	url := fmt.Sprintf("%s/api/v1/admin/settings/keys/%d", c.baseURL, id)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return parseAPIError(resp, body)
	}
	return nil
}
