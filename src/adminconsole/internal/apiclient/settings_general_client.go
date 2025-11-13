package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

// Settings General Client - AUTHENTICATED admin API for managing general settings
//
// This file implements methods on AuthServerClient for AUTHENTICATED operations on general settings.
// These methods call /api/v1/admin/settings/general which REQUIRES a valid access token with admin permissions.
//
// Key differences from settings_client.go (SettingsClient):
//
// 1. AUTHENTICATION:
//    - This file: REQUIRES authentication (Bearer token) - used for admin operations
//    - settings_client.go: NO authentication - used by middleware for public data
//
// 2. ENDPOINT:
//    - This file: /api/v1/admin/settings/general (authenticated admin API)
//    - settings_client.go: /api/public/settings (public unauthenticated API)
//
// 3. DATA SCOPE:
//    - This file: Full general settings (appName, issuer, passwordPolicy, selfRegistration, etc.)
//    - settings_client.go: Minimal public subset (appName, uiTheme, smtpEnabled)
//
// 4. OPERATIONS:
//    - This file: GET (read) and PATCH (update) operations
//    - settings_client.go: GET only (read-only public access)
//
// 5. USE CASE:
//    - This file: Admin UI pages for configuring general settings
//    - settings_client.go: Middleware that needs settings on every request (cached)

// GetSettingsGeneral fetches general settings via the authenticated admin API.
// Requires an access token with admin permissions.
// Returns all general settings including sensitive configuration.
func (c *AuthServerClient) GetSettingsGeneral(accessToken string) (*api.SettingsGeneralResponse, error) {
	fullURL := c.baseURL + "/api/v1/admin/settings/general"

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.SettingsGeneralResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &response, nil
}

// UpdateSettingsGeneral updates general settings via the authenticated admin API.
// Requires an access token with admin permissions.
// Returns the updated general settings.
func (c *AuthServerClient) UpdateSettingsGeneral(accessToken string, request *api.UpdateSettingsGeneralRequest) (*api.SettingsGeneralResponse, error) {
	fullURL := c.baseURL + "/api/v1/admin/settings/general"

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("PATCH", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.SettingsGeneralResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &response, nil
}
