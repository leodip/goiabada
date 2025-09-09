package apiclient

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"

    "github.com/leodip/goiabada/core/api"
)

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

func (c *AuthServerClient) UpdateSettingsGeneral(accessToken string, request *api.UpdateSettingsGeneralRequest) (*api.SettingsGeneralResponse, error) {
    fullURL := c.baseURL + "/api/v1/admin/settings/general"

    jsonData, err := json.Marshal(request)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
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

