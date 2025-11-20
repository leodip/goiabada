package apiclient

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"

    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/models"
)

// CreateResource creates a new resource via the auth server admin API
func (c *AuthServerClient) CreateResource(accessToken string, request *api.CreateResourceRequest) (*models.Resource, error) {
    url := fmt.Sprintf("%s/api/v1/admin/resources", c.baseURL)

    body, err := json.Marshal(request)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    defer func() { _ = resp.Body.Close() }()

    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    if resp.StatusCode != http.StatusCreated {
        return nil, parseAPIError(resp, respBody)
    }

    var apiResp api.CreateResourceResponse
    if err := json.Unmarshal(respBody, &apiResp); err != nil {
        return nil, fmt.Errorf("failed to parse response: %w", err)
    }

    resource := &models.Resource{
        Id:                 apiResp.Resource.Id,
        ResourceIdentifier: apiResp.Resource.ResourceIdentifier,
        Description:        apiResp.Resource.Description,
    }

    return resource, nil
}

// GetResourceById retrieves a single resource by ID via the auth server admin API
func (c *AuthServerClient) GetResourceById(accessToken string, resourceId int64) (*models.Resource, error) {
    url := fmt.Sprintf("%s/api/v1/admin/resources/%d", c.baseURL, resourceId)

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    defer func() { _ = resp.Body.Close() }()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    if resp.StatusCode != http.StatusOK {
        return nil, parseAPIError(resp, body)
    }

    var apiResp api.GetResourceResponse
    if err := json.Unmarshal(body, &apiResp); err != nil {
        return nil, fmt.Errorf("failed to parse response: %w", err)
    }

    resource := &models.Resource{
        Id:                 apiResp.Resource.Id,
        ResourceIdentifier: apiResp.Resource.ResourceIdentifier,
        Description:        apiResp.Resource.Description,
    }
    return resource, nil
}

// UpdateResource updates an existing resource via the auth server admin API
func (c *AuthServerClient) UpdateResource(accessToken string, resourceId int64, request *api.UpdateResourceRequest) (*models.Resource, error) {
    url := fmt.Sprintf("%s/api/v1/admin/resources/%d", c.baseURL, resourceId)

    body, err := json.Marshal(request)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    req, err := http.NewRequest("PUT", url, bytes.NewBuffer(body))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    defer func() { _ = resp.Body.Close() }()

    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    if resp.StatusCode != http.StatusOK {
        return nil, parseAPIError(resp, respBody)
    }

    var apiResp api.UpdateResourceResponse
    if err := json.Unmarshal(respBody, &apiResp); err != nil {
        return nil, fmt.Errorf("failed to parse response: %w", err)
    }

    resource := &models.Resource{
        Id:                 apiResp.Resource.Id,
        ResourceIdentifier: apiResp.Resource.ResourceIdentifier,
        Description:        apiResp.Resource.Description,
    }
    return resource, nil
}

// DeleteResource deletes a resource via the auth server admin API
func (c *AuthServerClient) DeleteResource(accessToken string, resourceId int64) error {
    url := fmt.Sprintf("%s/api/v1/admin/resources/%d", c.baseURL, resourceId)

    req, err := http.NewRequest("DELETE", url, nil)
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("request failed: %w", err)
    }
    defer func() { _ = resp.Body.Close() }()

    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        return fmt.Errorf("failed to read response body: %w", err)
    }

    if resp.StatusCode != http.StatusOK {
        return parseAPIError(resp, respBody)
    }
    return nil
}
