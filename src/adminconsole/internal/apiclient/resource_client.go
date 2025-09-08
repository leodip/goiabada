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
    defer resp.Body.Close()

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
