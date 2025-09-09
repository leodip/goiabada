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

// GetUserPermissions retrieves user permissions from the auth server
func (c *AuthServerClient) GetUserPermissions(accessToken string, userId int64) (*models.User, []models.Permission, error) {
	url := fmt.Sprintf("%s/api/v1/admin/users/%d/permissions", c.baseURL, userId)


	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response: %w", err)
	}


	if resp.StatusCode != http.StatusOK {
		apiErr := parseAPIError(resp, body)
		return nil, nil, apiErr
	}

	var apiResp api.GetUserPermissionsResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, nil, fmt.Errorf("failed to parse response: %w", err)
	}

	user := apiResp.User.ToUser()
	permissions := make([]models.Permission, len(apiResp.Permissions))
	for i, permResp := range apiResp.Permissions {
		permissions[i] = models.Permission{
			Id:                   permResp.Id,
			PermissionIdentifier: permResp.PermissionIdentifier,
			Description:          permResp.Description,
			ResourceId:           permResp.ResourceId,
			Resource: models.Resource{
				Id:                 permResp.Resource.Id,
				ResourceIdentifier: permResp.Resource.ResourceIdentifier,
				Description:        permResp.Resource.Description,
			},
		}
	}

	return user, permissions, nil
}

// UpdateUserPermissions updates user permissions via the auth server
func (c *AuthServerClient) UpdateUserPermissions(accessToken string, userId int64, request *api.UpdateUserPermissionsRequest) error {
	url := fmt.Sprintf("%s/api/v1/admin/users/%d/permissions", c.baseURL, userId)

	requestBody, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}


	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}


	if resp.StatusCode != http.StatusOK {
		apiErr := parseAPIError(resp, body)
		return apiErr
	}

	return nil
}

// GetAllResources retrieves all resources from the auth server
func (c *AuthServerClient) GetAllResources(accessToken string) ([]models.Resource, error) {
	url := fmt.Sprintf("%s/api/v1/admin/resources", c.baseURL)


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
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}


	if resp.StatusCode != http.StatusOK {
		apiErr := parseAPIError(resp, body)
		return nil, apiErr
	}

	var apiResp api.GetResourcesResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	resources := make([]models.Resource, len(apiResp.Resources))
	for i, resourceResp := range apiResp.Resources {
		resources[i] = models.Resource{
			Id:                 resourceResp.Id,
			ResourceIdentifier: resourceResp.ResourceIdentifier,
			Description:        resourceResp.Description,
		}
	}

	return resources, nil
}

// GetPermissionsByResource retrieves permissions for a specific resource from the auth server
func (c *AuthServerClient) GetPermissionsByResource(accessToken string, resourceId int64) ([]models.Permission, error) {
    url := fmt.Sprintf("%s/api/v1/admin/resources/%d/permissions", c.baseURL, resourceId)


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
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}


	if resp.StatusCode != http.StatusOK {
		apiErr := parseAPIError(resp, body)
		return nil, apiErr
	}

	var apiResp api.GetPermissionsByResourceResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	permissions := make([]models.Permission, len(apiResp.Permissions))
	for i, permResp := range apiResp.Permissions {
		permissions[i] = models.Permission{
			Id:                   permResp.Id,
			PermissionIdentifier: permResp.PermissionIdentifier,
			Description:          permResp.Description,
			ResourceId:           permResp.ResourceId,
			Resource: models.Resource{
				Id:                 permResp.Resource.Id,
				ResourceIdentifier: permResp.Resource.ResourceIdentifier,
				Description:        permResp.Resource.Description,
			},
		}
	}

    return permissions, nil
}

// UpdateResourcePermissions replaces the full set of permission definitions for a resource
func (c *AuthServerClient) UpdateResourcePermissions(accessToken string, resourceId int64, request *api.UpdateResourcePermissionsRequest) error {
    url := fmt.Sprintf("%s/api/v1/admin/resources/%d/permissions", c.baseURL, resourceId)

    body, err := json.Marshal(request)
    if err != nil {
        return fmt.Errorf("failed to marshal request: %w", err)
    }

    req, err := http.NewRequest("PUT", url, bytes.NewBuffer(body))
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()

    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        return fmt.Errorf("failed to read response: %w", err)
    }
    if resp.StatusCode != http.StatusOK {
        return parseAPIError(resp, respBody)
    }
    return nil
}
