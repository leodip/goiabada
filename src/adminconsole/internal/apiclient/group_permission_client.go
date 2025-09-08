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

func (c *AuthServerClient) GetGroupPermissions(accessToken string, groupId int64) (*models.Group, []models.Permission, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/groups/%d/permissions", c.baseURL, groupId)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, parseAPIError(resp, respBody)
	}

	var apiResp api.GetGroupPermissionsResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	group := apiResp.Group.ToGroup()
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

	return group, permissions, nil
}

func (c *AuthServerClient) UpdateGroupPermissions(accessToken string, groupId int64, request *api.UpdateGroupPermissionsRequest) error {
	fullURL := fmt.Sprintf("%s/api/v1/admin/groups/%d/permissions", c.baseURL, groupId)

	reqBody, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return parseAPIError(resp, respBody)
	}

	return nil
}
