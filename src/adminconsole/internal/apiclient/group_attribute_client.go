package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/models"
)

func (c *AuthServerClient) GetGroupAttributesByGroupId(accessToken string, groupId int64) ([]models.GroupAttribute, error) {
	fullURL := c.baseURL + "/api/v1/admin/groups/" + strconv.FormatInt(groupId, 10) + "/attributes"

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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, respBody)
	}

	var response api.GetGroupAttributesResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert responses back to models.GroupAttribute
	attributes := make([]models.GroupAttribute, len(response.Attributes))
	for i, attrResp := range response.Attributes {
		if attr := attrResp.ToGroupAttribute(); attr != nil {
			attributes[i] = *attr
		}
	}

	return attributes, nil
}

func (c *AuthServerClient) GetGroupAttributeById(accessToken string, attributeId int64) (*models.GroupAttribute, error) {
	fullURL := c.baseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attributeId, 10)

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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, respBody)
	}

	var response api.GetGroupAttributeResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Attribute.ToGroupAttribute(), nil
}

func (c *AuthServerClient) CreateGroupAttribute(accessToken string, request *api.CreateGroupAttributeRequest) (*models.GroupAttribute, error) {
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	fullURL := c.baseURL + "/api/v1/admin/group-attributes"

	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(reqBody))
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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, parseAPIError(resp, respBody)
	}

	var response api.CreateGroupAttributeResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Attribute.ToGroupAttribute(), nil
}

func (c *AuthServerClient) UpdateGroupAttribute(accessToken string, attributeId int64, request *api.UpdateGroupAttributeRequest) (*models.GroupAttribute, error) {
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	fullURL := c.baseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attributeId, 10)

	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(reqBody))
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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, respBody)
	}

	var response api.UpdateGroupAttributeResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Attribute.ToGroupAttribute(), nil
}

func (c *AuthServerClient) DeleteGroupAttribute(accessToken string, attributeId int64) error {
	fullURL := c.baseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attributeId, 10)

	req, err := http.NewRequest("DELETE", fullURL, nil)
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