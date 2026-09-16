package apiclient

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

func (c *AuthServerClient) GetUserAttributesByUserId(accessToken string, userId int64) ([]api.UserAttributeResponse, error) {
	fullURL := c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/attributes"

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, respBody)
	}

	var response api.GetUserAttributesResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return response.Attributes, nil
}

func (c *AuthServerClient) GetUserAttributeById(accessToken string, attributeId int64) (*api.UserAttributeResponse, error) {
	fullURL := c.baseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attributeId, 10)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, respBody)
	}

	var response api.GetUserAttributeResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &response.Attribute, nil
}

func (c *AuthServerClient) CreateUserAttribute(accessToken string, request *api.CreateUserAttributeRequest) (*api.UserAttributeResponse, error) {
	fullURL := c.baseURL + "/api/v1/admin/user-attributes"

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, errs.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, parseAPIError(resp, respBody)
	}

	var response api.CreateUserAttributeResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &response.Attribute, nil
}

func (c *AuthServerClient) UpdateUserAttribute(accessToken string, attributeId int64, request *api.UpdateUserAttributeRequest) (*api.UserAttributeResponse, error) {
	fullURL := c.baseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attributeId, 10)

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, errs.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, respBody)
	}

	var response api.UpdateUserAttributeResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}

	return &response.Attribute, nil
}

func (c *AuthServerClient) DeleteUserAttribute(accessToken string, attributeId int64) error {
	fullURL := c.baseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attributeId, 10)

	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errs.Errorf("failed to create request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return parseAPIError(resp, respBody)
	}

	return nil
}
