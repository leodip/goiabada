package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/models"
)

func (c *AuthServerClient) GetUserAttributesByUserId(accessToken string, userId int64) ([]models.UserAttribute, error) {
	fullURL := c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/attributes"

	start := time.Now()

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		c.debugLog("GET", fullURL, nil, nil, nil, time.Since(start), err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.debugLog("GET", fullURL, nil, nil, nil, duration, err)
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("GET", fullURL, nil, resp, nil, duration, err)
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	c.debugLog("GET", fullURL, nil, resp, respBody, duration, nil)

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, respBody)
	}

	var response api.GetUserAttributesResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert responses back to models.UserAttribute
	attributes := make([]models.UserAttribute, len(response.Attributes))
	for i, attrResp := range response.Attributes {
		if attr := attrResp.ToUserAttribute(); attr != nil {
			attributes[i] = *attr
		}
	}

	return attributes, nil
}

func (c *AuthServerClient) GetUserAttributeById(accessToken string, attributeId int64) (*models.UserAttribute, error) {
	fullURL := c.baseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attributeId, 10)

	start := time.Now()

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		c.debugLog("GET", fullURL, nil, nil, nil, time.Since(start), err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.debugLog("GET", fullURL, nil, nil, nil, duration, err)
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("GET", fullURL, nil, resp, nil, duration, err)
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	c.debugLog("GET", fullURL, nil, resp, respBody, duration, nil)

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, respBody)
	}

	var response api.GetUserAttributeResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Attribute.ToUserAttribute(), nil
}

func (c *AuthServerClient) CreateUserAttribute(accessToken string, request *api.CreateUserAttributeRequest) (*models.UserAttribute, error) {
	fullURL := c.baseURL + "/api/v1/admin/user-attributes"

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	start := time.Now()

	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		c.debugLog("POST", fullURL, jsonData, nil, nil, time.Since(start), err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.debugLog("POST", fullURL, jsonData, nil, nil, duration, err)
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("POST", fullURL, jsonData, resp, nil, duration, err)
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	c.debugLog("POST", fullURL, jsonData, resp, respBody, duration, nil)

	if resp.StatusCode != http.StatusCreated {
		return nil, parseAPIError(resp, respBody)
	}

	var response api.CreateUserAttributeResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Attribute.ToUserAttribute(), nil
}

func (c *AuthServerClient) UpdateUserAttribute(accessToken string, attributeId int64, request *api.UpdateUserAttributeRequest) (*models.UserAttribute, error) {
	fullURL := c.baseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attributeId, 10)

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	start := time.Now()

	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		c.debugLog("PUT", fullURL, jsonData, nil, nil, time.Since(start), err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.debugLog("PUT", fullURL, jsonData, nil, nil, duration, err)
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("PUT", fullURL, jsonData, resp, nil, duration, err)
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	c.debugLog("PUT", fullURL, jsonData, resp, respBody, duration, nil)

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, respBody)
	}

	var response api.UpdateUserAttributeResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Attribute.ToUserAttribute(), nil
}

func (c *AuthServerClient) DeleteUserAttribute(accessToken string, attributeId int64) error {
	fullURL := c.baseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attributeId, 10)

	start := time.Now()

	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		c.debugLog("DELETE", fullURL, nil, nil, nil, time.Since(start), err)
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.debugLog("DELETE", fullURL, nil, nil, nil, duration, err)
		return fmt.Errorf("failed to create request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("DELETE", fullURL, nil, resp, nil, duration, err)
		return fmt.Errorf("failed to read response body: %w", err)
	}

	c.debugLog("DELETE", fullURL, nil, resp, respBody, duration, nil)

	if resp.StatusCode != http.StatusOK {
		return parseAPIError(resp, respBody)
	}

	return nil
}