package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
)

type ApiClient interface {
	SearchUsersPaginated(accessToken, query string, page, pageSize int) ([]models.User, int, error)
	GetUserById(accessToken string, userId int64) (*models.User, error)
	UpdateUserEnabled(accessToken string, userId int64, enabled bool) (*models.User, error)
	UpdateUserProfile(accessToken string, userId int64, request *api.UpdateUserProfileRequest) (*models.User, error)
	UpdateUserAddress(accessToken string, userId int64, request *api.UpdateUserAddressRequest) (*models.User, error)
	CreateUserAdmin(accessToken string, request *api.CreateUserAdminRequest) (*models.User, error)
	DeleteUser(accessToken string, userId int64) error
	GetUserAttributesByUserId(accessToken string, userId int64) ([]models.UserAttribute, error)
	GetUserAttributeById(accessToken string, attributeId int64) (*models.UserAttribute, error)
	CreateUserAttribute(accessToken string, request *api.CreateUserAttributeRequest) (*models.UserAttribute, error)
	UpdateUserAttribute(accessToken string, attributeId int64, request *api.UpdateUserAttributeRequest) (*models.UserAttribute, error)
	DeleteUserAttribute(accessToken string, attributeId int64) error
}

type AuthServerClient struct {
	baseURL    string
	httpClient *http.Client
}

type APIError struct {
	Message    string
	Code       string
	StatusCode int
}

func (e *APIError) Error() string {
	return e.Message
}

func parseAPIError(resp *http.Response) *APIError {
	body, _ := io.ReadAll(resp.Body)

	// Try to parse as JSON error response
	var errorResp api.ErrorResponse
	if err := json.Unmarshal(body, &errorResp); err == nil {
		return &APIError{
			Message:    errorResp.Error.Message,
			Code:       errorResp.Error.Code,
			StatusCode: resp.StatusCode,
		}
	}

	// Fall back to plain text error (for backward compatibility)
	return &APIError{
		Message:    string(body),
		Code:       "UNKNOWN_ERROR",
		StatusCode: resp.StatusCode,
	}
}

func (c *AuthServerClient) debugLog(method, url string, reqBody []byte, resp *http.Response, respBody []byte, duration time.Duration, err error) {
	if !config.GetAdminConsole().DebugAPIRequests {
		return
	}

	// Sanitize auth header for logging
	authHeader := "None"
	if resp != nil && resp.Request != nil {
		if auth := resp.Request.Header.Get("Authorization"); auth != "" {
			if strings.HasPrefix(auth, "Bearer ") {
				authHeader = "Bearer ***"
			} else {
				authHeader = "*** (unknown type)"
			}
		}
	}

	// Log request
	slog.Info(fmt.Sprintf("[DEBUG API] → %s %s", method, url))
	slog.Info(fmt.Sprintf("[DEBUG API]   Headers: Authorization: %s", authHeader))

	// Log request body (if applicable)
	if len(reqBody) > 0 {
		var prettyReq bytes.Buffer
		if json.Indent(&prettyReq, reqBody, "[DEBUG API]   ", "  ") == nil {
			slog.Info(fmt.Sprintf("[DEBUG API]   Request Body:\n%s", prettyReq.String()))
		}
	}

	// Log response
	if resp != nil {
		if err != nil {
			slog.Info(fmt.Sprintf("[DEBUG API] ← ERROR %s (%s)", resp.Status, duration))
			slog.Info(fmt.Sprintf("[DEBUG API]   Error: %v", err))
		} else {
			slog.Info(fmt.Sprintf("[DEBUG API] ← %d %s (%s)", resp.StatusCode, resp.Status, duration))
		}
	} else if err != nil {
		slog.Info(fmt.Sprintf("[DEBUG API] ← ERROR (%s)", duration))
		slog.Info(fmt.Sprintf("[DEBUG API]   Error: %v", err))
	}

	// Log response body
	if len(respBody) > 0 {
		var prettyResp bytes.Buffer
		if json.Indent(&prettyResp, respBody, "[DEBUG API]   ", "  ") == nil {
			slog.Info(fmt.Sprintf("[DEBUG API]   Response Body:\n%s", prettyResp.String()))
		} else {
			slog.Info(fmt.Sprintf("[DEBUG API]   Response Body: %s", string(respBody)))
		}
	}

	slog.Info("[DEBUG API]") // Empty line for separation
}

func NewAuthServerClient() *AuthServerClient {
	authServerBaseURL := config.GetAuthServer().BaseURL

	return &AuthServerClient{
		baseURL:    authServerBaseURL,
		httpClient: &http.Client{},
	}
}

func (c *AuthServerClient) SearchUsersPaginated(accessToken, query string, page, pageSize int) ([]models.User, int, error) {
	// Build URL with query parameters
	fullURL := c.baseURL + "/api/v1/admin/users/search"
	u, err := url.Parse(fullURL)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse URL: %w", err)
	}

	params := url.Values{}
	params.Add("page", strconv.Itoa(page))
	params.Add("size", strconv.Itoa(pageSize))
	if query != "" {
		params.Add("query", query)
	}
	u.RawQuery = params.Encode()

	start := time.Now()

	// Create request
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		c.debugLog("GET", u.String(), nil, nil, nil, time.Since(start), err)
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	// Make request
	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.debugLog("GET", u.String(), nil, nil, nil, duration, err)
		return nil, 0, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("GET", u.String(), nil, resp, nil, duration, err)
		return nil, 0, fmt.Errorf("failed to read response body: %w", err)
	}

	c.debugLog("GET", u.String(), nil, resp, respBody, duration, nil)

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, 0, parseAPIError(resp)
	}

	// Parse response
	var response api.SearchUsersResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, 0, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert responses back to models.User
	users := make([]models.User, len(response.Users))
	for i, userResp := range response.Users {
		if user := userResp.ToUser(); user != nil {
			users[i] = *user
		}
	}

	return users, response.Total, nil
}

func (c *AuthServerClient) GetUserById(accessToken string, userId int64) (*models.User, error) {
	fullURL := c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10)

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
		return nil, parseAPIError(resp)
	}

	var response api.GetUserResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.User.ToUser(), nil
}

func (c *AuthServerClient) UpdateUserEnabled(accessToken string, userId int64, enabled bool) (*models.User, error) {
	fullURL := c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/enabled"

	request := api.UpdateUserEnabledRequest{
		Enabled: enabled,
	}

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
		return nil, parseAPIError(resp)
	}

	var response api.UpdateUserResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.User.ToUser(), nil
}

func (c *AuthServerClient) UpdateUserProfile(accessToken string, userId int64, request *api.UpdateUserProfileRequest) (*models.User, error) {
	fullURL := c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/profile"

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
		return nil, parseAPIError(resp)
	}

	var response api.UpdateUserResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.User.ToUser(), nil
}

func (c *AuthServerClient) UpdateUserAddress(accessToken string, userId int64, request *api.UpdateUserAddressRequest) (*models.User, error) {
	fullURL := c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/address"

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
		return nil, parseAPIError(resp)
	}

	var response api.UpdateUserResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.User.ToUser(), nil
}

func (c *AuthServerClient) CreateUserAdmin(accessToken string, request *api.CreateUserAdminRequest) (*models.User, error) {
	fullURL := c.baseURL + "/api/v1/admin/users/create"

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
		return nil, parseAPIError(resp)
	}

	var response api.CreateUserResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.User.ToUser(), nil
}

func (c *AuthServerClient) DeleteUser(accessToken string, userId int64) error {
	fullURL := c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10)

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
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("DELETE", fullURL, nil, resp, nil, duration, err)
		return fmt.Errorf("failed to read response body: %w", err)
	}

	c.debugLog("DELETE", fullURL, nil, resp, respBody, duration, nil)

	if resp.StatusCode != http.StatusOK {
		return parseAPIError(resp)
	}

	return nil
}

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
		return nil, parseAPIError(resp)
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
		return nil, parseAPIError(resp)
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
		return nil, parseAPIError(resp)
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
		return nil, parseAPIError(resp)
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
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("DELETE", fullURL, nil, resp, nil, duration, err)
		return fmt.Errorf("failed to read response body: %w", err)
	}

	c.debugLog("DELETE", fullURL, nil, resp, respBody, duration, nil)

	if resp.StatusCode != http.StatusOK {
		return parseAPIError(resp)
	}

	return nil
}