package apiclient

import (
	"bytes"
	"database/sql"
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
	UpdateUserEmail(accessToken string, userId int64, request *api.UpdateUserEmailRequest) (*models.User, error)
	UpdateUserPhone(accessToken string, userId int64, request *api.UpdateUserPhoneRequest) (*models.User, error)
	UpdateUserPassword(accessToken string, userId int64, request *api.UpdateUserPasswordRequest) (*models.User, error)
	UpdateUserOTP(accessToken string, userId int64, request *api.UpdateUserOTPRequest) (*models.User, error)
	CreateUserAdmin(accessToken string, request *api.CreateUserAdminRequest) (*models.User, error)
	DeleteUser(accessToken string, userId int64) error
	GetUserAttributesByUserId(accessToken string, userId int64) ([]models.UserAttribute, error)
	GetUserAttributeById(accessToken string, attributeId int64) (*models.UserAttribute, error)
	CreateUserAttribute(accessToken string, request *api.CreateUserAttributeRequest) (*models.UserAttribute, error)
	UpdateUserAttribute(accessToken string, attributeId int64, request *api.UpdateUserAttributeRequest) (*models.UserAttribute, error)
	DeleteUserAttribute(accessToken string, attributeId int64) error
	GetUserSessionsByUserId(accessToken string, userId int64) ([]api.EnhancedUserSessionResponse, error)
	DeleteUserSessionById(accessToken string, sessionId int64) error
	GetUserSession(accessToken string, sessionIdentifier string) (*models.UserSession, error)
	UpdateUserSession(accessToken string, sessionIdentifier string, request *api.UpdateUserSessionRequest) (*models.UserSession, error)
	GetUserConsents(accessToken string, userId int64) ([]models.UserConsent, error)
	DeleteUserConsent(accessToken string, consentId int64) error
	GetAllGroups(accessToken string) ([]models.Group, error)
	GetUserGroups(accessToken string, userId int64) (*models.User, []models.Group, error)
	UpdateUserGroups(accessToken string, userId int64, request *api.UpdateUserGroupsRequest) (*models.User, []models.Group, error)
	GetUserPermissions(accessToken string, userId int64) (*models.User, []models.Permission, error)
	UpdateUserPermissions(accessToken string, userId int64, request *api.UpdateUserPermissionsRequest) error
	GetAllResources(accessToken string) ([]models.Resource, error)
	GetPermissionsByResource(accessToken string, resourceId int64) ([]models.Permission, error)
	GetPhoneCountries(accessToken string) ([]api.PhoneCountryResponse, error)
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

func parseAPIError(resp *http.Response, body []byte) *APIError {
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
		return nil, 0, parseAPIError(resp, respBody)
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
		return nil, parseAPIError(resp, respBody)
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
		return nil, parseAPIError(resp, respBody)
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
		return nil, parseAPIError(resp, respBody)
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
		return nil, parseAPIError(resp, respBody)
	}

	var response api.UpdateUserResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.User.ToUser(), nil
}

func (c *AuthServerClient) UpdateUserEmail(accessToken string, userId int64, request *api.UpdateUserEmailRequest) (*models.User, error) {
	fullURL := c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/email"

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
		return nil, parseAPIError(resp, respBody)
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
		return parseAPIError(resp, respBody)
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
		return parseAPIError(resp, respBody)
	}

	return nil
}

func (c *AuthServerClient) GetUserConsents(accessToken string, userId int64) ([]models.UserConsent, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/users/%d/consents", c.baseURL, userId)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
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

	var response api.GetUserConsentsResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Convert API response to models
	consents := make([]models.UserConsent, len(response.Consents))
	for i, consentResp := range response.Consents {
		consent := models.UserConsent{
			Id:       consentResp.Id,
			ClientId: consentResp.ClientId,
			UserId:   consentResp.UserId,
			Scope:    consentResp.Scope,
		}

		if consentResp.CreatedAt != nil {
			consent.CreatedAt = sql.NullTime{Time: *consentResp.CreatedAt, Valid: true}
		}
		if consentResp.UpdatedAt != nil {
			consent.UpdatedAt = sql.NullTime{Time: *consentResp.UpdatedAt, Valid: true}
		}
		if consentResp.GrantedAt != nil {
			consent.GrantedAt = sql.NullTime{Time: *consentResp.GrantedAt, Valid: true}
		}

		// Set client information
		consent.Client = models.Client{
			Id:               consentResp.ClientId,
			ClientIdentifier: consentResp.ClientIdentifier,
			Description:      consentResp.ClientDescription,
		}

		consents[i] = consent
	}

	return consents, nil
}

func (c *AuthServerClient) DeleteUserConsent(accessToken string, consentId int64) error {
	fullURL := fmt.Sprintf("%s/api/v1/admin/user-consents/%d", c.baseURL, consentId)

	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
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
		return parseAPIError(resp, respBody)
	}

	return nil
}

func (c *AuthServerClient) GetAllGroups(accessToken string) ([]models.Group, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/groups", c.baseURL)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	start := time.Now()
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

	var apiResp api.GetGroupsResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	groups := make([]models.Group, len(apiResp.Groups))
	for i, groupResp := range apiResp.Groups {
		group := models.Group{
			Id:                   groupResp.Id,
			GroupIdentifier:      groupResp.GroupIdentifier,
			Description:          groupResp.Description,
			IncludeInIdToken:     groupResp.IncludeInIdToken,
			IncludeInAccessToken: groupResp.IncludeInAccessToken,
		}

		if groupResp.CreatedAt != nil {
			group.CreatedAt = sql.NullTime{Time: *groupResp.CreatedAt, Valid: true}
		}
		if groupResp.UpdatedAt != nil {
			group.UpdatedAt = sql.NullTime{Time: *groupResp.UpdatedAt, Valid: true}
		}

		groups[i] = group
	}

	return groups, nil
}

func (c *AuthServerClient) GetUserGroups(accessToken string, userId int64) (*models.User, []models.Group, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/users/%d/groups", c.baseURL, userId)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.debugLog("GET", fullURL, nil, nil, nil, duration, err)
		return nil, nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("GET", fullURL, nil, resp, nil, duration, err)
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	c.debugLog("GET", fullURL, nil, resp, respBody, duration, nil)

	if resp.StatusCode != http.StatusOK {
		return nil, nil, parseAPIError(resp, respBody)
	}

	var apiResp api.GetUserGroupsResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	user := apiResp.User.ToUser()
	groups := make([]models.Group, len(apiResp.Groups))
	for i, groupResp := range apiResp.Groups {
		group := models.Group{
			Id:                   groupResp.Id,
			GroupIdentifier:      groupResp.GroupIdentifier,
			Description:          groupResp.Description,
			IncludeInIdToken:     groupResp.IncludeInIdToken,
			IncludeInAccessToken: groupResp.IncludeInAccessToken,
		}

		if groupResp.CreatedAt != nil {
			group.CreatedAt = sql.NullTime{Time: *groupResp.CreatedAt, Valid: true}
		}
		if groupResp.UpdatedAt != nil {
			group.UpdatedAt = sql.NullTime{Time: *groupResp.UpdatedAt, Valid: true}
		}

		groups[i] = group
	}

	return user, groups, nil
}

func (c *AuthServerClient) UpdateUserGroups(accessToken string, userId int64, request *api.UpdateUserGroupsRequest) (*models.User, []models.Group, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/users/%d/groups", c.baseURL, userId)

	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.debugLog("PUT", fullURL, reqBody, nil, nil, duration, err)
		return nil, nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("PUT", fullURL, reqBody, resp, nil, duration, err)
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	c.debugLog("PUT", fullURL, reqBody, resp, respBody, duration, nil)

	if resp.StatusCode != http.StatusOK {
		return nil, nil, parseAPIError(resp, respBody)
	}

	var apiResp api.GetUserGroupsResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	user := apiResp.User.ToUser()
	groups := make([]models.Group, len(apiResp.Groups))
	for i, groupResp := range apiResp.Groups {
		group := models.Group{
			Id:                   groupResp.Id,
			GroupIdentifier:      groupResp.GroupIdentifier,
			Description:          groupResp.Description,
			IncludeInIdToken:     groupResp.IncludeInIdToken,
			IncludeInAccessToken: groupResp.IncludeInAccessToken,
		}

		if groupResp.CreatedAt != nil {
			group.CreatedAt = sql.NullTime{Time: *groupResp.CreatedAt, Valid: true}
		}
		if groupResp.UpdatedAt != nil {
			group.UpdatedAt = sql.NullTime{Time: *groupResp.UpdatedAt, Valid: true}
		}

		groups[i] = group
	}

	return user, groups, nil
}

// GetUserPermissions retrieves user permissions from the auth server
func (c *AuthServerClient) GetUserPermissions(accessToken string, userId int64) (*models.User, []models.Permission, error) {
	url := fmt.Sprintf("%s/api/v1/admin/users/%d/permissions", c.baseURL, userId)
	
	start := time.Now()
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		c.debugLog("GET", url, nil, nil, nil, time.Since(start), err)
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.debugLog("GET", url, nil, nil, nil, duration, err)
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("GET", url, nil, resp, nil, duration, err)
		return nil, nil, fmt.Errorf("failed to read response: %w", err)
	}

	c.debugLog("GET", url, nil, resp, body, duration, nil)

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

	start := time.Now()

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(requestBody))
	if err != nil {
		c.debugLog("PUT", url, requestBody, nil, nil, time.Since(start), err)
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.debugLog("PUT", url, requestBody, nil, nil, duration, err)
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("PUT", url, requestBody, resp, nil, duration, err)
		return fmt.Errorf("failed to read response: %w", err)
	}

	c.debugLog("PUT", url, requestBody, resp, body, duration, nil)

	if resp.StatusCode != http.StatusOK {
		apiErr := parseAPIError(resp, body)
		return apiErr
	}

	return nil
}

// GetAllResources retrieves all resources from the auth server
func (c *AuthServerClient) GetAllResources(accessToken string) ([]models.Resource, error) {
	url := fmt.Sprintf("%s/api/v1/admin/resources", c.baseURL)
	
	start := time.Now()
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		c.debugLog("GET", url, nil, nil, nil, time.Since(start), err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.debugLog("GET", url, nil, nil, nil, duration, err)
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("GET", url, nil, resp, nil, duration, err)
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	c.debugLog("GET", url, nil, resp, body, duration, nil)

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
	
	start := time.Now()
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		c.debugLog("GET", url, nil, nil, nil, time.Since(start), err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.debugLog("GET", url, nil, nil, nil, duration, err)
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("GET", url, nil, resp, nil, duration, err)
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	c.debugLog("GET", url, nil, resp, body, duration, nil)

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

func (c *AuthServerClient) UpdateUserPhone(accessToken string, userId int64, request *api.UpdateUserPhoneRequest) (*models.User, error) {
	fullURL := c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/phone"

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

	var response api.UpdateUserResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.User.ToUser(), nil
}

func (c *AuthServerClient) GetPhoneCountries(accessToken string) ([]api.PhoneCountryResponse, error) {
	fullURL := c.baseURL + "/api/v1/admin/phone-countries"

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

	var response api.GetPhoneCountriesResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.PhoneCountries, nil
}

func (c *AuthServerClient) GetUserSessionsByUserId(accessToken string, userId int64) ([]api.EnhancedUserSessionResponse, error) {
	fullURL := c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/sessions"

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

	var response api.GetUserSessionsResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Sessions, nil
}

func (c *AuthServerClient) DeleteUserSessionById(accessToken string, sessionId int64) error {
	fullURL := c.baseURL + "/api/v1/admin/user-sessions/" + strconv.FormatInt(sessionId, 10)

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
		return parseAPIError(resp, respBody)
	}

	var response api.SuccessResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return fmt.Errorf("API returned success=false")
	}

	return nil
}
