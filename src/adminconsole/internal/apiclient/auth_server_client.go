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

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
)

type ApiClient interface {
	SearchUsersPaginated(accessToken, query string, page, pageSize int) ([]models.User, int, error)
	GetUserById(accessToken string, userId int64) (*models.User, error)
	UpdateUserEnabled(accessToken string, userId int64, enabled bool) (*models.User, error)
	UpdateUserProfile(accessToken string, userId int64, request *UpdateUserProfileRequest) (*models.User, error)
	UpdateUserAddress(accessToken string, userId int64, request *UpdateUserAddressRequest) (*models.User, error)
	CreateUserAdmin(accessToken string, request *CreateUserAdminRequest) (*models.User, error)
	DeleteUser(accessToken string, userId int64) error
}

type AuthServerClient struct {
	baseURL    string
	httpClient *http.Client
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
				authHeader = "***"
			}
		}
	}

	slog.Info(fmt.Sprintf("[DEBUG API] → %s %s", method, url))
	slog.Info(fmt.Sprintf("[DEBUG API]   Headers: Authorization: %s", authHeader))

	if len(reqBody) > 0 {
		var prettyReq bytes.Buffer
		if json.Indent(&prettyReq, reqBody, "[DEBUG API]   ", "  ") == nil {
			slog.Info(fmt.Sprintf("[DEBUG API]   Request Body:\n%s", prettyReq.String()))
		} else {
			slog.Info(fmt.Sprintf("[DEBUG API]   Request Body: %s", string(reqBody)))
		}
	}

	if err != nil {
		slog.Error(fmt.Sprintf("[DEBUG API] ← ERROR (%v): %v", duration, err))
		return
	}

	status := "Unknown"
	if resp != nil {
		status = fmt.Sprintf("%d %s", resp.StatusCode, resp.Status)
	}

	slog.Info(fmt.Sprintf("[DEBUG API] ← %s (%v)", status, duration))

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

type UsersSearchResponse struct {
	Users []models.User `json:"users"`
	Total int           `json:"total"`
	Page  int           `json:"page"`
	Size  int           `json:"size"`
	Query string        `json:"query"`
}

type UserResponse struct {
	User *models.User `json:"user"`
}

type UpdateUserEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

type CreateUserAdminRequest struct {
	Email           string `json:"email"`
	EmailVerified   bool   `json:"emailVerified"`
	GivenName       string `json:"givenName"`
	MiddleName      string `json:"middleName"`
	FamilyName      string `json:"familyName"`
	SetPasswordType string `json:"setPasswordType"`    // "now" or "email"
	Password        string `json:"password,omitempty"` // if "now"
}

type UpdateUserProfileRequest struct {
	Username            string `json:"username"`
	GivenName           string `json:"givenName"`
	MiddleName          string `json:"middleName"`
	FamilyName          string `json:"familyName"`
	Nickname            string `json:"nickname"`
	Website             string `json:"website"`
	Gender              string `json:"gender"`
	DateOfBirth         string `json:"dateOfBirth"`
	ZoneInfoCountryName string `json:"zoneInfoCountryName"`
	ZoneInfo            string `json:"zoneInfo"`
	Locale              string `json:"locale"`
}

type UpdateUserAddressRequest struct {
	AddressLine1      string `json:"addressLine1"`
	AddressLine2      string `json:"addressLine2"`
	AddressLocality   string `json:"addressLocality"`
	AddressRegion     string `json:"addressRegion"`
	AddressPostalCode string `json:"addressPostalCode"`
	AddressCountry    string `json:"addressCountry"`
}

type SuccessResponse struct {
	Success bool `json:"success"`
}

type ErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
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
	var errorResp ErrorResponse
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
	var response UsersSearchResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, 0, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Users, response.Total, nil
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

	var response UserResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.User, nil
}

func (c *AuthServerClient) UpdateUserEnabled(accessToken string, userId int64, enabled bool) (*models.User, error) {
	fullURL := c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/enabled"

	request := UpdateUserEnabledRequest{
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

	var response UserResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.User, nil
}

func (c *AuthServerClient) CreateUserAdmin(accessToken string, request *CreateUserAdminRequest) (*models.User, error) {
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

	var response UserResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.User, nil
}

func (c *AuthServerClient) UpdateUserProfile(accessToken string, userId int64, request *UpdateUserProfileRequest) (*models.User, error) {
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

	var response UserResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.User, nil
}

func (c *AuthServerClient) UpdateUserAddress(accessToken string, userId int64, request *UpdateUserAddressRequest) (*models.User, error) {
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

	var response UserResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.User, nil
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
