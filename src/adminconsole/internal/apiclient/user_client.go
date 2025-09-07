package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/models"
)

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

func (c *AuthServerClient) UpdateUserPassword(accessToken string, userId int64, request *api.UpdateUserPasswordRequest) (*models.User, error) {
	fullURL := c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/password"

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

func (c *AuthServerClient) UpdateUserOTP(accessToken string, userId int64, request *api.UpdateUserOTPRequest) (*models.User, error) {
	fullURL := c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/otp"

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