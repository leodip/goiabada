package apiclient

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/models"
)

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
		return nil, parseAPIError(resp)
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
		return nil, parseAPIError(resp)
	}

	var response api.UpdateUserResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.User.ToUser(), nil
}

func (c *AuthServerClient) GetUserSession(accessToken string, sessionIdentifier string) (*models.UserSession, error) {
	fullURL := c.baseURL + "/api/v1/admin/user-sessions/" + sessionIdentifier

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

	var response api.GetUserSessionResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert response to models.UserSession
	session := &models.UserSession{
		Id:                         response.Session.Id,
		SessionIdentifier:          response.Session.SessionIdentifier,
		AuthMethods:                response.Session.AuthMethods,
		AcrLevel:                   response.Session.AcrLevel,
		IpAddress:                  response.Session.IpAddress,
		DeviceName:                 response.Session.DeviceName,
		DeviceType:                 response.Session.DeviceType,
		DeviceOS:                   response.Session.DeviceOS,
		Level2AuthConfigHasChanged: response.Session.Level2AuthConfigHasChanged,
		UserId:                     response.Session.UserId,
	}

	if response.Session.CreatedAt != nil {
		session.CreatedAt = sql.NullTime{Time: *response.Session.CreatedAt, Valid: true}
	}
	if response.Session.UpdatedAt != nil {
		session.UpdatedAt = sql.NullTime{Time: *response.Session.UpdatedAt, Valid: true}
	}
	if response.Session.Started != nil {
		session.Started = *response.Session.Started
	}
	if response.Session.LastAccessed != nil {
		session.LastAccessed = *response.Session.LastAccessed
	}
	if response.Session.AuthTime != nil {
		session.AuthTime = *response.Session.AuthTime
	}

	return session, nil
}

func (c *AuthServerClient) UpdateUserSession(accessToken string, sessionIdentifier string, request *api.UpdateUserSessionRequest) (*models.UserSession, error) {
	fullURL := c.baseURL + "/api/v1/admin/user-sessions/" + sessionIdentifier

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

	var response api.GetUserSessionResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert response to models.UserSession
	session := &models.UserSession{
		Id:                         response.Session.Id,
		SessionIdentifier:          response.Session.SessionIdentifier,
		AuthMethods:                response.Session.AuthMethods,
		AcrLevel:                   response.Session.AcrLevel,
		IpAddress:                  response.Session.IpAddress,
		DeviceName:                 response.Session.DeviceName,
		DeviceType:                 response.Session.DeviceType,
		DeviceOS:                   response.Session.DeviceOS,
		Level2AuthConfigHasChanged: response.Session.Level2AuthConfigHasChanged,
		UserId:                     response.Session.UserId,
	}

	if response.Session.CreatedAt != nil {
		session.CreatedAt = sql.NullTime{Time: *response.Session.CreatedAt, Valid: true}
	}
	if response.Session.UpdatedAt != nil {
		session.UpdatedAt = sql.NullTime{Time: *response.Session.UpdatedAt, Valid: true}
	}
	if response.Session.Started != nil {
		session.Started = *response.Session.Started
	}
	if response.Session.LastAccessed != nil {
		session.LastAccessed = *response.Session.LastAccessed
	}
	if response.Session.AuthTime != nil {
		session.AuthTime = *response.Session.AuthTime
	}

	return session, nil
}