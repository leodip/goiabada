package apiclient

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/models"
)

func (c *AuthServerClient) GetUserSessionsByUserId(accessToken string, userId int64) ([]api.EnhancedUserSessionResponse, error) {
	fullURL := c.baseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/sessions"


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

	var response api.GetUserSessionsResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Sessions, nil
}

func (c *AuthServerClient) DeleteUserSessionById(accessToken string, sessionId int64) error {
	fullURL := c.baseURL + "/api/v1/admin/user-sessions/" + strconv.FormatInt(sessionId, 10)


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

	var response api.SuccessResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return fmt.Errorf("API returned success=false")
	}

	return nil
}

func (c *AuthServerClient) GetClientSessionsByClientId(accessToken string, clientId int64, page, size int) ([]api.EnhancedUserSessionResponse, error) {
    // Build URL with pagination params
    fullURL := c.baseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/sessions"
    // simple defaulting at caller, but include if provided
    if page > 0 || size > 0 {
        q := "?"
        if page > 0 {
            q += "page=" + strconv.Itoa(page)
        }
        if size > 0 {
            if page > 0 {
                q += "&"
            }
            q += "size=" + strconv.Itoa(size)
        }
        fullURL += q
    }

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

    var response api.GetUserSessionsResponse
    if err := json.Unmarshal(respBody, &response); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return response.Sessions, nil
}

func (c *AuthServerClient) GetUserSession(accessToken string, sessionIdentifier string) (*models.UserSession, error) {
	fullURL := c.baseURL + "/api/v1/admin/user-sessions/" + sessionIdentifier


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


	req, err := http.NewRequest("PUT", fullURL, bytes.NewBuffer(jsonData))
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

func (c *AuthServerClient) GetUserConsents(accessToken string, userId int64) ([]models.UserConsent, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/users/%d/consents", c.baseURL, userId)

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
