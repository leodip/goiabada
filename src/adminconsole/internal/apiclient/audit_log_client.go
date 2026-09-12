package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

func (c *AuthServerClient) GetSettingsAuditLogs(accessToken string) (*api.SettingsAuditLogsResponse, error) {
	fullURL := c.baseURL + "/api/v1/admin/settings/audit-logs"

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.SettingsAuditLogsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}
	return &response, nil
}

func (c *AuthServerClient) UpdateSettingsAuditLogs(accessToken string, request *api.UpdateSettingsAuditLogsRequest) (*api.SettingsAuditLogsResponse, error) {
	fullURL := c.baseURL + "/api/v1/admin/settings/audit-logs"

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.SettingsAuditLogsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}
	return &response, nil
}

func (c *AuthServerClient) GetAuditLogsPaginated(accessToken string, page, pageSize int, auditEvent string,
	requestId string) (*api.GetAuditLogsResponse, error) {
	fullURL := fmt.Sprintf("%s/api/v1/admin/audit-logs?page=%d&size=%d", c.baseURL, page, pageSize)
	if auditEvent != "" {
		fullURL += fmt.Sprintf("&auditEvent=%s", auditEvent)
	}
	if requestId != "" {
		// Escaped, unlike auditEvent above: the request id is whatever the client put in
		// X-Request-Id, so it can carry an & or a # and would otherwise be read as another
		// parameter or truncate the query (#328).
		fullURL += fmt.Sprintf("&requestId=%s", url.QueryEscape(requestId))
	}

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, body)
	}

	var response api.GetAuditLogsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}
	return &response, nil
}
