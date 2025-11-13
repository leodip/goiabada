package apiclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/dtos"
	"github.com/pkg/errors"
)

// SettingsClient fetches PUBLIC settings from the authserver's unauthenticated API.
// This is used by the middleware to populate settings that need to be available on every request
// (e.g., appName for page titles, uiTheme for styling, smtpEnabled for feature flags).
//
// IMPORTANT: This client calls /api/public/settings which does NOT require authentication.
// It returns a minimal subset of settings that are safe to expose publicly.
//
// For AUTHENTICATED settings operations (create/update/delete), see settings_general_client.go
// and other settings_*_client.go files which use the /api/v1/admin/settings/* endpoints.
type SettingsClient struct {
	httpClient        *http.Client
	authServerBaseURL string
}

func NewSettingsClient(authServerBaseURL string) *SettingsClient {
	return &SettingsClient{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		authServerBaseURL: authServerBaseURL,
	}
}

// GetPublicSettings fetches public settings from the unauthenticated /api/public/settings endpoint.
// No access token is required for this call.
// Returns only safe-to-share settings: appName, uiTheme, smtpEnabled.
func (c *SettingsClient) GetPublicSettings() (*dtos.PublicSettingsResponse, error) {
	url := fmt.Sprintf("%s/api/public/settings", c.authServerBaseURL)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch public settings from authserver")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("authserver returned status %d: %s", resp.StatusCode, string(body))
	}

	var settings dtos.PublicSettingsResponse
	if err := json.NewDecoder(resp.Body).Decode(&settings); err != nil {
		return nil, errors.Wrap(err, "failed to decode public settings response")
	}

	return &settings, nil
}
