package apiclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/boundedread"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// SettingsClient fetches PUBLIC settings from the authserver's unauthenticated API.
// This is used by the middleware to populate settings that need to be available on every request
// (e.g., appName for page titles, uiTheme for styling, smtpEnabled for feature flags, issuer
// for validating the iss claim on the administrator's own tokens).
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
// Returns only safe-to-share settings: appName, uiTheme, smtpEnabled, issuer. The issuer is
// already served anonymously at /.well-known/openid-configuration, which OIDC Discovery
// section 3 requires, so carrying it here discloses nothing new (#285).
//
// This is the admin console's second caller of the auth server, so it is bounded and carries a
// context on the same terms as the general client (#386). Both arms read through boundedread.Read
// before anything looks at them: the success arm used to decode straight off the wire through a
// json.Decoder, which stops at the first complete value and would therefore accept a truncated
// prefix with keys missing and say nothing, and the failure arm discarded its read error. The 10
// second timeout stays as it was.
func (c *SettingsClient) GetPublicSettings(ctx context.Context) (*api.PublicSettingsResponse, error) {
	url := fmt.Sprintf("%s/api/public/settings", c.authServerBaseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, errs.Wrap(err, "failed to build the public settings request")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Wrap(err, "failed to fetch public settings from authserver")
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := boundedread.Read(resp.Body, maxAPIResponseBytes)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errs.Errorf("authserver returned status %d: %s", resp.StatusCode, string(body))
	}

	var settings api.PublicSettingsResponse
	if err := json.Unmarshal(body, &settings); err != nil {
		return nil, errs.Wrap(err, "failed to decode public settings response")
	}

	return &settings, nil
}
