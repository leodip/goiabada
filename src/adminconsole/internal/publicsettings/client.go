package publicsettings

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/noredirect"
	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/boundedread"
	"github.com/leodip/goiabada/core/errs"
)

// clientTimeout bounds the one request the client makes. Ten seconds, the value
// apiclient's generalAPITimeout, oauthclient.TokenExchangeTimeout and sessionbackend's
// httpBackendTimeout share: all four sit on the page-load path, and a fourth distinct value
// there would only invite the question of why they differ (#386 decision 6). It also bounds
// the cache's shared fetch, which no caller's cancellation ends (#441 decision 4).
const clientTimeout = 10 * time.Second

// maxResponseBytes is the ceiling on the public settings answer. 1 MiB, the same value as
// apiclient's ceiling, oauthclient.MaxTokenResponseBytes and the session wire's, declared here
// because apiclient's is unexported and this package does not reach into the admin API client
// for a number (#441). The answer is four short fields, so anything near it is a peer replying
// with something absurd, and it is refused rather than cut by boundedread.Read.
const maxResponseBytes = 1 << 20

// Client fetches PUBLIC settings from the authserver's unauthenticated API.
// This is used by the middleware to populate settings that need to be available on every request
// (e.g., appName for page titles, uiTheme for styling, smtpEnabled for feature flags, issuer
// for validating the iss claim on the administrator's own tokens).
//
// IMPORTANT: This client calls /api/public/settings which does NOT require authentication.
// It returns a minimal subset of settings that are safe to expose publicly.
//
// For AUTHENTICATED settings operations (create/update/delete), see apiclient's settings
// methods, which use the /api/v1/admin/settings/* endpoints.
type Client struct {
	httpClient        *http.Client
	authServerBaseURL string
}

// NewClient builds the client, every call it makes recorded by upstream under the settings
// target (#400 decision 6). rootCAs is the pool it verifies the auth server's certificate
// against, nil for the system roots alone; main hands it the pool it built, so an https internal
// URL a private CA signed verifies once the operator names the CA through
// GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE (#525).
func NewClient(authServerBaseURL string, rootCAs *x509.CertPool, upstream *upstreammetrics.Recorder) *Client {
	// The transport is the default one carrying the configured roots, so the file's authorities
	// are trusted beside the system roots rather than in their place (#525).
	client := &http.Client{Timeout: clientTimeout}
	if rootCAs != nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{RootCAs: rootCAs}
		client.Transport = transport
	}
	return &Client{
		httpClient:        noredirect.Client(upstream.Client(upstreammetrics.Settings, client)),
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
// prefix with keys missing and say nothing, and the failure arm discarded its read error.
func (c *Client) GetPublicSettings(ctx context.Context) (*api.PublicSettingsResponse, error) {
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

	body, err := boundedread.Read(resp.Body, maxResponseBytes)
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
