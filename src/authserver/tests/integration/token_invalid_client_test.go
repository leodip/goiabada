package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tokenRefusal is what a client receives from the token endpoint, status and challenge included,
// which postToTokenEndpoint does not return.
type tokenRefusal struct {
	status    int
	challenge string
	body      map[string]interface{}
}

// postTokenRequest posts form to the token endpoint, with clientId and clientSecret in the
// Authorization header when basic is set, and returns the refusal as received.
func postTokenRequest(t *testing.T, form url.Values, basic bool, clientId, clientSecret string) tokenRefusal {
	t.Helper()
	destUrl := appConfig.AuthServer.BaseURL + "/auth/token/"
	req, err := http.NewRequest("POST", destUrl, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", destUrl)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)
	if basic {
		req.SetBasicAuth(clientId, clientSecret)
	}

	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &body), "status %d, body: %s", resp.StatusCode, string(raw))
	return tokenRefusal{status: resp.StatusCode, challenge: resp.Header.Get("WWW-Authenticate"), body: body}
}

// TestToken_InvalidClient_OneShapeOverBothTransports is every invalid_client the token endpoint
// answers, as a client receives it over HTTP: 401 and WWW-Authenticate: Basic realm="goiabada",
// whether the credentials came in the Authorization header or in the form body. An unknown and a
// disabled client answered 400 with invalid_request and invalid_grant until #437, a form-body
// caller got no challenge and a Basic caller a bare "Basic"; the descriptions are unchanged but for
// the wrong secret, which is now one text for every grant (decisions 8, 9).
func TestToken_InvalidClient_OneShapeOverBothTransports(t *testing.T) {
	clientSecret := fake.Password(32)
	clientSecretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)

	newClient := func(enabled bool) *models.Client {
		client := &models.Client{
			ClientIdentifier:         "invalid-client-" + fake.LetterN(8),
			Enabled:                  enabled,
			ClientCredentialsEnabled: true,
			DefaultAcrLevel:          models.AcrLevel2Optional,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}
		require.NoError(t, database.CreateClient(context.Background(), nil, client))
		return client
	}
	enabled := newClient(true)
	disabled := newClient(false)

	rows := []struct {
		name        string
		clientId    string
		secret      string
		description string
	}{
		{"unknown client", "no-such-client-" + fake.LetterN(8), clientSecret, "Client does not exist."},
		{"disabled client", disabled.ClientIdentifier, clientSecret, "Client is disabled."},
		{"wrong secret", enabled.ClientIdentifier, "not-the-secret", "Client authentication failed. Please review your client_secret."},
		{"missing secret", enabled.ClientIdentifier, "",
			"This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed."},
	}

	for _, r := range rows {
		for _, basic := range []bool{false, true} {
			// Over Basic, a missing secret is the header's empty password ("client_id:").
			transport := "form body"
			if basic {
				transport = "Basic"
			}
			t.Run(r.name+", "+transport, func(t *testing.T) {
				form := url.Values{"grant_type": {"client_credentials"}}
				if !basic {
					form.Set("client_id", r.clientId)
					if r.secret != "" {
						form.Set("client_secret", r.secret)
					}
				}

				got := postTokenRequest(t, form, basic, r.clientId, r.secret)

				assert.Equal(t, http.StatusUnauthorized, got.status)
				assert.Equal(t, `Basic realm="goiabada"`, got.challenge)
				assert.Equal(t, "invalid_client", got.body["error"])
				assert.Equal(t, r.description, got.body["error_description"])
			})
		}
	}

	// The control: a request naming no client is invalid_request, 400, with no challenge.
	t.Run("missing client_id", func(t *testing.T) {
		got := postTokenRequest(t, url.Values{"grant_type": {"client_credentials"}}, false, "", "")

		assert.Equal(t, http.StatusBadRequest, got.status)
		assert.Empty(t, got.challenge)
		assert.Equal(t, "invalid_request", got.body["error"])
		assert.Equal(t, "Missing required client_id parameter.", got.body["error_description"])
	})

	// And the passing control, which shows the rows above were refused for the credential alone:
	// the same client and secret over each transport get past authentication, to the scope the
	// client holds none of.
	for _, basic := range []bool{false, true} {
		transport := "form body"
		if basic {
			transport = "Basic"
		}
		t.Run("right secret gets past authentication, "+transport, func(t *testing.T) {
			form := url.Values{"grant_type": {"client_credentials"}, "scope": {"no-such-resource:read"}}
			if !basic {
				form.Set("client_id", enabled.ClientIdentifier)
				form.Set("client_secret", clientSecret)
			}

			got := postTokenRequest(t, form, basic, enabled.ClientIdentifier, clientSecret)

			assert.Equal(t, http.StatusBadRequest, got.status)
			assert.Empty(t, got.challenge)
			assert.Equal(t, "invalid_scope", got.body["error"])
		})
	}
}

// TestToken_AuthCode_ClientSecretBasic_WrongSecretChallenge is the authorization code grant's wrong
// secret over Basic, the one transport RFC 6749 section 5.2 already required a challenge on: the
// challenge now names the realm RFC 7617 section 2 makes REQUIRED (#437 decision 9).
func TestToken_AuthCode_ClientSecretBasic_WrongSecretChallenge(t *testing.T) {
	clientSecret := fake.LetterN(32)
	_, code := createAuthCode(t, clientSecret, "openid profile email")

	got := postTokenRequest(t, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
	}, true, code.Client.ClientIdentifier, "wrong_secret")

	assert.Equal(t, http.StatusUnauthorized, got.status)
	assert.Equal(t, `Basic realm="goiabada"`, got.challenge)
	assert.Equal(t, "invalid_client", got.body["error"])
	assert.Equal(t, "Client authentication failed. Please review your client_secret.", got.body["error_description"])
}
