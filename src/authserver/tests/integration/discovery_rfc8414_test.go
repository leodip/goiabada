package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The OIDC discovery document is served unchanged at RFC 8414's address too, readable from any
// origin, so an OAuth client that looks only there, an MCP client built to the 2025-06-18
// specification among them, finds the same metadata (#576, decision 1).

func fetchDiscoveryAt(t *testing.T, path, origin string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, appConfig.AuthServer.BaseURL+path, nil)
	require.NoError(t, err)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, body
}

func TestDiscovery_TheRFC8414AddressServesTheOIDCDocument(t *testing.T) {
	// Both switch positions, since registration_endpoint is the one field a setting adds or drops.
	for _, dcr := range []bool{false, true} {
		name := "DCR off"
		if dcr {
			name = "DCR on"
		}
		t.Run(name, func(t *testing.T) {
			changeSettings(t, func(settings *record.Settings) { settings.DynamicClientRegistrationEnabled = dcr })

			oidcResp, oidcBody := fetchDiscoveryAt(t, "/.well-known/openid-configuration", "")
			rfcResp, rfcBody := fetchDiscoveryAt(t, "/.well-known/oauth-authorization-server", "")

			require.Equal(t, http.StatusOK, oidcResp.StatusCode)
			require.Equal(t, http.StatusOK, rfcResp.StatusCode, string(rfcBody))
			assert.Equal(t, oidcResp.Header.Get("Content-Type"), rfcResp.Header.Get("Content-Type"))

			var document map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(rfcBody, &document), string(rfcBody))
			// RFC 8414 section 2's required members, so the comparison below is of two documents.
			for _, required := range []string{"issuer", "authorization_endpoint", "token_endpoint", "response_types_supported"} {
				assert.Contains(t, document, required)
			}
			_, advertisesRegistration := document["registration_endpoint"]
			assert.Equal(t, dcr, advertisesRegistration)

			assert.JSONEq(t, string(oidcBody), string(rfcBody), "the two addresses serve one document")
		})
	}
}

func TestDiscovery_TheRFC8414AddressIsReadableCrossOrigin(t *testing.T) {
	const origin = "https://mcp-client.example"

	resp, _ := fetchDiscoveryAt(t, "/.well-known/oauth-authorization-server", origin)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, origin, resp.Header.Get("Access-Control-Allow-Origin"))
}
