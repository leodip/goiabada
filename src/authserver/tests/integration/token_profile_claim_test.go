package integration

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// profile off the real wire: the URL of the user's profile page, OIDC Core 1.0 section 5.1, which
// is the admin console's /account/profile. The auth server routes no such page, and its base URL
// is what the claim was built on until #527. The ID token, the access token and /userinfo each
// carry it, both token settings turned on so a missing claim is the mapper's doing and not the
// deployment's.
func TestToken_Profile_IsTheAdminConsolesProfilePage(t *testing.T) {
	changeSettings(t, func(settings *record.Settings) {
		settings.IncludeOpenIDConnectClaimsInIdToken = true
		settings.IncludeOpenIDConnectClaimsInAccessToken = true
	})
	want := appConfig.AdminConsole.BaseURL + "/account/profile"
	require.NotEqual(t, appConfig.AuthServer.BaseURL, appConfig.AdminConsole.BaseURL,
		"the two base URLs must differ, or a profile built on the auth server's would pass")

	clientSecret := fake.LetterN(32)
	httpClient, code := createAuthCodeWithUserProfile(t, clientSecret, "openid profile")

	data := postToTokenEndpoint(t, httpClient, appConfig.AuthServer.BaseURL+"/auth/token/",
		url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {code.Client.ClientIdentifier},
			"code":          {code.Code},
			"redirect_uri":  {code.RedirectURI},
			"code_verifier": {testCodeVerifier},
			"client_secret": {clientSecret},
		})

	idToken, ok := data["id_token"].(string)
	require.True(t, ok, "the grant carries openid, so an id_token is issued")
	assert.Equal(t, want, decodeJWTPayload(t, idToken)["profile"])

	accessToken, ok := data["access_token"].(string)
	require.True(t, ok)
	assert.Equal(t, want, decodeJWTPayload(t, accessToken)["profile"])

	req, err := http.NewRequest("GET", appConfig.AuthServer.BaseURL+"/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	userinfoResp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = userinfoResp.Body.Close() }()
	require.Equal(t, http.StatusOK, userinfoResp.StatusCode)

	var userinfo map[string]interface{}
	require.NoError(t, json.NewDecoder(userinfoResp.Body).Decode(&userinfo))
	assert.Equal(t, want, userinfo["profile"])
}
