package integrationtests

import (
    "encoding/json"
    "net/http"
    "net/url"
    "testing"

    "github.com/brianvoe/gofakeit/v6"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/models"
    "github.com/stretchr/testify/assert"
)

// Helper to get a user access token with account scope and also the auth code details (client, redirect, sid)
// Returns (httpClientWithCookies, accessToken, code)
func getUserAccessTokenAndCodeForAccountScope(t *testing.T) (*http.Client, string, *models.Code) {
    scope := "openid profile email " + constants.AdminConsoleResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
    clientSecret := gofakeit.LetterN(32)
    httpClient, code := createAuthCodeEnsuringUserScope(t, clientSecret, scope)

    // Exchange code for tokens using the same client to preserve cookies for session
    tokenEndpoint := config.GetAuthServer().BaseURL + "/auth/token/"
    form := url.Values{
        "grant_type":    {"authorization_code"},
        "client_id":     {code.Client.ClientIdentifier},
        "client_secret": {clientSecret},
        "code":          {code.Code},
        "redirect_uri":  {code.RedirectURI},
        "code_verifier": {"code-verifier"},
    }
    data := postToTokenEndpoint(t, httpClient, tokenEndpoint, form)
    accessToken, ok := data["access_token"].(string)
    assert.True(t, ok)
    assert.NotEmpty(t, accessToken)
    return httpClient, accessToken, code
}

func TestAPIAccountLogoutRequest_Success_And_LogoutFlow_WithAndWithoutCookie(t *testing.T) {
    // Arrange: create session and token with account scope
    httpClientWithCookies, accessToken, code := getUserAccessTokenAndCodeForAccountScope(t)

    // Request logout URL
    reqBody := api.AccountLogoutRequest{
        PostLogoutRedirectUri: code.RedirectURI,
        State:                 gofakeit.LetterN(12),
        ResponseMode:          "redirect",
    }
    urlLogoutReq := config.GetAuthServer().BaseURL + "/api/v1/account/logout-request"
    resp := makeAPIRequest(t, "POST", urlLogoutReq, accessToken, reqBody)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    var out api.AccountLogoutRedirectResponse
    err := json.NewDecoder(resp.Body).Decode(&out)
    assert.NoError(t, err)
    assert.NotEmpty(t, out.LogoutUrl)

    // Parse returned logout URL and verify parameters
    u, err := url.Parse(out.LogoutUrl)
    assert.NoError(t, err)
    assert.Equal(t, "/auth/logout", u.Path)
    q := u.Query()
    assert.NotEmpty(t, q.Get("id_token_hint"))
    assert.Equal(t, code.RedirectURI, q.Get("post_logout_redirect_uri"))
    assert.Equal(t, reqBody.State, q.Get("state"))

    // 1) Call /auth/logout with cookies: expect 302 to post_logout_redirect with sid present
    req1, _ := http.NewRequest("GET", out.LogoutUrl, nil)
    resp1, err := httpClientWithCookies.Do(req1)
    assert.NoError(t, err)
    defer resp1.Body.Close()
    assert.Equal(t, http.StatusFound, resp1.StatusCode)
    loc1, err := url.Parse(resp1.Header.Get("Location"))
    assert.NoError(t, err)
    assert.Equal(t, code.RedirectURI, loc1.Scheme+"://"+loc1.Host+loc1.Path)
    assert.Equal(t, reqBody.State, loc1.Query().Get("state"))
    assert.Equal(t, code.SessionIdentifier, loc1.Query().Get("sid"))

    // 2) Call /auth/logout without cookies (new client): expect 302 with sid from id_token_hint (fallback)
    httpClientNoCookies := createHttpClient(t)
    req2, _ := http.NewRequest("GET", out.LogoutUrl, nil)
    resp2, err := httpClientNoCookies.Do(req2)
    assert.NoError(t, err)
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusFound, resp2.StatusCode)
    loc2, err := url.Parse(resp2.Header.Get("Location"))
    assert.NoError(t, err)
    assert.Equal(t, code.RedirectURI, loc2.Scheme+"://"+loc2.Host+loc2.Path)
    assert.Equal(t, reqBody.State, loc2.Query().Get("state"))
    assert.Equal(t, code.SessionIdentifier, loc2.Query().Get("sid"))
}

func TestAPIAccountLogoutRequest_ValidationErrors_And_Scope(t *testing.T) {
    _, accessToken, _ := getUserAccessTokenAndCodeForAccountScope(t)
    urlLogoutReq := config.GetAuthServer().BaseURL + "/api/v1/account/logout-request"

    // Missing postLogoutRedirectUri
    resp1 := makeAPIRequest(t, "POST", urlLogoutReq, accessToken, map[string]string{})
    defer resp1.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
    var err1 api.ErrorResponse
    _ = json.NewDecoder(resp1.Body).Decode(&err1)
    assert.Equal(t, "postLogoutRedirectUri is required", err1.Error.Message)

    // Unresolvable postLogoutRedirectUri (no client matches)
    badReq := api.AccountLogoutRequest{PostLogoutRedirectUri: "https://invalid.example/"}
    resp2 := makeAPIRequest(t, "POST", urlLogoutReq, accessToken, badReq)
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
    var err2 api.ErrorResponse
    _ = json.NewDecoder(resp2.Body).Decode(&err2)
    assert.Equal(t, "Unable to resolve client from postLogoutRedirectUri; supply clientIdentifier.", err2.Error.Message)

    // Scope and auth checks
    // No token
    reqNoTok, _ := http.NewRequest("POST", urlLogoutReq, nil)
    httpClient := createHttpClient(t)
    resp3, err := httpClient.Do(reqNoTok)
    assert.NoError(t, err)
    defer resp3.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp3.StatusCode)

    // Insufficient scope
    tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
    resp4 := makeAPIRequest(t, "POST", urlLogoutReq, tok, api.AccountLogoutRequest{PostLogoutRedirectUri: "https://example.com/"})
    defer resp4.Body.Close()
    assert.Equal(t, http.StatusForbidden, resp4.StatusCode)
}
