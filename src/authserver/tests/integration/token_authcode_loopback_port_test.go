package integrationtests

import (
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestToken_AuthCode_LoopbackEphemeralPort walks the whole native app callback pattern from
// RFC 8252 section 7.3: the client registers a portless http loopback redirect URI, then
// presents an OS-assigned port at authorization time.
//
// The unit tests for this behaviour exercise a pure function (core/urlutil) and a mocked
// database (core/validators), so neither shows an ephemeral-port callback actually
// completing. This does (#41).
func TestToken_AuthCode_LoopbackEphemeralPort(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
	require.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "loopback-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 false,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	require.NoError(t, err)

	// Registered without a port, which is all a native app can know up front.
	registeredURI := "http://127.0.0.1/callback"
	err = database.CreateRedirectURI(nil, &models.RedirectURI{
		ClientId: client.Id,
		URI:      registeredURI,
	})
	require.NoError(t, err)

	// Ask the OS for a port the way a native app does, then release it: nothing in this
	// test connects to the callback, we only need a port number that could not have been
	// known at registration time.
	ephemeralPort := reserveEphemeralPort(t)
	requestedURI := fmt.Sprintf("http://127.0.0.1:%d/callback", ephemeralPort)

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	require.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	require.NoError(t, err)

	codeVerifier := "code-verifier"
	requestState := gofakeit.LetterN(8)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(requestedURI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + oauth.GeneratePKCECodeChallenge(codeVerifier) +
		"&scope=" + url.QueryEscape("openid profile email") +
		"&state=" + requestState +
		"&nonce=" + gofakeit.LetterN(8)

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// The authorization request is accepted despite the port mismatch against the
	// registered URI. Without the change this is where the flow would fail.
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// The code goes back to the port the client asked for, not the registered one:
	// handler_auth_issue.go redirects using code.RedirectURI.
	issuedLocation, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("127.0.0.1:%d", ephemeralPort), issuedLocation.Host)
	assert.Equal(t, "/callback", issuedLocation.Path)

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, requestedURI, code.RedirectURI)

	tokenUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// The token endpoint compares the code's stored URI against the one presented here,
	// which is requested against requested, and gets no port flexibility (decision 8).
	//
	// This must run BEFORE the successful exchange. Redeeming first would consume the code,
	// so a later wrong-port attempt would fail merely because the code was already used,
	// and this assertion would still pass even if the token endpoint had been switched to
	// flexible matching. A validation failure does not consume the code: ValidateTokenRequest
	// returns before MarkCodeAsUsed, and revocation only fires for AuthCodeReusedError.
	wrongPort := postToTokenEndpoint(t, httpClient, tokenUrl, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeVal},
		"redirect_uri":  {fmt.Sprintf("http://127.0.0.1:%d/callback", ephemeralPort+1)},
		"code_verifier": {codeVerifier},
	})
	assert.Equal(t, "invalid_grant", wrongPort["error"])
	assert.Equal(t, "Invalid redirect_uri.", wrongPort["error_description"])

	// Now redeem the still-unused code with the URI that was actually authorized.
	data := postToTokenEndpoint(t, httpClient, tokenUrl, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeVal},
		"redirect_uri":  {requestedURI},
		"code_verifier": {codeVerifier},
	})
	assert.Nil(t, data["error"])
	assert.NotNil(t, data["access_token"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.NotNil(t, data["id_token"])

	usedCode, err := database.GetCodeById(nil, code.Id)
	assert.NoError(t, err)
	assert.True(t, usedCode.Used)
}

// reserveEphemeralPort returns a port number the OS assigned, releasing it before returning
// so the test only carries the number and never occupies the port.
func reserveEphemeralPort(t *testing.T) int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	return port
}
