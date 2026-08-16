package integrationtests

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registeredQueryRedirectURI is a redirect URI registered with a query component of its own, which
// RFC 6749 section 3.1.2 expressly permits: the endpoint URI "MAY include an
// "application/x-www-form-urlencoded" formatted query component, which MUST be retained when adding
// additional query parameters".
//
// Its two fields do different jobs. "state=fixed" is a field the server is about to answer with, so
// it must be replaced rather than joined by a second one; before #146 the emitters called
// url.Values.Add and the client received both, with url.Values.Get returning the registered "fixed"
// as the CSRF token it was supposed to compare against. "lang=en" is a field the server never
// writes, so it must arrive exactly as registered.
const registeredQueryRedirectURI = "https://app.example.com/callback?state=fixed&lang=en"

// registeredQueryState is the state the client actually sends. Every character here has to survive
// the request parse, the auth context in the session cookie, the codes row and the escape on the way
// out: the space and the "+" because url.QueryEscape maps them onto each other, and "/" and "=" so
// that a base64 CSRF token, which is what RFC 9700 section 4.7.1 describes clients putting here,
// round-trips byte for byte. RFC 6749 section 4.1.2 requires "the exact value received from the
// client".
const registeredQueryState = "csrf a+b/c="

// registeredQueryStateEscaped is registeredQueryState as it must appear on the wire.
const registeredQueryStateEscaped = "csrf+a%2Bb%2Fc%3D"

// TestAuthorize_RegisteredQuery_SuccessRedirectCarriesOneState drives a whole authorization to the
// code redirect against a client whose registered redirect URI already carries a "state", and
// compares the emitted Location as a string.
//
// The unit tests around writeResponseParams hand-build a models.Code, so they assume a
// query-bearing redirect URI can be registered and then matched back by
// ValidateClientAndRedirectURI at all. This is the only tier that shows it (#146, decision 9).
func TestAuthorize_RegisteredQuery_SuccessRedirectCarriesOneState(t *testing.T) {
	client, user, password := newRegisteredQueryClient(t)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(registeredQueryRedirectURI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape("openid profile email") +
		"&state=" + url.QueryEscape(registeredQueryState) +
		"&nonce=" + gofakeit.LetterN(8)

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")

	// The code is read out of the response because only the server knows it. state is never read
	// this way: url.Values.Get returns the first of two, which is the registered value, so a
	// parsed read of the field under test would pass against the defect this case exists to catch.
	issued, err := url.Parse(location)
	require.NoError(t, err)
	code := issued.Query().Get("code")
	require.Len(t, code, 128)

	assert.Len(t, issued.Query()["state"], 1, "exactly one state must reach the client, got %q", location)
	assert.Equal(t,
		fmt.Sprintf("https://app.example.com/callback?lang=en&code=%s&state=%s", code, registeredQueryStateEscaped),
		location)
}

// TestAuthorize_RegisteredQuery_ErrorRedirectCarriesOneState is the same assertion on the error
// redirect, which is the one #146 was reported against.
//
// prompt=none with no session is the cheapest of the sixteen error redirects: handlePromptNone
// answers login_required on its first check, so there is no ceremony to walk and nothing about the
// error's cause is under test here, only the shape of the URI it is delivered in.
func TestAuthorize_RegisteredQuery_ErrorRedirectCarriesOneState(t *testing.T) {
	client, _, _ := newRegisteredQueryClient(t)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(registeredQueryRedirectURI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape("openid profile email") +
		"&state=" + url.QueryEscape(registeredQueryState) +
		"&nonce=" + gofakeit.LetterN(8) +
		"&prompt=none"

	// A fresh cookie jar, so this request carries no session and the silent authentication cannot
	// succeed.
	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")

	refused, err := url.Parse(location)
	require.NoError(t, err)

	assert.Len(t, refused.Query()["state"], 1, "exactly one state must reach the client, got %q", location)
	assert.Equal(t,
		"https://app.example.com/callback?lang=en&error=login_required"+
			"&error_description=User+authentication+is+required"+
			"&state="+registeredQueryStateEscaped,
		location)
}

// newRegisteredQueryClient creates a client whose only registered redirect URI carries a query, plus
// a user able to complete a level1 ceremony for it. It lives here rather than in utils_test.go
// because this file is its only reader.
func newRegisteredQueryClient(t *testing.T) (*models.Client, *models.User, string) {
	client := &models.Client{
		ClientIdentifier:         "registered-query-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
	}
	err := database.CreateClient(nil, client)
	require.NoError(t, err)

	err = database.CreateRedirectURI(nil, &models.RedirectURI{
		ClientId: client.Id,
		URI:      registeredQueryRedirectURI,
	})
	require.NoError(t, err)

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

	return client, user, password
}
