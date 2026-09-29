package integration

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The bearer guards answer RFC 6750 on both surfaces they guard, each in its own body (#435). The
// middleware's own table owns every row; this tier shows the few that prove routes.go hands each
// surface the right guard set: /userinfo and one admin route each, the realm-only challenge with no
// credential, a lowercase scheme admitted, a token sent twice refused, and a form body that does not
// parse refused beside a valid header. It is deliberately thin.

// bearerRFC6750Response is what a caller observes of one request.
type bearerRFC6750Response struct {
	status    int
	challenge string
	body      string
}

// sendBearerRequest sends method to path with the Authorization header set when authorization is
// not empty, and form as an application/x-www-form-urlencoded body when it is not empty. form is
// sent as written, so a caller can send a body that does not parse.
func sendBearerRequest(t *testing.T, method, path, authorization string, form string) bearerRFC6750Response {
	t.Helper()
	var body io.Reader
	if form != "" {
		body = strings.NewReader(form)
	}
	req, err := http.NewRequest(method, appConfig.AuthServer.BaseURL+path, body)
	require.NoError(t, err)
	if form != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return bearerRFC6750Response{status: resp.StatusCode, challenge: resp.Header.Get("WWW-Authenticate"), body: string(raw)}
}

const bearerRFC6750AdminRoute = "/api/v1/admin/settings/general"

// RFC 6750 section 3.1: a request lacking any authentication information SHOULD NOT be told an
// error code; section 3's one required auth-param is the realm.
func TestBearerRFC6750_NoCredentialIsTheRealmAlone(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		userinfo := sendBearerRequest(t, method, "/userinfo", "", "")
		assert.Equal(t, http.StatusUnauthorized, userinfo.status, "%s /userinfo: %s", method, userinfo.body)
		assert.Equal(t, `Bearer realm="goiabada"`, userinfo.challenge, "%s /userinfo", method)
		assert.Empty(t, userinfo.body, "%s /userinfo: no error information in the body either", method)
	}

	admin := sendBearerRequest(t, "GET", bearerRFC6750AdminRoute, "", "")
	assert.Equal(t, http.StatusUnauthorized, admin.status, admin.body)
	assert.Equal(t, `Bearer realm="goiabada"`, admin.challenge)
	assert.JSONEq(t, `{"error_code":"ACCESS_TOKEN_REQUIRED","error_description":"Access token required."}`, admin.body,
		"the admin API keeps its documented envelope")

	basic := sendBearerRequest(t, "GET", bearerRFC6750AdminRoute, "Basic dXNlcjpwYXNz", "")
	assert.Equal(t, http.StatusUnauthorized, basic.status, basic.body)
	assert.Equal(t, `Bearer realm="goiabada"`, basic.challenge, "another scheme is no bearer credential")
}

// RFC 6750 section 2.1's scheme is case insensitive (RFC 5234 section 2.3), and resource servers
// MUST support the method.
func TestBearerRFC6750_TheSchemeIsCaseInsensitive(t *testing.T) {
	userToken, user := createUserAccessTokenWithScope(t, "openid profile")
	for _, scheme := range []string{"bearer", "BEARER"} {
		userinfo := sendBearerRequest(t, "GET", "/userinfo", scheme+" "+userToken, "")
		require.Equal(t, http.StatusOK, userinfo.status, "%s /userinfo: %s", scheme, userinfo.body)
		assert.Contains(t, userinfo.body, user.Subject)
	}

	adminToken, _ := createAdminClientWithToken(t)
	admin := sendBearerRequest(t, "GET", bearerRFC6750AdminRoute, "bearer "+adminToken, "")
	assert.Equal(t, http.StatusOK, admin.status, admin.body)
}

// RFC 6750 section 2: clients MUST NOT use more than one method; section 3.1 names such a request
// invalid_request, which SHOULD be answered 400. Before #435 the header silently won.
func TestBearerRFC6750_ATokenSentTwiceIsInvalidRequest(t *testing.T) {
	const challenge = `Bearer realm="goiabada", error="invalid_request", error_description="The access token must be sent by one method only."`

	userToken, _ := createUserAccessTokenWithScope(t, "openid profile")
	userinfo := sendBearerRequest(t, "POST", "/userinfo", "Bearer "+userToken, url.Values{"access_token": {userToken}}.Encode())
	assert.Equal(t, http.StatusBadRequest, userinfo.status, userinfo.body)
	assert.Equal(t, challenge, userinfo.challenge)
	assert.JSONEq(t, `{"error":"invalid_request","error_description":"The access token must be sent by one method only."}`, userinfo.body)

	adminToken, _ := createAdminClientWithToken(t)
	admin := sendBearerRequest(t, "POST", "/api/v1/admin/resources", "Bearer "+adminToken, url.Values{"access_token": {adminToken}}.Encode())
	assert.Equal(t, http.StatusBadRequest, admin.status, admin.body)
	assert.Equal(t, challenge, admin.challenge)
	assert.JSONEq(t, `{"error_code":"INVALID_REQUEST","error_description":"The access token must be sent by one method only."}`, admin.body)
}

// RFC 6750 section 3.1 names a request that "is otherwise malformed" invalid_request. A form body
// that does not parse cannot say whether it carries a second token, so a valid header beside it is
// not admitted. Before this, the header was admitted and /userinfo answered 200.
func TestBearerRFC6750_AFormBodyThatDoesNotParseIsInvalidRequest(t *testing.T) {
	const challenge = `Bearer realm="goiabada", error="invalid_request", error_description="The request body could not be parsed."`

	userToken, _ := createUserAccessTokenWithScope(t, "openid profile")
	userinfo := sendBearerRequest(t, "POST", "/userinfo", "Bearer "+userToken, "access_token="+userToken+"&junk=%GG")
	assert.Equal(t, http.StatusBadRequest, userinfo.status, userinfo.body)
	assert.Equal(t, challenge, userinfo.challenge)
	assert.JSONEq(t, `{"error":"invalid_request","error_description":"The request body could not be parsed."}`, userinfo.body)

	adminToken, _ := createAdminClientWithToken(t)
	admin := sendBearerRequest(t, "POST", "/api/v1/admin/resources", "Bearer "+adminToken, "junk=%GG")
	assert.Equal(t, http.StatusBadRequest, admin.status, admin.body)
	assert.Equal(t, challenge, admin.challenge)
	assert.JSONEq(t, `{"error_code":"INVALID_REQUEST","error_description":"The request body could not be parsed."}`, admin.body)
}
