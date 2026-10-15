package integration

import (
	"context"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestToken_AuthCode_SessionRowSweptBeforeRedemption is the regression for #530.
//
// A session row can disappear without revoking its codes: a sign-out, a newer sign-in from
// the same device, and the background sweep of expired sessions all delete the row and leave
// a code in flight. The validator still redeems such a code (see the comment on
// TestValidateTokenRequest_AuthorizationCode_SessionOwnership: "the ordinary state of an
// older grant"), so issuance must not fail on the session read behind a session-bound
// refresh token's max lifetime. The grant answers with the access and ID tokens and no
// refresh token, never with a 500 server_error.
func TestToken_AuthCode_SessionRowSweptBeforeRedemption(t *testing.T) {
	clientSecret := fake.LetterN(32)
	// offline_access is left out on purpose: without it the grant is session-bound, which is
	// the only shape whose refresh token reads the session row.
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	// The sweep. The fixture's user is fresh, so the one session the ceremony left is the
	// code's own.
	sessions, err := database.GetUserSessionsByUserId(context.Background(), nil, code.User.Id)
	require.NoError(t, err)
	require.NotEmpty(t, sessions, "the ceremony should have left the user one session to sweep")
	for _, session := range sessions {
		err = database.DeleteUserSession(context.Background(), nil, session.Id)
		require.NoError(t, err)
	}

	gone, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, code.SessionIdentifier)
	require.NoError(t, err)
	require.Nil(t, gone, "the code's session row should be gone before the redemption")

	destUrl := appConfig.AuthServer.BaseURL + "/auth/token/"
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// The validator's contract holds: the code still redeems. What the answer must not carry
	// is a refresh token bound to a session row that no longer exists (#530).
	assert.NotEmpty(t, data["token_type"])
	assert.NotEmpty(t, data["access_token"])
	assert.NotEmpty(t, data["id_token"])
	assert.Contains(t, data["scope"], "openid")
	_, hasRefreshToken := data["refresh_token"]
	assert.False(t, hasRefreshToken, "a grant whose session row was swept must answer no session-bound refresh token")
	assert.NotContains(t, data, "error")
}
