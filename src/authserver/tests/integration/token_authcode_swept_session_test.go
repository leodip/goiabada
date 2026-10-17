package integration

import (
	"context"
	"net/http"
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
// a code in flight. The validator accepts such a code (see the comment on
// TestValidateTokenRequest_AuthorizationCode_SessionOwnership: "the ordinary state of an
// older grant"), and issuance then refuses a session-bound one as a revoked code is refused:
// 400 invalid_grant "Code is invalid.", never a 500 server_error, and never tokens whose sid
// names a session the server no longer holds, which /userinfo and the APIs would refuse at
// once.
func TestToken_AuthCode_SessionRowSweptBeforeRedemption(t *testing.T) {
	clientSecret := fake.LetterN(32)
	// offline_access is left out on purpose: without it the grant is session-bound, which is
	// the only shape whose tokens name the session row.
	_, code := createAuthCode(t, clientSecret, "openid profile email")

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

	status, body := postFormToTokenEndpoint(t, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
	})

	// The code is refused, as a revoked code is, and answers no tokens (#530).
	assertTokenRefusal(t, status, body, http.StatusBadRequest, "invalid_grant", "Code is invalid.")
	assert.Nil(t, body["id_token"])
	assert.Nil(t, body["refresh_token"])

	// The refusal comes after the claim, so the code is spent, as with any failed mint.
	storedCode, err := database.GetCodeById(context.Background(), nil, code.Id)
	require.NoError(t, err)
	require.NotNil(t, storedCode)
	assert.True(t, storedCode.Used, "the refused code should be spent")
}
