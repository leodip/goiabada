package integration

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #137 over HTTP: the token endpoint reads the state of a grant's user only after the caller has
// proved it may redeem the grant. Before, a stolen code presented with a wrong verifier answered
// "Code is invalid." for an account whose password had changed and "The user account is disabled."
// for a disabled one, and the PKCE refusal only for an untouched account; a stolen refresh token
// presented under any public client_id said the same in plain words. The validator's tables own
// every state and proof; this shows the order holds on the wire, for the two states an attacker can
// learn about and the untouched control they are compared with.

// moveAccountState applies one state to a user the way the rows are left by the operations that
// cause it: the enabled flag written directly, and the generation advanced by the statement a
// credential change runs. Written straight to the database, because the admin API's own paths
// also revoke the user's grants, and the subject here is a grant that is still there.
func moveAccountState(t *testing.T, userId int64, state string) {
	t.Helper()

	switch state {
	case "untouched":
	case "disabled":
		user, err := database.GetUserById(context.Background(), nil, userId)
		require.NoError(t, err)
		require.NotNil(t, user)
		user.Enabled = false
		require.NoError(t, database.UpdateUser(context.Background(), nil, user))
	case "superseded":
		require.NoError(t, database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
			_, err := database.IncrementUserAuthStateGeneration(context.Background(), tx, userId)
			return err
		}))
	default:
		t.Fatalf("unknown account state %q", state)
	}
}

// postFormToTokenEndpoint sends one token request with the credentials in the form body, through
// token_invalid_client_test.go's postTokenRequest, and returns the status and the JSON body.
func postFormToTokenEndpoint(t *testing.T, form url.Values) (int, map[string]interface{}) {
	t.Helper()

	answer := postTokenRequest(t, form, false, "", "")
	return answer.status, answer.body
}

func assertTokenRefusal(t *testing.T, status int, body map[string]interface{},
	wantStatus int, wantError, wantDescription string) {
	t.Helper()

	assert.Equal(t, wantStatus, status)
	assert.Equal(t, wantError, body["error"])
	assert.Equal(t, wantDescription, body["error_description"])
	assert.Nil(t, body["access_token"])
}

func TestToken_AuthCode_AccountStateReadAfterPKCE(t *testing.T) {
	// The right verifier's answer per state; the wrong verifier's is the same for all three.
	for _, tc := range []struct {
		state           string
		wantDescription string
	}{
		{"untouched", ""},
		{"disabled", "Code is invalid."},
		{"superseded", "Code is invalid."},
	} {
		t.Run(tc.state, func(t *testing.T) {
			clientSecret := fake.Password(32)
			_, code := createAuthCode(t, clientSecret, "openid")
			moveAccountState(t, code.UserId, tc.state)

			form := func(verifier string) url.Values {
				return url.Values{
					"grant_type":    {"authorization_code"},
					"client_id":     {code.Client.ClientIdentifier},
					"client_secret": {clientSecret},
					"code":          {code.Code},
					"redirect_uri":  {code.RedirectURI},
					"code_verifier": {verifier},
				}
			}

			// A presenter without the verifier learns nothing about the account. The
			// refusal comes before the code is claimed, so the code is still there for
			// the request below.
			status, body := postFormToTokenEndpoint(t, form(testCodeVerifier+"-not-the-one"))
			assertTokenRefusal(t, status, body, http.StatusBadRequest, "invalid_grant", "Invalid code_verifier (PKCE).")

			status, body = postFormToTokenEndpoint(t, form(testCodeVerifier))
			if tc.wantDescription == "" {
				assert.Equal(t, http.StatusOK, status, "the untouched account's code must redeem: %v", body)
				assert.NotEmpty(t, body["access_token"])
				return
			}
			// The flat wording: never "The user account is disabled." (#137).
			assertTokenRefusal(t, status, body, http.StatusBadRequest, "invalid_grant", tc.wantDescription)
		})
	}
}

func TestToken_Refresh_AccountStateReadAfterOwnership(t *testing.T) {
	// Any public client: it authenticates with nothing, so an attacker holding a stolen refresh
	// token can always present it under one.
	otherClient := &models.Client{
		ClientIdentifier:         "other-public-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 true,
		DefaultAcrLevel:          models.AcrLevel1,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, otherClient))

	// The own client's answer per state; the other client's is the same for all three.
	for _, tc := range []struct {
		state           string
		wantDescription string
	}{
		{"untouched", ""},
		{"disabled", "The refresh token is invalid."},
		{"superseded", "The refresh token is invalid because it was superseded."},
	} {
		t.Run(tc.state, func(t *testing.T) {
			clientSecret := fake.Password(32)
			httpClient, code := createAuthCode(t, clientSecret, "openid")
			refreshToken := exchangeAuthCode(t, httpClient, code.Client.ClientIdentifier, clientSecret,
				code.Code, code.RedirectURI, testCodeVerifier)
			moveAccountState(t, code.UserId, tc.state)

			status, body := postFormToTokenEndpoint(t, url.Values{
				"grant_type":    {"refresh_token"},
				"client_id":     {otherClient.ClientIdentifier},
				"refresh_token": {refreshToken},
			})
			assertTokenRefusal(t, status, body, http.StatusBadRequest, "invalid_request",
				"The refresh token is invalid because it does not belong to the client.")

			status, body = postFormToTokenEndpoint(t, url.Values{
				"grant_type":    {"refresh_token"},
				"client_id":     {code.Client.ClientIdentifier},
				"client_secret": {clientSecret},
				"refresh_token": {refreshToken},
			})
			if tc.wantDescription == "" {
				assert.Equal(t, http.StatusOK, status, "the untouched account's token must refresh: %v", body)
				assert.NotEmpty(t, body["access_token"])
				return
			}
			assertTokenRefusal(t, status, body, http.StatusBadRequest, "invalid_grant", tc.wantDescription)
		})
	}
}
