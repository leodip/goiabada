package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/hashutil"
)

// A user the administrator creates with a set-password email is inserted already holding the code
// its emailed link carries, with no write after the insert to store it (#471 decision 4). What this
// owns is the round trip the unit tier cannot follow: the row the create left holds the hash of the
// code in the link Goiabada actually mailed, and that link sets the new account's password. The
// address is left unverified, which an administrator may do, and which is why the code cannot be
// stored after the insert by the conditional store a recovery request uses.
func TestAPIUserCreatePost_TheSetupEmailLinkSetsThePassword(t *testing.T) {
	useMailpitSMTP(t)
	accessToken, _ := createAdminClientWithToken(t)

	email := plusAddress()
	resp := makeAPIRequest(t, "POST", appConfig.AuthServer.BaseURL+"/api/v1/admin/users/create", accessToken,
		api.CreateUserAdminRequest{
			Email:           email,
			GivenName:       "Setup",
			FamilyName:      "Email",
			EmailVerified:   false,
			SetPasswordType: api.SetPasswordTypeEmail,
		})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created api.CreateUserResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	_ = resp.Body.Close()
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, created.User.Id) })

	link := latestResetLink(t, email)
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	code := parsed.Query().Get("code")
	require.NotEmpty(t, code)

	stored, err := database.GetUserById(context.Background(), nil, created.User.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, hashutil.HashString(code), stored.ForgotPasswordCodeHash,
		"the created row must hold the hash of the code the emailed link carries")
	assert.True(t, stored.ForgotPasswordCodeIssuedAt.Valid)
	assert.Empty(t, stored.PasswordHash, "the account is created with no password, for the link to set")

	client := createHttpClient(t)
	cleanURL := followResetLink(t, client, link)
	continuationId := loadResetForm(t, client, cleanURL)

	const newPassword = "N3wP4ss!word"
	resp = postCleanReset(t, client, cleanURL, newPassword, continuationId)
	body := bodyString(t, resp)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, resetSucceededText)

	assert.True(t, passwordhash.Verify(passwordHashOf(t, created.User.Id), newPassword),
		"the setup link must set the new account's password")
}
