package integration

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
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

	newPassword := fake.Password(20)
	resp = postCleanReset(t, client, cleanURL, newPassword, continuationId)
	body := bodyString(t, resp)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, resetSucceededText)

	assert.True(t, passwordhash.Verify(passwordHashOf(t, created.User.Id), newPassword),
		"the setup link must set the new account's password")
}

// createUserMembers creates a user through the admin API and returns the answer's status and its
// top-level members as they were written, so a member that is false can be told from one that is
// not there. The user is deleted when the test ends.
func createUserMembers(t *testing.T, req api.CreateUserAdminRequest) (int, map[string]json.RawMessage) {
	t.Helper()

	accessToken, _ := createAdminClientWithToken(t)
	resp := makeAPIRequest(t, "POST", appConfig.AuthServer.BaseURL+"/api/v1/admin/users/create", accessToken, req)
	defer func() { _ = resp.Body.Close() }()
	t.Cleanup(func() {
		if created, err := database.GetUserByEmail(context.Background(), nil, req.Email); err == nil && created != nil {
			_ = database.DeleteUser(context.Background(), nil, created.Id)
		}
	})

	var members map[string]json.RawMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&members))
	return resp.StatusCode, members
}

// refusingSMTPPort is a loopback port nothing listens on, so a send to it is refused at once. The
// server under test runs on this machine, so the loopback is what its dial reaches.
func refusingSMTPPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// A setup email that is sent is reported in the answer, and arrives.
func TestAPIUserCreatePost_ASetupEmailSentIsReported(t *testing.T) {
	useMailpitSMTP(t)

	email := plusAddress()
	status, members := createUserMembers(t, api.CreateUserAdminRequest{
		Email:           email,
		GivenName:       "Setup",
		FamilyName:      "Sent",
		SetPasswordType: api.SetPasswordTypeEmail,
	})

	require.Equal(t, http.StatusCreated, status)
	assert.Equal(t, json.RawMessage("true"), members["setupEmailSent"])
	onlyMailTo(t, email)
}

// #725: a relay that refuses the setup email no longer turns a create into a 500 for a user that
// exists. The answer is 201 with the user and setupEmailSent false, and the user is stored with
// the code its setup link would have carried, so an administrator can set a password or have the
// user use "Forgot password?" once email works.
func TestAPIUserCreatePost_ASetupEmailThatCannotBeSentAnswersTheUser(t *testing.T) {
	useMailpitSMTP(t)
	port := refusingSMTPPort(t)
	changeSettings(t, func(settings *record.Settings) {
		settings.SMTPHost = "127.0.0.1"
		settings.SMTPPort = port
	})

	email := plusAddress()
	status, members := createUserMembers(t, api.CreateUserAdminRequest{
		Email:           email,
		GivenName:       "Setup",
		FamilyName:      "Refused",
		SetPasswordType: api.SetPasswordTypeEmail,
	})

	require.Equal(t, http.StatusCreated, status)
	assert.Equal(t, json.RawMessage("false"), members["setupEmailSent"])
	var answered api.UserResponse
	require.NoError(t, json.Unmarshal(members["user"], &answered))
	assert.Equal(t, email, answered.Email)

	stored, err := database.GetUserByEmail(context.Background(), nil, email)
	require.NoError(t, err)
	require.NotNil(t, stored, "the user is created although its email was not sent")
	assert.Equal(t, answered.Id, stored.Id)
	assert.NotEmpty(t, stored.ForgotPasswordCodeHash, "the setup code is stored as when the email goes out")
}

// With email disabled, a request naming "email" behaves as it always has: it must carry a password,
// which is set, and the answer does not mention a setup email.
func TestAPIUserCreatePost_WithEmailDisabledTheAnswerHasNoSetupEmailSent(t *testing.T) {
	changeSettings(t, func(settings *record.Settings) {
		settings.SMTPEnabled = false
	})

	email := plusAddress()
	status, members := createUserMembers(t, api.CreateUserAdminRequest{
		Email:           email,
		SetPasswordType: api.SetPasswordTypeEmail,
		Password:        fake.Password(20),
	})

	require.Equal(t, http.StatusCreated, status)
	assert.NotContains(t, members, "setupEmailSent")
	assert.Contains(t, members, "user")
}
