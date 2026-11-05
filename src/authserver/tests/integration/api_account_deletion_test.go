package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// POST /api/v1/account/deletion end to end (#783): the real server, its client guard, its rate
// limiter and its database. A user deletes their own account with their password and, while
// two-factor authentication is on, an authenticator code or a recovery code; their rows are gone,
// deleted_own_account is recorded, "Your account was deleted" arrives in Mailpit, and the token they
// called with is refused from then on. The route answers only tokens issued to the admin console's
// own client, so every deletion here signs in through that client.

const accountDeletionPath = "/api/v1/account/deletion"

// deletionUserPassword is the password every user here signs in with.
const deletionUserPassword = "Del3te!My-Account"

// consoleSignInUser creates an enabled user with a verified address, deletionUserPassword and the
// manage-account permission, as every user created through the server holds it. The user is deleted
// when the test ends, unless the test deleted them first.
func consoleSignInUser(t *testing.T, locale string) *record.User {
	t.Helper()
	hash, err := passwordhash.Hash(deletionUserPassword)
	require.NoError(t, err)
	user := &record.User{
		Subject: fake.UUID(), Enabled: true, Email: uniqueEmail("deleting@account.test"), EmailVerified: true,
		GivenName: "Dana", FamilyName: "Deleting", PasswordHash: hash, Locale: locale,
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	assignPermissionToUser(t, user.Id, authServerPermissionId(t, builtin.ManageAccountPermissionIdentifier))
	return user
}

// consoleAccessToken signs user in through the admin console's own client, as the console does, and
// answers the Account API access token it is issued. The helper the other Account API tests use
// signs in through a client it creates, and this route refuses those tokens.
func consoleAccessToken(t *testing.T, user *record.User) string {
	t.Helper()
	ctx := context.Background()
	console, err := database.GetClientByClientIdentifier(ctx, nil, builtin.AdminConsoleClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, console)
	secret, err := dataCipher.Decrypt(console.ClientSecretEncrypted)
	require.NoError(t, err)

	redirectURI := appConfig.AdminConsole.BaseURL + "/auth/callback"
	state := fake.LetterN(16)
	browser := createHttpClient(t)
	resp, err := browser.Get(appConfig.AuthServer.BaseURL + "/auth/authorize?" + url.Values{
		"client_id":             {builtin.AdminConsoleClientIdentifier},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {oauth.GeneratePKCECodeChallenge(testCodeVerifier)},
		"state":                 {state},
		"nonce":                 {fake.LetterN(16)},
		"scope":                 {"openid " + builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier},
	}.Encode())
	require.NoError(t, err)
	location := assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	location = assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()
	pwdPage := loadPage(t, browser, location)
	resp = authenticateWithPassword(t, browser, location, pwdPage, user.Email, deletionUserPassword)
	_ = pwdPage.Body.Close()
	location = assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	for strings.Contains(resp.Header.Get("Location"), "/auth/level2") {
		location = resp.Header.Get("Location")
		_ = resp.Body.Close()
		resp = loadPage(t, browser, location)
	}
	location = assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	location = assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()
	code, returnedState := getCodeAndStateFromUrl(t, resp)
	require.Equal(t, state, returnedState)

	tokens := postToTokenEndpoint(t, browser, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {builtin.AdminConsoleClientIdentifier},
		"client_secret": {secret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {testCodeVerifier},
	})
	accessToken, ok := tokens["access_token"].(string)
	require.True(t, ok, "the console's client is issued an access token: %v", tokens)
	return accessToken
}

// deleteAccount sends the deletion with accessToken and answers the status and the decoded body,
// with the request id it was sent under.
func deleteAccount(t *testing.T, accessToken string, body api.DeleteAccountRequest) (int, map[string]any, string) {
	t.Helper()
	resp, requestId := sendAdmin(t, accessToken, http.MethodPost, accountDeletionPath, body)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded), "body: %s", raw)
	return resp.StatusCode, decoded, requestId
}

// userExists reports whether the user's row is still there.
func userExists(t *testing.T, userId int64) bool {
	t.Helper()
	user, err := database.GetUserById(context.Background(), nil, userId)
	require.NoError(t, err)
	return user != nil
}

// assertTokenRefused checks that accessToken no longer reaches the Account API.
func assertTokenRefused(t *testing.T, accessToken string) {
	t.Helper()
	resp := makeAPIRequest(t, "GET", appConfig.AuthServer.BaseURL+"/api/v1/account/profile", accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "the deleted user's token is refused right after")
	var refusal api.ErrorResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&refusal))
	assert.Equal(t, "INVALID_TOKEN", refusal.ErrorCode)
}

// enableAuthenticatorOverAPI turns two-factor authentication on for the user through the Account
// API, with the console's token, and answers the seed and the recovery codes the enable created.
// The enable spends the previous step's code, so the current step's is left for the deletion.
func enableAuthenticatorOverAPI(t *testing.T, accessToken string) (string, []string) {
	t.Helper()
	secret := getOTPEnrollment(t, accessToken).SecretKey
	status, body := putAccountOTP(t, accessToken, api.UpdateAccountOTPRequest{
		Enabled: true, Password: deletionUserPassword, OtpCode: otptest.PreviousStepCode(t, secret),
	})
	require.Equal(t, http.StatusOK, status, body)
	var enabled api.UpdateAccountOTPResponse
	require.NoError(t, json.Unmarshal([]byte(body), &enabled))
	require.Len(t, enabled.RecoveryCodes, 10)
	return secret, enabled.RecoveryCodes
}

func TestAPIAccountDeletion_DeletesTheAccountWithThePassword(t *testing.T) {
	requireDatabaseAuditLogs(t)
	useMailpitSMTP(t)
	readerToken, _ := createAdminClientWithToken(t)
	user := consoleSignInUser(t, "en")
	accessToken := consoleAccessToken(t, user)

	status, body, requestId := deleteAccount(t, accessToken, api.DeleteAccountRequest{Password: deletionUserPassword})

	require.Equal(t, http.StatusOK, status, "body: %v", body)
	assert.Equal(t, map[string]any{"success": true}, body)
	assert.False(t, userExists(t, user.Id), "the account's row is gone")
	sessions, err := database.GetUserSessionsByUserId(context.Background(), nil, user.Id)
	require.NoError(t, err)
	assert.Empty(t, sessions, "the user is signed out everywhere")
	assertTokenRefused(t, accessToken)
	assert.Equal(t, []map[string]any{{"user_id": float64(user.Id), "logged_in_user": user.Subject}},
		auditRows(t, readerToken, "deleted_own_account", requestId))

	messages := awaitMailTo(t, user.Email)
	require.Len(t, messages, 1, "the account's address is told exactly once")
	assert.Equal(t, "Your account was deleted", messages[0].Subject)
	assert.Contains(t, messages[0].HTML, "someone else knew your password")
	assert.NotContains(t, messages[0].HTML, "href", "the notice carries no link")
}

func TestAPIAccountDeletion_TellsTheUserInTheirLanguage(t *testing.T) {
	useMailpitSMTP(t)
	user := consoleSignInUser(t, "pt-BR")
	accessToken := consoleAccessToken(t, user)

	status, body, _ := deleteAccount(t, accessToken, api.DeleteAccountRequest{Password: deletionUserPassword})

	require.Equal(t, http.StatusOK, status, "body: %v", body)
	messages := awaitMailTo(t, user.Email)
	require.Len(t, messages, 1)
	assert.Equal(t, "Sua conta foi excluída", messages[0].Subject)
}

func TestAPIAccountDeletion_DeletesWithAnAuthenticatorCode(t *testing.T) {
	user := consoleSignInUser(t, "en")
	accessToken := consoleAccessToken(t, user)
	secret, _ := enableAuthenticatorOverAPI(t, accessToken)

	// A password alone is refused while two-factor authentication is on, and spends nothing.
	status, body, _ := deleteAccount(t, accessToken, api.DeleteAccountRequest{Password: deletionUserPassword})
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "OTP_CODE_REQUIRED", body["error_code"])
	require.True(t, userExists(t, user.Id))

	code := otptest.Code(t, secret, time.Now())
	status, body, _ = deleteAccount(t, accessToken, api.DeleteAccountRequest{Password: deletionUserPassword, OtpCode: code})

	require.Equal(t, http.StatusOK, status, "body: %v", body)
	assert.False(t, userExists(t, user.Id))
	assertTokenRefused(t, accessToken)
}

// A recovery code stands in for the authenticator code, and the user is sent one email, the deletion's, and no recovery-code notice beside it.
func TestAPIAccountDeletion_DeletesWithARecoveryCode(t *testing.T) {
	useMailpitSMTP(t)
	user := consoleSignInUser(t, "en")
	accessToken := consoleAccessToken(t, user)
	_, codes := enableAuthenticatorOverAPI(t, accessToken)
	// The enable's own notice, read before the deletion so the count below is the deletion's.
	require.Len(t, awaitMailTo(t, user.Email), 1)

	status, body, _ := deleteAccount(t, accessToken, api.DeleteAccountRequest{
		Password: deletionUserPassword, RecoveryCode: codes[3]})

	require.Equal(t, http.StatusOK, status, "body: %v", body)
	assert.False(t, userExists(t, user.Id))
	assertTokenRefused(t, accessToken)
	require.Eventually(t, func() bool { return len(sentTo(t, user.Email)) == 2 }, afterResponseWait, 100*time.Millisecond,
		"the deletion's notice arrives beside the enable's")
	time.Sleep(time.Second)
	subjects := []string{}
	for _, summary := range sentTo(t, user.Email) {
		subjects = append(subjects, summary.Subject)
	}
	assert.ElementsMatch(t, []string{"Two-factor authentication was set up", "Your account was deleted"}, subjects,
		"one email for the deletion, and no recovery-code notice beside it")
}

// A wrong or used recovery code is refused with one answer and deletes nothing; a refused deletion
// spends no recovery code, so the same code still deletes afterwards.
func TestAPIAccountDeletion_RefusesAWrongOrUsedRecoveryCodeAndSpendsNone(t *testing.T) {
	user := consoleSignInUser(t, "en")
	accessToken := consoleAccessToken(t, user)
	_, codes := enableAuthenticatorOverAPI(t, accessToken)
	require.True(t, claimRecoveryCodeForTest(t, user.Id, codes[0]), "a code spent at a sign-in")

	for _, code := range []string{codes[0], "zzzz-zzzz-zzzz-zzzz-zzzz-zzzz"} {
		status, body, _ := deleteAccount(t, accessToken, api.DeleteAccountRequest{
			Password: deletionUserPassword, RecoveryCode: code})
		require.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "INVALID_RECOVERY_CODE", body["error_code"])
		assert.Equal(t, "That recovery code isn't right, or it was already used.", body["error_description"])
	}
	assert.True(t, userExists(t, user.Id))

	// Both codes at once is refused before anything is checked.
	status, body, _ := deleteAccount(t, accessToken, api.DeleteAccountRequest{
		Password: deletionUserPassword, OtpCode: "123456", RecoveryCode: codes[1]})
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "VALIDATION_ERROR", body["error_code"])
	assert.Equal(t, 9, getRecoveryCodesRemaining(t, accessToken), "no refused deletion spent a code")

	status, body, _ = deleteAccount(t, accessToken, api.DeleteAccountRequest{
		Password: deletionUserPassword, RecoveryCode: codes[1]})
	require.Equal(t, http.StatusOK, status, "body: %v", body)
	assert.False(t, userExists(t, user.Id))
}

// A wrong password is refused and deletes nothing; the five failures the account_password budget
// allows leave the user's password change refused too, since the two share the bucket.
func TestAPIAccountDeletion_AWrongPasswordSpendsTheSharedBudget(t *testing.T) {
	user := consoleSignInUser(t, "en")
	accessToken := consoleAccessToken(t, user)

	// A blank password compares nothing and spends nothing.
	status, body, _ := deleteAccount(t, accessToken, api.DeleteAccountRequest{Password: ""})
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "AUTHENTICATION_FAILED", body["error_code"])

	for i := 0; i < 5; i++ {
		status, body, _ = deleteAccount(t, accessToken, api.DeleteAccountRequest{Password: "Wr0ng!pass"})
		require.Equal(t, http.StatusBadRequest, status, "guess %d", i+1)
		assert.Equal(t, "AUTHENTICATION_FAILED", body["error_code"])
		assert.Equal(t, "That password isn't right. Try again.", body["error_description"])
	}
	assert.True(t, userExists(t, user.Id))

	resp := makeAPIRequest(t, "PUT", appConfig.AuthServer.BaseURL+"/api/v1/account/password", accessToken,
		api.UpdateAccountPasswordRequest{CurrentPassword: deletionUserPassword, NewPassword: fake.Password(20)})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "the deletion's failures spent the password change's budget")
}

// A token issued to any other client is refused by the route guard, whatever its scope, with the
// insufficient_scope challenge, and deletes nothing.
func TestAPIAccountDeletion_RefusesAnotherClientsToken(t *testing.T) {
	accessToken, user := getUserAccessTokenWithAccountScope(t)
	givePassword(t, user, deletionUserPassword)

	resp, _ := sendAdmin(t, accessToken, http.MethodPost, accountDeletionPath,
		api.DeleteAccountRequest{Password: deletionUserPassword})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, `Bearer realm="goiabada", error="insufficient_scope", error_description="This endpoint accepts only access tokens issued to the admin console's own client."`,
		resp.Header.Get("WWW-Authenticate"))
	var refusal api.ErrorResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&refusal))
	assert.Equal(t, "CLIENT_NOT_ALLOWED", refusal.ErrorCode)
	assert.True(t, userExists(t, user.Id))
}

// With the setting off, the deletion is refused before the password is read.
func TestAPIAccountDeletion_RefusedWhileTheSettingIsOff(t *testing.T) {
	user := consoleSignInUser(t, "en")
	accessToken := consoleAccessToken(t, user)
	changeSettings(t, func(settings *record.Settings) { settings.AccountDeletionEnabled = false })

	status, body, _ := deleteAccount(t, accessToken, api.DeleteAccountRequest{Password: deletionUserPassword})

	require.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "ACCOUNT_DELETION_DISABLED", body["error_code"])
	assert.Equal(t, "Account deletion is turned off. Ask your administrator to delete your account.", body["error_description"])
	assert.True(t, userExists(t, user.Id))
}

// The last enabled user holding authserver:manage is refused, with nothing deleted and, since the
// check comes before the password, nothing spent; once another administrator exists, they delete.
func TestAPIAccountDeletion_TheLastAdministratorIsRefused(t *testing.T) {
	disableOtherAdministrators(t)
	user := consoleSignInUser(t, "en")
	assignPermissionToUser(t, user.Id, authServerPermissionId(t, builtin.ManagePermissionIdentifier))
	accessToken := consoleAccessToken(t, user)

	for i := 0; i < 6; i++ {
		status, body, _ := deleteAccount(t, accessToken, api.DeleteAccountRequest{Password: "Wr0ng!pass"})
		require.Equal(t, http.StatusConflict, status, "attempt %d: %v", i+1, body)
		assert.Equal(t, "LAST_ADMINISTRATOR", body["error_code"])
		assert.Equal(t, "You're the last administrator, so you can't delete your account. Give another user authserver:manage first.",
			body["error_description"])
	}
	assert.True(t, userExists(t, user.Id))

	newAdministrator(t, authServerPermissionId(t, builtin.ManagePermissionIdentifier))
	status, body, _ := deleteAccount(t, accessToken, api.DeleteAccountRequest{Password: deletionUserPassword})
	require.Equal(t, http.StatusOK, status, "no password attempt was spent on the refusals: %v", body)
	assert.False(t, userExists(t, user.Id))
}
