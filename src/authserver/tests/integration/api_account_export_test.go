package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GET /api/v1/account/export end to end (#782): the real server, its guards in their order, its
// rate limiter and its database. The admin console's own client downloads the signed-in user's
// data, the administrator's download of them byte for byte but for when it was made, once its
// sign-in is within the last 300 seconds and at urn:goiabada:level2_optional or above; an older or
// weaker one gets RFC 9470's step-up challenge, and a prompt=login sign-in with those acr_values
// asks for the password, and the code from a user with an authenticator, keeps the session and its
// other apps, and downloads. Another client is CLIENT_NOT_ALLOWED. Every download is
// exported_own_user_data, and the sixth in an hour is refused.

const accountExportPath = "/api/v1/account/export"

// stepUpChallenge is the WWW-Authenticate value of every step-up refusal, written out from RFC 9470
// section 3 and #782 decision 1, with the DPoP challenge every 401 carries after the Bearer one.
const stepUpChallenge = `Bearer realm="goiabada", error="insufficient_user_authentication", ` +
	`error_description="This endpoint requires a more recent sign-in, or a stronger one.", ` +
	`acr_values="urn:goiabada:level2_optional", max_age="300", ` + dpopChallengeBare

// getAccountExport asks for the caller's own export with accessToken and the Accept-Encoding given.
func getAccountExport(t *testing.T, accessToken, acceptEncoding string) exportAnswer {
	t.Helper()
	return getExportAt(t, accessToken, accountExportPath, acceptEncoding)
}

// signInClient is a client a browser signs in through.
type signInClient struct {
	identifier, redirectURI, secret, scope string
}

// consoleSignInClient is the admin console's own client, asking for what the console asks for.
func consoleSignInClient(t *testing.T) signInClient {
	t.Helper()
	console, err := database.GetClientByClientIdentifier(context.Background(), nil, builtin.AdminConsoleClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, console)
	secret, err := dataCipher.Decrypt(console.ClientSecretEncrypted)
	require.NoError(t, err)
	return signInClient{
		identifier:  builtin.AdminConsoleClientIdentifier,
		redirectURI: appConfig.AdminConsole.BaseURL + "/auth/callback",
		secret:      secret,
		scope:       "openid " + builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier,
	}
}

// signIn is what one authorization on a browser asked for and was issued.
type signIn struct {
	tokens        map[string]interface{}
	askedPassword bool
	askedCode     bool
}

func (s signIn) accessToken(t *testing.T) string {
	t.Helper()
	token, ok := s.tokens["access_token"].(string)
	require.True(t, ok, "an access token is issued: %v", s.tokens)
	return token
}

// signInOn runs one authorization of client on browser, with the extra parameters given, to its
// tokens. It answers the password page with deletionUserPassword and the code page with code(),
// whichever the ceremony shows, and records which it showed. A browser holding a session may be
// shown neither.
func signInOn(t *testing.T, browser *http.Client, client signInClient, user *record.User, code func() string,
	extra url.Values) signIn {

	t.Helper()
	state := fake.LetterN(16)
	params := url.Values{
		"client_id":             {client.identifier},
		"redirect_uri":          {client.redirectURI},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {oauth.GeneratePKCECodeChallenge(testCodeVerifier)},
		"state":                 {state},
		"nonce":                 {fake.LetterN(16)},
		"scope":                 {client.scope},
	}
	for name, values := range extra {
		params[name] = values
	}

	var result signIn
	resp := loadPage(t, browser, appConfig.AuthServer.BaseURL+"/auth/authorize?"+params.Encode())
	// Bounded, so a ceremony that started cycling fails the test rather than hanging the suite.
	for step := 0; ; step++ {
		require.Less(t, step, 15, "the sign-in did not reach the client's redirect URI")
		require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, resp.StatusCode,
			"the sign-in stopped at %s", resp.Request.URL.Path)
		location := resp.Header.Get("Location")
		_ = resp.Body.Close()

		if strings.HasPrefix(location, client.redirectURI+"?") {
			redirected, err := url.Parse(location)
			require.NoError(t, err)
			require.Equal(t, state, redirected.Query().Get("state"))
			result.tokens = postToTokenEndpoint(t, browser, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {client.identifier},
				"client_secret": {client.secret},
				"code":          {redirected.Query().Get("code")},
				"redirect_uri":  {client.redirectURI},
				"code_verifier": {testCodeVerifier},
			})
			return result
		}

		parsed, err := url.Parse(location)
		require.NoError(t, err)
		switch parsed.Path {
		case "/auth/pwd":
			page := loadPage(t, browser, location)
			resp = authenticateWithPassword(t, browser, location, page, user.Email, deletionUserPassword)
			_ = page.Body.Close()
			result.askedPassword = true
		case "/auth/otp":
			require.NotNil(t, code, "the sign-in asked for a code from a user with no authenticator")
			page := loadPage(t, browser, location)
			resp = authenticateWithOtp(t, browser, location, page, code())
			_ = page.Body.Close()
			result.askedCode = true
		default:
			resp = loadPage(t, browser, location)
		}
	}
}

// signInAgain is the sign-in the console sends a refused download through: prompt=login with the
// challenge's acr_values, and no max_age.
var signInAgain = url.Values{"prompt": {"login"}, "acr_values": {"urn:goiabada:level2_optional"}}

// giveAuthenticator sets up an authenticator for the user, as a finished enrolment leaves it, and
// answers its secret.
func giveAuthenticator(t *testing.T, user *record.User) string {
	t.Helper()
	secret := newOTPSecretForTest(t, user.Email)
	user.OTPSecretEncrypted = encryptOTPSecretForTest(t, secret)
	user.OTPEnabled = true
	require.NoError(t, database.UpdateUser(context.Background(), nil, user))
	return secret
}

// theSession is the user's one session.
func theSession(t *testing.T, userId int64) record.UserSession {
	t.Helper()
	sessions, err := database.GetUserSessionsByUserId(context.Background(), nil, userId)
	require.NoError(t, err)
	require.Len(t, sessions, 1, "the user has one session")
	return sessions[0]
}

// ageSignIn moves the user's session's sign-in an hour back, password and all, as if it had been
// made then, and answers the session as it now is.
func ageSignIn(t *testing.T, userId int64) record.UserSession {
	t.Helper()
	session := theSession(t, userId)
	session.AuthTime = session.AuthTime.Add(-time.Hour)
	session.PasswordAuthTime = session.PasswordAuthTime.Add(-time.Hour)
	require.NoError(t, database.UpdateUserSession(context.Background(), nil, &session))
	return session
}

// authTimeOf is an access token's auth_time claim.
func authTimeOf(t *testing.T, accessToken string) time.Time {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := new(jwt.Parser).ParseUnverified(accessToken, claims)
	require.NoError(t, err)
	seconds, ok := claims["auth_time"].(float64)
	require.True(t, ok, "the token carries auth_time: %v", claims)
	return time.Unix(int64(seconds), 0)
}

// ownExportEvents is the exported_own_user_data rows about the user, oldest first.
func ownExportEvents(t *testing.T, userId int64) []record.AuditLog {
	t.Helper()
	rows, err := database.GetAuditLogsByUserId(context.Background(), nil, userId)
	require.NoError(t, err)
	var events []record.AuditLog
	for _, row := range rows {
		if row.AuditEvent == audit.EventExportedOwnUserData {
			events = append(events, row)
		}
	}
	return events
}

// assertOwnExportEvents waits for the user's exported_own_user_data rows to number n, then checks
// for a moment that no more arrive.
func assertOwnExportEvents(t *testing.T, userId int64, n int) []record.AuditLog {
	t.Helper()
	var events []record.AuditLog
	require.Eventually(t, func() bool {
		events = ownExportEvents(t, userId)
		return len(events) >= n
	}, afterResponseWait, 100*time.Millisecond, "%d exported_own_user_data about the user", n)
	time.Sleep(200 * time.Millisecond)
	events = ownExportEvents(t, userId)
	require.Len(t, events, n, "exported_own_user_data is written once for each download, and never for a refusal")
	return events
}

// assertStepUpRefusal holds an answer to RFC 9470's step-up refusal.
func assertStepUpRefusal(t *testing.T, answer exportAnswer) {
	t.Helper()
	require.Equal(t, http.StatusUnauthorized, answer.status, "%s", answer.raw)
	assert.Equal(t, stepUpChallenge, answer.header.Get("WWW-Authenticate"))
	assertExportErrorCode(t, answer, "INSUFFICIENT_USER_AUTHENTICATION")
	assert.Empty(t, answer.header.Get("Content-Disposition"))
}

// comparableExport is a document without exportedAt and without the audit entries the downloads
// themselves wrote, the two places two downloads of one user made one after the other differ.
func comparableExport(t *testing.T, document []byte) string {
	t.Helper()
	var parts map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(document, &parts))
	require.Contains(t, parts, "exportedAt")
	delete(parts, "exportedAt")
	var events []map[string]any
	require.NoError(t, json.Unmarshal(parts["auditEvents"], &events))
	kept := []map[string]any{}
	for _, event := range events {
		if name := event["auditEvent"]; name != audit.EventExportedUserData && name != audit.EventExportedOwnUserData {
			kept = append(kept, event)
		}
	}
	var err error
	parts["auditEvents"], err = json.Marshal(kept)
	require.NoError(t, err)
	out, err := json.Marshal(parts)
	require.NoError(t, err)
	return string(out)
}

// A console token from a fresh sign-in downloads the user's own document as the administrator's
// download answers it: the same headers, the attachment name, no-store, gzip when asked for, and the
// same document but for exportedAt and the downloads' own audit entries. An administrator's change
// to the account is marked as an administrator's without naming them. One exported_own_user_data
// is written, naming the user as the user and as who asked.
func TestAPIAccountExport_AFreshSignInDownloadsTheUsersOwnDocument(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, _ := createAdminClientWithToken(t)
	administratorToken, administrator := createUserAccessTokenWithScope(t, "openid authserver:manage-users authserver:manage-settings")
	user := consoleSignInUser(t, "en")
	signedIn := signInOn(t, createHttpClient(t), consoleSignInClient(t), user, nil, nil)
	require.True(t, signedIn.askedPassword)
	byAdministrator := enableUser(t, administratorToken, user.Id)
	// The sign-in's own rows are in before either download, so the two list the same ones.
	require.Eventually(t, func() bool {
		rows, err := database.GetAuditLogsByUserId(context.Background(), nil, user.Id)
		require.NoError(t, err)
		for _, row := range rows {
			if row.AuditEvent == audit.EventTokenIssuedAuthorizationCodeResponse {
				return true
			}
		}
		return false
	}, afterResponseWait, 100*time.Millisecond, "the sign-in's token issuance is recorded")
	before := time.Now().UTC()

	answer := getAccountExport(t, signedIn.accessToken(t), "gzip")

	require.Equal(t, http.StatusOK, answer.status, "%s", answer.raw)
	assert.Equal(t, "application/json", answer.header.Get("Content-Type"))
	assert.Equal(t, "gzip", answer.header.Get("Content-Encoding"))
	assert.Equal(t, "no-store", answer.header.Get("Cache-Control"), "the download is never cached")
	assert.Contains(t, answer.header.Values("Vary"), "Accept-Encoding")
	assert.Equal(t, strconv.Itoa(len(answer.raw)), answer.header.Get("Content-Length"))
	var document struct {
		ExportedAt  time.Time                         `json:"exportedAt"`
		Identifiers struct{ Id int64 }                `json:"identifiers"`
		User        struct{ Email, GivenName string } `json:"user"`
		AuditEvents []json.RawMessage                 `json:"auditEvents"`
	}
	require.NoError(t, json.Unmarshal(answer.document(t), &document))
	assert.False(t, document.ExportedAt.Before(before.Truncate(time.Second)))
	assert.Equal(t, user.Id, document.Identifiers.Id)
	assert.Equal(t, user.Email, document.User.Email)
	assert.Equal(t, "Dana", document.User.GivenName)
	assert.Equal(t, fmt.Sprintf(`attachment; filename="user-%d-%s.json"`, user.Id, document.ExportedAt.UTC().Format("2006-01-02")),
		answer.header.Get("Content-Disposition"))

	var marked []json.RawMessage
	for _, raw := range document.AuditEvents {
		var entry struct{ Id int64 }
		require.NoError(t, json.Unmarshal(raw, &entry))
		if entry.Id == byAdministrator.Id {
			marked = append(marked, raw)
		}
	}
	require.Len(t, marked, 1, "the administrator's change is in the user's copy")
	assert.JSONEq(t, expectedAuditEvent(byAdministrator, fmt.Sprintf(`{"user_id":%d}`, user.Id), fmt.Sprint(user.Id), "null", true),
		string(marked[0]))
	assert.NotContains(t, string(answer.document(t)), administrator.Subject, "the administrator is named nowhere")

	events := assertOwnExportEvents(t, user.Id, 1)
	assert.Equal(t, "exported_own_user_data", events[0].AuditEvent, "the stored event name")
	assert.Equal(t, sql.NullInt64{Int64: user.Id, Valid: true}, events[0].UserId)
	assert.Equal(t, sql.NullInt64{Int64: user.Id, Valid: true}, events[0].LoggedInUserId)
	assert.JSONEq(t, fmt.Sprintf(`{"user_id": %d, "logged_in_user": %q}`, user.Id, user.Subject), events[0].Details)
	assert.Empty(t, exportEvents(t, user.Id), "the user's own download is not exported_user_data")

	adminAnswer := getUserExport(t, adminToken, user.Id, "gzip")
	require.Equal(t, http.StatusOK, adminAnswer.status, "%s", adminAnswer.raw)
	for _, name := range []string{"Content-Type", "Content-Encoding", "Cache-Control", "Vary"} {
		assert.Equal(t, adminAnswer.header.Values(name), answer.header.Values(name), name)
	}
	assert.JSONEq(t, comparableExport(t, adminAnswer.document(t)), comparableExport(t, answer.document(t)),
		"the user's copy is the administrator's download of them")
}

// Another client's token carrying authserver:manage-account is CLIENT_NOT_ALLOWED, with the
// insufficient_scope challenge, even from a fresh sign-in. It writes no audit row and spends none of
// the tier: six refusals leave the console's download free.
func TestAPIAccountExport_AnotherClientsTokenIsRefused(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, user := getUserAccessTokenWithAccountScope(t)
	givePassword(t, user, deletionUserPassword)

	for i := 0; i < 6; i++ {
		answer := getAccountExport(t, accessToken, "")
		require.Equal(t, http.StatusForbidden, answer.status, "%s", answer.raw)
		assert.Equal(t, `Bearer realm="goiabada", error="insufficient_scope", error_description="This endpoint accepts only access tokens issued to the admin console's own client."`,
			answer.header.Get("WWW-Authenticate"))
		assertExportErrorCode(t, answer, "CLIENT_NOT_ALLOWED")
	}

	console := signInOn(t, createHttpClient(t), consoleSignInClient(t), user, nil, nil)
	answer := getAccountExport(t, console.accessToken(t), "")
	require.Equal(t, http.StatusOK, answer.status, "the refusals spent none of the user's downloads: %s", answer.raw)
	assertOwnExportEvents(t, user.Id, 1)
}

// An old sign-in is refused with RFC 9470's challenge: the session's sign-in is moved an hour back,
// and a console token is taken through the session without a password. The refusals write no audit
// row and spend none of the tier. A prompt=login sign-in with the challenge's acr_values then asks
// for the password, and the code of a user with an authenticator, and its token downloads, five
// times.
func TestAPIAccountExport_AnOldSignInSignsInAgainWithTheCode(t *testing.T) {
	requireDatabaseAuditLogs(t)
	user := consoleSignInUser(t, "en")
	secret := giveAuthenticator(t, user)
	browser := createHttpClient(t)
	first := signInOn(t, browser, consoleSignInClient(t), user, func() string { return otptest.PreviousStepCode(t, secret) }, nil)
	require.True(t, first.askedPassword && first.askedCode, "a sign-in at the console asks for the code of a user with one")
	ageSignIn(t, user.Id)

	old := signInOn(t, browser, consoleSignInClient(t), user, nil, nil)
	require.False(t, old.askedPassword || old.askedCode, "the session signs the console in again with nothing asked")
	assert.WithinDuration(t, time.Now().Add(-time.Hour), authTimeOf(t, old.accessToken(t)), time.Minute,
		"the token carries the session's sign-in time")
	for i := 0; i < 6; i++ {
		assertStepUpRefusal(t, getAccountExport(t, old.accessToken(t), "gzip"))
	}

	again := signInOn(t, browser, consoleSignInClient(t), user, func() string { return otptest.Code(t, secret, time.Now()) }, signInAgain)
	assert.True(t, again.askedPassword, "prompt=login asks for the password")
	assert.True(t, again.askedCode, "acr_values=urn:goiabada:level2_optional asks for the code of a user with an authenticator")
	assert.WithinDuration(t, time.Now(), authTimeOf(t, again.accessToken(t)), time.Minute)
	for i := 0; i < 5; i++ {
		answer := getAccountExport(t, again.accessToken(t), "")
		require.Equal(t, http.StatusOK, answer.status, "download %d: the refusals spent none of the tier: %s", i+1, answer.raw)
	}
	assertOwnExportEvents(t, user.Id, 5)
}

// The console's prompt=login sign-in keeps the user's other apps signed in. Another client signed in
// through the same session holds a session-bound refresh token and an access token; after the
// console signs in again the session row is the same one, with a fresh sign-in time, that client's
// refresh succeeds, its access token is still accepted, and no back-channel logout reaches it.
func TestAPIAccountExport_SigningInAgainKeepsTheOtherAppsSignedIn(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	receiver := newLogoutReceiver(t)
	otherClient := backchannelClient(t, adminToken, receiver.uri())
	otherRedirect := &record.RedirectURI{ClientId: otherClient.Id, URI: "https://other-app.example.com/callback"}
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, otherRedirect))
	otherSecret, err := dataCipher.Decrypt(otherClient.ClientSecretEncrypted)
	require.NoError(t, err)
	other := signInClient{identifier: otherClient.ClientIdentifier, redirectURI: otherRedirect.URI, secret: otherSecret,
		scope: "openid profile"}

	user := consoleSignInUser(t, "en")
	browser := createHttpClient(t)
	signInOn(t, browser, consoleSignInClient(t), user, nil, nil)
	otherSignIn := signInOn(t, browser, other, user, nil, nil)
	require.False(t, otherSignIn.askedPassword, "the other app signs in through the session")
	otherRefresh, ok := otherSignIn.tokens["refresh_token"].(string)
	require.True(t, ok, "the other app holds a refresh token: %v", otherSignIn.tokens)
	otherAccess := otherSignIn.accessToken(t)
	before := ageSignIn(t, user.Id)

	old := signInOn(t, browser, consoleSignInClient(t), user, nil, nil)
	assertStepUpRefusal(t, getAccountExport(t, old.accessToken(t), ""))
	again := signInOn(t, browser, consoleSignInClient(t), user, nil, signInAgain)
	require.True(t, again.askedPassword)
	require.Equal(t, http.StatusOK, getAccountExport(t, again.accessToken(t), "").status)

	after := theSession(t, user.Id)
	assert.Equal(t, before.Id, after.Id, "the session row is kept")
	assert.Equal(t, before.SessionIdentifier, after.SessionIdentifier)
	assert.WithinDuration(t, time.Now(), after.AuthTime, time.Minute, "the session's sign-in time is now")

	refreshed := postToTokenEndpoint(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {other.identifier},
		"client_secret": {other.secret},
		"refresh_token": {otherRefresh},
	})
	assert.NotEmpty(t, refreshed["access_token"], "the other app's session-bound refresh token still works: %v", refreshed)
	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+"/userinfo", otherAccess, nil)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the other app's access token is still accepted")
	assert.Never(t, func() bool { return len(receiver.received()) > 0 }, 2*time.Second, 100*time.Millisecond,
		"no back-channel logout is sent to the other app")
}

// With the console client set to urn:goiabada:level1, a fresh sign-in of a user with an
// authenticator asks for the password alone, and its token is refused: the download asks for the
// code whatever level the console is set to. The acr_values sign-in then asks for the code, and
// its token downloads. The console's level is put back afterwards.
func TestAPIAccountExport_AConsoleAtLevel1StillAsksForTheCode(t *testing.T) {
	ctx := context.Background()
	console, err := database.GetClientByClientIdentifier(ctx, nil, builtin.AdminConsoleClientIdentifier)
	require.NoError(t, err)
	configured := console.DefaultAcrLevel
	t.Cleanup(func() {
		restored, err := database.GetClientByClientIdentifier(ctx, nil, builtin.AdminConsoleClientIdentifier)
		require.NoError(t, err)
		restored.DefaultAcrLevel = configured
		require.NoError(t, database.UpdateClient(ctx, nil, restored))
	})
	console.DefaultAcrLevel = record.AcrLevel1
	require.NoError(t, database.UpdateClient(ctx, nil, console))

	user := consoleSignInUser(t, "en")
	secret := giveAuthenticator(t, user)
	browser := createHttpClient(t)
	weak := signInOn(t, browser, consoleSignInClient(t), user, nil, nil)
	require.True(t, weak.askedPassword)
	require.False(t, weak.askedCode, "a level 1 console asks for the password alone")
	assert.Equal(t, "urn:goiabada:level1", claimString(t, weak.accessToken(t), "acr"))
	assertStepUpRefusal(t, getAccountExport(t, weak.accessToken(t), ""))

	again := signInOn(t, browser, consoleSignInClient(t), user, func() string { return otptest.Code(t, secret, time.Now()) }, signInAgain)
	assert.True(t, again.askedPassword)
	assert.True(t, again.askedCode, "acr_values raises the console's level, so the code is asked for")
	assert.Equal(t, "urn:goiabada:level2_optional", claimString(t, again.accessToken(t), "acr"))
	assert.Equal(t, http.StatusOK, getAccountExport(t, again.accessToken(t), "").status)
}

// A refreshed console token keeps its sign-in's age: the token refreshed from an old sign-in's is
// still refused.
func TestAPIAccountExport_ARefreshedTokenKeepsItsSignInsAge(t *testing.T) {
	user := consoleSignInUser(t, "en")
	browser := createHttpClient(t)
	signInOn(t, browser, consoleSignInClient(t), user, nil, nil)
	ageSignIn(t, user.Id)
	old := signInOn(t, browser, consoleSignInClient(t), user, nil, nil)
	refreshToken, ok := old.tokens["refresh_token"].(string)
	require.True(t, ok, "the console holds a refresh token: %v", old.tokens)
	console := consoleSignInClient(t)

	refreshed := postToTokenEndpoint(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {console.identifier},
		"client_secret": {console.secret},
		"refresh_token": {refreshToken},
	})
	accessToken, ok := refreshed["access_token"].(string)
	require.True(t, ok, "the refresh is answered: %v", refreshed)
	assert.Equal(t, authTimeOf(t, old.accessToken(t)), authTimeOf(t, accessToken), "a refresh keeps the sign-in's auth_time")

	assertStepUpRefusal(t, getAccountExport(t, accessToken, ""))
}

// Five downloads an hour for each user: the sixth is refused with the Account API's 429 and the
// hour as Retry-After, and is not recorded as a download.
func TestAPIAccountExport_TheSixthDownloadInAnHourIsRefused(t *testing.T) {
	requireDatabaseAuditLogs(t)
	user := consoleSignInUser(t, "en")
	accessToken := signInOn(t, createHttpClient(t), consoleSignInClient(t), user, nil, nil).accessToken(t)

	for i := 0; i < 5; i++ {
		answer := getAccountExport(t, accessToken, "")
		require.Equal(t, http.StatusOK, answer.status, "download %d: %s", i+1, answer.raw)
	}
	answer := getAccountExport(t, accessToken, "")

	require.Equal(t, http.StatusTooManyRequests, answer.status, "%s", answer.raw)
	assert.Equal(t, "3600", answer.header.Get("Retry-After"))
	var refusal api.ErrorResponse
	require.NoError(t, json.Unmarshal(answer.raw, &refusal))
	assert.Equal(t, "TOO_MANY_REQUESTS", refusal.ErrorCode)
	assertOwnExportEvents(t, user.Id, 5)
}
