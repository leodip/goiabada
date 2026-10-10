package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// What a session claims once its user's authenticator has been removed (#542 decision 1). Removing
// one lowers each of the user's sessions to what a password alone earns, so no token issued from
// them afterwards names a code from an authenticator that is gone; a sign-in in flight when it
// happens starts over; and a session that still names one, as a session from before removals
// lowered sessions does, signs in again rather than vouching for it.

// signInAtLevel3 signs a new user with an authenticator in at a level 3 client on a fresh cookie
// jar, password and code, and returns the jar, which then holds a level 3 session naming
// "pwd otp", along with the client, its redirect URI and the user.
func signInAtLevel3(t *testing.T) (*http.Client, *record.Client, *record.RedirectURI, *record.User) {
	t.Helper()

	client, redirectUri, user, password, otpSecret := createLevel2MandatoryUser(t, true)
	httpClient, otpPage, otpUrl := startOtpCeremony(t, client, redirectUri, user, password, "")
	code, err := totp.GenerateCode(otpSecret, time.Now())
	require.NoError(t, err)
	resp := authenticateWithOtp(t, httpClient, otpUrl, otpPage, code)
	_ = otpPage.Body.Close()
	location := assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, location)
	location = assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, location)
	_ = resp.Body.Close()

	sessions, err := database.GetUserSessionsByUserId(context.Background(), nil, user.Id)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	require.Equal(t, record.AcrLevel2Mandatory, sessions[0].AcrLevel, "the sign-in leaves a level 3 session")
	require.Equal(t, "pwd otp", sessions[0].AuthMethods)
	return httpClient, client, redirectUri, user
}

// removeAuthenticatorAsAdministrator turns the user's two-factor authentication off through the
// admin API, the path the admin console's switch takes.
func removeAuthenticatorAsAdministrator(t *testing.T, userId int64) {
	t.Helper()

	token, _ := createAdminClientWithToken(t)
	resp, _ := sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/otp", userId),
		map[string]any{"enabled": false})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// issuedCode answers the code /auth/issue answered the client with, read back from the database, so
// a case can say what the tokens redeemed from it will claim. issueResponse is that step's response.
func issuedCode(t *testing.T, issueResponse *http.Response) *record.Code {
	t.Helper()

	require.Equal(t, http.StatusFound, issueResponse.StatusCode)
	location, err := url.Parse(issueResponse.Header.Get("Location"))
	require.NoError(t, err)
	code := location.Query().Get("code")
	require.NotEmpty(t, code, "the client is answered with a code, not %q", location.Query().Get("error"))
	return loadCodeFromDatabase(t, code)
}

// TestOtpCeremony_RemovingTheAuthenticatorLowersEverySession: an administrator turns off the
// two-factor authentication of a user signed in at level 3, on two sessions. Each is lowered to
// what a password alone earns, level 2 optional and "pwd", keeping its auth_time, and the next SSO
// sign-in at a level 1 client is issued a code saying so. Until the removal lowered them, that code
// said level 3 and "pwd otp", for an authenticator the administrator had just removed.
func TestOtpCeremony_RemovingTheAuthenticatorLowersEverySession(t *testing.T) {
	httpClient, _, _, user := signInAtLevel3(t)

	// A second session of the same user, on another device. Written directly, because a second
	// sign-in from this suite's one address and user agent would replace the first as the same
	// device.
	authTime := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	other := &record.UserSession{
		SessionIdentifier: fake.UUID(),
		Started:           authTime,
		LastAccessed:      authTime,
		AuthTime:          authTime,
		AuthMethods:       "pwd otp",
		AcrLevel:          record.AcrLevel2Mandatory,
		IpAddress:         "192.0.2.10",
		UserId:            user.Id,
	}
	require.NoError(t, database.CreateUserSession(context.Background(), nil, other))
	before, err := database.GetUserSessionsByUserId(context.Background(), nil, user.Id)
	require.NoError(t, err)
	require.Len(t, before, 2)
	authTimes := map[int64]time.Time{}
	for _, session := range before {
		authTimes[session.Id] = session.AuthTime
	}

	removeAuthenticatorAsAdministrator(t, user.Id)

	after, err := database.GetUserSessionsByUserId(context.Background(), nil, user.Id)
	require.NoError(t, err)
	require.Len(t, after, 2, "nobody is signed out")
	for _, session := range after {
		assert.Equal(t, record.AcrLevel2Optional, session.AcrLevel, "session %d is lowered to level 2 optional", session.Id)
		assert.Equal(t, "pwd", session.AuthMethods, "session %d no longer names the code", session.Id)
		assert.True(t, authTimes[session.Id].Equal(session.AuthTime),
			"session %d keeps its auth_time: the password it dates was entered then", session.Id)
	}

	level1Client, level1RedirectUri := createLevel1Client(t, false)
	where, page, _ := authorizeOnExistingSession(t, httpClient, level1Client, level1RedirectUri)
	_ = page.Body.Close()
	require.Equal(t, "/auth/issue", where, "SSO at a level 1 client goes straight through")

	code := issuedCode(t, page)
	assert.Equal(t, record.AcrLevel2Optional, code.AcrLevel, "the code's acr is what the session now holds")
	assert.Equal(t, "pwd", code.AuthMethods, "the code names no code from the removed authenticator")
}

// TestOtpCeremony_ASignInInFlightWhenTheAuthenticatorIsRemovedStartsOver: an SSO sign-in adopts the
// session's methods at /auth/authorize. When the authenticator is removed before it reaches
// /auth/completed, it still names "pwd otp", and binding it would merge otp back into the session
// the removal had just lowered, which every later SSO token would then claim. It starts over at
// level 1 instead, and the session stays lowered.
func TestOtpCeremony_ASignInInFlightWhenTheAuthenticatorIsRemovedStartsOver(t *testing.T) {
	httpClient, _, _, user := signInAtLevel3(t)
	level1Client, level1RedirectUri := createLevel1Client(t, false)

	authorizeUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + level1Client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(level1RedirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + fake.LetterN(43) +
		"&scope=openid" +
		"&state=" + fake.LetterN(8)
	resp := loadPage(t, httpClient, authorizeUrl)
	location := assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, location)
	completedLocation := assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()

	// The removal lands while the browser is between /auth/level1completed and /auth/completed.
	removeAuthenticatorAsAdministrator(t, user.Id)

	resp = loadPage(t, httpClient, completedLocation)
	assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()

	sessions, err := database.GetUserSessionsByUserId(context.Background(), nil, user.Id)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, record.AcrLevel2Optional, sessions[0].AcrLevel, "the ceremony did not raise the lowered session")
	assert.Equal(t, "pwd", sessions[0].AuthMethods, "the ceremony did not put otp back on the lowered session")
}

// TestOtpCeremony_ASessionStillNamingARemovedAuthenticatorSignsInAgain: a session that kept level 3
// and "pwd otp" after its user's authenticator went, which is what every removal left before
// removals lowered sessions, and what a server upgraded past that still holds. Its claims are no
// longer true, so it vouches for nothing that names the code: a silent request at a level 1 client
// is answered login_required, an interactive one starts over at level 1, and a level 3 client asks
// for a new authenticator to be set up.
func TestOtpCeremony_ASessionStillNamingARemovedAuthenticatorSignsInAgain(t *testing.T) {
	httpClient, level3Client, level3RedirectUri, user := signInAtLevel3(t)

	// The removal as it was before it lowered sessions: the secret cleared, the consumed step reset
	// and the counter moved, the session left as it was.
	user.OTPEnabled = false
	user.OTPSecretEncrypted = nil
	require.NoError(t, database.UpdateUser(context.Background(), nil, user))
	require.NoError(t, database.ResetUserOTPStep(context.Background(), nil, user.Id))
	advanceOtpConfigGeneration(t, user.Id)

	level1Client, level1RedirectUri := createLevel1Client(t, false)

	// Silent: the step-up rule has nothing to ask at level 1, so the request reaches /auth/issue,
	// which will not issue a code naming the removed authenticator.
	silentUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + level1Client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(level1RedirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + fake.LetterN(43) +
		"&scope=openid" +
		"&state=" + fake.LetterN(8) +
		"&prompt=none"
	resp := loadPage(t, httpClient, silentUrl)
	issueLocation := assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, issueLocation)
	_ = resp.Body.Close()
	answer, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "login_required", answer.Query().Get("error"))
	assert.Empty(t, answer.Query().Get("code"))

	// Interactive: it starts over at level 1 rather than binding the session's "pwd otp".
	where, page, _ := authorizeOnExistingSession(t, httpClient, level1Client, level1RedirectUri)
	_ = page.Body.Close()
	assert.Equal(t, "/auth/level1", where, "a sign-in naming a removed authenticator asks for the password again")

	// Level 3: the session's level matches, and the user has no authenticator, so one is set up.
	where, page, _ = authorizeOnExistingSession(t, httpClient, level3Client, level3RedirectUri)
	defer func() { _ = page.Body.Close() }()
	assert.Equal(t, "/auth/otp", where, "a level 3 sign-in of a user with no authenticator sets one up")
	if where == "/auth/otp" {
		assert.NotEmpty(t, getOtpSecretFromEnrollmentPage(t, page), "the OTP page must be the enrolment page")
	}
}
