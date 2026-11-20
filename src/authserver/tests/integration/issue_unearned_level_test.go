package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createdAuthCodeEvents counts the created_auth_code rows about userId: one per code /auth/issue
// stored for them.
func createdAuthCodeEvents(t *testing.T, userId int64) int {
	t.Helper()
	rows, err := database.GetAuditLogsByUserId(context.Background(), nil, userId)
	require.NoError(t, err)
	count := 0
	for _, row := range rows {
		if row.AuditEvent == audit.EventCreatedAuthCode {
			count++
		}
	}
	return count
}

// TestIssue_ALevelItsMethodsDoNotEarnSignsInAgain: a browser's session is stored at
// urn:goiabada:level2_mandatory with a password alone, the pair releases before 1.7.0 could write
// and none since does, so it is set up by storing the row. A single sign-on over it would issue a
// level 3 claim for a one-time code nobody entered. /auth/issue refuses it as it refuses every
// sign-in whose claim no longer stands: prompt=none is answered login_required from there, and any
// other request starts over at the password step, with no code stored either way. The sign-in that
// starts over earns its own level (#199 decisions 6 and 7).
func TestIssue_ALevelItsMethodsDoNotEarnSignsInAgain(t *testing.T) {
	enableAuditLogsInDatabase(t)

	// A level 3 sign-in, password and code, which leaves a level 3 session naming "pwd otp".
	level3Client, level3RedirectUri, user, password, otpSecret := createLevel2MandatoryUser(t, true)
	httpClient, otpPage, otpUrl := startOtpCeremony(t, level3Client, level3RedirectUri, user, password, "")
	resp := authenticateWithOtp(t, httpClient, otpUrl, otpPage, otptest.Code(t, otpSecret, time.Now()))
	_ = otpPage.Body.Close()
	location := assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, location)
	location = assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, location)
	_ = issuedCode(t, resp)
	_ = resp.Body.Close()
	require.Eventually(t, func() bool { return createdAuthCodeEvents(t, user.Id) == 1 }, afterResponseWait,
		100*time.Millisecond, "the level 3 sign-in stored one code")

	// The session's methods lose the code, its level kept.
	sessions, err := database.GetUserSessionsByUserId(context.Background(), nil, user.Id)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	session := sessions[0]
	require.Equal(t, record.AcrLevel2Mandatory, session.AcrLevel)
	session.AuthMethods = "pwd"
	require.NoError(t, database.UpdateUserSession(context.Background(), nil, &session))

	level1Client, level1RedirectUri := createLevel1Client(t, false)

	// Silent: the step-up rule has nothing to ask at level 1, so the request reaches /auth/issue,
	// and the answer read below is the one given there.
	state := fake.LetterN(8)
	silentUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + level1Client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(level1RedirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + randomCodeChallenge() +
		"&scope=openid" +
		"&state=" + state +
		"&prompt=none"
	resp = loadPage(t, httpClient, silentUrl)
	issueLocation := assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, issueLocation)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	answer, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, level1RedirectUri.URI, answer.Scheme+"://"+answer.Host+answer.Path, "the client is answered")
	assert.Equal(t, "login_required", answer.Query().Get("error"))
	assert.Equal(t, state, answer.Query().Get("state"))
	assert.Empty(t, answer.Query().Get("code"), "no code")

	// Interactive: the single sign-on reaches /auth/issue too, and is sent back to the password step.
	where, page, _ := authorizeOnExistingSession(t, httpClient, level1Client, level1RedirectUri)
	require.Equal(t, "/auth/issue", where, "nothing before issuance refuses the sign-on")
	location = assertRedirect(t, page, "/auth/level1")
	_ = page.Body.Close()
	resp = loadPage(t, httpClient, location)
	location = assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()

	// The sign-in that starts over enters the password, and is issued what a password earns.
	pwdPage := loadPage(t, httpClient, location)
	resp = authenticateWithPassword(t, httpClient, location, pwdPage, user.Email, password)
	_ = pwdPage.Body.Close()
	location = assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, location)
	location = assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, location)
	location = assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, location)
	code := issuedCode(t, resp)
	_ = resp.Body.Close()
	assert.Equal(t, record.AcrLevel1, code.AcrLevel, "the level a password alone earns")
	assert.Equal(t, "pwd", code.AuthMethods)

	// The restarted sign-in's code bounds the wait: once its row is stored, a code stored by either
	// refusal would be too. The level 3 sign-in's and the restarted one's are the only two.
	require.Eventually(t, func() bool { return createdAuthCodeEvents(t, user.Id) >= 2 }, afterResponseWait,
		100*time.Millisecond, "the restarted sign-in stored its code")
	assert.Equal(t, 2, createdAuthCodeEvents(t, user.Id), "neither refused sign-in stored a code")

	// The session behind it now claims what its methods name.
	repaired, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, session.SessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, repaired, "the sign-in that started over kept the browser's session")
	assert.Equal(t, record.AcrLevel1, repaired.AcrLevel)
	assert.Equal(t, "pwd", repaired.AuthMethods)
}
