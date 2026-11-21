package integration

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storedCodeIDs lists, in order, the ids of the codes rows stored for userID: what /auth/issue
// committed for them, read from the table itself. The issuer commits a code before its response is
// written, so a read after the response sees it.
func storedCodeIDs(t *testing.T, userID int64) []int64 {
	t.Helper()
	var ids []int64
	require.NoError(t, database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		ids = nil
		rows, err := tx.QueryContext(context.Background(),
			fmt.Sprintf("SELECT id FROM codes WHERE user_id = %d ORDER BY id", userID))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	}))
	return ids
}

// TestIssue_ALevelItsMethodsDoNotEarnSignsInAgain: a browser's session is stored at
// urn:goiabada:level2_mandatory with a password alone, the pair releases before 1.7.0 could write
// and none since does, so it is set up by storing the row. A single sign-on over it would issue a
// level 3 claim for a one-time code nobody entered. /auth/issue refuses it as it refuses every
// sign-in whose claim no longer stands: prompt=none is answered login_required from there, and any
// other request starts over at the password step, with no code stored either way. The sign-in that
// starts over earns its own level (#199 decisions 6 and 7).
func TestIssue_ALevelItsMethodsDoNotEarnSignsInAgain(t *testing.T) {
	// A level 3 sign-in, password and code, which leaves a level 3 session naming "pwd otp".
	level3Client, level3RedirectURI, user, password, otpSecret := createLevel2MandatoryUser(t, true)
	httpClient, otpPage, otpURL := startOTPCeremony(t, level3Client, level3RedirectURI, user, password, "")
	resp := authenticateWithOTP(t, httpClient, otpURL, otpPage, otptest.Code(t, otpSecret, time.Now()))
	_ = otpPage.Body.Close()
	location := assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, location)
	location = assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, location)
	level3Code := issuedCode(t, resp)
	_ = resp.Body.Close()
	codesBefore := storedCodeIDs(t, user.ID)
	require.Equal(t, []int64{level3Code.ID}, codesBefore, "the level 3 sign-in stored one code")

	// The session's methods lose the code, its level kept.
	sessions, err := database.GetUserSessionsByUserID(context.Background(), nil, user.ID)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	session := sessions[0]
	require.Equal(t, record.ACRLevel2Mandatory, session.ACRLevel)
	session.AuthMethods = "pwd"
	require.NoError(t, database.UpdateUserSession(context.Background(), nil, &session))

	level1Client, level1RedirectURI := createLevel1Client(t, false)

	// Silent: the step-up rule has nothing to ask at level 1, so the request reaches /auth/issue,
	// and the answer read below is the one given there.
	state := fake.LetterN(8)
	silentURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + level1Client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(level1RedirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + randomCodeChallenge() +
		"&scope=openid" +
		"&state=" + state +
		"&prompt=none"
	resp = loadPage(t, httpClient, silentURL)
	issueLocation := assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, issueLocation)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	answer, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, level1RedirectURI.URI, answer.Scheme+"://"+answer.Host+answer.Path, "the client is answered")
	assert.Equal(t, "login_required", answer.Query().Get("error"))
	assert.Equal(t, state, answer.Query().Get("state"))
	assert.Empty(t, answer.Query().Get("code"), "no code")
	assert.Equal(t, codesBefore, storedCodeIDs(t, user.ID), "the silent refusal stored no code")

	// Interactive: the single sign-on reaches /auth/issue too, and is sent back to the password step.
	where, page, _ := authorizeOnExistingSession(t, httpClient, level1Client, level1RedirectURI)
	require.Equal(t, "/auth/issue", where, "nothing before issuance refuses the sign-on")
	location = assertRedirect(t, page, "/auth/level1")
	_ = page.Body.Close()
	assert.Equal(t, codesBefore, storedCodeIDs(t, user.ID), "the interactive refusal stored no code")
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
	assert.Equal(t, record.ACRLevel1, code.ACRLevel, "the level a password alone earns")
	assert.Equal(t, "pwd", code.AuthMethods)
	assert.Equal(t, []int64{level3Code.ID, code.ID}, storedCodeIDs(t, user.ID),
		"the level 3 sign-in's code and the restarted one's are the only two stored")

	// The session behind it now claims what its methods name.
	repaired, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, session.SessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, repaired, "the sign-in that started over kept the browser's session")
	assert.Equal(t, record.ACRLevel1, repaired.ACRLevel)
	assert.Equal(t, "pwd", repaired.AuthMethods)
}
