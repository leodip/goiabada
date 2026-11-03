package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The password change's notice over real SMTP (#724): once the change is answered, the account's
// verified address receives one notice in the user's language, with no link and no password.
// Where the rules say none, nothing arrives: SMTP off, or an address the account never verified.

// passwordNoticeCurrent is the password every user here starts with.
const passwordNoticeCurrent = "Corr3ct!Pass"

// passwordNoticeUser is a user holding an account-scoped token, with passwordNoticeCurrent, the
// locale given and the verified flag given.
func passwordNoticeUser(t *testing.T, locale string, verified bool) (string, *record.User) {
	t.Helper()
	accessToken, u := getUserAccessTokenWithAccountScope(t)
	givePassword(t, u, passwordNoticeCurrent)
	stored, err := database.GetUserById(context.Background(), nil, u.Id)
	require.NoError(t, err)
	stored.Locale = locale
	stored.EmailVerified = verified
	require.NoError(t, database.UpdateUser(context.Background(), nil, stored))
	return accessToken, stored
}

// changePassword changes the caller's password from passwordNoticeCurrent, requires the 200, and
// returns the new password.
func changePassword(t *testing.T, accessToken string) string {
	t.Helper()
	next := fake.Password(20)
	resp := makeAPIRequest(t, "PUT", appConfig.AuthServer.BaseURL+"/api/v1/account/password", accessToken,
		api.UpdateAccountPasswordRequest{CurrentPassword: passwordNoticeCurrent, NewPassword: next})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return next
}

func TestAPIAccountPasswordPut_TellsTheUser(t *testing.T) {
	useMailpitSMTP(t)

	for _, tc := range []struct {
		locale  string
		subject string
		warning string
	}{
		{"en", "Your password was changed", "someone else may be using your account"},
		{"pt-BR", "Sua senha foi alterada", "outra pessoa pode estar usando a sua conta"},
	} {
		t.Run(tc.locale, func(t *testing.T) {
			accessToken, u := passwordNoticeUser(t, tc.locale, true)

			next := changePassword(t, accessToken)

			messages := awaitMailTo(t, u.Email)
			require.Len(t, messages, 1, "the account's address is told exactly once")
			notice := messages[0]
			assert.Equal(t, tc.subject, notice.Subject)
			assert.Contains(t, notice.HTML, tc.warning)
			assert.NotContains(t, notice.HTML, "href", "the notice carries no link")
			assert.NotContains(t, notice.HTML+notice.Text, next, "the notice carries no password")
			assert.NotContains(t, notice.HTML+notice.Text, passwordNoticeCurrent, "the notice carries no password")
		})
	}
}

// An address the account never verified is told nothing. The notice is sent after the response,
// so its absence is read once a verified user's change, made after it, has been told: that shows
// mail was on, though it is no barrier for the first job, which runs on its own goroutine. The
// proof ordered on completion is the handler's TestHandleAccountPasswordPut_SendsNoNoticeWhereNoneMayGo.
func TestAPIAccountPasswordPut_SendsNoNoticeToAnUnverifiedAddress(t *testing.T) {
	useMailpitSMTP(t)

	unverifiedToken, unverified := passwordNoticeUser(t, "en", false)
	verifiedToken, verified := passwordNoticeUser(t, "en", true)

	changePassword(t, unverifiedToken)
	changePassword(t, verifiedToken)

	require.Len(t, awaitMailTo(t, verified.Email), 1, "the verified user is told, so mail was on")
	assert.Empty(t, sentTo(t, unverified.Email), "an unverified address is sent nothing")
}

// With SMTP off, a change sends nothing, and nothing is held to send once it is turned on.
func TestAPIAccountPasswordPut_SendsNoNoticeWithSMTPOff(t *testing.T) {
	offToken, off := passwordNoticeUser(t, "en", true)
	changePassword(t, offToken)

	useMailpitSMTP(t)
	onToken, on := passwordNoticeUser(t, "en", true)
	changePassword(t, onToken)

	require.Len(t, awaitMailTo(t, on.Email), 1, "the change made with mail on is told")
	assert.Empty(t, sentTo(t, off.Email), "the change made with SMTP off is sent nothing")
}
