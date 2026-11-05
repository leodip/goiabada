package integration

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The notice for an administrator's deletion of a user, over real SMTP (#783 decision 10). It
// reaches the deleted user's verified address once, in their language, with no link, after the
// deletion; an unverified address is sent nothing.

const adminDeletedSubjectEn = "An administrator deleted your account"

// deleteUserAsAdministrator deletes the user through the admin API and requires the 200.
func deleteUserAsAdministrator(t *testing.T, accessToken string, userId int64) {
	t.Helper()
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAPIUserDelete_TellsTheUserAnAdministratorDeletedTheirAccount(t *testing.T) {
	useMailpitSMTP(t)
	accessToken, _ := createAdminClientWithToken(t)

	for _, tc := range []struct {
		locale  string
		subject string
		advice  string
	}{
		{"en", adminDeletedSubjectEn, "If you didn't expect this, contact your administrator."},
		{"it", "Un amministratore ha eliminato il tuo account", //nolint:misspell // the it catalog's text: "eliminato" is Italian
			"Se non te lo aspettavi, contatta il tuo amministratore."},
	} {
		t.Run(tc.locale, func(t *testing.T) {
			user := adminNoticeUser(t, tc.locale, "the-hash")

			deleteUserAsAdministrator(t, accessToken, user.Id)

			deleted, err := database.GetUserById(context.Background(), nil, user.Id)
			require.NoError(t, err)
			assert.Nil(t, deleted, "the user's row is gone")
			messages := awaitMailTo(t, user.Email)
			require.Len(t, messages, 1, "the deleted user's address is told exactly once")
			assert.Equal(t, tc.subject, messages[0].Subject)
			assert.Contains(t, messages[0].HTML, tc.advice)
			assert.NotContains(t, messages[0].HTML, "href", "the notice carries no link")
		})
	}
}

// An address the account never verified is told nothing. The notice is sent after the response,
// so its absence is read once a verified user's deletion, made after it, has been told: that shows
// mail was on. The proof ordered on completion is the handler's
// TestHandleUserDelete_SendsNoNoticeWhereNoneMayGo.
func TestAPIUserDelete_SendsNoNoticeToAnUnverifiedAddress(t *testing.T) {
	useMailpitSMTP(t)
	accessToken, _ := createAdminClientWithToken(t)

	unverified := adminNoticeUser(t, "en", "the-hash")
	unverified.EmailVerified = false
	require.NoError(t, database.UpdateUser(context.Background(), nil, unverified))
	verified := adminNoticeUser(t, "en", "the-hash")

	deleteUserAsAdministrator(t, accessToken, unverified.Id)
	deleteUserAsAdministrator(t, accessToken, verified.Id)

	require.Len(t, awaitMailWithSubject(t, verified.Email, adminDeletedSubjectEn, 1), 1,
		"the verified user is told, so mail was on")
	assert.Empty(t, sentTo(t, unverified.Email), "an unverified address is sent nothing")
}
