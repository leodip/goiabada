package integration

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
)

// A reset code belongs to the address it was mailed to, so changing the account's address, by an
// administrator or by the account itself, retires a link mailed to the previous one (#471 decision
// 6). The case that motivates it is an administrator correcting a mistyped address after sending
// the setup email: whoever holds the mistyped address could otherwise still set the account's
// password. The link is refused with the message any dead link gets, at the first hop for a browser
// that never followed it, and at the form and its submission for one that followed it before the
// change.
func TestResetPassword_AnEmailChangeRetiresTheLinkMailedToThePreviousAddress(t *testing.T) {
	useMailpitSMTP(t)

	for _, tc := range []struct {
		name string
		// account returns a user holding a verified, enabled address, its password, and the change
		// that moves its address.
		account func(t *testing.T) (user *record.User, password string, change func(t *testing.T, toEmail string))
	}{
		{
			name: "the administrator's change",
			account: func(t *testing.T) (*record.User, string, func(t *testing.T, toEmail string)) {
				user, password := createResetTestUser(t, plusAddress())
				adminToken, _ := createAdminClientWithToken(t)
				return user, password, func(t *testing.T, toEmail string) {
					target := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/email"
					resp := makeAPIRequest(t, "PUT", target, adminToken, api.UpdateUserEmailRequest{Email: toEmail, EmailVerified: true})
					_ = resp.Body.Close()
					require.Equal(t, http.StatusOK, resp.StatusCode)
				}
			},
		},
		{
			name: "the account's own change",
			account: func(t *testing.T) (*record.User, string, func(t *testing.T, toEmail string)) {
				accessToken, u := accountEmailUserWithPassword(t)
				stored, err := database.GetUserById(context.Background(), nil, u.Id)
				require.NoError(t, err)
				stored.Email = plusAddress()
				stored.EmailVerified = true
				stored.Enabled = true
				require.NoError(t, database.UpdateUser(context.Background(), nil, stored))
				return stored, accountEmailPassword, func(t *testing.T, toEmail string) {
					resp := makeAPIRequest(t, "PUT", appConfig.AuthServer.BaseURL+"/api/v1/account/email", accessToken,
						api.UpdateAccountEmailRequest{Email: toEmail, CurrentPassword: accountEmailPassword})
					_ = resp.Body.Close()
					require.Equal(t, http.StatusOK, resp.StatusCode)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user, password, change := tc.account(t)
			previous := user.Email

			requestPasswordReset(t, createHttpClient(t), previous)
			link := latestResetLink(t, previous)

			// One browser follows the link before the change and holds the form.
			early := createHttpClient(t)
			cleanURL := followResetLink(t, early, link)
			continuationId := loadResetForm(t, early, cleanURL)

			change(t, plusAddress())

			// A browser following the link only now is refused at the first hop.
			late := createHttpClient(t)
			resp := loadPage(t, late, link)
			body := bodyString(t, resp)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode, "the first hop keeps its 200, as for every dead link")
			assert.Contains(t, body, resetCodeInvalidText)
			assert.NotContains(t, body, `name="password"`)

			// The browser that followed it earlier is refused at the form and at its submission.
			resp = loadPage(t, early, cleanURL)
			body = bodyString(t, resp)
			_ = resp.Body.Close()
			assert.Contains(t, body, resetCodeInvalidText)
			assert.NotContains(t, body, `name="password"`)

			resp = postCleanReset(t, early, cleanURL, "N3wP4ss!word", continuationId)
			body = bodyString(t, resp)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Contains(t, body, resetCodeInvalidText)

			assert.True(t, passwordhash.Verify(passwordHashOf(t, user.Id), password),
				"a link mailed to the previous address must not set the account's password")
		})
	}
}
