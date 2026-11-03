package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/testutil/mailpit"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The notices for a password an administrator sets and for a reset through a forgot-password link,
// over real SMTP (#724). Each reaches the account's verified address once, in the user's language,
// with no link and no password. A first password sends nothing, whether the setup link an
// administrator emailed sets it or an administrator does (decision 6).

const (
	adminChangedSubjectEn = "An administrator changed your password"
	resetSubjectEn        = "Your password was reset"
)

// awaitMailWithSubject returns the messages sent to an address with the subject given, once at
// least count have arrived or afterResponseWait has run out, for the caller to refuse a short
// result. The notices are sent after the response, so they are waited for.
func awaitMailWithSubject(t *testing.T, to string, subject string, count int) []mailpit.Message {
	t.Helper()

	deadline := time.Now().Add(afterResponseWait)
	for {
		matched := []mailpit.Message{}
		for _, message := range messagesTo(t, to) {
			if message.Subject == subject {
				matched = append(matched, message)
			}
		}
		if len(matched) >= count || time.Now().After(deadline) {
			return matched
		}
		time.Sleep(afterResponsePoll)
	}
}

// messagesTo returns every message Mailpit holds for an address now, without waiting.
func messagesTo(t *testing.T, to string) []mailpit.Message {
	t.Helper()

	client := mailpit.New(mailpitURL)
	messages := []mailpit.Message{}
	for _, summary := range sentTo(t, to) {
		message, err := client.Message(summary.ID)
		require.NoError(t, err)
		messages = append(messages, message)
	}
	return messages
}

// adminNoticeUser is a user with a verified address, the locale given and the password hash given,
// "" for an account whose setup link is still pending.
func adminNoticeUser(t *testing.T, locale string, passwordHash string) *record.User {
	t.Helper()
	user := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         plusAddress(),
		EmailVerified: true,
		GivenName:     "Dora",
		FamilyName:    "Lima",
		Locale:        locale,
		PasswordHash:  passwordHash,
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	return user
}

// setPasswordAsAdministrator sets the user's password through the admin API, requires the 200 and
// returns the password set.
func setPasswordAsAdministrator(t *testing.T, accessToken string, userId int64) string {
	t.Helper()
	password := fake.Password(20)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/password"
	resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserPasswordRequest{NewPassword: password})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return password
}

func TestAPIUserPasswordPut_TellsTheUserAnAdministratorChangedIt(t *testing.T) {
	useMailpitSMTP(t)
	accessToken, _ := createAdminClientWithToken(t)

	for _, tc := range []struct {
		locale  string
		subject string
		advice  string
	}{
		{"en", adminChangedSubjectEn, "contact your administrator"},
		{"pt-BR", "Um administrador alterou a sua senha", "entre em contato com o administrador"},
	} {
		t.Run(tc.locale, func(t *testing.T) {
			user := adminNoticeUser(t, tc.locale, "the-old-hash")

			password := setPasswordAsAdministrator(t, accessToken, user.Id)

			messages := awaitMailTo(t, user.Email)
			require.Len(t, messages, 1, "the account's address is told exactly once")
			notice := messages[0]
			assert.Equal(t, tc.subject, notice.Subject)
			assert.Contains(t, notice.HTML, tc.advice)
			assert.NotContains(t, notice.HTML, "href", "the notice carries no link")
			assert.NotContains(t, notice.HTML+notice.Text, password, "the notice carries no password")
		})
	}
}

// An account with no password, whose setup link is still pending, is given its first password by
// the administrator, and told nothing. The notice is sent after the response, so its absence is
// read once a later change to an account that has a password has been told: that shows mail was
// on, though it is no barrier for the first job. The proof ordered on completion is the handler's
// TestHandleUserPasswordPut_SendsNoNoticeWhereNoneMayGo.
func TestAPIUserPasswordPut_AFirstPasswordSendsNothing(t *testing.T) {
	useMailpitSMTP(t)
	accessToken, _ := createAdminClientWithToken(t)

	first := adminNoticeUser(t, "en", "")
	replaced := adminNoticeUser(t, "en", "the-old-hash")

	setPasswordAsAdministrator(t, accessToken, first.Id)
	setPasswordAsAdministrator(t, accessToken, replaced.Id)

	require.Len(t, awaitMailWithSubject(t, replaced.Email, adminChangedSubjectEn, 1), 1,
		"the account that had a password is told, so mail was on")
	assert.Empty(t, sentTo(t, first.Email), "an account given its first password is sent nothing")
}

// resetThroughEmailedLink requests a reset link for email, waits for it beside the earlier links
// the address already holds, follows it and sets a new password with it, requiring the success
// page. It returns the password set.
func resetThroughEmailedLink(t *testing.T, email string, earlierLinks int) string {
	t.Helper()
	client := createHttpClient(t)
	requestPasswordReset(t, client, email)
	links := awaitResetLinks(t, email, earlierLinks+1)
	require.Len(t, links, earlierLinks+1, "the reset link arrived")
	return setPasswordThroughLink(t, client, links[0])
}

// setPasswordThroughLink follows an emailed reset or setup link and sets a new password with it,
// requiring the success page. It returns the password set.
func setPasswordThroughLink(t *testing.T, client *http.Client, link string) string {
	t.Helper()
	cleanURL := followResetLink(t, client, link)
	continuationId := loadResetForm(t, client, cleanURL)
	password := fake.Password(20)
	resp := postCleanReset(t, client, cleanURL, password, continuationId)
	body := bodyString(t, resp)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, body, resetSucceededText)
	return password
}

func TestResetPassword_TellsTheUserTheirPasswordWasReset(t *testing.T) {
	useMailpitSMTP(t)

	for _, tc := range []struct {
		locale  string
		subject string
		warning string
	}{
		{"en", resetSubjectEn, "someone else may be able to read your email"},
		{"pt-BR", "Sua senha foi redefinida", "outra pessoa pode estar lendo o seu e-mail"},
	} {
		t.Run(tc.locale, func(t *testing.T) {
			email := plusAddress()
			user, _ := createResetTestUser(t, email)
			stored, err := database.GetUserById(context.Background(), nil, user.Id)
			require.NoError(t, err)
			stored.Locale = tc.locale
			require.NoError(t, database.UpdateUser(context.Background(), nil, stored))

			password := resetThroughEmailedLink(t, email, 0)

			notices := awaitMailWithSubject(t, email, tc.subject, 1)
			require.Len(t, notices, 1, "the account's address is told exactly once")
			notice := notices[0]
			assert.Contains(t, notice.HTML, tc.warning)
			assert.NotContains(t, notice.HTML, "href", "the notice carries no link")
			assert.NotContains(t, notice.HTML+notice.Text, password, "the notice carries no password")
			assert.Len(t, sentTo(t, email), 2, "the address holds the reset link and the notice, and nothing else")
		})
	}
}

// The setup link an administrator emails a new user sets the account's first password and sends no
// notice. A reset made afterwards, once the account has a password, is told: that shows mail was
// on, and the address then holds the setup mail, the reset link and that one notice.
func TestAPIUserCreatePost_TheSetupLinkSendsNoNotice(t *testing.T) {
	useMailpitSMTP(t)
	accessToken, _ := createAdminClientWithToken(t)

	email := plusAddress()
	resp := makeAPIRequest(t, "POST", appConfig.AuthServer.BaseURL+"/api/v1/admin/users/create", accessToken,
		api.CreateUserAdminRequest{
			Email:           email,
			GivenName:       "Setup",
			FamilyName:      "Notice",
			SetPasswordType: api.SetPasswordTypeEmail,
		})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created api.CreateUserResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	_ = resp.Body.Close()
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, created.User.Id) })

	setPasswordThroughLink(t, createHttpClient(t), latestResetLink(t, email))

	resetThroughEmailedLink(t, email, 1)

	require.Len(t, awaitMailWithSubject(t, email, resetSubjectEn, 1), 1,
		"the reset that replaced a password is told, so mail was on")
	assert.Len(t, sentTo(t, email), 3, "the setup mail, the reset link and the reset's notice, and no notice for the setup link")
}
