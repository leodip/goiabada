package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil"
)

// The password reset flow, end to end, over real HTTP with a real cookie jar.
//
// This tier owns what nothing below it can see (#112 seam 4): the 303 to a URL with no
// credential in it, the session marker surviving that redirect in a real cookie, and above
// all a COPY of that cookie being refused after the fact. A copy is the only thing that shows
// the marker is not a bearer token: the session is a client-side encrypted cookie, so the
// server clearing it replaces the browser's copy and cannot invalidate one an attacker kept.
//
// Every link followed here is the one the handler actually emailed, read back out of mailpit
// rather than rebuilt (decision 6). That is the structural gap that let #112 survive: the
// only integration test that followed a reset-style link built the URL itself with
// url.QueryEscape, so it exercised a correct URL against a handler fed a correct URL and
// would have kept passing with every build site broken.

// plusAddress returns a unique address containing a '+', which is the class of address #112
// reports as broken: Go parses a query with form-urlencoded rules, where '+' decodes to a
// space, so the address came back mangled and the lookup failed.
func plusAddress() string {
	return "reset+tag." + strings.ToLower(gofakeit.LetterN(10)) + "@example.com"
}

// useMailpitSMTP points the deployment's SMTP settings at mailpit for the duration of a test
// and puts them back afterwards.
//
// Necessary rather than defensive: the settings API tests write these rows through the admin
// API and do not restore them, and Go runs the files in this package in name order, so by the
// time this one runs the host can be blank and the send fails with "dial tcp :0". The
// registration tests solve the same problem the same way, with saveAndRestoreRegSettings.
func useMailpitSMTP(t *testing.T) func() {
	t.Helper()

	settings, err := database.GetSettingsById(nil, 1)
	require.NoError(t, err)
	previous := *settings

	settings.SMTPEnabled = true
	settings.SMTPHost = "mailpit"
	settings.SMTPPort = 1025
	settings.SMTPEncryption = enums.SMTPEncryptionNone.String()
	settings.SMTPFromName = "Goiabada"
	settings.SMTPFromEmail = "noreply@goiabada.dev"
	require.NoError(t, database.UpdateSettings(nil, settings))

	return func() {
		restored := previous
		_ = database.UpdateSettings(nil, &restored)
	}
}

func createResetTestUser(t *testing.T, email string) (*models.User, string) {
	t.Helper()

	password := gofakeit.Password(true, true, true, true, false, 12) + "aA1!"
	passwordHashed, err := hashutil.HashPassword(password)
	require.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        email,
		PasswordHash: passwordHashed,
	}
	require.NoError(t, database.CreateUser(nil, user))
	return user, password
}

// requestPasswordReset drives POST /forgot-password, which is what issues the code and sends
// the email.
func requestPasswordReset(t *testing.T, client *http.Client, email string) {
	t.Helper()

	target := config.GetAuthServer().BaseURL + "/forgot-password"
	form := url.Values{"email": {email}}
	req, err := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", target)
	req.Header.Set("Origin", config.GetAuthServer().BaseURL)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

var resetLinkPattern = regexp.MustCompile(`https?://[^"'<>\s]+/reset-password[^"'<>\s]*`)

// emailedResetLinks returns every reset link Goiabada has sent to an address, newest first.
func emailedResetLinks(t *testing.T, to string) []string {
	t.Helper()
	return emailedLinksMatching(t, to, resetLinkPattern)
}

// emailedLinksMatching returns every link matching pattern that Goiabada has sent to an
// address, newest first. Shared with the activation flow, which reads its own links back out
// of mailpit exactly the same way rather than rebuilding them (#112 decision 6).
func emailedLinksMatching(t *testing.T, to string, pattern *regexp.Regexp) []string {
	t.Helper()

	resp, err := http.Get("http://mailpit:8025/api/v1/messages?limit=200")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)

	var listing testutil.MailpitData
	require.NoError(t, json.Unmarshal(body, &listing))

	matched := listing.Messages[:0:0]
	for _, msg := range listing.Messages {
		for _, addr := range msg.To {
			if strings.EqualFold(addr.Address, to) {
				matched = append(matched, msg)
				break
			}
		}
	}
	// Newest first, so a test that issued two codes can name which link it means rather than
	// depending on the API's ordering.
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].Created.After(matched[j].Created)
	})

	links := []string{}
	for _, msg := range matched {
		detailResp, err := http.Get("http://mailpit:8025/api/v1/message/" + msg.ID)
		require.NoError(t, err)
		detailBody, err := io.ReadAll(detailResp.Body)
		_ = detailResp.Body.Close()
		require.NoError(t, err)

		var message testutil.MailpitMessage
		require.NoError(t, json.Unmarshal(detailBody, &message))

		if found := pattern.FindString(message.HTML + " " + message.Text); found != "" {
			links = append(links, found)
		}
	}
	return links
}

// latestResetLink is the link a user would click, with the two properties #112 exists for
// asserted at the source: no address in it at all, and so nothing in it that needs escaping.
func latestResetLink(t *testing.T, to string) string {
	t.Helper()

	links := emailedResetLinks(t, to)
	require.NotEmpty(t, links, "expected a reset link emailed to %s", to)

	link := links[0]
	assert.NotContains(t, link, "@", "the reset link must carry no email address")
	assert.NotContains(t, link, "email=", "the reset link must carry no email parameter")

	parsed, err := url.Parse(link)
	require.NoError(t, err)
	assert.Equal(t, []string{"code"}, queryKeys(parsed), "the link must carry the code and nothing else")

	return link
}

func queryKeys(u *url.URL) []string {
	keys := []string{}
	for k := range u.Query() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// followResetLink performs the first hop and asserts the credential leaves the URL there. It
// returns the clean URL the browser is sent to.
func followResetLink(t *testing.T, client *http.Client, link string) string {
	t.Helper()

	resp := loadPage(t, client, link)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusSeeOther, resp.StatusCode,
		"following the emailed link must answer 303, not render the form")

	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "/reset-password", location.Path)
	assert.Empty(t, location.RawQuery,
		"the redirect target must carry no query, so the code cannot persist in history or a Referer")

	return config.GetAuthServer().BaseURL + location.Path
}

// postCleanReset submits the form to the clean URL, which is where the template's empty
// action sends it.
func postCleanReset(t *testing.T, client *http.Client, cleanURL string, password string) *http.Response {
	t.Helper()

	form := url.Values{
		"password":             {password},
		"passwordConfirmation": {password},
	}
	req, err := http.NewRequest("POST", cleanURL, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", cleanURL)
	req.Header.Set("Origin", config.GetAuthServer().BaseURL)

	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// capturedSessionCookies is what an attacker holding a copy of the browser's cookies would
// replay, and what the "same marker used twice" cases below present.
func capturedSessionCookies(t *testing.T, client *http.Client) []*http.Cookie {
	t.Helper()

	base, err := url.Parse(config.GetAuthServer().BaseURL)
	require.NoError(t, err)
	cookies := client.Jar.Cookies(base)
	require.NotEmpty(t, cookies, "the first hop must have set a session cookie")
	return cookies
}

func clientCarrying(t *testing.T, cookies []*http.Cookie) *http.Client {
	t.Helper()

	client := createHttpClient(t)
	base, err := url.Parse(config.GetAuthServer().BaseURL)
	require.NoError(t, err)
	client.Jar.SetCookies(base, cookies)
	return client
}

func passwordHashOf(t *testing.T, userId int64) string {
	t.Helper()

	user, err := database.GetUserById(nil, userId)
	require.NoError(t, err)
	require.NotNil(t, user)
	return user.PasswordHash
}

const resetCodeInvalidText = "The verification code appears to be invalid or expired"
const resetSucceededText = "Your password has been successfully set."

// The end-to-end guard for #112 itself: an address containing '+' completes a reset from the
// link Goiabada emailed it. Before this change the link carried the address, form-urlencoded
// parsing turned the '+' into a space, and this user could never recover their password.
func TestResetPassword_PlusAddressCompletesTheFlowFromTheEmailedLink(t *testing.T) {
	defer useMailpitSMTP(t)()

	email := plusAddress()
	user, oldPassword := createResetTestUser(t, email)

	client := createHttpClient(t)
	requestPasswordReset(t, client, email)

	link := latestResetLink(t, email)
	cleanURL := followResetLink(t, client, link)

	// The clean URL renders the form from the marker alone.
	formResp := loadPage(t, client, cleanURL)
	defer func() { _ = formResp.Body.Close() }()
	require.Equal(t, http.StatusOK, formResp.StatusCode)
	formBody := bodyString(t, formResp)
	assert.Contains(t, formBody, `name="password"`)
	assert.Contains(t, formBody, `name="passwordConfirmation"`)
	assert.NotContains(t, formBody, resetCodeInvalidText)

	const newPassword = "N3wP4ss!word"
	resp := postCleanReset(t, client, cleanURL, newPassword)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, bodyString(t, resp), resetSucceededText)

	after := passwordHashOf(t, user.Id)
	assert.True(t, hashutil.VerifyPasswordHash(after, newPassword),
		"the reset must have replaced the password hash")
	assert.False(t, hashutil.VerifyPasswordHash(after, oldPassword))
}

// The replay case a cookie jar is needed to see. The marker lives in a client-side cookie, so
// the server cannot invalidate a copy taken before it cleared it; what refuses the copy is the
// code hash it names no longer being outstanding once the password write claimed it.
func TestResetPassword_ReplayedMarkerAfterCompletionIsRefused(t *testing.T) {
	defer useMailpitSMTP(t)()

	email := plusAddress()
	user, _ := createResetTestUser(t, email)

	client := createHttpClient(t)
	requestPasswordReset(t, client, email)
	cleanURL := followResetLink(t, client, latestResetLink(t, email))

	// Taken while the marker is still live and usable.
	captured := capturedSessionCookies(t, client)

	const newPassword = "N3wP4ss!word"
	resp := postCleanReset(t, client, cleanURL, newPassword)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	hashAfterReset := passwordHashOf(t, user.Id)
	require.True(t, hashutil.VerifyPasswordHash(hashAfterReset, newPassword))

	attacker := clientCarrying(t, captured)

	// The form is refused, so the replay does not even get as far as a usable page.
	getResp := loadPage(t, attacker, cleanURL)
	getBody := bodyString(t, getResp)
	_ = getResp.Body.Close()
	assert.Contains(t, getBody, resetCodeInvalidText)

	// And the submission is refused, with the password left exactly as the real reset set it.
	postResp := postCleanReset(t, attacker, cleanURL, "Att4cker!Pass")
	postBody := bodyString(t, postResp)
	_ = postResp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, postResp.StatusCode)
	assert.Contains(t, postBody, resetCodeInvalidText)

	assert.Equal(t, hashAfterReset, passwordHashOf(t, user.Id),
		"a replayed marker must not change the password")
}

// A marker names the code hash outstanding when it was written, so issuing a newer code
// retires it. Without that binding a marker naming only the user id would survive every
// reissue, which is weaker than the flow this change replaces: today the password write NULLs
// the code and a stale link simply fails.
func TestResetPassword_MarkerIssuedBeforeANewerCodeIsRefused(t *testing.T) {
	defer useMailpitSMTP(t)()

	email := plusAddress()
	user, oldPassword := createResetTestUser(t, email)

	first := createHttpClient(t)
	requestPasswordReset(t, first, email)
	cleanURL := followResetLink(t, first, latestResetLink(t, email))

	// A second request replaces the outstanding code, and with it the hash the first marker
	// names.
	requestPasswordReset(t, createHttpClient(t), email)
	require.Len(t, emailedResetLinks(t, email), 2, "the second request must have emailed a second link")

	getResp := loadPage(t, first, cleanURL)
	getBody := bodyString(t, getResp)
	_ = getResp.Body.Close()
	assert.Contains(t, getBody, resetCodeInvalidText)

	postResp := postCleanReset(t, first, cleanURL, "St4le!Marker")
	postBody := bodyString(t, postResp)
	_ = postResp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, postResp.StatusCode)
	assert.Contains(t, postBody, resetCodeInvalidText)

	assert.True(t, hashutil.VerifyPasswordHash(passwordHashOf(t, user.Id), oldPassword),
		"a marker superseded by a newer code must not change the password")
}

// Two clients holding one copied marker, submitting different passwords. Exactly one may
// win: the password write claims the code hash in the same conditional UPDATE, so the second
// matches no row. Without the claim both would set a password and the later would silently
// overwrite the earlier.
func TestResetPassword_OneCopiedMarkerLeavesExactlyOnePasswordChange(t *testing.T) {
	defer useMailpitSMTP(t)()

	email := plusAddress()
	user, _ := createResetTestUser(t, email)

	client := createHttpClient(t)
	requestPasswordReset(t, client, email)
	cleanURL := followResetLink(t, client, latestResetLink(t, email))

	copied := clientCarrying(t, capturedSessionCookies(t, client))

	const firstPassword = "F1rst!Winner"
	const secondPassword = "S3cond!Loser"

	firstResp := postCleanReset(t, client, cleanURL, firstPassword)
	firstBody := bodyString(t, firstResp)
	_ = firstResp.Body.Close()

	secondResp := postCleanReset(t, copied, cleanURL, secondPassword)
	secondBody := bodyString(t, secondResp)
	_ = secondResp.Body.Close()

	assert.Equal(t, http.StatusOK, firstResp.StatusCode)
	assert.Contains(t, firstBody, resetSucceededText)
	assert.Equal(t, http.StatusBadRequest, secondResp.StatusCode)
	assert.Contains(t, secondBody, resetCodeInvalidText)

	after := passwordHashOf(t, user.Id)
	assert.True(t, hashutil.VerifyPasswordHash(after, firstPassword),
		"the winner's password must be the one that stands")
	assert.False(t, hashutil.VerifyPasswordHash(after, secondPassword),
		"the second submission of one marker must not overwrite the first")
}
