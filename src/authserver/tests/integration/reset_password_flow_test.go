package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/testutil/mailpit"
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
	return "reset+tag." + strings.ToLower(fake.LetterN(10)) + "@example.com"
}

// mailpitURL is the API of the Mailpit useMailpitSMTP sends through.
const mailpitURL = "http://mailpit:8025"

// useMailpitSMTP turns SMTP on and points it at mailpit until the test ends. TestMain points the
// row at mailpit but leaves SMTP off, as seeded, so a test that sends mail turns it on itself.
func useMailpitSMTP(t *testing.T) {
	t.Helper()
	changeSettings(t, func(settings *models.Settings) {
		settings.SMTPEnabled = true
		settings.SMTPHost = "mailpit"
		settings.SMTPPort = 1025
		settings.SMTPEncryption = emaildelivery.SMTPEncryptionNone.String()
		settings.SMTPFromName = "Goiabada"
		settings.SMTPFromEmail = "noreply@goiabada.dev"
	})
}

func createResetTestUser(t *testing.T, email string) (*models.User, string) {
	t.Helper()

	password := fake.Password(12) + "aA1!"
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)

	// Verified, because recovery goes only to an address the account has proven (#404
	// decision 1): an unverified one is sent nothing.
	user := &models.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         email,
		EmailVerified: true,
		PasswordHash:  passwordHashed,
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	return user, password
}

// requestPasswordReset drives POST /forgot-password, which is what issues the code and sends
// the email.
func requestPasswordReset(t *testing.T, client *http.Client, email string) {
	t.Helper()
	_ = requestPasswordResetPage(t, client, email)
}

// requestPasswordResetPage is requestPasswordReset returning the page it was answered with.
func requestPasswordResetPage(t *testing.T, client *http.Client, email string) string {
	t.Helper()

	target := appConfig.AuthServer.BaseURL + "/forgot-password"
	form := url.Values{"email": {email}}
	req, err := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", target)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return bodyString(t, resp)
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

	client := mailpit.New(mailpitURL)
	summaries, err := client.List()
	require.NoError(t, err)

	matched := []mailpit.Summary{}
	for _, msg := range summaries {
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
		message, err := client.Message(msg.ID)
		require.NoError(t, err)

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

	return appConfig.AuthServer.BaseURL + location.Path
}

var continuationIdPattern = regexp.MustCompile(
	`<input[^>]*name="continuationId"[^>]*value="([^"]*)"`)

// continuationIdIn reads the hidden field out of a rendered form, which is the only place
// a browser gets it from. Parsing the page rather than reaching into the session is what
// makes these cases able to fail: a template that stopped emitting the field, or a handler
// that stopped binding it, breaks the flow here exactly as it would in a browser (#112).
func continuationIdIn(t *testing.T, formBody string) string {
	t.Helper()

	match := continuationIdPattern.FindStringSubmatch(formBody)
	require.NotNil(t, match, "the reset form must carry the continuation id it was rendered from")
	require.NotEmpty(t, match[1])
	return match[1]
}

// loadResetForm fetches the clean URL and returns the continuation id its form carries.
func loadResetForm(t *testing.T, client *http.Client, cleanURL string) string {
	t.Helper()

	resp := loadPage(t, client, cleanURL)
	body := bodyString(t, resp)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, body, `name="password"`)
	return continuationIdIn(t, body)
}

// postCleanReset submits the form to the clean URL, which is where the template's empty
// action sends it, carrying the continuation id the rendered form held.
func postCleanReset(t *testing.T, client *http.Client, cleanURL string, password string,
	continuationId string) *http.Response {
	t.Helper()

	form := url.Values{
		"password":             {password},
		"passwordConfirmation": {password},
		"continuationId":       {continuationId},
	}
	req, err := http.NewRequest("POST", cleanURL, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", cleanURL)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)

	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// capturedSessionCookies is what an attacker holding a copy of the browser's cookies would
// replay, and what the "same marker used twice" cases below present.
func capturedSessionCookies(t *testing.T, client *http.Client) []*http.Cookie {
	t.Helper()

	base, err := url.Parse(appConfig.AuthServer.BaseURL)
	require.NoError(t, err)
	cookies := client.Jar.Cookies(base)
	require.NotEmpty(t, cookies, "the first hop must have set a session cookie")
	return cookies
}

func clientCarrying(t *testing.T, cookies []*http.Cookie) *http.Client {
	t.Helper()

	client := createHttpClient(t)
	base, err := url.Parse(appConfig.AuthServer.BaseURL)
	require.NoError(t, err)
	client.Jar.SetCookies(base, cookies)
	return client
}

func passwordHashOf(t *testing.T, userId int64) string {
	t.Helper()

	user, err := database.GetUserById(context.Background(), nil, userId)
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
	useMailpitSMTP(t)

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
	resp := postCleanReset(t, client, cleanURL, newPassword, continuationIdIn(t, formBody))
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, bodyString(t, resp), resetSucceededText)

	after := passwordHashOf(t, user.Id)
	assert.True(t, passwordhash.Verify(after, newPassword),
		"the reset must have replaced the password hash")
	assert.False(t, passwordhash.Verify(after, oldPassword))
}

// The replay case a cookie jar is needed to see. The marker lives in a client-side cookie, so
// the server cannot invalidate a copy taken before it cleared it; what refuses the copy is the
// code hash it names no longer being outstanding once the password write claimed it.
func TestResetPassword_ReplayedMarkerAfterCompletionIsRefused(t *testing.T) {
	useMailpitSMTP(t)

	email := plusAddress()
	user, _ := createResetTestUser(t, email)

	client := createHttpClient(t)
	requestPasswordReset(t, client, email)
	cleanURL := followResetLink(t, client, latestResetLink(t, email))
	continuationId := loadResetForm(t, client, cleanURL)

	// Taken while the marker is still live and usable.
	captured := capturedSessionCookies(t, client)

	const newPassword = "N3wP4ss!word"
	resp := postCleanReset(t, client, cleanURL, newPassword, continuationId)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	hashAfterReset := passwordHashOf(t, user.Id)
	require.True(t, passwordhash.Verify(hashAfterReset, newPassword))

	attacker := clientCarrying(t, captured)

	// The form is refused, so the replay does not even get as far as a usable page.
	getResp := loadPage(t, attacker, cleanURL)
	getBody := bodyString(t, getResp)
	_ = getResp.Body.Close()
	assert.Contains(t, getBody, resetCodeInvalidText)

	// And the submission is refused, with the password left exactly as the real reset set it.
	// The replay carries the captured continuation id as well as the captured cookies, so
	// what refuses it is the code hash no longer resolving rather than a missing field.
	postResp := postCleanReset(t, attacker, cleanURL, "Att4cker!Pass", continuationId)
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
	useMailpitSMTP(t)

	email := plusAddress()
	user, oldPassword := createResetTestUser(t, email)

	first := createHttpClient(t)
	requestPasswordReset(t, first, email)
	cleanURL := followResetLink(t, first, latestResetLink(t, email))
	continuationId := loadResetForm(t, first, cleanURL)

	// A second request replaces the outstanding code, and with it the hash the first marker
	// names.
	requestPasswordReset(t, createHttpClient(t), email)
	require.Len(t, emailedResetLinks(t, email), 2, "the second request must have emailed a second link")

	getResp := loadPage(t, first, cleanURL)
	getBody := bodyString(t, getResp)
	_ = getResp.Body.Close()
	assert.Contains(t, getBody, resetCodeInvalidText)

	postResp := postCleanReset(t, first, cleanURL, "St4le!Marker", continuationId)
	postBody := bodyString(t, postResp)
	_ = postResp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, postResp.StatusCode)
	assert.Contains(t, postBody, resetCodeInvalidText)

	assert.True(t, passwordhash.Verify(passwordHashOf(t, user.Id), oldPassword),
		"a marker superseded by a newer code must not change the password")
}

// The wrong-account credential write, in the tier that shows it: one cookie jar, two
// accounts, and a form already on screen (#112 decision 13).
//
// One session holds one marker and the form names nothing about the marker that rendered it,
// so before the first-writer-wins rule a reset link followed between the form rendering and
// its submit retargeted that submit. SameSite=Lax sends the session cookie on a top-level GET
// navigation, so one steered click was enough for the password a victim typed to be written
// into an account somebody else controls, with the victim shown the ordinary success page and
// their own password left unchanged.
//
// Nothing below this tier can see it: it needs two live continuations in one real cookie jar.
func TestResetPassword_ASecondLinkDoesNotRetargetTheFormOnScreen(t *testing.T) {
	useMailpitSMTP(t)

	victimEmail := plusAddress()
	victim, victimOldPassword := createResetTestUser(t, victimEmail)

	otherEmail := plusAddress()
	other, otherOldPassword := createResetTestUser(t, otherEmail)

	browser := createHttpClient(t)
	requestPasswordReset(t, browser, victimEmail)
	cleanURL := followResetLink(t, browser, latestResetLink(t, victimEmail))

	// The victim's form is on screen, carrying the continuation it was rendered from.
	formResp := loadPage(t, browser, cleanURL)
	formBody := bodyString(t, formResp)
	_ = formResp.Body.Close()
	require.Contains(t, formBody, `name="password"`)
	continuationId := continuationIdIn(t, formBody)

	// The steered navigation: a reset link for the other account, followed in the same jar.
	// Issued from elsewhere, because what matters is where it is FOLLOWED.
	requestPasswordReset(t, createHttpClient(t), otherEmail)

	steeredResp := loadPage(t, browser, latestResetLink(t, otherEmail))
	steeredBody := bodyString(t, steeredResp)
	_ = steeredResp.Body.Close()

	assert.NotEqual(t, http.StatusSeeOther, steeredResp.StatusCode,
		"a second link followed while one is live must not take over the session")
	assert.Contains(t, steeredBody, resetCodeInvalidText)

	// The victim submits the form they were already looking at.
	const newPassword = "V1ctim!Choice"
	resp := postCleanReset(t, browser, cleanURL, newPassword, continuationId)
	body := bodyString(t, resp)
	_ = resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, resetSucceededText)

	victimHash := passwordHashOf(t, victim.Id)
	assert.True(t, passwordhash.Verify(victimHash, newPassword),
		"the password typed must land in the account whose link rendered the form")
	assert.False(t, passwordhash.Verify(victimHash, victimOldPassword))

	otherHash := passwordHashOf(t, other.Id)
	assert.True(t, passwordhash.Verify(otherHash, otherOldPassword),
		"the second account must be untouched")
	assert.False(t, passwordhash.Verify(otherHash, newPassword))
}

// The retarget that survives every rule about WRITING the marker, and the reason the form
// carries a continuation id (#112 decision 14).
//
// One browser, two tabs on the same reset. Tab 1 completes, which clears the marker, so the
// slot is free and a second account's link legitimately takes it. Tab 2 is still on screen,
// names nothing but its own continuation, and posts to the identical clean URL. Without the
// binding the password typed for the victim's own reset is written into the other account.
//
// This is leg 2 of the family reached without a clock: the marker's five-minute expiry
// produces exactly this state, a live marker for another account under a form rendered from
// a marker that is gone, and a completed reset produces it in seconds instead.
func TestResetPassword_AStaleFormIsRefusedOnceTheSessionHoldsAnotherContinuation(t *testing.T) {
	useMailpitSMTP(t)

	victimEmail := plusAddress()
	victim, _ := createResetTestUser(t, victimEmail)

	otherEmail := plusAddress()
	other, otherOldPassword := createResetTestUser(t, otherEmail)

	browser := createHttpClient(t)
	requestPasswordReset(t, browser, victimEmail)
	cleanURL := followResetLink(t, browser, latestResetLink(t, victimEmail))

	// Two tabs on one reset, so both forms carry the same continuation.
	staleTabContinuationId := loadResetForm(t, browser, cleanURL)
	activeTabContinuationId := loadResetForm(t, browser, cleanURL)
	require.Equal(t, staleTabContinuationId, activeTabContinuationId,
		"one link followed once is one continuation, however many times its form is rendered")

	const victimPassword = "V1ctim!Choice"
	resp := postCleanReset(t, browser, cleanURL, victimPassword, activeTabContinuationId)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	victimHash := passwordHashOf(t, victim.Id)
	require.True(t, passwordhash.Verify(victimHash, victimPassword))

	// The slot is free now, so the other account's link takes it legitimately: this is not
	// the refused second link, it is the session moving on.
	requestPasswordReset(t, createHttpClient(t), otherEmail)
	otherCleanURL := followResetLink(t, browser, latestResetLink(t, otherEmail))
	require.Equal(t, cleanURL, otherCleanURL, "both flows land on the same clean URL, which is the whole problem")

	// The stale tab submits. It names a continuation the session no longer holds.
	const typedInTheStaleTab = "St4le!TabChoice"
	staleResp := postCleanReset(t, browser, cleanURL, typedInTheStaleTab, staleTabContinuationId)
	staleBody := bodyString(t, staleResp)
	_ = staleResp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, staleResp.StatusCode)
	assert.Contains(t, staleBody, resetCodeInvalidText)

	otherHash := passwordHashOf(t, other.Id)
	assert.True(t, passwordhash.Verify(otherHash, otherOldPassword),
		"a form rendered for one account must not write into the account the session moved on to")
	assert.False(t, passwordhash.Verify(otherHash, typedInTheStaleTab))

	// And the account the stale form did belong to is untouched too: its reset already
	// completed, and this submission changed nothing.
	assert.Equal(t, victimHash, passwordHashOf(t, victim.Id))
}

// Two clients holding one copied marker, submitting different passwords. Exactly one may
// win: the password write claims the code hash in the same conditional UPDATE, so the second
// matches no row. Without the claim both would set a password and the later would silently
// overwrite the earlier.
func TestResetPassword_OneCopiedMarkerLeavesExactlyOnePasswordChange(t *testing.T) {
	useMailpitSMTP(t)

	email := plusAddress()
	user, _ := createResetTestUser(t, email)

	client := createHttpClient(t)
	requestPasswordReset(t, client, email)
	cleanURL := followResetLink(t, client, latestResetLink(t, email))
	continuationId := loadResetForm(t, client, cleanURL)

	copied := clientCarrying(t, capturedSessionCookies(t, client))

	const firstPassword = "F1rst!Winner"
	const secondPassword = "S3cond!Loser"

	// Both submissions name the same continuation, because both hold the same marker. What
	// separates them is the conditional claim, which is the subject here.
	firstResp := postCleanReset(t, client, cleanURL, firstPassword, continuationId)
	firstBody := bodyString(t, firstResp)
	_ = firstResp.Body.Close()

	secondResp := postCleanReset(t, copied, cleanURL, secondPassword, continuationId)
	secondBody := bodyString(t, secondResp)
	_ = secondResp.Body.Close()

	assert.Equal(t, http.StatusOK, firstResp.StatusCode)
	assert.Contains(t, firstBody, resetSucceededText)
	assert.Equal(t, http.StatusBadRequest, secondResp.StatusCode)
	assert.Contains(t, secondBody, resetCodeInvalidText)

	after := passwordHashOf(t, user.Id)
	assert.True(t, passwordhash.Verify(after, firstPassword),
		"the winner's password must be the one that stands")
	assert.False(t, passwordhash.Verify(after, secondPassword),
		"the second submission of one marker must not overwrite the first")
}

// linkSentText is the modal the forgot-password page shows once a request is accepted, whatever
// became of it. Cut before the apostrophe, which the page's script escapes.
const linkSentText = "a password reset link has been sent to your email address."

// Recovery goes only to a verified address on an enabled account. An unverified address and a
// disabled account are answered as an address with no account is, and nothing is mailed or
// stored for them (#404 decisions 1 and 2). The live account beside them is the positive
// control: without it, mail not arriving could mean SMTP was never on.
func TestForgotPassword_SendsNothingUnlessTheAddressIsVerifiedAndTheAccountEnabled(t *testing.T) {
	useMailpitSMTP(t)

	unknown := plusAddress()
	unverifiedEmail := plusAddress()
	unverified, _ := createResetTestUser(t, unverifiedEmail)
	unverified.EmailVerified = false
	require.NoError(t, database.UpdateUser(context.Background(), nil, unverified))

	disabledEmail := plusAddress()
	disabled, _ := createResetTestUser(t, disabledEmail)
	flipped, err := database.TrySetUserEnabled(context.Background(), nil, disabled.Id, true, false)
	require.NoError(t, err)
	require.True(t, flipped)

	liveEmail := plusAddress()
	createResetTestUser(t, liveEmail)

	client := createHttpClient(t)
	unknownPage := requestPasswordResetPage(t, client, unknown)
	assert.Contains(t, unknownPage, linkSentText)

	for _, tc := range []struct {
		name  string
		email string
		user  *models.User
	}{
		{name: "an unverified address", email: unverifiedEmail, user: unverified},
		{name: "a disabled account", email: disabledEmail, user: disabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := requestPasswordResetPage(t, client, tc.email)
			assert.Contains(t, page, linkSentText, "answered as an address with no account is")

			stored, err := database.GetUserById(context.Background(), nil, tc.user.Id)
			require.NoError(t, err)
			assert.Empty(t, stored.ForgotPasswordCodeHash, "no reset code may be stored")
			assert.Empty(t, stored.ForgotPasswordCodeEncrypted, "no reset code may be stored")
		})
	}

	requestPasswordReset(t, client, liveEmail)
	require.NotEmpty(t, emailedResetLinks(t, liveEmail), "the live account is mailed, so SMTP was on")

	assert.Empty(t, emailedResetLinks(t, unverifiedEmail), "an unverified address must be sent nothing")
	assert.Empty(t, emailedResetLinks(t, disabledEmail), "a disabled account must be sent nothing")
}

// failedResetReasonsFor returns the reasons of every failed_reset_password_code record naming a
// user, which is where a refusal's cause is visible, since the page is the same for all of them.
func failedResetReasonsFor(t *testing.T, userId int64) []string {
	t.Helper()

	adminToken, _ := createAdminClientWithToken(t)
	logs, resp := getAuditLogs(t, adminToken, "auditEvent="+audit.AuditFailedResetPasswordCode+"&size=200")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	reasons := []string{}
	for _, entry := range logs.AuditLogs {
		var details map[string]interface{}
		if err := json.Unmarshal([]byte(entry.Details), &details); err != nil {
			continue
		}
		if id, ok := details["userId"].(float64); ok && int64(id) == userId {
			reason, _ := details["reason"].(string)
			reasons = append(reasons, reason)
		}
	}
	return reasons
}

// A reset link stops working the moment its account is disabled, at each of the three steps,
// and the refusal is the one every dead link gets (#404 decision 2). The steps are reached in
// order on one browser, so each refusal is of a link that was live a moment before.
func TestResetPassword_DisablingTheAccountStopsTheLinkAtEveryStep(t *testing.T) {
	useMailpitSMTP(t)
	requireDatabaseAuditLogs(t)

	setEnabled := func(t *testing.T, userId int64, enabled bool) {
		t.Helper()
		flipped, err := database.TrySetUserEnabled(context.Background(), nil, userId, !enabled, enabled)
		require.NoError(t, err)
		require.True(t, flipped)
	}

	email := plusAddress()
	user, oldPassword := createResetTestUser(t, email)
	hashBefore := passwordHashOf(t, user.Id)

	client := createHttpClient(t)
	requestPasswordReset(t, client, email)
	link := latestResetLink(t, email)

	// 1. Following the emailed link.
	setEnabled(t, user.Id, false)
	resp := loadPage(t, client, link)
	body := bodyString(t, resp)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the first hop keeps its 200, as for every dead link")
	assert.Contains(t, body, resetCodeInvalidText)

	// 2. Rendering the form, from a marker set while the account was enabled.
	setEnabled(t, user.Id, true)
	cleanURL := followResetLink(t, client, link)
	continuationId := loadResetForm(t, client, cleanURL)

	setEnabled(t, user.Id, false)
	resp = loadPage(t, client, cleanURL)
	body = bodyString(t, resp)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, resetCodeInvalidText)
	assert.NotContains(t, body, `name="password"`)

	// 3. Submitting the form.
	resp = postCleanReset(t, client, cleanURL, "N3wP4ss!word", continuationId)
	body = bodyString(t, resp)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, body, resetCodeInvalidText)

	assert.Equal(t, hashBefore, passwordHashOf(t, user.Id), "a disabled account must not be given a password")
	assert.True(t, passwordhash.Verify(passwordHashOf(t, user.Id), oldPassword))

	assert.Equal(t, []string{"account_disabled", "account_disabled", "account_disabled"},
		failedResetReasonsFor(t, user.Id), "each refused step is audited with the reason account_disabled")
}
