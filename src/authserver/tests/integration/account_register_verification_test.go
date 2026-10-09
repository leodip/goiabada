package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Registration with email verification answers every well-formed address alike, and what it led
// to travels in the mail (#207 decisions 4, 5 and 8). This tier is the only one that sees the
// response arrive before the mail does, and the mail each address actually gets.

// checkYourEmailTitle is the title of the one page every well-formed registration with
// verification is answered with.
const checkYourEmailTitle = "Check your email"

// existingAccountNoticeSubject is the notice's subject in English (#207 decision 13).
const existingAccountNoticeSubject = "You already have an account"

// registerAddress returns a unique address with no '+', so the page can be compared across
// addresses with the address taken out of it, html/template writing it the same way each time.
func registerAddress() string {
	return "register." + strings.ToLower(fake.LetterN(10)) + "@example.com"
}

// registerPage submits an address to the register form with verification on and returns the
// page it was answered with, requiring the 200 every well-formed address gets.
func registerPage(t *testing.T, client *http.Client, email string) string {
	t.Helper()
	resp := postRegisterAddress(t, client, email)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return bodyString(t, resp)
}

// disableAccount disables an account as an administrator would.
func disableAccount(t *testing.T, userId int64) {
	t.Helper()
	flipped, err := database.TrySetUserEnabled(context.Background(), nil, userId, true, false)
	require.NoError(t, err)
	require.True(t, flipped)
}

// unverifyAddress marks an account's address unverified.
func unverifyAddress(t *testing.T, user *record.User) {
	t.Helper()
	user.EmailVerified = false
	require.NoError(t, database.UpdateUser(context.Background(), nil, user))
}

// awaitRequestedRegistrationRecords returns the payload of every requested_registration record
// whose emailDigest is the SHA-256 hex of the address, digested here with crypto/sha256 rather than
// through the server's own helper, once at least count have arrived or afterResponseWait has run
// out. A well-formed request's record is written after its response (#207 decision 4).
func awaitRequestedRegistrationRecords(t *testing.T, address string, count int) []map[string]interface{} {
	t.Helper()

	sum := sha256.Sum256([]byte(address))
	digest := hex.EncodeToString(sum[:])
	adminToken, _ := createAdminClientWithToken(t)

	deadline := time.Now().Add(afterResponseWait)
	for {
		logs, resp := getAuditLogs(t, adminToken, "auditEvent="+audit.EventRequestedRegistration+"&size=200")
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		records := []map[string]interface{}{}
		for _, entry := range logs.AuditLogs {
			var details map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(entry.Details), &details))
			if details["email_digest"] == digest {
				assert.NotEmpty(t, entry.RequestId, "the record carries the request's id")
				records = append(records, details)
			}
		}
		if len(records) >= count || time.Now().After(deadline) {
			return records
		}
		time.Sleep(afterResponsePoll)
	}
}

// outcomesOf is the outcome of each record, sorted, so a test names what happened rather than the
// order the audit API lists it in.
func outcomesOf(records []map[string]interface{}) []string {
	outcomes := []string{}
	for _, details := range records {
		outcome, _ := details["outcome"].(string)
		outcomes = append(outcomes, outcome)
	}
	sort.Strings(outcomes)
	return outcomes
}

// Every well-formed address gets the same page, with only the address itself differing, and the
// mail each one's case calls for: a new address its link, a verified, enabled account the notice,
// and an unverified account, a disabled one and a pending address nothing (#207 decisions 4 and
// 5). The new address and the notice are the positive controls: without them, mail not arriving
// could mean SMTP was never on.
func TestSelfRegister_WithVerificationEveryAddressGetsTheSamePage(t *testing.T) {
	useMailpitSMTP(t)
	requireDatabaseAuditLogs(t)
	setRegSettings(t, true, true, true)

	newAddress := registerAddress()

	verifiedEmail := registerAddress()
	createResetTestUser(t, verifiedEmail)

	unverifiedEmail := registerAddress()
	unverified, _ := createResetTestUser(t, unverifiedEmail)
	unverifyAddress(t, unverified)

	disabledEmail := registerAddress()
	disabled, _ := createResetTestUser(t, disabledEmail)
	disableAccount(t, disabled.Id)

	pendingEmail := registerAddress()
	client := createHttpClient(t)
	loadRegisterPage(t, client)
	registerPage(t, client, pendingEmail)
	require.Len(t, awaitActivationLinks(t, pendingEmail, 1), 1, "the pending address's first registration is sent its link")

	pages := map[string]string{}
	for _, email := range []string{newAddress, verifiedEmail, unverifiedEmail, disabledEmail, pendingEmail} {
		page := registerPage(t, client, email)
		assert.Contains(t, page, checkYourEmailTitle)
		assert.Contains(t, page, "We&#39;ve sent a message to "+email+" with the next step.")
		assert.Contains(t, page, "register again in 10 minutes to get a new link.")
		pages[email] = strings.ReplaceAll(page, email, "{email}")
	}
	for email, page := range pages {
		assert.Equal(t, pages[newAddress], page, "the page for %s differs from a new address's", email)
	}

	t.Run("a new address is sent its link", func(t *testing.T) {
		require.Len(t, awaitActivationLinks(t, newAddress, 1), 1)
		messages := awaitMailTo(t, newAddress)
		require.Len(t, messages, 1)
		assert.Equal(t, "Activate your account", messages[0].Subject)
	})

	t.Run("a verified, enabled account is sent the notice", func(t *testing.T) {
		messages := awaitMailTo(t, verifiedEmail)
		require.Len(t, messages, 1)
		message := messages[0]

		settings, err := database.GetSettingsById(context.Background(), nil, 1)
		require.NoError(t, err)
		forgotPasswordURL := appConfig.AuthServer.BaseURL + "/forgot-password"

		assert.Equal(t, existingAccountNoticeSubject, message.Subject)
		assert.Contains(t, message.HTML, "Someone, possibly you, tried to create a new "+settings.AppName+
			" account with this email address. This address already has an account, so no new account was created.")
		assert.Contains(t, message.HTML, "If it was you, sign in with your existing account. If you don't remember your password, you can reset it here:")
		assert.Contains(t, message.HTML, `href="`+forgotPasswordURL+`"`)
		assert.Contains(t, message.HTML, "If it wasn't you, you can ignore this message. Your account has not been changed.")
		assert.NotContains(t, message.HTML, "code=", "the notice carries no code")
		assert.Empty(t, emailedLinksMatching(t, verifiedEmail, activationLinkPattern), "and no activation link")
	})

	for _, tc := range []struct {
		name    string
		email   string
		records int
	}{
		{name: "an unverified account is sent nothing", email: unverifiedEmail, records: 1},
		{name: "a disabled account is sent nothing", email: disabledEmail, records: 1},
		{name: "a pending address is sent nothing new", email: pendingEmail, records: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The record is the last thing the work after the response does for an address it
			// sends nothing to, so once it is there nothing more is coming.
			require.Len(t, awaitRequestedRegistrationRecords(t, tc.email, tc.records), tc.records)
			wantMail := tc.records - 1
			assert.Len(t, sentTo(t, tc.email), wantMail)
		})
	}

	for _, email := range []string{newAddress, pendingEmail} {
		user, err := database.GetUserByEmail(context.Background(), nil, email)
		require.NoError(t, err)
		assert.Nil(t, user, "registering %s creates no account before the link is used", email)
	}
}

// The notice is rendered in the account's stored locale (#207 decision 5).
func TestSelfRegister_WithVerificationTheNoticeIsInTheAccountsLocale(t *testing.T) {
	useMailpitSMTP(t)
	setRegSettings(t, true, true, true)

	email := registerAddress()
	user, _ := createResetTestUser(t, email)
	user.Locale = "pt-BR"
	require.NoError(t, database.UpdateUser(context.Background(), nil, user))

	client := createHttpClient(t)
	loadRegisterPage(t, client)
	registerPage(t, client, email)

	messages := awaitMailTo(t, email)
	require.Len(t, messages, 1)
	assert.Equal(t, "Você já tem uma conta", messages[0].Subject)
	assert.Contains(t, messages[0].HTML, "Este endereço já tem uma conta, então nenhuma conta nova foi criada.")
}

// Every registration with verification leaves exactly one requested_registration record saying
// what became of it, with the address digested rather than recorded (#207 decision 8).
func TestSelfRegister_WithVerificationEveryRequestIsAuditedOnce(t *testing.T) {
	useMailpitSMTP(t)
	requireDatabaseAuditLogs(t)
	setRegSettings(t, true, true, true)

	newAddress := registerAddress()
	malformed := "not-an-address-" + strings.ToLower(fake.LetterN(10))

	verifiedEmail := registerAddress()
	verified, _ := createResetTestUser(t, verifiedEmail)

	unverifiedEmail := registerAddress()
	unverified, _ := createResetTestUser(t, unverifiedEmail)
	unverifyAddress(t, unverified)

	disabledEmail := registerAddress()
	disabled, _ := createResetTestUser(t, disabledEmail)
	disableAccount(t, disabled.Id)

	client := createHttpClient(t)
	loadRegisterPage(t, client)
	for _, address := range []string{newAddress, verifiedEmail, unverifiedEmail, disabledEmail} {
		registerPage(t, client, address)
	}
	// Submitted in capitals: the digest is of the address as it was looked up, lowercased.
	malformedPage := registerPage(t, client, strings.ToUpper(malformed))
	assert.NotContains(t, malformedPage, checkYourEmailTitle, "a malformed address keeps its own redrawn form")

	newRecords := awaitRequestedRegistrationRecords(t, newAddress, 1)
	require.Len(t, newRecords, 1)
	preRegistration, err := database.GetPreRegistrationByEmail(context.Background(), nil, newAddress)
	require.NoError(t, err)
	require.NotNil(t, preRegistration)

	for _, tc := range []struct {
		name              string
		address           string
		userId            int64
		preRegistrationId int64
		outcome           string
	}{
		{name: "a new address", address: newAddress, preRegistrationId: preRegistration.Id, outcome: "link_issued"},
		{name: "a verified, enabled account", address: verifiedEmail, userId: verified.Id, outcome: "notice_issued"},
		{name: "an unverified account", address: unverifiedEmail, userId: unverified.Id, outcome: "unverified_address"},
		{name: "a disabled account", address: disabledEmail, userId: disabled.Id, outcome: "account_disabled"},
		{name: "a malformed address", address: malformed, outcome: "invalid_address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := awaitRequestedRegistrationRecords(t, tc.address, 1)
			require.Len(t, records, 1, "exactly one record per request")
			details := records[0]

			assert.Equal(t, tc.outcome, details["outcome"])
			assert.NotEmpty(t, details["ip"])
			if tc.userId == 0 {
				assert.NotContains(t, details, "user_id", "no account matched, so none is named")
			} else {
				assert.InDelta(t, float64(tc.userId), details["user_id"], 0)
			}
			if tc.preRegistrationId == 0 {
				assert.NotContains(t, details, "pre_registration_id")
			} else {
				assert.InDelta(t, float64(tc.preRegistrationId), details["pre_registration_id"], 0)
			}
			for key, value := range details {
				assert.NotContains(t, strings.ToLower(fmt.Sprint(value)), tc.address,
					"the address must not appear in the record, found under %q", key)
			}
		})
	}
}

// A new address is answered before its mail is sent, and a mail server that never answers is not
// the registrant's problem: the page is the "check your email" one at 200, where a send inside the
// request held it until the sender gave up and then answered 500, which an address with an account
// never got (#207 decision 4). The send is seen to start after the page has arrived, and the
// pending registration and the record are there although no mail went out.
func TestSelfRegister_WithVerificationAnswersBeforeTheMailIsSent(t *testing.T) {
	useMailpitSMTP(t)
	requireDatabaseAuditLogs(t)
	setRegSettings(t, true, true, true)
	port, accepted := silentSMTPServer(t)
	changeSettings(t, func(settings *record.Settings) {
		settings.SMTPHost = "127.0.0.1"
		settings.SMTPPort = port
	})

	email := registerAddress()
	client := createHttpClient(t)
	loadRegisterPage(t, client)

	start := time.Now()
	page := registerPage(t, client, email)
	answeredIn := time.Since(start)

	assert.Contains(t, page, checkYourEmailTitle)
	assert.Less(t, answeredIn, 5*time.Second, "the response must not wait on the mail server")

	select {
	case <-accepted:
	case <-time.After(afterResponseWait):
		t.Fatal("the mail was never attempted")
	}

	records := awaitRequestedRegistrationRecords(t, email, 1)
	require.Len(t, records, 1)
	assert.Equal(t, "link_issued", records[0]["outcome"])

	preRegistration, err := database.GetPreRegistrationByEmail(context.Background(), nil, email)
	require.NoError(t, err)
	assert.NotNil(t, preRegistration, "the pending registration is written before the send")
}
