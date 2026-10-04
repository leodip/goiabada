package integration

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A pending registration can complete until 10 minutes after its link was sent; past that it is
// dead, and the next registration for its address replaces it (#207 decision 6). A row's age is
// set by writing its issued-at directly, never by waiting.

// ageRegistration moves a pending registration's link back in time, as if it had been sent that
// long ago.
func ageRegistration(t *testing.T, email string, age time.Duration) *record.PreRegistration {
	t.Helper()
	preReg, err := database.GetPreRegistrationByEmail(context.Background(), nil, email)
	require.NoError(t, err)
	require.NotNil(t, preReg)
	preReg.VerificationCodeIssuedAt = sql.NullTime{Time: time.Now().UTC().Add(-age), Valid: true}
	require.NoError(t, database.UpdatePreRegistration(context.Background(), nil, preReg))
	return preReg
}

// With verification, a registration for an address whose pending registration is dead gets the
// same page, and a fresh link that completes the registration; the dead link no longer does.
func TestSelfRegister_WithVerificationADeadRegistrationIsReplaced(t *testing.T) {
	useMailpitSMTP(t)
	requireDatabaseAuditLogs(t)
	setRegSettings(t, true, true, true)

	browser := createHttpClient(t)
	loadRegisterPage(t, browser)

	email := registerAddress()
	registerPage(t, browser, email)
	deadLink := latestActivationLink(t, email)
	dead := ageRegistration(t, email, 11*time.Minute)

	body := registerPage(t, browser, email)
	assert.Contains(t, body, checkYourEmailTitle)

	records := awaitRequestedRegistrationRecords(t, email, 2)
	require.Len(t, records, 2)
	assert.Equal(t, []string{"link_issued", "link_issued"}, outcomesOf(records),
		"a dead registration's replacement issues a link, as a new address's does")

	links := awaitActivationLinks(t, email, 2)
	require.Len(t, links, 2, "a fresh link is mailed for the dead registration")
	freshLink := links[0]
	assert.NotEqual(t, deadLink, freshLink)

	after, err := database.GetPreRegistrationByEmail(context.Background(), nil, email)
	require.NoError(t, err)
	require.NotNil(t, after)
	assert.Equal(t, dead.Id, after.Id, "the dead row is replaced in place")
	assert.NotEqual(t, dead.VerificationCodeHash, after.VerificationCodeHash)
	assert.WithinDuration(t, time.Now().UTC(), after.VerificationCodeIssuedAt.Time, time.Minute,
		"the fresh code is issued now")

	// The dead link finds nothing any more.
	stale := createHttpClient(t)
	resp := loadPage(t, stale, deadLink)
	staleBody := bodyString(t, resp)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, staleBody, activationExpiredText)

	// The fresh one completes the registration.
	cleanURL := followActivationLink(t, browser, freshLink)
	continuationId := loadActivationForm(t, browser, cleanURL, email)
	const chosenPassword = "Chosen-After-Replacement-1!"
	activateResp := postActivation(t, browser, cleanURL, chosenPassword, chosenPassword, continuationId)
	activationBody := bodyString(t, activateResp)
	_ = activateResp.Body.Close()
	assert.Equal(t, http.StatusOK, activateResp.StatusCode)
	assert.Contains(t, activationBody, activationSucceededText)

	user, err := database.GetUserByEmail(context.Background(), nil, email)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.True(t, user.EmailVerified)
	assert.True(t, passwordhash.Verify(user.PasswordHash, chosenPassword))
}

// With verification, a registration whose link was sent just inside the 10 minutes can still
// complete, so a repeat sends nothing and leaves it as it is.
func TestSelfRegister_WithVerificationARegistrationJustInsideTheWindowIsKept(t *testing.T) {
	useMailpitSMTP(t)
	requireDatabaseAuditLogs(t)
	setRegSettings(t, true, true, true)

	browser := createHttpClient(t)
	loadRegisterPage(t, browser)

	email := registerAddress()
	registerPage(t, browser, email)
	firstLink := latestActivationLink(t, email)
	pending := ageRegistration(t, email, 9*time.Minute)

	registerPage(t, browser, email)

	records := awaitRequestedRegistrationRecords(t, email, 2)
	require.Len(t, records, 2)
	assert.Equal(t, []string{"link_issued", "link_pending"}, outcomesOf(records))
	assert.Equal(t, []string{firstLink}, emailedLinksMatching(t, email, activationLinkPattern))

	after, err := database.GetPreRegistrationByEmail(context.Background(), nil, email)
	require.NoError(t, err)
	require.NotNil(t, after)
	assert.Equal(t, pending.VerificationCodeHash, after.VerificationCodeHash, "the row is untouched")
}

// Without verification, a pending registration that can still complete keeps the address taken,
// and a dead one is treated as absent (#207 decisions 3 and 6).
func TestSelfRegister_WithoutVerificationADeadRegistrationDoesNotTakeTheAddress(t *testing.T) {
	setRegSettings(t, true, false, false)

	seedPending := func(t *testing.T, age time.Duration) string {
		t.Helper()
		email := registerAddress()
		preReg := &record.PreRegistration{
			Email:                     email,
			VerificationCodeEncrypted: []byte(fake.UUID()),
			VerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC().Add(-age), Valid: true},
			VerificationCodeHash:      fake.UUID(),
		}
		require.NoError(t, database.CreatePreRegistration(context.Background(), nil, preReg))
		return email
	}

	t.Run("one that can still complete", func(t *testing.T) {
		email := seedPending(t, 9*time.Minute)
		httpClient := createHttpClient(t)
		loadRegisterPage(t, httpClient)

		resp := postRegister(t, httpClient, email, "Password123!", "Password123!")
		body := bodyString(t, resp)
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, body, "this email address is already registered")
		user, err := database.GetUserByEmail(context.Background(), nil, email)
		require.NoError(t, err)
		assert.Nil(t, user)
	})

	t.Run("a dead one", func(t *testing.T) {
		email := seedPending(t, 11*time.Minute)
		httpClient := createHttpClient(t)
		loadRegisterPage(t, httpClient)

		resp := postRegister(t, httpClient, email, "Password123!", "Password123!")
		body := bodyString(t, resp)
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, body, "Your account has been created.")
		user, err := database.GetUserByEmail(context.Background(), nil, email)
		require.NoError(t, err)
		require.NotNil(t, user, "a dead pending registration does not keep the address taken")
		assert.False(t, user.EmailVerified)
	})
}
