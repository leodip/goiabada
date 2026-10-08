package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An address typed into the sign-in form is stored in the audit log only as its digest: a failed
// sign-in records the SHA-256 of the address as the lookup normalized it, never the address, and
// names the account it was tried against when there is one (#522 decision 10).

// passwordFormSubmission is one password form reached by a fresh ceremony, ready to be submitted.
type passwordFormSubmission struct {
	httpClient *http.Client
	pwdURL     string
	ceremonyId string
}

// reachPasswordForm starts a code ceremony for a new client and stops at the password form.
func reachPasswordForm(t *testing.T) *passwordFormSubmission {
	t.Helper()

	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		DefaultAcrLevel:          record.AcrLevel1,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })

	redirectURI := &record.RedirectURI{ClientId: client.Id, URI: fake.URL()}
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, redirectURI))

	httpClient := createHttpClient(t)
	resp, err := httpClient.Get(appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + fake.LetterN(43) +
		"&scope=openid" +
		"&state=" + fake.LetterN(8) +
		"&nonce=" + fake.LetterN(8))
	require.NoError(t, err)
	_ = resp.Body.Close()

	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/level1"))
	_ = resp.Body.Close()

	pwdURL := assertRedirect(t, resp, "/auth/pwd")
	pwdPage := loadPage(t, httpClient, pwdURL)
	defer func() { _ = pwdPage.Body.Close() }()

	return &passwordFormSubmission{
		httpClient: httpClient,
		pwdURL:     pwdURL,
		ceremonyId: getCeremonyIdFromPage(t, pwdPage),
	}
}

// submit posts the form under a request id of its own and returns that id, so the audit rows the
// submission left can be read back by it.
func (f *passwordFormSubmission) submit(t *testing.T, email, password string) string {
	t.Helper()

	form := url.Values{"email": {email}, "password": {password}, "ceremonyId": {f.ceremonyId}}
	req, err := http.NewRequest(http.MethodPost, f.pwdURL, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", f.pwdURL)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)
	requestId := "pwd-" + fake.LetterN(16)
	req.Header.Set("X-Request-Id", requestId)

	resp, err := f.httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "a refused sign-in re-renders the form")
	return requestId
}

// sha256Hex is the digest the audit row is expected to carry, computed here rather than through
// the server's own helper.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestAuthFailedPwd_TheTypedAddressIsStoredOnlyAsItsDigest(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, adminClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, adminClient.Id) })

	t.Run("an address that names no account", func(t *testing.T) {
		local := "nobody-" + strings.ToLower(fake.LetterN(10))
		typed := "  " + strings.ToUpper(local) + "@Example.com "

		requestId := reachPasswordForm(t).submit(t, typed, fake.Password(12))

		assert.Equal(t, []map[string]any{{"email_digest": sha256Hex(local + "@example.com")}},
			auditRows(t, adminToken, "auth_failed_pwd", requestId))
	})

	t.Run("a wrong password for an account that exists", func(t *testing.T) {
		passwordHashed, err := passwordhash.Hash(fake.Password(12))
		require.NoError(t, err)
		user := &record.User{
			Subject:      fake.UUID(),
			Enabled:      true,
			Email:        strings.ToLower(fake.Email()),
			PasswordHash: passwordHashed,
		}
		require.NoError(t, database.CreateUser(context.Background(), nil, user))
		t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })

		requestId := reachPasswordForm(t).submit(t, strings.ToUpper(user.Email), "not-"+fake.Password(12))

		assert.Equal(t, []map[string]any{{
			"email_digest": sha256Hex(user.Email),
			"user_id":      float64(user.Id),
		}}, auditRows(t, adminToken, "auth_failed_pwd", requestId))
	})
}
