package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
)

// The client authentication limit at the token endpoint, over HTTP (#707 decisions 1 to 7, 10 and
// 11): 200 missing or wrong secrets an hour for one confidential client, across every grant, then
// 429 Too Many Requests with Retry-After, its right secret included, whatever the rate limiter
// switch says. This tier runs with the switch off. Every test creates its own clients, so a budget
// it spends is its own; the counts are written out rather than read from the limiter.

// clientAuthAnswer is what a client receives from the token endpoint.
type clientAuthAnswer struct {
	status     int
	retryAfter string
	challenge  string
	body       map[string]interface{}
}

func (a clientAuthAnswer) String() string {
	return fmt.Sprintf("%d %v", a.status, a.body)
}

// postClientAuthentication posts form to the token endpoint for clientId with secret, in the
// Authorization header when basic is set and in the body otherwise; an empty secret sends none.
func postClientAuthentication(t *testing.T, form url.Values, basic bool, clientId, secret string) clientAuthAnswer {
	t.Helper()
	sent := url.Values{}
	for k, v := range form {
		sent[k] = v
	}
	if !basic {
		sent.Set("client_id", clientId)
		if secret != "" {
			sent.Set("client_secret", secret)
		}
	}
	destUrl := appConfig.AuthServer.BaseURL + "/auth/token/"
	req, err := http.NewRequest(http.MethodPost, destUrl, strings.NewReader(sent.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth(clientId, secret)
	}

	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	answer := clientAuthAnswer{status: resp.StatusCode, retryAfter: resp.Header.Get("Retry-After"),
		challenge: resp.Header.Get("WWW-Authenticate")}
	require.NoError(t, json.Unmarshal(raw, &answer.body), "status %d, body: %s", resp.StatusCode, string(raw))
	return answer
}

// The token endpoint's grants, each as a request that reaches the client's secret check.
var (
	clientCredentialsForm = url.Values{"grant_type": {"client_credentials"}}
	refreshTokenForm      = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"not-a-refresh-token"}}
)

func passwordForm(username, password string) url.Values {
	return url.Values{"grant_type": {"password"}, "username": {username}, "password": {password}, "scope": {"openid"}}
}

// newLimitedClient creates an enabled confidential client for the client credentials, password and
// authorization code grants, with secret.
func newLimitedClient(t *testing.T, secret string) *record.Client {
	t.Helper()
	encrypted, err := dataCipher.Encrypt(secret)
	require.NoError(t, err)
	ropc := true
	client := &record.Client{
		ClientIdentifier:                        "client-auth-limit-" + strings.ToLower(fake.LetterN(10)),
		Enabled:                                 true,
		ClientCredentialsEnabled:                true,
		AuthorizationCodeEnabled:                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropc,
		DefaultAcrLevel:                         record.AcrLevel1,
		ClientSecretEncrypted:                   encrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	return client
}

func assertInvalidClient(t *testing.T, answer clientAuthAnswer, msgAndArgs ...interface{}) {
	t.Helper()
	assert.Equal(t, http.StatusUnauthorized, answer.status, msgAndArgs...)
	assert.Equal(t, "invalid_client", answer.body["error"], msgAndArgs...)
}

func assertOverTheLimit(t *testing.T, answer clientAuthAnswer, msgAndArgs ...interface{}) {
	t.Helper()
	assert.Equal(t, http.StatusTooManyRequests, answer.status, msgAndArgs...)
	assert.Equal(t, "3600", answer.retryAfter, msgAndArgs...)
	assert.Empty(t, answer.challenge, msgAndArgs...)
	assert.Equal(t, map[string]interface{}{
		"error":             "invalid_request",
		"error_description": "Too many requests. Please wait and try again later.",
	}, answer.body, msgAndArgs...)
}

// clientAuthCounted reports the failures the database holds for clientIdentifier on PostgreSQL,
// MySQL and SQL Server, over the current and the previous window: the key is the SHA-256 of the
// tier's name, a NUL and the identifier, and windows start at a multiple of an hour since the Unix
// epoch (#394 decision 3). ok is false on SQLite, which counts in the process.
func clientAuthCounted(t *testing.T, clientIdentifier string) (int, bool) {
	t.Helper()
	dialect, err := data.ParseDialect(appConfig.Database.Type)
	require.NoError(t, err)
	if dialect == data.SQLite {
		return 0, false
	}
	sum := sha256.Sum256([]byte("client_auth\x00" + clientIdentifier))
	current := time.Unix(time.Now().Unix()/3600*3600, 0).UTC()
	curr, prev, err := database.GetRateLimitCounts(context.Background(), nil, hex.EncodeToString(sum[:]),
		current, current.Add(-time.Hour))
	require.NoError(t, err)
	return curr + prev, true
}

// TestClientAuthenticationLimit_TheTwoHundredAndFirstFailureIsRefusedAtEveryGrant spends one
// client's 200 failures across the grants and both ways of sending a secret, missing secrets
// included, then finds the client refused 429 at every grant, its right secret included, while
// another client is untouched.
func TestClientAuthenticationLimit_TheTwoHundredAndFirstFailureIsRefusedAtEveryGrant(t *testing.T) {
	secret := fake.Password(32)
	client := newLimitedClient(t, secret)
	other := newLimitedClient(t, secret)
	user := createROPCUser(t, "a-password-1234")

	forms := []url.Values{clientCredentialsForm, refreshTokenForm, passwordForm(user.Email, "a-password-1234")}
	for i := 0; i < 200; i++ {
		wrong := "wrong-" + fake.LetterN(8)
		if i%10 == 0 {
			wrong = ""
		}
		answer := postClientAuthentication(t, forms[i%3], i%2 == 0, client.ClientIdentifier, wrong)
		require.Equal(t, http.StatusUnauthorized, answer.status, "failure %d is within the budget: %v", i+1, answer)
	}
	if counted, ok := clientAuthCounted(t, client.ClientIdentifier); ok {
		assert.Equal(t, 200, counted, "every replica reads the count from the database")
	}

	for _, form := range forms {
		for _, basic := range []bool{false, true} {
			assertOverTheLimit(t, postClientAuthentication(t, form, basic, client.ClientIdentifier, secret),
				"the right secret, %s, basic %v", form.Get("grant_type"), basic)
			assertOverTheLimit(t, postClientAuthentication(t, form, basic, client.ClientIdentifier, "wrong"),
				"a wrong secret, %s, basic %v", form.Get("grant_type"), basic)
		}
	}

	// The limit is consulted where the grant checks the secret: an invalid code is answered first.
	code := postClientAuthentication(t, url.Values{"grant_type": {"authorization_code"}, "code": {"not-a-code"},
		"redirect_uri": {"https://app.example.com/callback"}}, false, client.ClientIdentifier, secret)
	assert.Equal(t, http.StatusBadRequest, code.status)
	assert.Equal(t, "invalid_grant", code.body["error"])
	assert.Equal(t, "Code is invalid.", code.body["error_description"])

	// Another client's budget is its own.
	assertInvalidClient(t, postClientAuthentication(t, clientCredentialsForm, false, other.ClientIdentifier, "wrong"))
	answer := postClientAuthentication(t, passwordForm(user.Email, "a-password-1234"), false, other.ClientIdentifier, secret)
	assert.Equal(t, http.StatusOK, answer.status, "%v", answer)
}

// TestClientAuthenticationLimit_ARightSecretSpendsNothing: 199 failures, then right secrets, then the
// 200th failure is still answered invalid_client and only the next one is refused.
func TestClientAuthenticationLimit_ARightSecretSpendsNothing(t *testing.T) {
	secret := fake.Password(32)
	client := newLimitedClient(t, secret)
	user := createROPCUser(t, "a-password-1234")

	for i := 0; i < 199; i++ {
		require.Equal(t, http.StatusUnauthorized,
			postClientAuthentication(t, clientCredentialsForm, false, client.ClientIdentifier, "wrong").status)
	}
	for i := 0; i < 5; i++ {
		answer := postClientAuthentication(t, passwordForm(user.Email, "a-password-1234"), i%2 == 0, client.ClientIdentifier, secret)
		require.Equal(t, http.StatusOK, answer.status, "%v", answer)
	}
	if counted, ok := clientAuthCounted(t, client.ClientIdentifier); ok {
		assert.Equal(t, 199, counted, "a right secret's reservation is refunded")
	}
	assertInvalidClient(t, postClientAuthentication(t, clientCredentialsForm, true, client.ClientIdentifier, "wrong"))
	assertOverTheLimit(t, postClientAuthentication(t, clientCredentialsForm, true, client.ClientIdentifier, secret))
}

// TestClientAuthenticationLimit_ARequestThatComparesNoSecretSpendsNothing: an unknown identifier, a
// disabled client and a public client, with a secret or without, compare no secret, so 201 of each
// leave a budget whole for the client the identifier later names (decision 3).
func TestClientAuthenticationLimit_ARequestThatComparesNoSecretSpendsNothing(t *testing.T) {
	ctx := context.Background()
	secret := fake.Password(32)
	unknown := "client-auth-limit-unknown-" + strings.ToLower(fake.LetterN(10))
	disabled := newLimitedClient(t, secret)
	disabled.Enabled = false
	require.NoError(t, database.UpdateClient(ctx, nil, disabled))
	public := newLimitedClient(t, secret)
	public.IsPublic = true
	public.ClientCredentialsEnabled = false
	require.NoError(t, database.UpdateClient(ctx, nil, public))

	for i := 0; i < 201; i++ {
		assertInvalidClient(t, postClientAuthentication(t, clientCredentialsForm, i%2 == 0, unknown, "wrong"))
		assertInvalidClient(t, postClientAuthentication(t, clientCredentialsForm, i%2 == 0, disabled.ClientIdentifier, "wrong"))
		withSecret := postClientAuthentication(t, refreshTokenForm, false, public.ClientIdentifier, "wrong")
		require.Equal(t, http.StatusBadRequest, withSecret.status, "%v", withSecret)
		withoutSecret := postClientAuthentication(t, refreshTokenForm, false, public.ClientIdentifier, "")
		require.Equal(t, http.StatusBadRequest, withoutSecret.status, "%v", withoutSecret)
	}

	// Now each identifier names an enabled confidential client, whose first failure is its first.
	created := newLimitedClient(t, secret)
	created.ClientIdentifier = unknown
	require.NoError(t, database.UpdateClient(ctx, nil, created))
	disabled.Enabled = true
	require.NoError(t, database.UpdateClient(ctx, nil, disabled))
	public.IsPublic = false
	public.ClientCredentialsEnabled = true
	require.NoError(t, database.UpdateClient(ctx, nil, public))

	for _, identifier := range []string{unknown, disabled.ClientIdentifier, public.ClientIdentifier} {
		if counted, ok := clientAuthCounted(t, identifier); ok {
			assert.Zero(t, counted, identifier)
		}
		assertInvalidClient(t, postClientAuthentication(t, clientCredentialsForm, false, identifier, "wrong"), identifier)
	}
}

// TestClientAuthenticationLimit_TheAdminConsolesClientIsNeverCounted: wrong secrets for
// admin-console-client are answered invalid_client however many arrive, and its right secret still
// authenticates (decision 4).
func TestClientAuthenticationLimit_TheAdminConsolesClientIsNeverCounted(t *testing.T) {
	adminConsole, err := database.GetClientByClientIdentifier(context.Background(), nil, builtin.AdminConsoleClientIdentifier)
	require.NoError(t, err)
	secret, err := dataCipher.Decrypt(adminConsole.ClientSecretEncrypted)
	require.NoError(t, err)

	for i := 0; i < 201; i++ {
		answer := postClientAuthentication(t, clientCredentialsForm, i%2 == 0, builtin.AdminConsoleClientIdentifier, "wrong")
		require.Equal(t, http.StatusUnauthorized, answer.status, "wrong secret %d: %v", i+1, answer)
	}
	if counted, ok := clientAuthCounted(t, builtin.AdminConsoleClientIdentifier); ok {
		assert.Zero(t, counted)
	}
	answer := postClientAuthentication(t, clientCredentialsForm, true, builtin.AdminConsoleClientIdentifier, secret)
	assert.Equal(t, http.StatusOK, answer.status, "%v", answer)
	assert.NotEmpty(t, answer.body["access_token"])
}

// TestClientAuthenticationLimit_ThePasswordGrantKeepsTheTwoBudgetsApart: a wrong password never
// charges the client's budget, and a wrong client secret never charges the account's (decision 10).
func TestClientAuthenticationLimit_ThePasswordGrantKeepsTheTwoBudgetsApart(t *testing.T) {
	t.Run("a wrong password does not charge the client", func(t *testing.T) {
		secret := fake.Password(32)
		client := newLimitedClient(t, secret)
		user := createROPCUser(t, "a-password-1234")

		for i := 0; i < 199; i++ {
			require.Equal(t, http.StatusUnauthorized,
				postClientAuthentication(t, clientCredentialsForm, false, client.ClientIdentifier, "wrong").status)
		}
		for i := 0; i < 5; i++ {
			answer := postClientAuthentication(t, passwordForm(user.Email, "not-the-password"), false, client.ClientIdentifier, secret)
			require.Equal(t, http.StatusBadRequest, answer.status, "%v", answer)
			require.Equal(t, "invalid_grant", answer.body["error"])
		}
		assertInvalidClient(t, postClientAuthentication(t, clientCredentialsForm, false, client.ClientIdentifier, "wrong"),
			"the 200th failed secret is within the budget")
		assertOverTheLimit(t, postClientAuthentication(t, clientCredentialsForm, false, client.ClientIdentifier, "wrong"))
	})

	// The account-wide password tier allows 100 failures an hour and applies with the switch off.
	t.Run("a wrong client secret does not charge the account", func(t *testing.T) {
		secret := fake.Password(32)
		client := newLimitedClient(t, secret)
		user := createROPCUser(t, "a-password-1234")

		for i := 0; i < 101; i++ {
			assertInvalidClient(t, postClientAuthentication(t, passwordForm(user.Email, "not-the-password"), i%2 == 0,
				client.ClientIdentifier, "wrong"), "wrong secret %d", i+1)
		}
		answer := postClientAuthentication(t, passwordForm(user.Email, "a-password-1234"), false, client.ClientIdentifier, secret)
		assert.Equal(t, http.StatusOK, answer.status, "%v", answer)
		assert.NotEmpty(t, answer.body["access_token"])
	})
}
