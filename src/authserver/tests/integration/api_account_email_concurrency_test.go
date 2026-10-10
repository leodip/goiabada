package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The account email endpoints under concurrent requests, end to end (#404). Each used to read the
// user row, decide, and write without repeating the decision, so requests sent at once all acted
// on one read: every verification send passed the cooldown and mailed a code to whatever address
// the account held, and every email change notified the previous address. The data tier's
// concurrent cases prove each conditional write on the engine; these prove the handlers act on
// what the write reports.

// concurrentResult is one response, read whole, or the error that stopped the request.
type concurrentResult struct {
	status int
	body   []byte
	err    error
}

// sendConcurrently sends n requests to url at once, the i-th carrying body(i), and returns every
// response. It does not use makeAPIRequest, whose require calls must not run off the test's own
// goroutine; every failure is returned and reported here instead.
func sendConcurrently(t *testing.T, n int, method, url, accessToken string, body func(i int) any) []concurrentResult {
	t.Helper()
	client := createHttpClient(t)
	requests := make([]*http.Request, n)
	for i := range requests {
		encoded, err := json.Marshal(body(i))
		require.NoError(t, err)
		req, err := http.NewRequest(method, url, bytes.NewReader(encoded))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		requests[i] = req
	}

	results := make([]concurrentResult, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range requests {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			resp, err := client.Do(requests[i])
			if err != nil {
				results[i] = concurrentResult{err: err}
				return
			}
			defer func() { _ = resp.Body.Close() }()
			read, err := io.ReadAll(resp.Body)
			results[i] = concurrentResult{status: resp.StatusCode, body: read, err: err}
		}(i)
	}
	close(start)
	wg.Wait()

	for i, result := range results {
		require.NoError(t, result.err, "request %d", i)
	}
	return results
}

// TestAPIAccountEmailVerificationSend_ConcurrentSendsMailOneCode is the resend cooldown under
// concurrency: of sends made at once, exactly one mails a code and the rest are told to wait.
// The send mails before it answers, so once every response is in, every mail that was going to be
// sent has been, and the count read from Mailpit is exact.
func TestAPIAccountEmailVerificationSend_ConcurrentSendsMailOneCode(t *testing.T) {
	useMailpitSMTP(t)
	accessToken, u := getUserAccessTokenWithAccountScope_EmailVerification(t)

	// A fresh address no other test mails, unverified, with no code ever issued.
	stored, err := database.GetUserById(context.Background(), nil, u.Id)
	require.NoError(t, err)
	stored.Email = "concurrent.send." + strings.ToLower(fake.LetterN(12)) + "@example.com"
	stored.EmailVerified = false
	stored.EmailVerificationCodeEncrypted = nil
	stored.EmailVerificationCodeIssuedAt = sql.NullTime{}
	require.NoError(t, database.UpdateUser(context.Background(), nil, stored))

	// Five, the verification-mail limit's budget per user, which holds whatever the rate limiter
	// switch says (#542): a sixth send within the hour is refused before it reaches the handler.
	const sends = 5
	results := sendConcurrently(t, sends, http.MethodPost,
		appConfig.AuthServer.BaseURL+"/api/v1/account/email/verification/send", accessToken,
		func(int) any { return map[string]string{} })

	sent, waited := 0, 0
	for i, result := range results {
		require.Equal(t, http.StatusOK, result.status, "send %d: %s", i, result.body)
		var resp api.AccountEmailVerificationSendResponse
		require.NoError(t, json.Unmarshal(result.body, &resp), "send %d", i)
		switch {
		case resp.EmailVerificationSent:
			sent++
		case resp.TooManyRequests:
			waited++
		default:
			t.Errorf("send %d was neither sent nor told to wait: %s", i, result.body)
		}
	}
	assert.Equal(t, 1, sent, "exactly one of %d concurrent sends mails a code", sends)
	assert.Equal(t, sends-1, waited, "every other send is told to wait")
	assert.Len(t, sentTo(t, stored.Email), 1, "the address is mailed one code")
}

// TestAPIAccountEmailPut_ConcurrentChangesNotifyThePreviousAddressOnce is the notice's bound
// under concurrency: changes sent at once from a verified address notify it once. The one change
// that moves the row off that address sends the notice. A request that read the row before then
// writes nothing and answers 409; one that read it after, from the new unverified address, may
// change it again, which notifies nobody. So the invariant is one notice and no third answer, not
// one 200.
//
// The notice is sent after the response by a server in another process, whose jobs this test
// cannot wait on, so the count below is read once one notice has arrived: it sees a duplicate
// already delivered by then, not one still in flight. The conclusive count is
// TestInitRoutes_ConcurrentEmailChangesNotifyThePreviousAddressOnce in internal/server, which runs
// the same routes, handler, runner and sender in process and counts after the server's own
// Jobs.Wait; the engines' compare-and-set is the data tier's
// TestTrySetUserEmail_ConcurrentChangesFromOneReadProduceOneWinner. What this adds is the two
// together, over a real database and real SMTP.
func TestAPIAccountEmailPut_ConcurrentChangesNotifyThePreviousAddressOnce(t *testing.T) {
	useMailpitSMTP(t)
	accessToken, u := accountEmailUserWithPassword(t)

	stored, err := database.GetUserById(context.Background(), nil, u.Id)
	require.NoError(t, err)
	previous := "concurrent.change." + strings.ToLower(fake.LetterN(12)) + "@example.com"
	stored.Email = previous
	stored.EmailVerified = true
	require.NoError(t, database.UpdateUser(context.Background(), nil, stored))

	// Five, the account-password limit's budget per user, which holds whatever the rate limiter
	// switch says and counts a check still in flight against it (#542).
	const changes = 5
	newEmails := make([]string, changes)
	for i := range newEmails {
		newEmails[i] = "concurrent.to." + strings.ToLower(fake.LetterN(12)) + "@example.com"
	}
	results := sendConcurrently(t, changes, http.MethodPut,
		appConfig.AuthServer.BaseURL+"/api/v1/account/email", accessToken,
		func(i int) any {
			return api.UpdateAccountEmailRequest{Email: newEmails[i], CurrentPassword: accountEmailPassword}
		})

	changed := 0
	for i, result := range results {
		switch result.status {
		case http.StatusOK:
			changed++
		case http.StatusConflict:
			var body map[string]string
			require.NoError(t, json.Unmarshal(result.body, &body), "change %d", i)
			assert.Equal(t, "CONCURRENT_UPDATE", body["error_code"], "change %d", i)
		default:
			t.Errorf("change %d answered %d: %s", i, result.status, result.body)
		}
	}
	require.GreaterOrEqual(t, changed, 1, "at least one change is made")

	after, err := database.GetUserById(context.Background(), nil, u.Id)
	require.NoError(t, err)
	assert.Contains(t, newEmails, after.Email, "the account holds one of the requested addresses")
	assert.False(t, after.EmailVerified)

	notices := awaitMailTo(t, previous)
	assert.Len(t, notices, 1, "the verified address is told once, however many changes were sent")
}
