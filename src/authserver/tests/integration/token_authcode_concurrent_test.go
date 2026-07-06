package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/stretchr/testify/assert"
)

// concurrentTokenPost performs a token-endpoint POST and is safe to call from
// multiple goroutines. Unlike postToTokenEndpoint it never touches *testing.T
// (calling t.Fatal from a spawned goroutine is illegal), and it tolerates a
// non-JSON body: a 500 renders an HTML error page, so it returns the status
// code alongside the parsed body (nil when the body is not JSON) and lets the
// caller classify the outcome.
func concurrentTokenPost(client *http.Client, urlStr string, formData url.Values) (int, map[string]interface{}, error) {
	req, err := http.NewRequest("POST", urlStr, strings.NewReader(formData.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", urlStr)
	req.Header.Set("Origin", config.GetAuthServer().BaseURL)

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	var data map[string]interface{}
	_ = json.Unmarshal(body, &data) // a non-JSON (HTML) body leaves data nil; the status still classifies it
	return resp.StatusCode, data, nil
}

// TestToken_AuthCode_ConcurrentDoubleSpend_IssuesOnlyOnce is the end-to-end
// guard for #77: many requests race to redeem the SAME authorization code and
// the server must issue exactly one token set. The pre-fix flow (read the code,
// mint tokens, then unconditionally mark it used) left a window in which two
// racing requests both observed used=false and both minted. The atomic
// compare-and-set in MarkCodeAsUsed lets exactly one request win the claim; the
// rest are treated as reuse.
func TestToken_AuthCode_ConcurrentDoubleSpend_IssuesOnlyOnce(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	const concurrency = 8
	var wg sync.WaitGroup
	statuses := make([]int, concurrency)
	bodies := make([]map[string]interface{}, concurrency)
	reqErrs := make([]error, concurrency)
	release := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-release // release all goroutines together to maximize contention on the code
			statuses[idx], bodies[idx], reqErrs[idx] = concurrentTokenPost(httpClient, destUrl, formData)
		}(i)
	}
	close(release)
	wg.Wait()

	successes := 0
	for i := 0; i < concurrency; i++ {
		assert.NoErrorf(t, reqErrs[i], "request %d failed at the transport level", i)

		accessToken := ""
		if bodies[i] != nil {
			accessToken, _ = bodies[i]["access_token"].(string)
		}

		if accessToken != "" {
			successes++
			assert.Equalf(t, http.StatusOK, statuses[i], "the winning request %d must be a 200", i)
		} else {
			// A losing request must never receive any token material.
			assert.NotEqualf(t, http.StatusOK, statuses[i], "a losing request %d must not be a 200", i)
			if bodies[i] != nil {
				assert.Nilf(t, bodies[i]["access_token"], "loser %d must not get an access_token", i)
				assert.Nilf(t, bodies[i]["refresh_token"], "loser %d must not get a refresh_token", i)
			}
		}
	}

	// The invariant that matters: one authorization code yields at most one token
	// set, no matter how many requests race for it.
	assert.Equal(t, 1, successes, "exactly one concurrent redemption may succeed")

	// The code must be durably consumed.
	stored, err := database.GetCodeById(nil, code.Id)
	assert.NoError(t, err)
	assert.True(t, stored.Used, "the code must be marked used after the race")
}
