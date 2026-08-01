package integrationtests

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refreshTokenJti pulls the jti claim out of a serialized refresh token. The tests
// below need it to find the persisted row, since the response carries the JWT and the
// database is keyed by the claim inside it.
func refreshTokenJti(t *testing.T, refreshToken string) string {
	t.Helper()

	parts := strings.Split(refreshToken, ".")
	require.Len(t, parts, 3, "refresh token is not a three-part JWT")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err, "decode refresh token payload")

	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(payload, &claims), "unmarshal refresh token claims")

	jti, ok := claims["jti"].(string)
	require.True(t, ok, "refresh token has no jti claim")
	return jti
}

// TestToken_Refresh_ConcurrentDoubleSpend_IssuesOnlyOnce is the end-to-end guard for
// defect 1 of #128: many requests race to present the SAME refresh token and the server
// must issue exactly one token set.
//
// Before the fix the handler read Revoked during request validation and then wrote
// unconditionally, so two racing presentations could both observe revoked = false and
// each mint a child. The compare-and-set in MarkRefreshTokenAsRevoked lets exactly one
// request win the claim. Mirrors TestToken_AuthCode_ConcurrentDoubleSpend_IssuesOnlyOnce,
// which guards the same shape on authorization codes (#77).
//
// What it cannot prove: which branch a given loser took. A loser whose lookup preceded
// the winner's claim loses the compare-and-set; one whose lookup landed after it reads
// the token already revoked and takes the replay branch instead. This test does not force
// either ordering and must not claim to. The two resulting handler states are pinned
// deterministically by unit tests instead:
// TestHandleTokenPost_Refresh_ConcurrentDoubleSpendLoses covers a validation read of live
// followed by a lost claim, and the already-revoked subtest of TestHandleTokenPost covers
// a validation read of already revoked. Those pin the states, not the orderings that
// produce them, which no mocked test could.
func TestToken_Refresh_ConcurrentDoubleSpend_IssuesOnlyOnce(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// Exchange the authorization code once, legitimately, to obtain the refresh token
	// the race below contends for.
	data := postToTokenEndpoint(t, httpClient, destUrl, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	})
	require.NotNil(t, data["refresh_token"], "the authorization code exchange must return a refresh token")

	parentToken := data["refresh_token"].(string)
	parentJti := refreshTokenJti(t, parentToken)

	formData := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {code.Client.ClientIdentifier},
		"refresh_token": {parentToken},
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
			<-release // release all goroutines together to maximize contention on the row
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
			// A losing request must never receive any token material, whichever branch
			// refused it.
			assert.NotEqualf(t, http.StatusOK, statuses[i], "a losing request %d must not be a 200", i)
			if bodies[i] != nil {
				assert.Nilf(t, bodies[i]["access_token"], "loser %d must not get an access_token", i)
				assert.Nilf(t, bodies[i]["refresh_token"], "loser %d must not get a refresh_token", i)
			}
		}
	}

	// The invariant that matters: one refresh token yields at most one token set, no
	// matter how many requests race for it.
	assert.Equal(t, 1, successes, "exactly one concurrent presentation may succeed")

	// The presented parent must be durably consumed.
	storedParent, err := database.GetRefreshTokenByJti(nil, parentJti)
	require.NoError(t, err)
	require.NotNil(t, storedParent, "the presented refresh token row must still exist")
	assert.True(t, storedParent.Revoked, "the presented refresh token must be revoked after the race")

	// Every descendant of this grant hangs off the same authorization code, so this is
	// the whole family plus the parent.
	family, err := database.GetRefreshTokensByCodeId(nil, code.Id)
	require.NoError(t, err)

	children := make([]*models.RefreshToken, 0, len(family))
	live := make([]*models.RefreshToken, 0, len(family))
	for _, rt := range family {
		if rt.PreviousRefreshTokenJti == parentJti {
			children = append(children, rt)
		}
		if !rt.Revoked {
			live = append(live, rt)
		}
		assert.Equalf(t, storedParent.FirstRefreshTokenJti, rt.FirstRefreshTokenJti,
			"every row descending from this code must carry the same family identifier")
	}

	// No fork. Multiple rows sharing one non-empty previous_refresh_token_jti is the
	// structural fingerprint of the defect: two children persisted from one parent.
	// This is also decision 6's check, which is the only thing that reads
	// previous_refresh_token_jti at all.
	assert.Len(t, children, 1, "exactly one child may be persisted for the presented parent")

	// AT MOST one, not exactly one, and this weaker assertion is load-bearing rather
	// than slack. KEEP IT. Under the strict rotation policy a delayed duplicate whose
	// lookup lands after the winner's claim takes the replay branch, and once stage 4
	// wires containment into that branch it revokes the winner's child. The family then
	// legitimately ends with zero or one live member, and asserting exactly one would
	// fail on correct behaviour.
	assert.LessOrEqual(t, len(live), 1, "at most one family member may be left live after the race")
}
