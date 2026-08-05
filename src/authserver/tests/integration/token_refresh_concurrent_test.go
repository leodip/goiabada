package integrationtests

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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

// terminatedGrantMessage is what validator/refresh-code-revoked answers with, and reading it is
// how the cases below tell WHICH gate refused a token. The handler's own revoked-row branch
// answers the same invalid_grant with "This refresh token has been revoked.", and the marker is
// read first because it lives in ValidateTokenRequest, ahead of the handler.
const terminatedGrantMessage = "The refresh token is invalid because the associated session has expired or been terminated."

// concurrentDelete issues an authenticated DELETE and returns rather than asserting, so it can run
// in a goroutine beside the refresh presentations below. Same contract and same reason as
// concurrentTokenPost: require and assert.FailNow are not safe off the test's own goroutine.
func concurrentDelete(client *http.Client, urlStr string, accessToken string) (int, error) {
	req, err := http.NewRequest("DELETE", urlStr, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, nil
}

// TestToken_Refresh_ChildOfATerminatedGrantIsBornRejected is #129 gap 2's evidence, which is the
// last thing decision 1 wants before the issue closes.
//
// Gap 2 is the concurrency window inside rotation: the presented token is claimed and its
// replacement inserted as two separate commits, so a refresh that validated before a termination
// swept the grant inserts its child AFTER that sweep committed. For an offline grant nothing else
// invalidates that child, because the Offline branch of ValidateTokenRequest checks only the max
// lifetime and deliberately never consults the session.
//
// Decision 4 closes it structurally rather than by serializing anything. A rotated child inherits
// its parent's code_id, so marking the code marks every descendant, present and future: the child
// is born already rejected because the fact predates its existence. This test is that claim,
// checked both ways round, the child issued before the termination and the child issued after it.
//
// offline_access is required rather than incidental. A session-bound refresh token dies at the
// Refresh branch's session lookup the moment the row is gone, so it would be refused whatever the
// marker did and the case would prove nothing. The Offline and empty-session-identifier
// requirements below are what keep this test out of that trap.
func TestToken_Refresh_ChildOfATerminatedGrantIsBornRejected(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	grant := createOfflineGrant(t)

	parentRow, err := database.GetRefreshTokenByJti(nil, refreshTokenJti(t, grant.refreshToken))
	require.NoError(t, err)
	require.NotNil(t, parentRow, "the redeemed grant must have a refresh token row")

	// Rotate once while the session is still live, so the child under test is a genuine
	// server-minted token written by rotation rather than a fixture.
	rotated := grant.refresh(t)
	require.NotEmpty(t, rotated["access_token"], "the grant must refresh before the termination: %v", rotated)
	childToken, ok := rotated["refresh_token"].(string)
	require.True(t, ok, "rotation must return a replacement refresh token: %v", rotated)
	grant.refreshToken = childToken

	childJti := refreshTokenJti(t, childToken)
	childRow, err := database.GetRefreshTokenByJti(nil, childJti)
	require.NoError(t, err)
	require.NotNil(t, childRow, "the rotated child must have been persisted")

	// Decision 4's load-bearing property, asserted rather than assumed: the child hangs off the
	// SAME code as its parent, which is what lets one marker reject a whole grant.
	require.True(t, childRow.CodeId.Valid, "an auth-code-derived refresh token must carry a code id")
	require.Equal(t, parentRow.CodeId.Int64, childRow.CodeId.Int64,
		"the rotated child must inherit its parent's code id, or nothing below tests the marker")

	// And the two requirements that stop this being the benign member of its class.
	require.Equal(t, "Offline", childRow.RefreshTokenType,
		"the grant must be offline, or the Refresh branch's session check refuses it whatever the marker does")
	require.Empty(t, childRow.SessionIdentifier,
		"an offline token carries no session identifier of its own, which is why only the code can reach it")

	session, err := database.GetUserSessionBySessionIdentifier(nil, grant.sessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, session, "the ceremony's session must exist before it can be terminated")

	deleteURL := config.GetAuthServer().BaseURL + "/api/v1/admin/user-sessions/" + strconv.FormatInt(session.Id, 10)
	resp := makeAPIRequest(t, "DELETE", deleteURL, adminToken, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// One: the child that already existed when the termination ran. Its own row was revoked by
	// the sweep, and its code was marked in the same transaction, so BOTH gates could refuse it.
	// The error_description is what says which one did, and it must be the marker's: the check
	// lives in the validator, ahead of the handler's revoked-row branch. It is also incidental
	// evidence that termination left the user's generation alone, since moving it would answer
	// with the generation message instead (section 4.6).
	afterSweep := grant.refresh(t)
	assert.Equal(t, "invalid_grant", afterSweep["error"],
		"the child of a terminated grant must not refresh: %v", afterSweep)
	assert.Equal(t, terminatedGrantMessage, afterSweep["error_description"],
		"the revoked-code marker must be the gate that answers, ahead of the handler's revoked-row branch: %v", afterSweep)
	assert.Empty(t, afterSweep["access_token"])

	// Two: the child the sweep never saw, which is gap 2 itself.
	//
	// THE ONE COLUMN CLEARED BELOW IS THE ONLY THING THE INTERLEAVING DECIDES. A refresh whose
	// insert lands after the sweep read refresh_tokens leaves exactly this row state: revoked =
	// false on the child, its code_id pointing at the code the same termination marked. Nothing
	// here fabricates a grant: the JWT was minted by the server, the row was written by rotation,
	// the code was marked by the real DELETE above, and the session is really gone. Hand-building
	// a signed token and its row instead would prove less, because the shape would then be this
	// test's invention rather than rotation's.
	//
	// The window cannot be driven from outside the server, which is why it is reconstructed here
	// and only approached by the racing case below.
	swept, err := database.GetRefreshTokenByJti(nil, childJti)
	require.NoError(t, err)
	require.NotNil(t, swept)
	require.True(t, swept.Revoked,
		"the termination sweep must have revoked the child that existed when it ran, or the fixture below means nothing")

	swept.Revoked = false
	require.NoError(t, database.UpdateRefreshToken(nil, swept))
	relived, err := database.GetRefreshTokenByJti(nil, childJti)
	require.NoError(t, err)
	require.False(t, relived.Revoked, "the child must be live again, or this case proves nothing")

	familyBefore, err := database.GetRefreshTokensByCodeId(nil, childRow.CodeId.Int64)
	require.NoError(t, err)

	// This is the presentation that would succeed without the marker: the row is live, so the
	// handler's compare-and-set claim wins and rotation mints a working replacement.
	born := grant.refresh(t)
	assert.Equal(t, "invalid_grant", born["error"],
		"a live child of a terminated grant must still be refused, which is gap 2: %v", born)
	assert.Equal(t, terminatedGrantMessage, born["error_description"],
		"only the revoked-code marker can refuse a child whose own row is live: %v", born)
	assert.Empty(t, born["access_token"], "no access token may be issued for a terminated grant")
	assert.Empty(t, born["refresh_token"], "no replacement may be issued for a terminated grant")

	familyAfter, err := database.GetRefreshTokensByCodeId(nil, childRow.CodeId.Int64)
	require.NoError(t, err)
	assert.Len(t, familyAfter, len(familyBefore),
		"a refused presentation must mint no descendant")
}

// TestToken_Refresh_RacingATermination_LeavesNoUsableDescendant drives the window of gap 2 for
// real, rather than reconstructing its outcome the way the case above does: eight presentations of
// one offline refresh token and the administrative DELETE, all released together.
//
// The invariant is unconditional, and that is the point rather than a convenience. The termination
// marks the grant's code, every descendant carries that code_id, and the marker is read from the
// joined code on every presentation, so no interleaving can leave a usable descendant. What the
// interleaving decides is only WHICH gate refuses a child: the handler's revoked-row branch when
// the sweep saw it, the validator's marker when it did not.
//
// WHAT IT CANNOT FORCE, and must not claim to: which interleaving occurred. A race whose DELETE
// commits first refuses all eight at the marker and shows only that nothing was minted. The
// interesting ordering, a validation that read the code live followed by an insert landing after
// the sweep, is not reachable from outside the server, and it is what
// TestToken_Refresh_ChildOfATerminatedGrantIsBornRejected reconstructs. The number of replacements
// the race produced is logged rather than asserted, so a run that proved little says so.
func TestToken_Refresh_RacingATermination_LeavesNoUsableDescendant(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	grant := createOfflineGrant(t)

	// One clean rotation first, so a refusal after the race is attributable to the termination
	// rather than to a grant that never worked.
	warmup := grant.refresh(t)
	require.NotEmpty(t, warmup["access_token"], "the grant must refresh before the race: %v", warmup)
	racedToken, ok := warmup["refresh_token"].(string)
	require.True(t, ok, "rotation must return a replacement refresh token: %v", warmup)
	grant.refreshToken = racedToken

	session, err := database.GetUserSessionBySessionIdentifier(nil, grant.sessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, session)

	deleteURL := config.GetAuthServer().BaseURL + "/api/v1/admin/user-sessions/" + strconv.FormatInt(session.Id, 10)
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	formData := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {grant.client.ClientIdentifier},
		"refresh_token": {racedToken},
		"client_secret": {grant.clientSecret},
	}

	httpClient := createHttpClient(t)

	const concurrency = 8
	var wg sync.WaitGroup
	statuses := make([]int, concurrency)
	bodies := make([]map[string]interface{}, concurrency)
	reqErrs := make([]error, concurrency)
	deleteStatus := 0
	var deleteErr error
	release := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-release // release everything together, so the termination lands mid-rotation
			statuses[idx], bodies[idx], reqErrs[idx] = concurrentTokenPost(httpClient, destUrl, formData)
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-release
		// A PROBABILITY KNOB, NOT A SYNCHRONIZATION POINT. Released at the same instant the
		// termination consistently commits before any presentation has finished verifying the
		// refresh token's signature, so the race produces no replacement at all and the
		// assertions below have nothing to chew on. A few milliseconds lets a rotation get as
		// far as its insert. Every assertion in this test holds at any value including zero,
		// which is what keeps this a knob rather than a dependency, and the log line below says
		// what the chosen value actually produced.
		time.Sleep(5 * time.Millisecond)
		deleteStatus, deleteErr = concurrentDelete(createHttpClient(t), deleteURL, adminToken)
	}()
	close(release)
	wg.Wait()

	require.NoError(t, deleteErr, "the termination request failed at the transport level")
	if deleteStatus != http.StatusOK {
		// Contention with rotation can legitimately fail the termination transaction on the
		// server engines, as a lock timeout or a deadlock. That is not what this case is about,
		// so it is retried once, sequentially. Tolerating it weakens nothing: a failed
		// termination mints no token, and the invariant below is asserted only once the session
		// is verified gone.
		t.Logf("the concurrent termination answered %d, retrying it sequentially", deleteStatus)
		resp := makeAPIRequest(t, "DELETE", deleteURL, adminToken, nil)
		deleteStatus = resp.StatusCode
		_ = resp.Body.Close()
	}
	require.Equal(t, http.StatusOK, deleteStatus, "the session must actually have been terminated")

	gone, err := database.GetUserSessionBySessionIdentifier(nil, grant.sessionIdentifier)
	require.NoError(t, err)
	require.Nil(t, gone, "the session must be gone before anything below means anything")

	replacements := make([]string, 0, concurrency)
	for i := 0; i < concurrency; i++ {
		assert.NoErrorf(t, reqErrs[i], "request %d failed at the transport level", i)

		refreshToken := ""
		if bodies[i] != nil {
			refreshToken, _ = bodies[i]["refresh_token"].(string)
		}

		if refreshToken != "" {
			replacements = append(replacements, refreshToken)
			assert.Equalf(t, http.StatusOK, statuses[i], "the winning request %d must be a 200", i)
		} else {
			assert.NotEqualf(t, http.StatusOK, statuses[i], "a refused request %d must not be a 200", i)
			if bodies[i] != nil {
				assert.Nilf(t, bodies[i]["access_token"], "a refused request %d must not get an access_token", i)
				// Logged rather than asserted: which gate refuses a given presentation is
				// exactly what the interleaving decides, and this run cannot choose it. Seeing
				// both descriptions here is the interleaving spread visible in the log.
				t.Logf("request %d was refused with: %v", i, bodies[i]["error_description"])
			}
		}
	}

	// Rotation's own invariant, which the termination racing it must not break.
	assert.LessOrEqual(t, len(replacements), 1,
		"one refresh token may yield at most one replacement, whichever way the race fell")
	t.Logf("the race produced %d replacement token(s) alongside the termination", len(replacements))

	// The invariant this case exists for: whatever the race handed out is unusable afterwards.
	for i, replacement := range replacements {
		// Which interleaving actually happened is recorded rather than asserted, because both
		// are legitimate and this test cannot choose between them. A replacement the sweep
		// revoked was inserted before the sweep read refresh_tokens; one still live is gap 2's
		// own interleaving, the child the sweep never saw, and then the marker is the only thing
		// standing between it and a working grant. Read before presenting it, since the refusal
		// below leaves the row alone.
		row, rowErr := database.GetRefreshTokenByJti(nil, refreshTokenJti(t, replacement))
		require.NoError(t, rowErr)
		require.NotNil(t, row, "a replacement the server handed out must have a row")
		if row.Revoked {
			t.Logf("replacement %d was revoked in storage: it landed before the termination's sweep", i)
		} else {
			t.Logf("replacement %d is still live in storage: the sweep never saw it, which is gap 2's own interleaving", i)
		}

		presented := postToTokenEndpoint(t, createHttpClient(t), destUrl, url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {grant.client.ClientIdentifier},
			"refresh_token": {replacement},
			"client_secret": {grant.clientSecret},
		})
		assert.Equalf(t, "invalid_grant", presented["error"],
			"replacement %d must not be usable after the termination: %v", i, presented)
		assert.Emptyf(t, presented["access_token"], "replacement %d must yield no access token", i)
		t.Logf("replacement %d was refused with: %v", i, presented["error_description"])
	}

	// And the token the race contended for, which is consumed either way.
	parent := grant.refresh(t)
	assert.Equal(t, "invalid_grant", parent["error"],
		"the raced refresh token must not be usable after the termination: %v", parent)
	assert.Empty(t, parent["access_token"])
}
