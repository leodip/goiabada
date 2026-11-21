package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A client whose Consent required is off loses nothing from the stored consent's deletion
// at the refresh arm, which consults a stored consent only for a client with Consent
// required on or an offline grant. The withdrawal therefore revokes the refresh tokens
// the user holds with that client, and the grant stops at the withdrawal instead of
// running to the session's end (#622).
func TestToken_Refresh_ConsentRemovedFromAConsentNotRequiredClient(t *testing.T) {
	clientSecret := fake.Password(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destURL := appConfig.AuthServer.BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
	}
	data := postToTokenEndpointWithBasicAuth(t, httpClient, destURL, formData, code.Client.ClientIdentifier, clientSecret)
	require.NotNil(t, data["refresh_token"])
	refreshToken := data["refresh_token"].(string)

	// The stored consent the user once granted through the consent screen, for a client
	// whose Consent required is off today: the row the account consent endpoint lists and
	// deletes.
	consent := &record.UserConsent{
		UserID:    code.User.ID,
		ClientID:  code.Client.ID,
		Scope:     "openid profile email",
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	require.NoError(t, database.CreateUserConsent(context.Background(), nil, consent))

	// Baseline: the grant refreshes while the consent stands, and rotation hands back the
	// token the withdrawal below has to kill.
	formData = url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	data = postToTokenEndpointWithBasicAuth(t, httpClient, destURL, formData, code.Client.ClientIdentifier, clientSecret)
	require.NotNil(t, data["access_token"])
	require.NotNil(t, data["refresh_token"])
	rotatedRefreshToken := data["refresh_token"].(string)

	// The user withdraws the consent. The account and admin consent DELETEs and both
	// connected-clients DELETEs route it through revocation.DisconnectClientTx; calling it
	// here runs the identical transaction those handlers do, without minting the Account
	// API token the endpoint itself would ask for.
	result, err := revocation.DisconnectClientTx(context.Background(), database, consent.UserID, consent.ClientID, nil,
		func(tx *sql.Tx) (bool, error) {
			return database.DeleteUserConsent(context.Background(), tx, consent.ID)
		})
	require.NoError(t, err)
	assert.True(t, result.ConsentDeleted, "this call deleted the consent")
	assert.Len(t, result.RevokedRefreshTokenJTIs, 1, "the rotated token is the one live token it revoked")
	assert.Equal(t, 1, result.RecordedFamilyCount, "the grant's one family is newly recorded")

	// The same disconnect again finds nothing left to end, and says so.
	again, err := revocation.DisconnectClientTx(context.Background(), database, consent.UserID, consent.ClientID, nil,
		func(tx *sql.Tx) (bool, error) {
			return database.DeleteUserConsent(context.Background(), tx, consent.ID)
		})
	require.NoError(t, err)
	assert.False(t, again.Changed(), "a repeated disconnect changes nothing: %+v", again)

	formData = url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rotatedRefreshToken},
	}
	refreshResp := postToTokenEndpointWithBasicAuth(t, httpClient, destURL, formData, code.Client.ClientIdentifier, clientSecret)

	assert.Equal(t, "invalid_grant", refreshResp["error"])
	assert.Equal(t, "This refresh token has been revoked.", refreshResp["error_description"])
}

// consentWithdrawalFixture is one user holding two live grants, each from a browser of its own:
// one with the client whose consent is withdrawn, its Consent required off and its refresh token
// rotated once, and one with a second client the withdrawal must leave alone. The stored consent
// is the row the withdrawal endpoints delete (#622).
type consentWithdrawalFixture struct {
	withdrawnCode *record.Code
	// withdrawnRefresh is the grant's rotated token, the one live after the first refresh.
	withdrawnRefresh string
	withdrawnSecret  string
	otherCode        *record.Code
	otherRefresh     string
	otherSecret      string
	consent          *record.UserConsent
}

// newConsentWithdrawalFixture builds the fixture for user, who signs in with password.
func newConsentWithdrawalFixture(t *testing.T, user *record.User, password string) consentWithdrawalFixture {
	t.Helper()
	f := consentWithdrawalFixture{withdrawnSecret: fake.LetterN(32), otherSecret: fake.LetterN(32)}

	withdrawnClient, withdrawnCode := createAuthCode(t, f.withdrawnSecret, "openid profile email",
		authCodeOptions{user: user, userPassword: password})
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, withdrawnCode.ClientID) })
	otherClient, otherCode := createAuthCode(t, f.otherSecret, "openid profile email",
		authCodeOptions{user: user, userPassword: password})
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, otherCode.ClientID) })
	require.Equal(t, withdrawnCode.UserID, otherCode.UserID, "both grants must belong to one user")
	// Consent required off is the case the refresh arm never checks a stored consent for, so a
	// refusal below is the withdrawal's revocation and nothing else.
	require.False(t, withdrawnCode.Client.ConsentRequired)
	f.withdrawnCode, f.otherCode = withdrawnCode, otherCode

	withdrawnTokens := redeemCode(t, withdrawnClient, withdrawnCode, f.withdrawnSecret)
	otherTokens := redeemCode(t, otherClient, otherCode, f.otherSecret)
	var ok bool
	f.otherRefresh, ok = otherTokens["refresh_token"].(string)
	require.True(t, ok, "the other grant must carry a refresh token: %v", otherTokens)

	f.consent = &record.UserConsent{
		UserID:    user.ID,
		ClientID:  withdrawnCode.ClientID,
		Scope:     "openid profile email",
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	require.NoError(t, database.CreateUserConsent(context.Background(), nil, f.consent))

	// The positive control: the grant refreshes while the consent stands, and rotation hands back
	// the token the withdrawal has to end.
	initial, ok := withdrawnTokens["refresh_token"].(string)
	require.True(t, ok, "the withdrawn grant must carry a refresh token: %v", withdrawnTokens)
	before := presentRefreshToken(t, withdrawnCode.Client.ClientIdentifier, initial, f.withdrawnSecret)
	require.Nil(t, before["error"], "the grant must refresh before the withdrawal: %v", before["error_description"])
	f.withdrawnRefresh, ok = before["refresh_token"].(string)
	require.True(t, ok, "rotation must return a replacement: %v", before)
	return f
}

// assertWithdrawn holds what a withdrawal through either endpoint leaves: the consent row gone,
// the client's grant refused as revoked, the user's grant with the other client still refreshing,
// and one disconnected_client record naming the user, the client and the one token the sweep
// moved from live to revoked, beside one deletionEvent naming the consent (#135 decision 6).
func (f consentWithdrawalFixture) assertWithdrawn(t *testing.T, adminToken string, loggedInUser string,
	deletionEvent string) {
	t.Helper()

	got, err := database.GetUserConsentByID(context.Background(), nil, f.consent.ID)
	require.NoError(t, err)
	assert.Nil(t, got, "the consent row is deleted")

	after := presentRefreshToken(t, f.withdrawnCode.Client.ClientIdentifier, f.withdrawnRefresh, f.withdrawnSecret)
	assert.Equal(t, "invalid_grant", after["error"], "the withdrawal must revoke the client's grant: %v", after["error_description"])
	assert.Equal(t, "This refresh token has been revoked.", after["error_description"])
	assert.Empty(t, after["access_token"])

	survives := presentRefreshToken(t, f.otherCode.Client.ClientIdentifier, f.otherRefresh, f.otherSecret)
	assert.Nil(t, survives["error"],
		"the same user's grant with another client must survive the withdrawal: %v", survives["error_description"])
	assert.NotEmpty(t, survives["access_token"])

	logs, resp := getAuditLogs(t, adminToken, "auditEvent="+audit.EventDisconnectedClient)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	found := 0
	for _, entry := range logs.AuditLogs {
		var details map[string]interface{}
		if err := json.Unmarshal([]byte(entry.Details), &details); err != nil {
			continue
		}
		if int64(details["client_id"].(float64)) != f.withdrawnCode.ClientID {
			continue
		}
		found++
		assert.Equal(t, f.withdrawnCode.UserID, int64(details["user_id"].(float64)))
		assert.Equal(t, loggedInUser, details["logged_in_user"])
		// The initial token was already revoked by its rotation, so the rotated one is the only
		// token this withdrawal moved, and its code was used, so the mark moved none.
		assert.Len(t, details["revoked_refresh_token_jtis"], 1)
		assert.InDelta(t, float64(0), details["revoked_code_count"], 0)
	}
	assert.Equal(t, 1, found, "the withdrawal must record %v once for this client", audit.EventDisconnectedClient)

	deletions, deletionsResp := getAuditLogs(t, adminToken, "auditEvent="+deletionEvent)
	defer func() { _ = deletionsResp.Body.Close() }()
	require.Equal(t, http.StatusOK, deletionsResp.StatusCode)
	foundDeletion := 0
	for _, entry := range deletions.AuditLogs {
		var details map[string]interface{}
		if err := json.Unmarshal([]byte(entry.Details), &details); err != nil {
			continue
		}
		if int64(details["consent_id"].(float64)) == f.consent.ID {
			foundDeletion++
		}
	}
	assert.Equal(t, 1, foundDeletion, "the withdrawal must record %v once for this consent", deletionEvent)
}
