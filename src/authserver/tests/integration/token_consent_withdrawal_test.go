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

	destUrl := appConfig.AuthServer.BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
	}
	data := postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, code.Client.ClientIdentifier, clientSecret)
	require.NotNil(t, data["refresh_token"])
	refreshToken := data["refresh_token"].(string)

	// The stored consent the user once granted through the consent screen, for a client
	// whose Consent required is off today: the row is what Account, Manage consents shows
	// and deletes.
	consent := &record.UserConsent{
		UserId:    code.User.Id,
		ClientId:  code.Client.Id,
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
	data = postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, code.Client.ClientIdentifier, clientSecret)
	require.NotNil(t, data["access_token"])
	require.NotNil(t, data["refresh_token"])
	rotatedRefreshToken := data["refresh_token"].(string)

	// The user withdraws the consent. Account, Manage consents and the admin console's
	// user page both route the deletion through revocation.RevokeOnConsentWithdrawalTx;
	// calling it here runs the identical transaction those handlers do, without minting
	// the Account API token the endpoint itself would ask for.
	_, err := revocation.RevokeOnConsentWithdrawalTx(context.Background(), database, consent.UserId, consent.ClientId,
		func(tx *sql.Tx) error {
			return database.DeleteUserConsent(context.Background(), tx, consent.Id)
		})
	require.NoError(t, err)

	formData = url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rotatedRefreshToken},
	}
	refreshResp := postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, code.Client.ClientIdentifier, clientSecret)

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
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, withdrawnCode.ClientId) })
	otherClient, otherCode := createAuthCode(t, f.otherSecret, "openid profile email",
		authCodeOptions{user: user, userPassword: password})
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, otherCode.ClientId) })
	require.Equal(t, withdrawnCode.UserId, otherCode.UserId, "both grants must belong to one user")
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
		UserId:    user.Id,
		ClientId:  withdrawnCode.ClientId,
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
// and the revoked_consent_grants record naming the user, the client and the one token the sweep
// moved from live to revoked, beside the deletion event.
func (f consentWithdrawalFixture) assertWithdrawn(t *testing.T, adminToken string, loggedInUser string) {
	t.Helper()

	got, err := database.GetUserConsentById(context.Background(), nil, f.consent.Id)
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

	logs, resp := getAuditLogs(t, adminToken, "auditEvent="+audit.EventRevokedConsentGrants)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	found := 0
	for _, entry := range logs.AuditLogs {
		var details map[string]interface{}
		if err := json.Unmarshal([]byte(entry.Details), &details); err != nil {
			continue
		}
		if int64(details["client_id"].(float64)) != f.withdrawnCode.ClientId {
			continue
		}
		found++
		assert.Equal(t, f.withdrawnCode.UserId, int64(details["user_id"].(float64)))
		assert.Equal(t, loggedInUser, details["logged_in_user"])
		// The initial token was already revoked by its rotation, so the rotated one is the only
		// token this withdrawal moved.
		assert.Len(t, details["revoked_refresh_token_jtis"], 1)
	}
	assert.Equal(t, 1, found, "the withdrawal must record %v once for this client", audit.EventRevokedConsentGrants)
}
