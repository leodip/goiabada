package integration

import (
	"context"
	"database/sql"
	"net/url"
	"testing"
	"time"

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
