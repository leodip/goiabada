package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIAccountConsentsGet_Success(t *testing.T) {
	accessToken, u := getUserAccessTokenWithAccountScope(t)

	// Create a client and a consent for this user
	client := &record.Client{
		ClientIdentifier: "acct-consents-client-" + fake.UUID()[:8],
		Description:      "Account Consents Test Client",
		Enabled:          true,
		IsPublic:         true,
	}
	err := database.CreateClient(context.Background(), nil, client)
	require.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	consent := &record.UserConsent{
		UserId:    u.Id,
		ClientId:  client.Id,
		Scope:     "openid profile email",
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	err = database.CreateUserConsent(context.Background(), nil, consent)
	require.NoError(t, err)
	defer func() { _ = database.DeleteUserConsent(context.Background(), nil, consent.Id) }()

	url := appConfig.AuthServer.BaseURL + "/api/v1/account/consents"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var getResp api.GetUserConsentsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResp)
	require.NoError(t, err)
	assert.NotNil(t, getResp.Consents)
	assert.GreaterOrEqual(t, len(getResp.Consents), 1)

	// Find our consent and assert fields
	var found *api.UserConsentResponse
	for i := range getResp.Consents {
		if getResp.Consents[i].Id == consent.Id {
			found = &getResp.Consents[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected to find consent id %d in response", consent.Id)
	}
	assert.Equal(t, u.Id, found.UserId)
	assert.Equal(t, client.Id, found.ClientId)
	assert.Equal(t, consent.Scope, found.Scope)
	assert.Equal(t, client.ClientIdentifier, found.ClientIdentifier)
	assert.Equal(t, client.ClientIdentifier, found.ClientName, "a client with no display name shown is named by its identifier")
	assert.False(t, found.ClientNameUnverified)
	assert.Empty(t, found.ClientDescription, "a description the sign-in screens do not show does not reach the user here either")
}

// The account endpoint names each client as the consent screen did, and carries a description only
// when that screen shows it: an administrator's name and description shown, and a self-registered
// client's own name, marked unverified and not repeated as its description.
func TestAPIAccountConsentsGet_NamesClientsAsTheConsentScreenDid(t *testing.T) {
	accessToken, u := getUserAccessTokenWithAccountScope(t)

	named := &record.Client{
		ClientIdentifier: "acct-consents-named-" + fake.UUID()[:8],
		DisplayName:      "Customer portal",
		ShowDisplayName:  true,
		Description:      "Orders and invoices",
		ShowDescription:  true,
		Enabled:          true,
		IsPublic:         true,
	}
	selfRegistered := &record.Client{
		ClientIdentifier: "dcr_" + fake.UUID()[:8],
		Description:      "Payroll Portal",
		ShowDescription:  true,
		CreatedViaDCR:    true,
		Enabled:          true,
		IsPublic:         true,
	}
	consentIds := map[int64]*record.Client{}
	for _, client := range []*record.Client{named, selfRegistered} {
		require.NoError(t, database.CreateClient(context.Background(), nil, client))
		defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()
		consent := &record.UserConsent{UserId: u.Id, ClientId: client.Id, Scope: "openid",
			GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}}
		require.NoError(t, database.CreateUserConsent(context.Background(), nil, consent))
		defer func() { _ = database.DeleteUserConsent(context.Background(), nil, consent.Id) }()
		consentIds[consent.Id] = client
	}

	resp := makeAPIRequest(t, "GET", appConfig.AuthServer.BaseURL+"/api/v1/account/consents", accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var getResp api.GetUserConsentsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&getResp))

	got := map[string]api.UserConsentResponse{}
	for _, c := range getResp.Consents {
		if client, ok := consentIds[c.Id]; ok {
			got[client.ClientIdentifier] = c
		}
	}
	require.Len(t, got, 2)
	assert.Equal(t, "Customer portal", got[named.ClientIdentifier].ClientName)
	assert.False(t, got[named.ClientIdentifier].ClientNameUnverified)
	assert.Equal(t, "Orders and invoices", got[named.ClientIdentifier].ClientDescription)
	assert.Equal(t, "Payroll Portal", got[selfRegistered.ClientIdentifier].ClientName)
	assert.True(t, got[selfRegistered.ClientIdentifier].ClientNameUnverified)
	assert.Empty(t, got[selfRegistered.ClientIdentifier].ClientDescription)
}

func TestAPIAccountConsentsGet_UnauthorizedAndScope(t *testing.T) {
	url := appConfig.AuthServer.BaseURL + "/api/v1/account/consents"

	// No token
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body1, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Contains(t, string(body1), "Access token required.")

	// Invalid token
	resp2 := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
	body2, _ := io.ReadAll(resp2.Body)
	assert.Contains(t, string(body2), "The access token is invalid.")

	// Insufficient scope (a client-credentials token whose scope no route grants)
	tok := createClientCredentialsTokenWithoutRouteScope(t)
	resp3 := makeAPIRequest(t, "GET", url, tok, nil)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
	body3, _ := io.ReadAll(resp3.Body)
	assert.Contains(t, string(body3), "Insufficient scope.")
}

func TestAPIAccountConsentDelete_Success(t *testing.T) {
	accessToken, u := getUserAccessTokenWithAccountScope(t)

	// Create a client and consent for this user
	client := &record.Client{
		ClientIdentifier: "acct-consents-del-client-" + fake.UUID()[:8],
		Description:      "Account Consents Delete Client",
		Enabled:          true,
		IsPublic:         true,
	}
	err := database.CreateClient(context.Background(), nil, client)
	require.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	consent := &record.UserConsent{
		UserId:    u.Id,
		ClientId:  client.Id,
		Scope:     "openid profile",
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	err = database.CreateUserConsent(context.Background(), nil, consent)
	require.NoError(t, err)

	url := appConfig.AuthServer.BaseURL + "/api/v1/account/consents/" + fmt.Sprintf("%d", consent.Id)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var delResp api.SuccessResponse
	err = json.NewDecoder(resp.Body).Decode(&delResp)
	require.NoError(t, err)
	assert.True(t, delResp.Success)

	// Confirm deletion
	got, err := database.GetUserConsentById(context.Background(), nil, consent.Id)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// Account, Manage consents withdraws a consent through this endpoint, the path #622 names: the
// withdrawal revokes the refresh tokens the user holds with that client, of a client whose
// Consent required is off too, while the user's grant with another client keeps refreshing.
func TestAPIAccountConsentDelete_RevokesTheClientsRefreshTokens(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, _ := createAdminClientWithToken(t)
	accessToken, u := getUserAccessTokenWithAccountScope(t)

	// The fixture signs the same user in to two more clients through the password form, so the
	// user needs a password the test knows. A narrow write of the hash, which revokes nothing.
	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	require.NoError(t, database.SetUserPasswordHash(context.Background(), nil, u.Id, passwordHashed))
	f := newConsentWithdrawalFixture(t, u, password)

	url := appConfig.AuthServer.BaseURL + "/api/v1/account/consents/" + fmt.Sprintf("%d", f.consent.Id)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	f.assertWithdrawn(t, adminToken, u.Subject)
}

// A code issued before the withdrawal and redeemed after it would start a grant the withdrawal's
// sweep never saw, since redemption consults no stored consent. The withdrawal marks the user's
// unused codes with that client revoked, so the redemption is refused, while the same user's code
// with another client still redeems (#622).
func TestAPIAccountConsentDelete_RefusesACodeIssuedBeforeTheWithdrawal(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, _ := createAdminClientWithToken(t)
	accessToken, u := getUserAccessTokenWithAccountScope(t)

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	require.NoError(t, database.SetUserPasswordHash(context.Background(), nil, u.Id, passwordHashed))

	withdrawnSecret, otherSecret := fake.LetterN(32), fake.LetterN(32)
	withdrawnClient, withdrawnCode := createAuthCode(t, withdrawnSecret, "openid profile email",
		authCodeOptions{user: u, userPassword: password})
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, withdrawnCode.ClientId) })
	otherClient, otherCode := createAuthCode(t, otherSecret, "openid profile email",
		authCodeOptions{user: u, userPassword: password})
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, otherCode.ClientId) })
	// Consent required off, so nothing but the withdrawal's mark can refuse the redemption.
	require.False(t, withdrawnCode.Client.ConsentRequired)

	consent := &record.UserConsent{
		UserId:    u.Id,
		ClientId:  withdrawnCode.ClientId,
		Scope:     "openid profile email",
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	require.NoError(t, database.CreateUserConsent(context.Background(), nil, consent))

	deleteURL := appConfig.AuthServer.BaseURL + "/api/v1/account/consents/" + fmt.Sprintf("%d", consent.Id)
	resp := makeAPIRequest(t, "DELETE", deleteURL, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {withdrawnCode.Client.ClientIdentifier},
		"client_secret": {withdrawnSecret},
		"code":          {withdrawnCode.Code},
		"redirect_uri":  {withdrawnCode.RedirectURI},
		"code_verifier": {testCodeVerifier},
	}
	refused := postToTokenEndpoint(t, withdrawnClient, appConfig.AuthServer.BaseURL+"/auth/token/", form)
	assert.Equal(t, "invalid_grant", refused["error"])
	assert.Equal(t, "Code is invalid.", refused["error_description"])
	assert.Empty(t, refused["refresh_token"])

	stored, err := database.GetCodeById(context.Background(), nil, withdrawnCode.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.True(t, stored.Revoked, "the withdrawal marks the unused code revoked")

	// The same user's code with another client is outside the withdrawal and still redeems.
	redeemCode(t, otherClient, otherCode, otherSecret)

	logs, logsResp := getAuditLogs(t, adminToken, "auditEvent="+audit.EventRevokedConsentGrants)
	defer func() { _ = logsResp.Body.Close() }()
	require.Equal(t, http.StatusOK, logsResp.StatusCode)
	found := 0
	for _, entry := range logs.AuditLogs {
		var details map[string]interface{}
		if err := json.Unmarshal([]byte(entry.Details), &details); err != nil {
			continue
		}
		if int64(details["client_id"].(float64)) != withdrawnCode.ClientId {
			continue
		}
		found++
		assert.InDelta(t, float64(1), details["revoked_code_count"], 0, "the record counts the code the mark moved")
		assert.Empty(t, details["revoked_refresh_token_jtis"])
	}
	assert.Equal(t, 1, found, "the withdrawal must record %v once for this client", audit.EventRevokedConsentGrants)
}

func TestAPIAccountConsentDelete_ForbiddenOnOtherUser(t *testing.T) {
	// Create token for user1
	accessToken, user1 := getUserAccessTokenWithAccountScope(t)

	// Create another user (user2)
	user2 := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("otheruser@consents.test"),
		GivenName:  "Other",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, user2)
	require.NoError(t, err)
	defer func() { _ = database.DeleteUser(context.Background(), nil, user2.Id) }()

	// Create client and consent for user2
	client := &record.Client{
		ClientIdentifier: "acct-consents-oth-client-" + fake.UUID()[:8],
		Description:      "Other User Client",
		Enabled:          true,
		IsPublic:         true,
	}
	err = database.CreateClient(context.Background(), nil, client)
	require.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	consent := &record.UserConsent{
		UserId:    user2.Id,
		ClientId:  client.Id,
		Scope:     "openid",
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	err = database.CreateUserConsent(context.Background(), nil, consent)
	require.NoError(t, err)
	defer func() { _ = database.DeleteUserConsent(context.Background(), nil, consent.Id) }()

	// Attempt to delete using user1 token
	url := appConfig.AuthServer.BaseURL + "/api/v1/account/consents/" + fmt.Sprintf("%d", consent.Id)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Forbidden", errResp.ErrorDescription)
	assert.Equal(t, "FORBIDDEN", errResp.ErrorCode)

	// Ensure consent still exists
	got, err := database.GetUserConsentById(context.Background(), nil, consent.Id)
	require.NoError(t, err)
	assert.NotNil(t, got)

	// Sanity check user ids differ
	assert.NotEqual(t, user1.Id, user2.Id)
}

func TestAPIAccountConsentDelete_NotFoundAndBadId(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)

	// Not found
	urlNF := appConfig.AuthServer.BaseURL + "/api/v1/account/consents/999999999"
	respNF := makeAPIRequest(t, "DELETE", urlNF, accessToken, nil)
	defer func() { _ = respNF.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, respNF.StatusCode)
	var errNF api.ErrorResponse
	_ = json.NewDecoder(respNF.Body).Decode(&errNF)
	assert.Equal(t, "Consent not found", errNF.ErrorDescription)
	assert.Equal(t, "NOT_FOUND", errNF.ErrorCode)

	// Bad id format
	urlBad := appConfig.AuthServer.BaseURL + "/api/v1/account/consents/abc"
	respBad := makeAPIRequest(t, "DELETE", urlBad, accessToken, nil)
	defer func() { _ = respBad.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, respBad.StatusCode)
	var errBad api.ErrorResponse
	_ = json.NewDecoder(respBad.Body).Decode(&errBad)
	assert.Equal(t, "Invalid consent ID format", errBad.ErrorDescription)
	assert.Equal(t, "VALIDATION_ERROR", errBad.ErrorCode)
}
