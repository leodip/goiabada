package integration

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"testing"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/data/mssqldb"
	"github.com/leodip/goiabada/authserver/internal/data/mysqldb"
	"github.com/leodip/goiabada/authserver/internal/data/postgresdb"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The token endpoint's half of #499: a client that may not request the administrative scopes is
// refused them when it redeems a code carrying one, on the refresh token grant, whichever grant
// issued the refresh token, and on the password grant (decision 6). A code redemption is refused
// invalid_grant; a refresh is refused invalid_grant before the token is spent, so the same token
// still refreshes once the request leaves the administrative scope out; the password grant is
// refused invalid_scope. Each refusal leaves an administrative_scope_refused row naming the grant as
// its checkpoint (decision 9).
//
// The codes and refresh tokens here are issued while the client is allowed, and the allowance is
// then withdrawn: the grant an operator's withdrawal, or the upgrade itself, leaves in a client's
// hands.

// refreshAdministrativeScopeRefusal is the refresh grant's answer, byte for byte, in the shape of
// the other per-scope refresh re-checks (decision 7).
const refreshAdministrativeScopeRefusal = "Scope 'authserver:manage' is not recognized. " +
	"The client is not allowed to request the administrative scope 'authserver:manage'."

// withdrawAdministrativeScopes switches a client's stored allowance off, as an operator withdrawing
// it does. Written to the row directly, because the client save never writes the column.
func withdrawAdministrativeScopes(t *testing.T, clientId int64) {
	t.Helper()

	var handle *sql.DB
	var flavor sqlbuilder.Flavor
	switch d := database.(type) {
	case *sqlitedb.Database:
		handle, flavor = d.DB, d.Flavor
	case *mysqldb.Database:
		handle, flavor = d.DB, d.Flavor
	case *postgresdb.Database:
		handle, flavor = d.DB, d.Flavor
	case *mssqldb.Database:
		handle, flavor = d.DB, d.Flavor
	default:
		t.Fatalf("no raw handle for database type %T", database)
	}

	update := flavor.NewUpdateBuilder()
	update.Update("clients").
		Set(update.Assign("administrative_scopes_allowed", false)).
		Where(update.Equal("id", clientId))
	query, args := update.Build()
	_, err := handle.ExecContext(context.Background(), query, args...)
	require.NoError(t, err)

	client, err := database.GetClientById(context.Background(), nil, clientId)
	require.NoError(t, err)
	require.False(t, client.AdministrativeScopesAllowed, "the allowance is withdrawn")
}

// assertRefusedAtTheTokenEndpoint holds the rows naming client to the one a refusal at checkpoint
// leaves.
func assertRefusedAtTheTokenEndpoint(t *testing.T, client *record.Client, userId int64, checkpoint string) {
	t.Helper()
	rows := administrativeScopeRefusedRows(t, client.ClientIdentifier)
	require.Len(t, rows, 1, "one row for the refusal")
	assert.Equal(t, map[string]any{
		"clientId":         float64(client.Id),
		"clientIdentifier": client.ClientIdentifier,
		"scopes":           []any{"authserver:manage"},
		"checkpoint":       checkpoint,
		"userId":           float64(userId),
	}, rows[0])
}

// assertRefreshRefused holds a refresh's answer to the refusal, with no token in it.
func assertRefreshRefused(t *testing.T, status int, body map[string]interface{}) {
	t.Helper()
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Equal(t, refreshAdministrativeScopeRefusal, body["error_description"])
	assert.NotContains(t, body, "access_token")
	assert.NotContains(t, body, "refresh_token")
}

// A code issued while the client was allowed, redeemed after the allowance was withdrawn and within
// its 60 second life. /auth/issue was the last check before the code existed, so this redemption is
// what would otherwise turn an operator's withdrawal into a fresh administrative token.
func TestToken_AdministrativeScope_CodeRedeemedAfterTheAllowanceWasWithdrawn(t *testing.T) {
	requireDatabaseAuditLogs(t)

	clientSecret := fake.LetterN(32)
	httpClient, code := createAuthCodeEnsuringUserScope(t, clientSecret, "openid profile authserver:manage")
	require.True(t, code.Client.AdministrativeScopesAllowed, "the fixture allows its client for an administrative scope")
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.Client.Id) })

	withdrawAdministrativeScopes(t, code.Client.Id)

	status, body, err := concurrentTokenPost(httpClient, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
	})
	require.NoError(t, err, "code redemption failed at the transport level")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Equal(t, administrativeScopeRefusal, body["error_description"])
	assert.NotContains(t, body, "access_token")
	assert.NotContains(t, body, "refresh_token")
	assertRefusedAtTheTokenEndpoint(t, &code.Client, code.UserId, "authorization_code")
}

// A refresh token descended from an authorization code, issued while the client was allowed. It
// refreshes with authserver:manage while the allowance stands; once it is withdrawn the next
// refresh is refused, and the same token then refreshes with the scope left out.
func TestToken_AdministrativeScope_RefreshFromACodeAfterTheAllowanceWasWithdrawn(t *testing.T) {
	requireDatabaseAuditLogs(t)

	clientSecret := fake.LetterN(32)
	httpClient, code := createAuthCodeEnsuringUserScope(t, clientSecret, "openid profile authserver:manage")
	require.True(t, code.Client.AdministrativeScopesAllowed, "the fixture allows its client for an administrative scope")
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.Client.Id) })

	tokens := postToTokenEndpoint(t, httpClient, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
	})
	refreshToken, ok := tokens["refresh_token"].(string)
	require.True(t, ok, "the code grant yields a refresh token: %v", tokens)

	// The control: while the client is allowed, the grant refreshes whole.
	status, body := refreshWithScope(t, httpClient, code.Client.ClientIdentifier, clientSecret, refreshToken, "")
	require.Equal(t, http.StatusOK, status, "an allowed client refreshes the administrative scope: %v", body)
	assert.Equal(t, "openid profile authserver:manage", body["scope"])
	refreshToken = body["refresh_token"].(string)

	withdrawAdministrativeScopes(t, code.Client.Id)

	status, body = refreshWithScope(t, httpClient, code.Client.ClientIdentifier, clientSecret, refreshToken, "")
	assertRefreshRefused(t, status, body)
	assertRefusedAtTheTokenEndpoint(t, &code.Client, code.UserId, "refresh_token")

	// The token was not spent: narrowed to leave the administrative scope out, it refreshes.
	status, body = refreshWithScope(t, httpClient, code.Client.ClientIdentifier, clientSecret, refreshToken, "openid profile")
	require.Equal(t, http.StatusOK, status, "a refresh leaving the administrative scope out succeeds: %v", body)
	assert.Equal(t, "openid profile", body["scope"])
	assert.NotEmpty(t, body["access_token"])
}

// newAdministrativeROPCClient is a confidential client that may use the password grant and is
// allowed to request the administrative scopes, or not, and a user holding authserver:manage with
// its password.
func newAdministrativeROPCClient(t *testing.T, allowed bool) (*record.Client, string, *record.User, string) {
	t.Helper()

	changeSettings(t, func(settings *record.Settings) { settings.ResourceOwnerPasswordCredentialsEnabled = true })

	clientSecret := fake.Password(32)
	client := createROPCClientAllowing(t, clientSecret, false, allowed)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })

	password := fake.Password(12)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: fake.Email(), PasswordHash: passwordHashed}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	assignPermissionToUser(t, user.Id, authServerPermissionId(t, builtin.ManagePermissionIdentifier))

	return client, clientSecret, user, password
}

// passwordGrant makes a password grant for user through client, asking for scope.
func passwordGrant(t *testing.T, client *record.Client, clientSecret string, user *record.User, password string,
	scope string) (int, map[string]interface{}) {
	t.Helper()

	status, body, err := concurrentTokenPost(createHttpClient(t), appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"password"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"username":      {user.Email},
		"password":      {password},
		"scope":         {scope},
	})
	require.NoError(t, err, "password grant failed at the transport level")
	return status, body
}

// A refresh token the password grant issued, which carries no code, while the client was allowed.
// The same answers as the code-descended token.
func TestToken_AdministrativeScope_RefreshFromThePasswordGrantAfterTheAllowanceWasWithdrawn(t *testing.T) {
	requireDatabaseAuditLogs(t)

	client, clientSecret, user, password := newAdministrativeROPCClient(t, true)

	status, tokens := passwordGrant(t, client, clientSecret, user, password, "openid authserver:manage")
	require.Equal(t, http.StatusOK, status, "an allowed client obtains the administrative scope: %v", tokens)
	refreshToken, ok := tokens["refresh_token"].(string)
	require.True(t, ok, "the password grant yields a refresh token: %v", tokens)

	withdrawAdministrativeScopes(t, client.Id)

	httpClient := createHttpClient(t)
	status, body := refreshWithScope(t, httpClient, client.ClientIdentifier, clientSecret, refreshToken, "")
	assertRefreshRefused(t, status, body)
	assertRefusedAtTheTokenEndpoint(t, client, user.Id, "refresh_token")

	status, body = refreshWithScope(t, httpClient, client.ClientIdentifier, clientSecret, refreshToken, "openid")
	require.Equal(t, http.StatusOK, status, "a refresh leaving the administrative scope out succeeds: %v", body)
	assert.Equal(t, "openid", body["scope"])
	assert.NotEmpty(t, body["access_token"])
}

// The password grant refuses the administrative scope to a client that is not allowed, with
// invalid_scope and the sentence the authorization endpoint gives, though the user holds the
// permission and proved the password.
func TestToken_AdministrativeScope_PasswordGrantRefused(t *testing.T) {
	requireDatabaseAuditLogs(t)

	client, clientSecret, user, password := newAdministrativeROPCClient(t, false)

	status, body := passwordGrant(t, client, clientSecret, user, password, "openid authserver:manage")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_scope", body["error"])
	assert.Equal(t, administrativeScopeRefusal, body["error_description"])
	assert.NotContains(t, body, "access_token")
	assertRefusedAtTheTokenEndpoint(t, client, user.Id, "password")

	// The same client and user obtain what is not administrative.
	status, body = passwordGrant(t, client, clientSecret, user, password, "openid")
	require.Equal(t, http.StatusOK, status, "the password grant without the administrative scope succeeds: %v", body)
	assert.NotEmpty(t, body["access_token"])
}
