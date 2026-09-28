package integration

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These are #125 end to end. An ROPC grant reports one auth_time, the moment its password was
// checked, on the access and ID tokens of the password grant and of every refresh after it:
// OpenID Connect Core 1.0 section 12.2 requires "the time of the original authentication - not
// the time that the new ID token is issued" of a refreshed ID token, and RFC 9068 section 2.2.1
// holds an access token's auth_time fixed across refreshes. Until #125 every refresh reported
// itself. A refresh token issued before migration 000051 records no instant and is refused.

// ropcAuthTimeFixture is an ROPC-enabled confidential client and a user of it.
type ropcAuthTimeFixture struct {
	client       *models.Client
	clientSecret string
	user         *models.User
	password     string
	httpClient   *http.Client
	tokenURL     string
}

func newROPCAuthTimeFixture(t *testing.T) ropcAuthTimeFixture {
	t.Helper()
	changeSettings(t, func(settings *models.Settings) { settings.ResourceOwnerPasswordCredentialsEnabled = true })

	clientSecret := fake.Password(32)
	password := fake.Password(12)
	return ropcAuthTimeFixture{
		client:       createROPCClient(t, clientSecret, false),
		clientSecret: clientSecret,
		user:         createROPCUser(t, password),
		password:     password,
		httpClient:   createHttpClient(t),
		tokenURL:     config.GetAuthServer().BaseURL + "/auth/token/",
	}
}

// refresh presents refreshToken and answers the status and the decoded body.
func (f ropcAuthTimeFixture) refresh(t *testing.T, refreshToken string) (int, map[string]interface{}) {
	t.Helper()
	status, body, err := concurrentTokenPost(f.httpClient, f.tokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {f.client.ClientIdentifier},
		"client_secret": {f.clientSecret},
		"refresh_token": {refreshToken},
	})
	require.NoError(t, err)
	return status, body
}

// tokenRow reads back the refresh_tokens row a refresh token names.
func tokenRow(t *testing.T, refreshToken string) *models.RefreshToken {
	t.Helper()
	jti, ok := decodeJWTPayload(t, refreshToken)["jti"].(string)
	require.True(t, ok, "the refresh token carries no jti")
	row, err := database.GetRefreshTokenByJti(context.Background(), nil, jti)
	require.NoError(t, err)
	require.NotNil(t, row, "no row for the refresh token")
	return row
}

// requireAuthTime answers the auth_time and iat of the access and ID tokens of a token response,
// requiring both tokens and both claims.
func requireAuthTime(t *testing.T, body map[string]interface{}) (accessAuthTime, idAuthTime, accessIat float64) {
	t.Helper()
	accessToken, ok := body["access_token"].(string)
	require.True(t, ok, "no access token: %v", body)
	idToken, ok := body["id_token"].(string)
	require.True(t, ok, "no ID token: %v", body)
	access, id := decodeJWTPayload(t, accessToken), decodeJWTPayload(t, idToken)
	accessAuthTime, ok = access["auth_time"].(float64)
	require.True(t, ok, "the access token carries no auth_time: %v", access)
	idAuthTime, ok = id["auth_time"].(float64)
	require.True(t, ok, "the ID token carries no auth_time: %v", id)
	accessIat, ok = access["iat"].(float64)
	require.True(t, ok, "the access token carries no iat: %v", access)
	return accessAuthTime, idAuthTime, accessIat
}

// A real password grant and two rotations of it. The password grant's tokens and its first
// refresh token row agree on one instant, and both refreshes report that instant, one second or
// more later, while iat moves on. The second refresh is what shows the instant was copied to the
// child row rather than read from the parent alone.
func TestROPC_RefreshKeepsThePasswordGrantsAuthTime(t *testing.T) {
	f := newROPCAuthTimeFixture(t)

	status, granted, err := concurrentTokenPost(f.httpClient, f.tokenURL, url.Values{
		"grant_type":    {"password"},
		"client_id":     {f.client.ClientIdentifier},
		"client_secret": {f.clientSecret},
		"username":      {f.user.Email},
		"password":      {f.password},
		"scope":         {"openid"},
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "the password grant: %v", granted)

	accessAuthTime, idAuthTime, _ := requireAuthTime(t, granted)
	assert.Equal(t, accessAuthTime, idAuthTime, "the password grant's two tokens disagree")

	refreshToken, ok := granted["refresh_token"].(string)
	require.True(t, ok, "no refresh token: %v", granted)
	first := tokenRow(t, refreshToken)
	require.True(t, first.AuthenticatedAt.Valid, "the password grant's refresh token recorded no instant")
	assert.EqualValues(t, first.AuthenticatedAt.Time.Unix(), accessAuthTime,
		"the refresh token row and the tokens disagree on the instant")

	// auth_time is whole seconds, so a refresh inside the same second as the grant would report
	// the grant's second whether or not it carried the instant. Bounded, and the only wait here.
	time.Sleep(1100 * time.Millisecond)

	for rotation := 1; rotation <= 2; rotation++ {
		status, refreshed := f.refresh(t, refreshToken)
		require.Equal(t, http.StatusOK, status, "refresh %d: %v", rotation, refreshed)

		gotAccess, gotId, iat := requireAuthTime(t, refreshed)
		assert.Equal(t, accessAuthTime, gotAccess, "refresh %d: the access token's auth_time moved", rotation)
		assert.Equal(t, accessAuthTime, gotId, "refresh %d: the ID token's auth_time moved", rotation)
		assert.Greater(t, iat, accessAuthTime, "refresh %d: iat is the refresh, later than the grant", rotation)

		refreshToken, ok = refreshed["refresh_token"].(string)
		require.True(t, ok, "refresh %d returned no refresh token: %v", rotation, refreshed)
		child := tokenRow(t, refreshToken)
		require.True(t, child.AuthenticatedAt.Valid, "refresh %d: the child row recorded no instant", rotation)
		assert.True(t, first.AuthenticatedAt.Time.Equal(child.AuthenticatedAt.Time),
			"refresh %d: the child row records %v, not the family's %v",
			rotation, child.AuthenticatedAt.Time, first.AuthenticatedAt.Time)
	}
}

// issueROPCRefreshToken writes an ROPC refresh token row recording instant and signs a refresh
// token for it with the server's current key, with the claims generateRefreshTokenForROPC writes.
// It is how a test holds a family whose password grant was days ago, or one issued before
// migration 000051, without waiting for either.
func issueROPCRefreshToken(t *testing.T, f ropcAuthTimeFixture, instant sql.NullTime) string {
	t.Helper()

	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	maxLifetime := now.Add(24 * time.Hour)
	jti := fake.UUID()

	require.NoError(t, database.CreateRefreshToken(context.Background(), nil, &models.RefreshToken{
		UserId:               sql.NullInt64{Int64: f.user.Id, Valid: true},
		ClientId:             sql.NullInt64{Int64: f.client.Id, Valid: true},
		RefreshTokenJti:      jti,
		FirstRefreshTokenJti: jti,
		RefreshTokenType:     "Offline",
		Scope:                "openid",
		IssuedAt:             sql.NullTime{Time: now, Valid: true},
		ExpiresAt:            sql.NullTime{Time: exp, Valid: true},
		MaxLifetime:          sql.NullTime{Time: maxLifetime, Valid: true},
		AuthStateGeneration:  f.user.AuthStateGeneration,
		AuthenticatedAt:      instant,
	}))

	keyPair, err := database.GetCurrentSigningKey(context.Background(), nil)
	require.NoError(t, err)
	privateKey, err := signingkeys.ParsePrivateKey(keyPair)
	require.NoError(t, err)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":                         settings.Issuer,
		"iat":                         now.Unix(),
		"nbf":                         now.Unix(),
		"jti":                         jti,
		"aud":                         settings.Issuer,
		"sub":                         f.user.Subject,
		"typ":                         "Offline",
		"offline_access_max_lifetime": maxLifetime.Unix(),
		"exp":                         exp.Unix(),
		"scope":                       "openid",
	})
	token.Header["kid"] = keyPair.KeyIdentifier
	signed, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return signed
}

// A family whose password grant was three days ago reports three days ago on the tokens of a
// refresh today, and its child row carries the same instant on.
func TestROPC_RefreshOfAFamilyStartedDaysAgoReportsThatStart(t *testing.T) {
	f := newROPCAuthTimeFixture(t)
	threeDaysAgo := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)

	before := time.Now().UTC().Unix()
	status, refreshed := f.refresh(t, issueROPCRefreshToken(t, f, sql.NullTime{Time: threeDaysAgo, Valid: true}))
	require.Equal(t, http.StatusOK, status, "the refresh: %v", refreshed)

	accessAuthTime, idAuthTime, iat := requireAuthTime(t, refreshed)
	assert.EqualValues(t, threeDaysAgo.Unix(), accessAuthTime, "the access token reports the refresh, not the grant")
	assert.EqualValues(t, threeDaysAgo.Unix(), idAuthTime, "the ID token reports the refresh, not the grant")
	assert.GreaterOrEqual(t, iat, float64(before), "iat is the refresh")

	childToken, ok := refreshed["refresh_token"].(string)
	require.True(t, ok, "no refresh token: %v", refreshed)
	child := tokenRow(t, childToken)
	require.True(t, child.AuthenticatedAt.Valid)
	assert.True(t, threeDaysAgo.Equal(child.AuthenticatedAt.Time),
		"the child row records %v, not the family's %v", child.AuthenticatedAt.Time, threeDaysAgo)
}

// An ROPC refresh token issued before migration 000051 records no instant, so no refresh of it can
// report the original authentication. It is refused as invalid_grant with nothing issued and the
// token left as it was, and the client's way on is a password grant, which starts a family that
// does record one.
func TestROPC_RefreshOfATokenRecordingNoInstantIsRefused(t *testing.T) {
	f := newROPCAuthTimeFixture(t)
	legacy := issueROPCRefreshToken(t, f, sql.NullTime{})

	status, body := f.refresh(t, legacy)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Equal(t, "The refresh token is invalid.", body["error_description"])
	assert.NotContains(t, body, "access_token")
	assert.NotContains(t, body, "refresh_token")

	row := tokenRow(t, legacy)
	assert.False(t, row.Revoked, "a refusal is not a redemption: the token was revoked")
	assert.False(t, row.AuthenticatedAt.Valid, "the refusal wrote an instant onto the token")
	family, err := database.GetRefreshTokensByUserId(context.Background(), nil, f.user.Id)
	require.NoError(t, err)
	assert.Len(t, family, 1, "the refusal issued a refresh token")

	status, granted, err := concurrentTokenPost(f.httpClient, f.tokenURL, url.Values{
		"grant_type":    {"password"},
		"client_id":     {f.client.ClientIdentifier},
		"client_secret": {f.clientSecret},
		"username":      {f.user.Email},
		"password":      {f.password},
		"scope":         {"openid"},
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "the password grant after the refusal: %v", granted)
	fresh, ok := granted["refresh_token"].(string)
	require.True(t, ok, "no refresh token: %v", granted)
	assert.True(t, tokenRow(t, fresh).AuthenticatedAt.Valid, "the new family records no instant")
}
