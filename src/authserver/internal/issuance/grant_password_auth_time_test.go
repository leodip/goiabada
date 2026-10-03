package issuance

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The tests in this file pin #125: an ROPC grant reports one authentication instant, the moment
// its password was checked, on every token it issues and on every token any refresh of it issues.
// OpenID Connect Core 1.0 section 12.2 requires that of the ID token ("the time of the original
// authentication - not the time that the new ID token is issued") and RFC 9068 section 2.2.1 of
// the access token. The refresh half is in TestMintROPCRefreshTokens.

// ropcGrantFixture is a password grant's issuer over strict mocks, with the first refresh token
// the grant writes captured.
type ropcGrantFixture struct {
	issuer    *TokenIssuer
	settings  *record.Settings
	input     *ROPCGrantInput
	publicKey []byte
	written   **record.RefreshToken
}

func newROPCGrantFixture(t *testing.T) ropcGrantFixture {
	t.Helper()

	mockDB := datamocks.NewDatabase(t)
	user := &record.User{Id: 1, Subject: fake.UUID(), Email: "user@example.com", Enabled: true}
	client := &record.Client{Id: 1, ClientIdentifier: "ropc-client"}

	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&record.KeyPair{
		Id:            1,
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, getTestPrivateKey(t)),
		PublicKeyPEM:  getTestPublicKey(t),
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, user).Return(nil)
	var written *record.RefreshToken
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*record.RefreshToken")).
		Run(func(args mock.Arguments) { written = args.Get(2).(*record.RefreshToken) }).
		Return(nil)

	return ropcGrantFixture{
		issuer: NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil),
		settings: &record.Settings{
			Issuer:                                  "https://test-issuer.com",
			TokenExpirationInSeconds:                600,
			RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
			RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
		},
		input:     &ROPCGrantInput{Client: client, User: user, Scope: "openid"},
		publicKey: getTestPublicKey(t),
		written:   &written,
	}
}

// The password grant's access token, ID token and first refresh token all carry the one instant
// the grant stamped, which is the moment of the grant: the refresh token row is where every later
// refresh reads it back from.
func TestIssuePasswordGrant_EveryTokenCarriesTheGrantsInstant(t *testing.T) {
	f := newROPCGrantFixture(t)

	before := time.Now().UTC()
	response, err := f.issuer.IssuePasswordGrant(context.Background(), f.settings, f.input)
	after := time.Now().UTC()
	require.NoError(t, err)

	written := *f.written
	require.NotNil(t, written, "the grant wrote no refresh token")
	require.True(t, written.AuthenticatedAt.Valid, "the first refresh token records no instant")
	assert.False(t, written.AuthenticatedAt.Time.Before(before), "the instant is before the grant")
	assert.False(t, written.AuthenticatedAt.Time.After(after), "the instant is after the grant")

	instant := written.AuthenticatedAt.Time.Unix()
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, f.publicKey)
	idClaims := verifyAndDecodeToken(t, response.IdToken, f.publicKey)
	assert.EqualValues(t, instant, accessClaims["auth_time"])
	assert.EqualValues(t, instant, idClaims["auth_time"])
}

// The issuer writes the instant, not the caller: the password is checked for this request, so a
// value the caller left on the input is not an authentication anybody performed, and the input is
// not written through either.
func TestIssuePasswordGrant_TheIssuerStampsTheInstantNotTheCaller(t *testing.T) {
	for _, tc := range []struct {
		name  string
		given time.Time
	}{
		{"left zero", time.Time{}},
		{"set by the caller to a year ago", time.Now().UTC().AddDate(-1, 0, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newROPCGrantFixture(t)
			f.input.AuthenticatedAt = tc.given

			before := time.Now().UTC()
			response, err := f.issuer.IssuePasswordGrant(context.Background(), f.settings, f.input)
			require.NoError(t, err)

			written := *f.written
			require.NotNil(t, written)
			assert.False(t, written.AuthenticatedAt.Time.Before(before), "the caller's value was recorded")
			accessClaims := verifyAndDecodeToken(t, response.AccessToken, f.publicKey)
			assert.GreaterOrEqual(t, accessClaims["auth_time"], float64(before.Unix()))

			assert.Equal(t, tc.given, f.input.AuthenticatedAt, "the caller's input was written through")
		})
	}
}

// An ROPC token with no instant, one issued before migration 000051, is refused before anything is
// read or signed. The token endpoint refuses it first; this is what stops a caller that skipped
// the validator from signing auth_time as the zero time. The strict mock fails the test on any
// database call.
func TestMintROPCRefreshTokens_ATokenWithNoInstantIsRefused(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	response, err := issuer.mintROPCRefreshTokens(context.Background(), nil, &record.Settings{},
		&record.RefreshToken{
			RefreshTokenJti: "pre-000051-jti",
			UserId:          sql.NullInt64{Int64: 1, Valid: true},
			ClientId:        sql.NullInt64{Int64: 1, Valid: true},
			Scope:           "openid",
		}, "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "records no authentication instant")
	assert.Nil(t, response)
}
