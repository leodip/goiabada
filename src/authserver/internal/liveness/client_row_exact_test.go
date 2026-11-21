package liveness

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"math"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A client's internal id is an int64, and PostgreSQL and SQL Server allocate them beyond 2^53-1,
// the last integer a float64 holds exactly. The binding of an access token to its client's row
// (#710 decision 9) compares the id exactly across that whole range: a token signed for a row
// above it is live for that row and refused for its neighbour, whose id decodes to the same
// float64. The token is signed as issuance signs it, with the id as an integer, and parsed by the
// auth server's own token parser.
func TestAccessToken_ClientRowAboveTheFloat64SafeRange(t *testing.T) {
	const row = int64(1)<<53 + 1
	require.Equal(t, math.Float64bits(float64(row)), math.Float64bits(float64(row-1)),
		"the two ids decode to one float64")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	issuedAt := checkedAt.Add(-5 * time.Minute)
	unsigned := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":                testIssuer,
		"client_id":          clientIdentifier,
		"client_internal_id": row,
		"sub":                clientIdentifier,
		"jti":                testJTI,
		"typ":                "Bearer",
		"iat":                issuedAt.Unix(),
		"nbf":                issuedAt.Unix(),
		"exp":                time.Now().Add(time.Hour).Unix(),
	})
	unsigned.Header["typ"] = "at+jwt"
	signed, err := unsigned.SignedString(key)
	require.NoError(t, err)

	keys := datamocks.NewDatabase(t)
	keys.On("GetCurrentSigningKey", mock.Anything, (*sql.Tx)(nil)).
		Return(&record.KeyPair{PublicKeyPEM: publicPEM}, nil)
	token, err := signingkeys.NewTokenParser(keys).DecodeAndValidateTokenString(context.Background(), signed, true)
	require.NoError(t, err)

	created := sql.NullTime{Time: issuedAt.Add(-time.Hour), Valid: true}
	for _, tc := range []struct {
		label       string
		holder      int64
		wantRefusal Refusal
	}{
		{label: "the row the token was issued to", holder: row, wantRefusal: Live},
		{label: "the neighbouring row", holder: row - 1, wantRefusal: ClientNotFound},
	} {
		t.Run(tc.label, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			holder := &record.Client{ID: tc.holder, ClientIdentifier: clientIdentifier, Enabled: true, CreatedAt: created}
			database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), clientIdentifier).Return(holder, nil).Once()
			if tc.wantRefusal == Live {
				database.On("IsAccessTokenRevoked", mock.Anything, (*sql.Tx)(nil), testJTI).Return(false, nil).Once()
			}

			verdict, err := AccessToken(context.Background(), database, *token, settings, checkedAt)

			require.NoError(t, err)
			assert.Equal(t, tc.wantRefusal, verdict.Refusal)
		})
	}
}

// A claim beyond the float64 safe range is read from the payload the signature covers, so a token
// without its compact serialization cannot be read there and is refused, failing closed; and a
// number that is not a whole int64 as written is malformed.
func TestTokenClientRow_AboveTheFloat64SafeRange(t *testing.T) {
	large := float64(int64(1) << 53)

	_, present, ok := tokenClientRow(accessToken(map[string]interface{}{"client_internal_id": large}))
	assert.True(t, present)
	assert.False(t, ok, "without the compact serialization the number cannot be read exactly")

	for _, written := range []string{`1e20`, `9223372036854775808`, `9007199254740993.5`} {
		t.Run(written, func(t *testing.T) {
			_, readOK := signedClientRow(compactWithPayload(`{"client_internal_id":` + written + `}`))
			assert.False(t, readOK)
		})
	}
	clientRow, ok := signedClientRow(compactWithPayload(`{"client_internal_id":9007199254740993}`))
	require.True(t, ok)
	assert.Equal(t, int64(9007199254740993), clientRow)
}

// The payload read for a large id is matched by member name exactly, as the token parser matched
// the claim it decoded (RFC 7519 section 7.3): a member whose name differs only in case is another
// member, wherever it sits in the object, and the whole int64 range is read.
func TestSignedClientRow_ExactMemberName(t *testing.T) {
	for _, tc := range []struct {
		label   string
		payload string
		wantRow int64
		wantOK  bool
	}{
		{label: "a case variant after the claim",
			payload: `{"client_internal_id":9007199254740993,"Client_Internal_Id":9007199254740995}`,
			wantRow: 9007199254740993, wantOK: true},
		{label: "a case variant before the claim",
			payload: `{"CLIENT_INTERNAL_ID":9007199254740995,"client_internal_id":9007199254740993}`,
			wantRow: 9007199254740993, wantOK: true},
		{label: "only a case variant",
			payload: `{"Client_Internal_Id":9007199254740993}`,
			wantOK:  false},
		{label: "the largest int64",
			payload: `{"client_internal_id":9223372036854775807}`,
			wantRow: math.MaxInt64, wantOK: true},
		{label: "a string",
			payload: `{"client_internal_id":"9007199254740993"}`,
			wantOK:  false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			clientRow, ok := signedClientRow(compactWithPayload(tc.payload))
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.wantRow, clientRow)
			}
		})
	}

	// Through tokenClientRow, the claim the parser decoded and the member read from the payload are
	// the same one, and a case variant beside it changes nothing.
	token := accessToken(map[string]interface{}{"client_internal_id": float64(int64(1)<<53 + 1)})
	token.TokenBase64 = compactWithPayload(
		`{"client_internal_id":9007199254740993,"Client_Internal_Id":9007199254740992}`)
	clientRow, present, wellFormed := tokenClientRow(token)
	assert.True(t, present)
	assert.True(t, wellFormed)
	assert.Equal(t, int64(9007199254740993), clientRow)
}

// compactWithPayload is a compact JWS around this payload, signature and header aside.
func compactWithPayload(payload string) string {
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
}
