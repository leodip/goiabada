package signingkeys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #386 for the token parser, and thin for the reason section 5 gives: what the key read
// does with a context belongs to the data tier.
//
// The parser is reached from the bearer-token middleware on every authenticated API request, so
// its key read is on the request path even though the type itself takes no *http.Request. Before
// this stage getPublicKey had no context to pass; the accept arm is what says it has one now, and
// that the one it passes is its caller's.

type parserCtxKey struct{}

// theParsersCallersContext matches only the context handed to DecodeAndValidateTokenString, so
// a key read issued on context.Background() matches nothing and the strict mock reports an
// unexpected call.
func theParsersCallersContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool {
		return ctx.Value(parserCtxKey{}) == "caller"
	})
}

func callersContext() context.Context {
	return context.WithValue(context.Background(), parserCtxKey{}, "caller")
}

// signedToken is an unexpired RS256 token signed by privateKey. A token has to be present: an
// empty one parses to an empty result without reading a key.
func signedToken(t *testing.T, privateKey *rsa.PrivateKey) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "subject",
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(privateKey)
	require.NoError(t, err)
	return token
}

// The accept arm: the current signing key is read on behalf of whoever asked for the token to be
// parsed.
func TestDecodeAndValidateTokenString_ReadsTheKeyUnderTheCallersContext(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tp := NewTokenParser(mockDB)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockDB.On("GetCurrentSigningKey", theParsersCallersContext(), mock.Anything).
		Return(&models.KeyPair{PublicKeyPEM: []byte(exportRSAPublicKeyAsPEMStr(&privateKey.PublicKey))}, nil).Once()

	_, err = tp.DecodeAndValidateTokenString(callersContext(), signedToken(t, privateKey), true)

	require.NoError(t, err)
	mockDB.AssertExpectations(t)
}

// The fallback arm: a token the current key does not verify sends the parser to the whole key set,
// and that read is on the caller's behalf too.
func TestDecodeAndValidateTokenString_ReadsTheFallbackKeysUnderTheCallersContext(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tp := NewTokenParser(mockDB)

	currentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockDB.On("GetCurrentSigningKey", theParsersCallersContext(), mock.Anything).
		Return(&models.KeyPair{PublicKeyPEM: []byte(exportRSAPublicKeyAsPEMStr(&currentKey.PublicKey))}, nil).Once()
	mockDB.On("GetAllSigningKeys", theParsersCallersContext(), mock.Anything).
		Return([]models.KeyPair{}, nil).Once()

	_, err = tp.DecodeAndValidateTokenString(callersContext(), signedToken(t, otherKey), true)

	require.Error(t, err)
	mockDB.AssertExpectations(t)
}

// The reject arm: a key read that fails stops the parse before any token is looked at, so nothing
// downstream is reached and there is no context to get wrong. Without it the accept arm would also
// pass on a parser that read the key and then ignored the answer.
func TestDecodeAndValidateTokenString_AFailedKeyReadReachesNoSecondPort(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tp := NewTokenParser(mockDB)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockDB.On("GetCurrentSigningKey", theParsersCallersContext(), mock.Anything).
		Return(nil, context.Canceled).Once()

	_, err = tp.DecodeAndValidateTokenString(callersContext(), signedToken(t, privateKey), true)

	require.ErrorIs(t, err, context.Canceled)
	mockDB.AssertNotCalled(t, "GetAllSigningKeys", mock.Anything, mock.Anything)
}
