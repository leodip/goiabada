package signingkeys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/oauth"
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

// theParsersCallersContext matches only the context handed to DecodeAndValidateTokenResponse, so
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

// The accept arm: the current signing key is read on behalf of whoever asked for the token to be
// parsed.
func TestDecodeAndValidateTokenResponse_ReadsTheKeyUnderTheCallersContext(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tp := NewTokenParser(mockDB)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockDB.On("GetCurrentSigningKey", theParsersCallersContext(), mock.Anything).
		Return(&models.KeyPair{PublicKeyPEM: []byte(exportRSAPublicKeyAsPEMStr(&privateKey.PublicKey))}, nil).Once()

	// An empty token response, which parses nothing and returns before any claim is read. The
	// key read happens first and unconditionally, which is the whole of what this case is about.
	_, err = tp.DecodeAndValidateTokenResponse(callersContext(), &oauth.TokenResponse{})

	require.NoError(t, err)
	mockDB.AssertExpectations(t)
}

// The reject arm: a key read that fails stops the parse before any token is looked at, so nothing
// downstream is reached and there is no context to get wrong. Without it the accept arm would also
// pass on a parser that read the key and then ignored the answer.
func TestDecodeAndValidateTokenResponse_AFailedKeyReadReachesNoSecondPort(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tp := NewTokenParser(mockDB)

	mockDB.On("GetCurrentSigningKey", theParsersCallersContext(), mock.Anything).
		Return(nil, context.Canceled).Once()

	_, err := tp.DecodeAndValidateTokenResponse(callersContext(), &oauth.TokenResponse{})

	require.Error(t, err)
	mockDB.AssertNotCalled(t, "GetAllSigningKeys", mock.Anything, mock.Anything)
}
