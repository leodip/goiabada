package signingkeys

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// #709 findings 1 to 4, at the auth server's parser. Each token below is signed with the current
// key, so only its structure can be what refuses it, and it is refused as a malformed token is:
// with ErrTokenRefused and no other mark, before any key is read. The database's key reads are
// stubbed as optional and then asserted unread, so a parser that let such a token through would
// fail on the verified result rather than on a strict mock's unexpected call.

// signRawRS256 signs header and payload, given as raw JSON text so that a case can hold bytes no
// JSON encoder would write, with RS256 (RFC 7518 section 3.3) over the compact signing input.
func signRawRS256(t *testing.T, key *rsa.PrivateKey, header, payload string) string {
	t.Helper()
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload))
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// optionalKeyDatabase answers the current key and the stored keys with key's, if asked at all.
func optionalKeyDatabase(t *testing.T, key *rsa.PrivateKey) *datamocks.Database {
	t.Helper()
	pair := record.KeyPair{Id: 1, State: record.KeyStateCurrent.String(),
		PublicKeyPEM: []byte(exportRSAPublicKeyAsPEMStr(&key.PublicKey))}
	database := datamocks.NewDatabase(t)
	database.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&pair, nil).Maybe()
	database.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return([]record.KeyPair{pair}, nil).Maybe()
	return database
}

func TestDecodeAndValidateTokenString_RefusesATokenOfInvalidStructure(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	exp := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	payload := `{"sub":"user123","exp":` + exp + `}`
	valid := signRawRS256(t, key, `{"alg":"RS256","typ":"at+jwt","kid":"k1"}`, payload)

	// The builder's own token, with nothing altered, verifies: whatever refuses a case below is the
	// alteration, not the signature.
	result, err := NewTokenParser(optionalKeyDatabase(t, key)).DecodeAndValidateTokenString(context.Background(), valid, true)
	require.NoError(t, err)
	require.Equal(t, "user123", result.StringClaim("sub"))

	segments := strings.Split(valid, ".")
	withSignature := func(signature string) string { return segments[0] + "." + segments[1] + "." + signature }
	withSegment := func(i int, text string) string {
		altered := append([]string(nil), segments...)
		altered[i] += text
		return strings.Join(altered, ".")
	}

	tokens := map[string]string{
		"a crit header naming an unknown extension": signRawRS256(t, key,
			`{"alg":"RS256","crit":["unhandled"],"unhandled":true}`, payload),
		"a crit header holding the empty list": signRawRS256(t, key, `{"alg":"RS256","crit":[]}`, payload),
		"a cty of JWT":                         signRawRS256(t, key, `{"alg":"RS256","cty":"JWT"}`, payload),
		"a cty of jwt":                         signRawRS256(t, key, `{"alg":"RS256","cty":"jwt"}`, payload),
		"a cty of application/jwt":             signRawRS256(t, key, `{"alg":"RS256","cty":"application/jwt"}`, payload),
		"an invalid UTF-8 byte in the header": signRawRS256(t, key,
			"{\"alg\":\"RS256\",\"kid\":\"k\xff1\"}", payload),
		"an invalid UTF-8 byte in the payload": signRawRS256(t, key, `{"alg":"RS256"}`,
			"{\"sub\":\"user\xff123\",\"exp\":"+exp+"}"),
		"a CR appended to the signature":          withSignature(segments[2] + "\r"),
		"an LF appended to the signature":         withSignature(segments[2] + "\n"),
		"a CRLF appended to the signature":        withSignature(segments[2] + "\r\n"),
		"an LF inside the signature":              withSignature(segments[2][:40] + "\n" + segments[2][40:]),
		"a CRLF every 64 characters of signature": withSignature(segments[2][:64] + "\r\n" + segments[2][64:128] + "\r\n" + segments[2][128:]),
		"= padding appended to the header":        withSegment(0, "="),
		"= padding appended to the payload":       withSegment(1, "=="),
		"= padding appended to the signature":     withSegment(2, "=="),
	}
	for name, token := range tokens {
		t.Run(name, func(t *testing.T) {
			database := optionalKeyDatabase(t, key)

			result, err := NewTokenParser(database).DecodeAndValidateTokenString(context.Background(), token, true)

			require.Error(t, err, "the token is signed by the current key, so only its structure can refuse it")
			assert.Nil(t, result)
			require.ErrorIs(t, err, ErrTokenRefused, "answered as a malformed token is")
			require.ErrorIs(t, err, jwt.ErrTokenMalformed, "marked as the library marks a malformed token")
			require.NotErrorIs(t, err, ErrTokenExpired)
			database.AssertNotCalled(t, "GetCurrentSigningKey", mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "GetAllSigningKeys", mock.Anything, mock.Anything)
		})
	}
}

// Without the expiration check no claim is validated, which is how an id_token_hint is read, and
// the structure is still checked: the logout hint's inner ID token is read this way.
func TestDecodeAndValidateTokenString_ChecksTheStructureWithoutTheExpirationCheck(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	payload := `{"sub":"user123","exp":1}`
	valid := signRawRS256(t, key, `{"alg":"RS256","typ":"JWT","kid":"k1"}`, payload)

	result, err := NewTokenParser(optionalKeyDatabase(t, key)).DecodeAndValidateTokenString(context.Background(), valid, false)
	require.NoError(t, err, "an expired hint still names its subject")
	require.Equal(t, "user123", result.StringClaim("sub"))

	for name, token := range map[string]string{
		"a crit header":                   signRawRS256(t, key, `{"alg":"RS256","crit":["unhandled"],"unhandled":true}`, payload),
		"a cty of JWT":                    signRawRS256(t, key, `{"alg":"RS256","cty":"JWT"}`, payload),
		"an LF appended to the signature": valid + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			database := optionalKeyDatabase(t, key)

			result, err := NewTokenParser(database).DecodeAndValidateTokenString(context.Background(), token, false)

			require.Error(t, err)
			assert.Nil(t, result)
			require.ErrorIs(t, err, ErrTokenRefused)
			database.AssertNotCalled(t, "GetCurrentSigningKey", mock.Anything, mock.Anything)
		})
	}
}
