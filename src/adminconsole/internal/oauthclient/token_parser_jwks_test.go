package oauthclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/adminconsole/internal/boundedread"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient/oauthclienttest"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKSTokenParserRejectsNonRS256Token(t *testing.T) {
	tp := NewJWKSTokenParser("https://auth.example.com", nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	claims := jwt.MapClaims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("secret"))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), tokenString)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signing method HS256 is invalid")
	assert.Nil(t, result)
}

// =============================================================================
// JWKSTokenParser
//
// This parser is what the admin console uses to validate the one token it
// decodes, the ID token. The tests below cover how it finds and trusts the
// JWKS-published key, through DecodeAndValidateStoredIDToken, the method that
// checks everything but the expiry: the accept path and, more importantly, the
// reject paths: a token signed by the wrong key, an unknown kid, and an
// unavailable JWKS. The ID-token claim rules are token_parser_id_token_test.go's.
// =============================================================================

// -----------------------------------------------------------------------------
// Constructor
// -----------------------------------------------------------------------------

func TestNewJWKSTokenParser_BuildsCertsURL(t *testing.T) {
	testCases := []struct {
		name    string
		baseURL string
		want    string
	}{
		{"no trailing slash", "https://auth.example.com", "https://auth.example.com/certs"},
		{"one trailing slash", "https://auth.example.com/", "https://auth.example.com/certs"},
		{"several trailing slashes", "https://auth.example.com///", "https://auth.example.com/certs"},
		{"with a path prefix", "https://example.com/auth", "https://example.com/auth/certs"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tp := NewJWKSTokenParser(tc.baseURL, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

			assert.Equal(t, tc.want, tp.jwksURL)
		})
	}
}

func TestNewJWKSTokenParser_DefaultsHttpClient(t *testing.T) {
	tp := NewJWKSTokenParser("https://auth.example.com", nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
	require.NotNil(t, tp.httpClient)
	// The value, not merely a client: a nil client used to mean an unbounded one, and
	// asserting non-nil alone leaves restoring `&http.Client{}` green. This is the same
	// guarantee TestNewTokenExchanger_DefaultsANilClientToTheConfiguredTimeout pins for
	// the exchanger's own nil arm (#338).
	assert.Equal(t, TokenExchangeTimeout, tp.httpClient.Timeout,
		"a nil client gets the deadline rather than no deadline")

	custom := &http.Client{Timeout: time.Second}
	tp = NewJWKSTokenParser("https://auth.example.com", custom, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
	assert.Same(t, custom, tp.httpClient)
}

// -----------------------------------------------------------------------------
// The accept path
// -----------------------------------------------------------------------------

func TestJWKSTokenParser_AcceptsTokenSignedByPublishedKey(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server, hits := oauthclienttest.NewJwksServer(t, oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client(), oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	tokenString := oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims())

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), tokenString)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, tokenString, result.TokenBase64)
	assert.Equal(t, "1234567890", result.Claims["sub"])
	assert.Equal(t, int32(1), hits.Load(), "the JWKS must be fetched once on a cold cache")
}

// The JWKS is cached after the first fetch, so validating more tokens must not
// produce more HTTP requests.
func TestJWKSTokenParser_CachesJwksAcrossCalls(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server, hits := oauthclienttest.NewJwksServer(t, oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client(), oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	for i := 0; i < 3; i++ {
		_, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims()))
		assert.NoError(t, err)
	}

	assert.Equal(t, int32(1), hits.Load(), "the JWKS must be fetched only once")
}

// A token with no kid header is accepted only when the JWKS publishes exactly
// one key, which is the single-key fallback in getPublicKeyFromCache.
func TestJWKSTokenParser_TokenWithoutKidUsesTheOnlyPublishedKey(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server, _ := oauthclienttest.NewJwksServer(t, oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client(), oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "", oauthclienttest.ValidClaims()))

	assert.NoError(t, err)
	assert.Equal(t, "1234567890", result.Claims["sub"])
}

func TestJWKSTokenParser_SelectsCorrectKeyWhenSeveralArePublished(t *testing.T) {
	key, attacker := oauthclienttest.Keys(t)
	// The attacker's key is published under a different kid; the token names key-2.
	server, _ := oauthclienttest.NewJwksServer(t,
		oauthclienttest.JwkFromPublicKey("key-1", &attacker.PublicKey),
		oauthclienttest.JwkFromPublicKey("key-2", &key.PublicKey),
	)
	tp := NewJWKSTokenParser(server.URL, server.Client(), oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "key-2", oauthclienttest.ValidClaims()))

	assert.NoError(t, err)
	assert.Equal(t, "1234567890", result.Claims["sub"])
}

// -----------------------------------------------------------------------------
// The reject paths
// -----------------------------------------------------------------------------

// The core security property: a token signed by a key the JWKS does not publish
// must be rejected, even when it names a kid that the JWKS does publish.
func TestJWKSTokenParser_RejectsTokenSignedByUnpublishedKey(t *testing.T) {
	key, attacker := oauthclienttest.Keys(t)
	server, _ := oauthclienttest.NewJwksServer(t, oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client(), oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	// Signed by the attacker but claiming to be key-1.
	forged := oauthclienttest.SignRS256(t, attacker, "key-1", oauthclienttest.ValidClaims())

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), forged)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid)
}

func TestJWKSTokenParser_RejectsUnknownKid(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server, hits := oauthclienttest.NewJwksServer(t, oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client(), oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "key-does-not-exist", oauthclienttest.ValidClaims()))

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "public key not found for token kid")
	assert.Equal(t, int32(1), hits.Load(), "an unknown kid must trigger exactly one refresh attempt")
}

// With no kid and more than one published key there is no way to choose, so the
// token must be rejected rather than tried against every key.
func TestJWKSTokenParser_RejectsTokenWithoutKidWhenSeveralKeysArePublished(t *testing.T) {
	key, attacker := oauthclienttest.Keys(t)
	server, _ := oauthclienttest.NewJwksServer(t,
		oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey),
		oauthclienttest.JwkFromPublicKey("key-2", &attacker.PublicKey),
	)
	tp := NewJWKSTokenParser(server.URL, server.Client(), oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "", oauthclienttest.ValidClaims()))

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "public key not found for token kid")
}

func TestJWKSTokenParser_RejectsMalformedToken(t *testing.T) {
	tp := NewJWKSTokenParser("https://auth.example.com", nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	for _, tokenString := range []string{"not-a-jwt", "a.b", "a.b.c", "...."} {
		t.Run(tokenString, func(t *testing.T) {
			result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), tokenString)

			assert.Error(t, err)
			assert.Nil(t, result)
		})
	}
}

// -----------------------------------------------------------------------------
// JWKS retrieval failures
//
// A failure to reach or parse the JWKS must surface as an error, never as an
// accepted token.
// -----------------------------------------------------------------------------

func TestJWKSTokenParser_JwksEndpointReturnsNonOK(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	tp := NewJWKSTokenParser(server.URL, server.Client(), oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims()))

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to fetch JWKS")
}

func TestJWKSTokenParser_JwksEndpointReturnsInvalidJson(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this is not json"))
	}))
	t.Cleanup(server.Close)
	tp := NewJWKSTokenParser(server.URL, server.Client(), oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims()))

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestJWKSTokenParser_JwksEndpointUnreachable(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server, _ := oauthclienttest.NewJwksServer(t, oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey))
	tokenString := oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims())
	serverURL := server.URL
	server.Close() // nothing is listening any more

	tp := NewJWKSTokenParser(serverURL, &http.Client{Timeout: 2 * time.Second}, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), tokenString)

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestJWKSTokenParser_JwksEndpointReturnsEmptyKeySet(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server, _ := oauthclienttest.NewJwksServer(t) // no keys
	tp := NewJWKSTokenParser(server.URL, server.Client(), oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims()))

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "public key not found for token kid")
}

func TestJWKSTokenParser_RefreshJwksStoresKeys(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server, _ := oauthclienttest.NewJwksServer(t, oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client(), oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	assert.Empty(t, tp.cachedJwks.Keys)

	err := tp.refreshJwks(context.Background())

	assert.NoError(t, err)
	assert.Len(t, tp.cachedJwks.Keys, 1)
	assert.Equal(t, "key-1", tp.cachedJwks.Keys[0].Kid)
}

// A malformed jwksURL fails at request construction, before any network call.
func TestJWKSTokenParser_RefreshJwksInvalidURL(t *testing.T) {
	tp := NewJWKSTokenParser("http://\x7f-invalid", nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	err := tp.refreshJwks(context.Background())

	assert.Error(t, err)
}

// -----------------------------------------------------------------------------
// jwkToRSAPublicKey
// -----------------------------------------------------------------------------

func TestJwkToRSAPublicKey_ValidKey(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)

	pub, err := jwkToRSAPublicKey(oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey))

	assert.NoError(t, err)
	assert.NotNil(t, pub)
	assert.Equal(t, key.N, pub.N)
	assert.Equal(t, key.E, pub.E)
}

func TestJwkToRSAPublicKey_Rejections(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	valid := oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey)

	testCases := []struct {
		name string
		jwk  oauth.Jwk
	}{
		{"unsupported kty", oauth.Jwk{Kty: "EC", N: valid.N, E: valid.E}},
		{"empty kty", oauth.Jwk{Kty: "", N: valid.N, E: valid.E}},
		{"lowercase kty is not accepted", oauth.Jwk{Kty: "rsa", N: valid.N, E: valid.E}},
		{"invalid base64 modulus", oauth.Jwk{Kty: "RSA", N: "!!!not base64!!!", E: valid.E}},
		{"invalid base64 exponent", oauth.Jwk{Kty: "RSA", N: valid.N, E: "!!!not base64!!!"}},
		{"standard base64 padding is rejected", oauth.Jwk{Kty: "RSA", N: valid.N + "==", E: valid.E}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pub, err := jwkToRSAPublicKey(tc.jwk)

			assert.Error(t, err)
			assert.Nil(t, pub)
		})
	}
}

// The exponent is decoded big-endian from its base64 bytes.
func TestJwkToRSAPublicKey_DecodesExponent(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	base := oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey)

	testCases := []struct {
		name string
		e    []byte
		want int
	}{
		{"single byte", []byte{0x03}, 3},
		{"two bytes", []byte{0x01, 0x00}, 256},
		{"the usual 65537", []byte{0x01, 0x00, 0x01}, 65537},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jwk := base
			jwk.E = base64.RawURLEncoding.EncodeToString(tc.e)

			pub, err := jwkToRSAPublicKey(jwk)

			assert.NoError(t, err)
			assert.Equal(t, tc.want, pub.E)
		})
	}
}

// -----------------------------------------------------------------------------
// getPublicKeyFromCache
// -----------------------------------------------------------------------------

func TestGetPublicKeyFromCache(t *testing.T) {
	key, attacker := oauthclienttest.Keys(t)

	t.Run("empty cache returns nil", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

		assert.Nil(t, tp.getPublicKeyFromCache("key-1"))
		assert.Nil(t, tp.getPublicKeyFromCache(""))
	})

	t.Run("matching kid returns the key", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
		tp.cachedJwks = oauth.Jwks{Keys: []oauth.Jwk{oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey)}}

		pub := tp.getPublicKeyFromCache("key-1")

		assert.NotNil(t, pub)
		assert.Equal(t, key.N, pub.N)
	})

	t.Run("non-matching kid returns nil", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
		tp.cachedJwks = oauth.Jwks{Keys: []oauth.Jwk{oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey)}}

		assert.Nil(t, tp.getPublicKeyFromCache("key-2"))
	})

	t.Run("empty kid with a single key returns that key", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
		tp.cachedJwks = oauth.Jwks{Keys: []oauth.Jwk{oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey)}}

		pub := tp.getPublicKeyFromCache("")

		assert.NotNil(t, pub)
		assert.Equal(t, key.N, pub.N)
	})

	t.Run("empty kid with several keys returns nil", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
		tp.cachedJwks = oauth.Jwks{Keys: []oauth.Jwk{
			oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey),
			oauthclienttest.JwkFromPublicKey("key-2", &attacker.PublicKey),
		}}

		assert.Nil(t, tp.getPublicKeyFromCache(""))
	})

	t.Run("empty kid with a single undecodable key returns nil", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
		tp.cachedJwks = oauth.Jwks{Keys: []oauth.Jwk{{Kty: "EC", Kid: "key-1"}}}

		assert.Nil(t, tp.getPublicKeyFromCache(""))
	})

	t.Run("matching kid on an undecodable key returns nil", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
		tp.cachedJwks = oauth.Jwks{Keys: []oauth.Jwk{{Kty: "EC", Kid: "key-1"}}}

		assert.Nil(t, tp.getPublicKeyFromCache("key-1"))
	})
}

// =============================================================================
// The JWKS read bound, goal 9 of #338.
//
// refreshJwks is the third of the admin console's three reads of the auth
// server and the only one that decodes straight off the body rather than
// reading it first, so neither the exchanger's cases nor the middleware's
// observe it. The counting body from token_exchanger_bounds_test.go is the same
// seam seen through the parser's own injected client.
// =============================================================================

// oversizedJwks is a valid JWKS document padded past the cap by one key's
// modulus. Valid matters for the same reason as oversizedTokenResponse: without
// the cap it decodes cleanly, so the case fails on both the count and the
// outcome when the cap goes.
//
// A balanced prefix is what made cutting unsound here rather than merely
// indistinguishable. json.Decoder stops at the first complete value, so a
// document cut at the cap whose first key happened to close would have decoded
// with the rest of the keys missing and nothing would have said so -- and this
// parser would then have cached a JWKS short of the key the next token needed.
// The overrun is refused instead (#386 decision 4).
func oversizedJwks(t *testing.T) *countingBody {
	t.Helper()
	prefix := `{"keys":[{"kty":"RSA","kid":"key-1","alg":"RS256","use":"sig","e":"AQAB","n":"`
	suffix := `"}]}`
	padding := MaxTokenResponseBytes + 1024 - len(prefix) - len(suffix)
	return &countingBody{remaining: []byte(prefix + strings.Repeat("x", padding) + suffix)}
}

func TestRefreshJwks_RefusesADocumentOverTheCap(t *testing.T) {
	body := oversizedJwks(t)

	tp := NewJWKSTokenParser("https://auth.example.com",
		clientReturning(http.StatusOK, body), oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	err := tp.refreshJwks(context.Background())

	require.Error(t, err)
	assert.True(t, errors.Is(err, boundedread.ErrResponseTooLarge),
		"the document is refused as oversized rather than reaching the decoder truncated: %v", err)
	assert.Equal(t, int64(MaxTokenResponseBytes)+1, body.read.Load(),
		"one byte past the cap is read, which is what makes the overrun detectable, and no more")
	assert.Empty(t, tp.cachedJwks.Keys, "nothing is cached from a document that was refused")
}

// The document exactly at the cap is accepted, so the case above is the overrun
// and not the size. It is the one boundary a reader would otherwise have to take
// on trust, since the two padded documents above and below it are a megabyte
// apart.
func TestRefreshJwks_AcceptsADocumentOfExactlyTheCap(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwk := oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey)
	encoded, err := json.Marshal(oauth.Jwks{Keys: []oauth.Jwk{jwk}})
	require.NoError(t, err)

	// Pad the one field of unbounded length until the encoding is the cap to the byte.
	jwk.Kid = "key-1" + strings.Repeat("x", MaxTokenResponseBytes-len(encoded))
	encoded, err = json.Marshal(oauth.Jwks{Keys: []oauth.Jwk{jwk}})
	require.NoError(t, err)
	require.Len(t, encoded, MaxTokenResponseBytes)

	tp := NewJWKSTokenParser("https://auth.example.com",
		clientReturning(http.StatusOK, io.NopCloser(bytes.NewReader(encoded))), oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	require.NoError(t, tp.refreshJwks(context.Background()))
	require.Len(t, tp.cachedJwks.Keys, 1)
	assert.Equal(t, jwk.Kid, tp.cachedJwks.Keys[0].Kid)
}

// The benign member of the class: a document under the cap still decodes, so the
// case above cannot be read as "large JWKS documents are refused".
func TestRefreshJwks_AcceptsADocumentUnderTheCap(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	encoded, err := json.Marshal(oauth.Jwks{Keys: []oauth.Jwk{oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey)}})
	require.NoError(t, err)
	require.Less(t, len(encoded), MaxTokenResponseBytes)

	tp := NewJWKSTokenParser("https://auth.example.com",
		clientReturning(http.StatusOK, io.NopCloser(bytes.NewReader(encoded))), oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	require.NoError(t, tp.refreshJwks(context.Background()))
	require.Len(t, tp.cachedJwks.Keys, 1)
	assert.Equal(t, "key-1", tp.cachedJwks.Keys[0].Kid)
}
