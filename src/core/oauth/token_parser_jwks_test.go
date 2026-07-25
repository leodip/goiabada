package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestJWKSTokenParserRejectsNonRS256Token(t *testing.T) {
	tp := NewJWKSTokenParser("https://auth.example.com", nil)

	claims := jwt.MapClaims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("secret"))

	result, err := tp.DecodeAndValidateTokenString(tokenString, nil, true)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signing method HS256 is invalid")
	assert.Nil(t, result)
}

// =============================================================================
// JWKSTokenParser
//
// This parser is what the admin console uses to validate tokens it receives
// from the auth server (handler_auth_callback.go). It trusts nothing but the
// signature over the JWKS-published key, so the tests below cover both the
// accept path and, more importantly, the reject paths: a token signed by the
// wrong key, an unknown kid, an expired token, and an unavailable JWKS.
// =============================================================================

var (
	testKeysOnce sync.Once
	// signingKey is the key the "auth server" publishes via JWKS.
	signingKey *rsa.PrivateKey
	// attackerKey is a valid RSA key that the JWKS does NOT publish.
	attackerKey *rsa.PrivateKey
)

// RSA key generation is slow, so both keys are generated once per test binary.
func testKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	testKeysOnce.Do(func() {
		var err error
		signingKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		attackerKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
	})
	return signingKey, attackerKey
}

func jwkFromPublicKey(kid string, pub *rsa.PublicKey) Jwk {
	return Jwk{
		Alg: "RS256",
		Kid: kid,
		Kty: "RSA",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// newJwksServer serves the given keys at /certs and counts how many times it is
// hit, so tests can assert the parser caches rather than refetching per token.
func newJwksServer(t *testing.T, keys ...Jwk) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/certs" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Jwks{Keys: keys})
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	assert.NoError(t, err)
	return signed
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub": "1234567890",
		"iss": "https://auth.example.com",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
}

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
			tp := NewJWKSTokenParser(tc.baseURL, nil)

			assert.Equal(t, tc.want, tp.jwksURL)
		})
	}
}

func TestNewJWKSTokenParser_DefaultsHttpClient(t *testing.T) {
	tp := NewJWKSTokenParser("https://auth.example.com", nil)
	assert.NotNil(t, tp.httpClient)

	custom := &http.Client{Timeout: time.Second}
	tp = NewJWKSTokenParser("https://auth.example.com", custom)
	assert.Same(t, custom, tp.httpClient)
}

// -----------------------------------------------------------------------------
// The accept path
// -----------------------------------------------------------------------------

func TestJWKSTokenParser_AcceptsTokenSignedByPublishedKey(t *testing.T) {
	key, _ := testKeys(t)
	server, hits := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client())

	tokenString := signRS256(t, key, "key-1", validClaims())

	result, err := tp.DecodeAndValidateTokenString(tokenString, nil, true)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, tokenString, result.TokenBase64)
	assert.Equal(t, "1234567890", result.Claims["sub"])
	assert.Equal(t, int32(1), hits.Load(), "the JWKS must be fetched once on a cold cache")
}

// The JWKS is cached after the first fetch, so validating more tokens must not
// produce more HTTP requests.
func TestJWKSTokenParser_CachesJwksAcrossCalls(t *testing.T) {
	key, _ := testKeys(t)
	server, hits := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client())

	for i := 0; i < 3; i++ {
		_, err := tp.DecodeAndValidateTokenString(signRS256(t, key, "key-1", validClaims()), nil, true)
		assert.NoError(t, err)
	}

	assert.Equal(t, int32(1), hits.Load(), "the JWKS must be fetched only once")
}

// A token with no kid header is accepted only when the JWKS publishes exactly
// one key, which is the single-key fallback in getPublicKeyFromCache.
func TestJWKSTokenParser_TokenWithoutKidUsesTheOnlyPublishedKey(t *testing.T) {
	key, _ := testKeys(t)
	server, _ := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client())

	result, err := tp.DecodeAndValidateTokenString(signRS256(t, key, "", validClaims()), nil, true)

	assert.NoError(t, err)
	assert.Equal(t, "1234567890", result.Claims["sub"])
}

func TestJWKSTokenParser_SelectsCorrectKeyWhenSeveralArePublished(t *testing.T) {
	key, attacker := testKeys(t)
	// The attacker's key is published under a different kid; the token names key-2.
	server, _ := newJwksServer(t,
		jwkFromPublicKey("key-1", &attacker.PublicKey),
		jwkFromPublicKey("key-2", &key.PublicKey),
	)
	tp := NewJWKSTokenParser(server.URL, server.Client())

	result, err := tp.DecodeAndValidateTokenString(signRS256(t, key, "key-2", validClaims()), nil, true)

	assert.NoError(t, err)
	assert.Equal(t, "1234567890", result.Claims["sub"])
}

func TestJWKSTokenParser_EmptyTokenIsNotAnError(t *testing.T) {
	tp := NewJWKSTokenParser("https://auth.example.com", nil)

	result, err := tp.DecodeAndValidateTokenString("", nil, true)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "", result.TokenBase64)
	assert.Nil(t, result.Claims)
}

// -----------------------------------------------------------------------------
// The reject paths
// -----------------------------------------------------------------------------

// The core security property: a token signed by a key the JWKS does not publish
// must be rejected, even when it names a kid that the JWKS does publish.
func TestJWKSTokenParser_RejectsTokenSignedByUnpublishedKey(t *testing.T) {
	key, attacker := testKeys(t)
	server, _ := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client())

	// Signed by the attacker but claiming to be key-1.
	forged := signRS256(t, attacker, "key-1", validClaims())

	result, err := tp.DecodeAndValidateTokenString(forged, nil, true)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid)
}

// Skipping claims validation must not skip signature validation.
func TestJWKSTokenParser_RejectsForgedTokenEvenWithoutExpirationCheck(t *testing.T) {
	key, attacker := testKeys(t)
	server, _ := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client())

	forged := signRS256(t, attacker, "key-1", validClaims())

	result, err := tp.DecodeAndValidateTokenString(forged, nil, false)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid)
}

func TestJWKSTokenParser_RejectsUnknownKid(t *testing.T) {
	key, _ := testKeys(t)
	server, hits := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client())

	result, err := tp.DecodeAndValidateTokenString(signRS256(t, key, "key-does-not-exist", validClaims()), nil, true)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "public key not found for token kid")
	assert.Equal(t, int32(1), hits.Load(), "an unknown kid must trigger exactly one refresh attempt")
}

// With no kid and more than one published key there is no way to choose, so the
// token must be rejected rather than tried against every key.
func TestJWKSTokenParser_RejectsTokenWithoutKidWhenSeveralKeysArePublished(t *testing.T) {
	key, attacker := testKeys(t)
	server, _ := newJwksServer(t,
		jwkFromPublicKey("key-1", &key.PublicKey),
		jwkFromPublicKey("key-2", &attacker.PublicKey),
	)
	tp := NewJWKSTokenParser(server.URL, server.Client())

	result, err := tp.DecodeAndValidateTokenString(signRS256(t, key, "", validClaims()), nil, true)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "public key not found for token kid")
}

func TestJWKSTokenParser_RejectsMalformedToken(t *testing.T) {
	tp := NewJWKSTokenParser("https://auth.example.com", nil)

	for _, tokenString := range []string{"not-a-jwt", "a.b", "a.b.c", "...."} {
		t.Run(tokenString, func(t *testing.T) {
			result, err := tp.DecodeAndValidateTokenString(tokenString, nil, true)

			assert.Error(t, err)
			assert.Nil(t, result)
		})
	}
}

// -----------------------------------------------------------------------------
// Expiration handling
//
// withExpirationCheck is true for access and id tokens and false for refresh
// tokens, which the auth server validates against its own database instead.
// -----------------------------------------------------------------------------

func TestJWKSTokenParser_RejectsExpiredTokenWhenCheckingExpiration(t *testing.T) {
	key, _ := testKeys(t)
	server, _ := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client())

	claims := validClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()

	result, err := tp.DecodeAndValidateTokenString(signRS256(t, key, "key-1", claims), nil, true)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, jwt.ErrTokenExpired)
}

func TestJWKSTokenParser_AcceptsExpiredTokenWhenNotCheckingExpiration(t *testing.T) {
	key, _ := testKeys(t)
	server, _ := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client())

	claims := validClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()

	result, err := tp.DecodeAndValidateTokenString(signRS256(t, key, "key-1", claims), nil, false)

	assert.NoError(t, err, "refresh tokens are validated against the database, not their exp claim")
	assert.Equal(t, "1234567890", result.Claims["sub"])
}

func TestJWKSTokenParser_RequiresExpClaimWhenCheckingExpiration(t *testing.T) {
	key, _ := testKeys(t)
	server, _ := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client())

	claims := jwt.MapClaims{"sub": "1234567890"} // no exp

	result, err := tp.DecodeAndValidateTokenString(signRS256(t, key, "key-1", claims), nil, true)

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestJWKSTokenParser_AllowsMissingExpWhenNotCheckingExpiration(t *testing.T) {
	key, _ := testKeys(t)
	server, _ := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client())

	claims := jwt.MapClaims{"sub": "1234567890"} // no exp

	result, err := tp.DecodeAndValidateTokenString(signRS256(t, key, "key-1", claims), nil, false)

	assert.NoError(t, err)
	assert.Equal(t, "1234567890", result.Claims["sub"])
}

// -----------------------------------------------------------------------------
// JWKS retrieval failures
//
// A failure to reach or parse the JWKS must surface as an error, never as an
// accepted token.
// -----------------------------------------------------------------------------

func TestJWKSTokenParser_JwksEndpointReturnsNonOK(t *testing.T) {
	key, _ := testKeys(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	tp := NewJWKSTokenParser(server.URL, server.Client())

	result, err := tp.DecodeAndValidateTokenString(signRS256(t, key, "key-1", validClaims()), nil, true)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to fetch JWKS")
}

func TestJWKSTokenParser_JwksEndpointReturnsInvalidJson(t *testing.T) {
	key, _ := testKeys(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this is not json"))
	}))
	t.Cleanup(server.Close)
	tp := NewJWKSTokenParser(server.URL, server.Client())

	result, err := tp.DecodeAndValidateTokenString(signRS256(t, key, "key-1", validClaims()), nil, true)

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestJWKSTokenParser_JwksEndpointUnreachable(t *testing.T) {
	key, _ := testKeys(t)
	server, _ := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
	tokenString := signRS256(t, key, "key-1", validClaims())
	serverURL := server.URL
	server.Close() // nothing is listening any more

	tp := NewJWKSTokenParser(serverURL, &http.Client{Timeout: 2 * time.Second})

	result, err := tp.DecodeAndValidateTokenString(tokenString, nil, true)

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestJWKSTokenParser_JwksEndpointReturnsEmptyKeySet(t *testing.T) {
	key, _ := testKeys(t)
	server, _ := newJwksServer(t) // no keys
	tp := NewJWKSTokenParser(server.URL, server.Client())

	result, err := tp.DecodeAndValidateTokenString(signRS256(t, key, "key-1", validClaims()), nil, true)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "public key not found for token kid")
}

func TestJWKSTokenParser_RefreshJwksStoresKeys(t *testing.T) {
	key, _ := testKeys(t)
	server, _ := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client())

	assert.Empty(t, tp.cachedJwks.Keys)

	err := tp.refreshJwks()

	assert.NoError(t, err)
	assert.Len(t, tp.cachedJwks.Keys, 1)
	assert.Equal(t, "key-1", tp.cachedJwks.Keys[0].Kid)
}

// A malformed jwksURL fails at request construction, before any network call.
func TestJWKSTokenParser_RefreshJwksInvalidURL(t *testing.T) {
	tp := NewJWKSTokenParser("http://\x7f-invalid", nil)

	err := tp.refreshJwks()

	assert.Error(t, err)
}

// -----------------------------------------------------------------------------
// DecodeAndValidateTokenResponse
// -----------------------------------------------------------------------------

func TestDecodeAndValidateTokenResponse_AllThreeTokens(t *testing.T) {
	key, _ := testKeys(t)
	server, _ := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client())

	accessClaims := validClaims()
	accessClaims["typ"] = "access"
	idClaims := validClaims()
	idClaims["typ"] = "id"
	// The refresh token is deliberately expired: it is parsed without claims
	// validation, so it must still come through.
	refreshClaims := validClaims()
	refreshClaims["typ"] = "refresh"
	refreshClaims["exp"] = time.Now().Add(-time.Hour).Unix()

	tokenResponse := &TokenResponse{
		AccessToken:  signRS256(t, key, "key-1", accessClaims),
		IdToken:      signRS256(t, key, "key-1", idClaims),
		RefreshToken: signRS256(t, key, "key-1", refreshClaims),
		TokenType:    "Bearer",
		ExpiresIn:    300,
		Scope:        "openid profile",
	}

	result, err := tp.DecodeAndValidateTokenResponse(tokenResponse)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "access", result.AccessToken.Claims["typ"])
	assert.Equal(t, "id", result.IdToken.Claims["typ"])
	assert.Equal(t, "refresh", result.RefreshToken.Claims["typ"])
	assert.Equal(t, "Bearer", result.TokenResponse.TokenType)
	assert.Equal(t, "openid profile", result.TokenResponse.Scope)
}

func TestDecodeAndValidateTokenResponse_OnlyAccessToken(t *testing.T) {
	key, _ := testKeys(t)
	server, _ := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client())

	result, err := tp.DecodeAndValidateTokenResponse(&TokenResponse{
		AccessToken: signRS256(t, key, "key-1", validClaims()),
	})

	assert.NoError(t, err)
	assert.NotNil(t, result.AccessToken)
	assert.Nil(t, result.IdToken)
	assert.Nil(t, result.RefreshToken)
}

func TestDecodeAndValidateTokenResponse_EmptyResponse(t *testing.T) {
	tp := NewJWKSTokenParser("https://auth.example.com", nil)

	result, err := tp.DecodeAndValidateTokenResponse(&TokenResponse{})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Nil(t, result.AccessToken)
	assert.Nil(t, result.IdToken)
	assert.Nil(t, result.RefreshToken)
}

// A forged token in any of the three slots must fail the whole response.
func TestDecodeAndValidateTokenResponse_RejectsForgedTokenInAnySlot(t *testing.T) {
	key, attacker := testKeys(t)

	valid := func(t *testing.T) string { return signRS256(t, key, "key-1", validClaims()) }
	forged := func(t *testing.T) string { return signRS256(t, attacker, "key-1", validClaims()) }

	testCases := []struct {
		name     string
		response func(t *testing.T) *TokenResponse
	}{
		{
			name: "forged access token",
			response: func(t *testing.T) *TokenResponse {
				return &TokenResponse{AccessToken: forged(t)}
			},
		},
		{
			name: "forged id token",
			response: func(t *testing.T) *TokenResponse {
				return &TokenResponse{AccessToken: valid(t), IdToken: forged(t)}
			},
		},
		{
			name: "forged refresh token",
			response: func(t *testing.T) *TokenResponse {
				return &TokenResponse{AccessToken: valid(t), IdToken: valid(t), RefreshToken: forged(t)}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
			tp := NewJWKSTokenParser(server.URL, server.Client())

			result, err := tp.DecodeAndValidateTokenResponse(tc.response(t))

			assert.Error(t, err)
			assert.Nil(t, result, "a forged token anywhere must fail the whole response")
		})
	}
}

func TestDecodeAndValidateTokenResponse_RejectsExpiredAccessToken(t *testing.T) {
	key, _ := testKeys(t)
	server, _ := newJwksServer(t, jwkFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client())

	claims := validClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()

	result, err := tp.DecodeAndValidateTokenResponse(&TokenResponse{
		AccessToken: signRS256(t, key, "key-1", claims),
	})

	assert.Error(t, err)
	assert.Nil(t, result)
}

// -----------------------------------------------------------------------------
// jwkToRSAPublicKey
// -----------------------------------------------------------------------------

func TestJwkToRSAPublicKey_ValidKey(t *testing.T) {
	key, _ := testKeys(t)

	pub, err := jwkToRSAPublicKey(jwkFromPublicKey("key-1", &key.PublicKey))

	assert.NoError(t, err)
	assert.NotNil(t, pub)
	assert.Equal(t, key.N, pub.N)
	assert.Equal(t, key.E, pub.E)
}

func TestJwkToRSAPublicKey_Rejections(t *testing.T) {
	key, _ := testKeys(t)
	valid := jwkFromPublicKey("key-1", &key.PublicKey)

	testCases := []struct {
		name string
		jwk  Jwk
	}{
		{"unsupported kty", Jwk{Kty: "EC", N: valid.N, E: valid.E}},
		{"empty kty", Jwk{Kty: "", N: valid.N, E: valid.E}},
		{"lowercase kty is not accepted", Jwk{Kty: "rsa", N: valid.N, E: valid.E}},
		{"invalid base64 modulus", Jwk{Kty: "RSA", N: "!!!not base64!!!", E: valid.E}},
		{"invalid base64 exponent", Jwk{Kty: "RSA", N: valid.N, E: "!!!not base64!!!"}},
		{"standard base64 padding is rejected", Jwk{Kty: "RSA", N: valid.N + "==", E: valid.E}},
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
	key, _ := testKeys(t)
	base := jwkFromPublicKey("key-1", &key.PublicKey)

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
	key, attacker := testKeys(t)

	t.Run("empty cache returns nil", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil)

		assert.Nil(t, tp.getPublicKeyFromCache("key-1"))
		assert.Nil(t, tp.getPublicKeyFromCache(""))
	})

	t.Run("matching kid returns the key", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil)
		tp.cachedJwks = Jwks{Keys: []Jwk{jwkFromPublicKey("key-1", &key.PublicKey)}}

		pub := tp.getPublicKeyFromCache("key-1")

		assert.NotNil(t, pub)
		assert.Equal(t, key.N, pub.N)
	})

	t.Run("non-matching kid returns nil", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil)
		tp.cachedJwks = Jwks{Keys: []Jwk{jwkFromPublicKey("key-1", &key.PublicKey)}}

		assert.Nil(t, tp.getPublicKeyFromCache("key-2"))
	})

	t.Run("empty kid with a single key returns that key", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil)
		tp.cachedJwks = Jwks{Keys: []Jwk{jwkFromPublicKey("key-1", &key.PublicKey)}}

		pub := tp.getPublicKeyFromCache("")

		assert.NotNil(t, pub)
		assert.Equal(t, key.N, pub.N)
	})

	t.Run("empty kid with several keys returns nil", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil)
		tp.cachedJwks = Jwks{Keys: []Jwk{
			jwkFromPublicKey("key-1", &key.PublicKey),
			jwkFromPublicKey("key-2", &attacker.PublicKey),
		}}

		assert.Nil(t, tp.getPublicKeyFromCache(""))
	})

	t.Run("empty kid with a single undecodable key returns nil", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil)
		tp.cachedJwks = Jwks{Keys: []Jwk{{Kty: "EC", Kid: "key-1"}}}

		assert.Nil(t, tp.getPublicKeyFromCache(""))
	})

	t.Run("matching kid on an undecodable key returns nil", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil)
		tp.cachedJwks = Jwks{Keys: []Jwk{{Kty: "EC", Kid: "key-1"}}}

		assert.Nil(t, tp.getPublicKeyFromCache("key-1"))
	})
}
