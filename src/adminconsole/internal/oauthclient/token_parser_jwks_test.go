package oauthclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient/oauthclienttest"
	"github.com/leodip/goiabada/core/boundedread"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKSTokenParserRejectsNonRS256Token(t *testing.T) {
	tp := NewJWKSTokenParser("https://auth.example.com", nil, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	claims := jwt.MapClaims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("secret"))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), tokenString)

	require.Error(t, err)
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
			tp := NewJWKSTokenParser(tc.baseURL, nil, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

			assert.Equal(t, tc.want, tp.jwksURL)
		})
	}
}

func TestNewJWKSTokenParser_DefaultsHTTPClient(t *testing.T) {
	tp := NewJWKSTokenParser("https://auth.example.com", nil, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
	require.NotNil(t, tp.httpClient)
	// The value, not merely a client: a nil client used to mean an unbounded one, and
	// asserting non-nil alone leaves restoring `&http.Client{}` green. This is the same
	// guarantee TestNewTokenClient_DefaultsANilClientToTheConfiguredTimeout pins for
	// the token client's own nil arm (#338).
	assert.Equal(t, TokenExchangeTimeout, tp.httpClient.Timeout,
		"a nil client gets the deadline rather than no deadline")

	custom := &http.Client{Timeout: time.Second}
	tp = NewJWKSTokenParser("https://auth.example.com", custom, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
	assert.Equal(t, time.Second, tp.httpClient.Timeout,
		"an injected client keeps its deadline, in the copy that refuses redirects")
}

// -----------------------------------------------------------------------------
// The accept path
// -----------------------------------------------------------------------------

func TestJWKSTokenParser_AcceptsTokenSignedByPublishedKey(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server, hits := oauthclienttest.NewJWKSServer(t, oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	tokenString := oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims())

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), tokenString)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, tokenString, result.TokenBase64)
	assert.Equal(t, "1234567890", result.Claims["sub"])
	assert.Equal(t, int32(1), hits.Load(), "the JWKS must be fetched once on a cold cache")
}

// The JWKS is cached after the first fetch, so validating more tokens must not
// produce more HTTP requests.
func TestJWKSTokenParser_CachesJWKSAcrossCalls(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server, hits := oauthclienttest.NewJWKSServer(t, oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	for i := 0; i < 3; i++ {
		_, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims()))
		require.NoError(t, err)
	}

	assert.Equal(t, int32(1), hits.Load(), "the JWKS must be fetched only once")
}

// A token with no kid header is accepted only when the JWKS publishes exactly
// one key, which is the single-key fallback in getPublicKeyFromCache.
func TestJWKSTokenParser_TokenWithoutKidUsesTheOnlyPublishedKey(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server, _ := oauthclienttest.NewJWKSServer(t, oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "", oauthclienttest.ValidClaims()))

	require.NoError(t, err)
	assert.Equal(t, "1234567890", result.Claims["sub"])
}

func TestJWKSTokenParser_SelectsCorrectKeyWhenSeveralArePublished(t *testing.T) {
	key, attacker := oauthclienttest.Keys(t)
	// The attacker's key is published under a different kid; the token names key-2.
	server, _ := oauthclienttest.NewJWKSServer(t,
		oauthclienttest.JWKFromPublicKey("key-1", &attacker.PublicKey),
		oauthclienttest.JWKFromPublicKey("key-2", &key.PublicKey),
	)
	tp := NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "key-2", oauthclienttest.ValidClaims()))

	require.NoError(t, err)
	assert.Equal(t, "1234567890", result.Claims["sub"])
}

// -----------------------------------------------------------------------------
// The cache's age
//
// OIDC Core 10.1.1's rule, refetch on an unfamiliar kid, never shows a warm cache
// that a key it holds has left /certs, because the auth server publishes its next
// key before signing with it. So the cache answers for at most jwksMaxAge after
// its fetch, and a removed key stops verifying from then on (#427).
// -----------------------------------------------------------------------------

// newWarmParser returns a parser over server, reading clock, that has verified
// token once and so cached server's keys.
func newWarmParser(t *testing.T, server *oauthclienttest.JWKSServer, token string) (*JWKSTokenParser, *oauthclienttest.Clock) {
	t.Helper()
	clock := oauthclienttest.NewClock()
	tp := NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID,
		oauthclienttest.StaticIssuer(oauthclienttest.Issuer), WithClock(clock.Now))
	_, err := tp.DecodeAndValidateStoredIDToken(context.Background(), token)
	require.NoError(t, err, "the token verifies while its key is published")
	require.Equal(t, int32(1), server.Hits.Load())
	return tp, clock
}

// A key removed from /certs after the cache fetched it keeps verifying until the
// cache's age, and not from the age on, in each shape a key leaves this auth
// server's key set: the only key removed; its rotation, which deletes the old
// current key and promotes a next key the cache already holds, so no unfamiliar
// kid ever arrives; and a token with no kid against a single key that was swapped.
func TestJWKSTokenParser_ARemovedKeyVerifiesUntilTheCacheIsPastItsAge(t *testing.T) {
	removed, other := oauthclienttest.Keys(t)

	testCases := []struct {
		name      string
		before    []oauth.JWK
		after     []oauth.JWK
		token     string
		promoted  string // a token under the key the change promoted, verified from the cache
		wantError error
		wantText  string
	}{
		{
			name:     "the only key removed",
			before:   []oauth.JWK{oauthclienttest.JWKFromPublicKey("removed", &removed.PublicKey)},
			after:    nil,
			token:    oauthclienttest.SignRS256(t, removed, "removed", oauthclienttest.ValidClaims()),
			wantText: "public key not found for token kid",
		},
		{
			name: "a rotation: next promoted, current deleted",
			before: []oauth.JWK{
				oauthclienttest.JWKFromPublicKey("next", &other.PublicKey),
				oauthclienttest.JWKFromPublicKey("removed", &removed.PublicKey),
			},
			after:    []oauth.JWK{oauthclienttest.JWKFromPublicKey("next", &other.PublicKey)},
			token:    oauthclienttest.SignRS256(t, removed, "removed", oauthclienttest.ValidClaims()),
			promoted: oauthclienttest.SignRS256(t, other, "next", oauthclienttest.ValidClaims()),
			wantText: "public key not found for token kid",
		},
		{
			name:      "no kid, and the one key swapped",
			before:    []oauth.JWK{oauthclienttest.JWKFromPublicKey("removed", &removed.PublicKey)},
			after:     []oauth.JWK{oauthclienttest.JWKFromPublicKey("new", &other.PublicKey)},
			token:     oauthclienttest.SignRS256(t, removed, "", oauthclienttest.ValidClaims()),
			wantError: jwt.ErrTokenSignatureInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := oauthclienttest.NewMutableJWKSServer(t, tc.before...)
			tp, clock := newWarmParser(t, server, tc.token)
			server.Publish(tc.after...)

			clock.Advance(jwksMaxAge - time.Second)
			result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), tc.token)
			require.NoError(t, err, "within the age the cache still answers for the removed key")
			assert.Equal(t, tc.token, result.TokenBase64)
			if tc.promoted != "" {
				_, err = tp.DecodeAndValidateStoredIDToken(context.Background(), tc.promoted)
				require.NoError(t, err, "the promoted key was already cached")
			}
			assert.Equal(t, int32(1), server.Hits.Load(), "nothing sent the cache back to /certs")

			clock.Advance(time.Second)
			result, err = tp.DecodeAndValidateStoredIDToken(context.Background(), tc.token)
			require.Error(t, err, "at the age the keys are refetched and the removed one is gone")
			assert.Nil(t, result)
			if tc.wantError != nil {
				require.ErrorIs(t, err, tc.wantError)
			}
			if tc.wantText != "" {
				assert.Contains(t, err.Error(), tc.wantText)
			}
			assert.Equal(t, int32(2), server.Hits.Load(), "one refetch")
		})
	}
}

// A refetch restarts the age: the keys it brought answer for another jwksMaxAge,
// not only until the first fetch's age.
func TestJWKSTokenParser_ARefetchRestartsTheCachesAge(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server := oauthclienttest.NewMutableJWKSServer(t, oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))
	token := oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims())
	tp, clock := newWarmParser(t, server, token)

	verify := func() {
		t.Helper()
		_, err := tp.DecodeAndValidateStoredIDToken(context.Background(), token)
		require.NoError(t, err)
	}

	clock.Advance(jwksMaxAge)
	verify()
	assert.Equal(t, int32(2), server.Hits.Load(), "the age lapsed, so the keys were refetched")

	clock.Advance(jwksMaxAge - time.Second)
	verify()
	assert.Equal(t, int32(2), server.Hits.Load(), "the refetched keys answer for a whole age")

	clock.Advance(time.Second)
	verify()
	assert.Equal(t, int32(3), server.Hits.Load(), "and not past it")
}

// A cache past its age is not trusted for want of a newer one: when /certs cannot
// be fetched, the token is refused rather than verified against the keys the fetch
// was meant to replace. Within the age an unreachable /certs changes nothing,
// because nothing asks it, and a fetch that failed is retried by the next check
// rather than remembered.
func TestJWKSTokenParser_RefusesATokenWhenTheKeysCannotBeRefetchedPastTheAge(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server := oauthclienttest.NewMutableJWKSServer(t, oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))
	token := oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims())
	tp, clock := newWarmParser(t, server, token)
	server.GoDown()

	clock.Advance(jwksMaxAge - time.Second)
	_, err := tp.DecodeAndValidateStoredIDToken(context.Background(), token)
	require.NoError(t, err, "within the age the cache answers without asking /certs")
	assert.Equal(t, int32(1), server.Hits.Load())

	clock.Advance(time.Second)
	for attempt := int32(2); attempt <= 3; attempt++ {
		result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), token)
		require.Error(t, err, "past the age a failed refetch refuses the token")
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to fetch JWKS")
		assert.Equal(t, attempt, server.Hits.Load(), "each check tries /certs again")
	}
}

// OIDC Core 10.1.1's half, on a warm cache and inside the age: an unfamiliar kid
// sends the parser back to /certs, and what it fetches replaces the cache whole,
// so a key the auth server has removed meanwhile is refused from then on.
func TestJWKSTokenParser_AnUnfamiliarKidRefetchesWithinTheAge(t *testing.T) {
	removed, promoted := oauthclienttest.Keys(t)
	server := oauthclienttest.NewMutableJWKSServer(t, oauthclienttest.JWKFromPublicKey("removed", &removed.PublicKey))
	underRemoved := oauthclienttest.SignRS256(t, removed, "removed", oauthclienttest.ValidClaims())
	tp, _ := newWarmParser(t, server, underRemoved)
	server.Publish(oauthclienttest.JWKFromPublicKey("promoted", &promoted.PublicKey))

	_, err := tp.DecodeAndValidateStoredIDToken(context.Background(),
		oauthclienttest.SignRS256(t, promoted, "promoted", oauthclienttest.ValidClaims()))
	require.NoError(t, err)
	assert.Equal(t, int32(2), server.Hits.Load(), "the unfamiliar kid was refetched")

	_, err = tp.DecodeAndValidateStoredIDToken(context.Background(), underRemoved)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public key not found for token kid")
}

// Requests that find the cache wanting together make one fetch between them: one
// that waited on the fetch lock behind another's fetch finds the generation it saw
// replaced and uses that fetch. A caller whose generation is current fetches.
func TestRefreshJWKSSince_UsesAFetchThatLandedWhileItWaited(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server := oauthclienttest.NewMutableJWKSServer(t, oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	require.NoError(t, tp.refreshJWKSSince(context.Background(), 0))
	assert.Equal(t, int32(1), server.Hits.Load(), "the caller's generation was current, so it fetched")

	require.NoError(t, tp.refreshJWKSSince(context.Background(), 0))
	assert.Equal(t, int32(1), server.Hits.Load(), "generation 0 was replaced while it waited, so no second fetch")

	require.NoError(t, tp.refreshJWKSSince(context.Background(), 1))
	assert.Equal(t, int32(2), server.Hits.Load())
}

// The same promise through the public method: however many checks find the cache
// past its age at once, /certs is fetched once. That holds in every interleaving,
// since a check that looks before the refetch lands waits on it and finds its
// generation replaced, and one that looks after finds the cache fresh. The race
// tier runs this over the parser's two locks.
func TestJWKSTokenParser_ChecksThatFindTheCachePastItsAgeTogetherFetchOnce(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server := oauthclienttest.NewMutableJWKSServer(t, oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))
	token := oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims())
	tp, clock := newWarmParser(t, server, token)
	clock.Advance(jwksMaxAge)

	const checks = 8
	results := make(chan error, checks)
	var wg sync.WaitGroup
	for range checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := tp.DecodeAndValidateStoredIDToken(context.Background(), token)
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	for err := range results {
		require.NoError(t, err)
	}
	assert.Equal(t, int32(2), server.Hits.Load(), "the warm-up's fetch and one refetch between all of them")
}

// -----------------------------------------------------------------------------
// The reject paths
// -----------------------------------------------------------------------------

// The core security property: a token signed by a key the JWKS does not publish
// must be rejected, even when it names a kid that the JWKS does publish.
func TestJWKSTokenParser_RejectsTokenSignedByUnpublishedKey(t *testing.T) {
	key, attacker := oauthclienttest.Keys(t)
	server, _ := oauthclienttest.NewJWKSServer(t, oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	// Signed by the attacker but claiming to be key-1.
	forged := oauthclienttest.SignRS256(t, attacker, "key-1", oauthclienttest.ValidClaims())

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), forged)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid)
}

func TestJWKSTokenParser_RejectsUnknownKid(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server, hits := oauthclienttest.NewJWKSServer(t, oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "key-does-not-exist", oauthclienttest.ValidClaims()))

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "public key not found for token kid")
	assert.Equal(t, int32(1), hits.Load(), "an unknown kid must trigger exactly one refresh attempt")
}

// With no kid and more than one published key there is no way to choose, so the
// token must be rejected rather than tried against every key.
func TestJWKSTokenParser_RejectsTokenWithoutKidWhenSeveralKeysArePublished(t *testing.T) {
	key, attacker := oauthclienttest.Keys(t)
	server, _ := oauthclienttest.NewJWKSServer(t,
		oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey),
		oauthclienttest.JWKFromPublicKey("key-2", &attacker.PublicKey),
	)
	tp := NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "", oauthclienttest.ValidClaims()))

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "public key not found for token kid")
}

func TestJWKSTokenParser_RejectsMalformedToken(t *testing.T) {
	tp := NewJWKSTokenParser("https://auth.example.com", nil, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	for _, tokenString := range []string{"not-a-jwt", "a.b", "a.b.c", "...."} {
		t.Run(tokenString, func(t *testing.T) {
			result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), tokenString)

			require.Error(t, err)
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

func TestJWKSTokenParser_JWKSEndpointReturnsNonOK(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	tp := NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims()))

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to fetch JWKS")
}

func TestJWKSTokenParser_JWKSEndpointReturnsInvalidJSON(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this is not json"))
	}))
	t.Cleanup(server.Close)
	tp := NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims()))

	require.Error(t, err)
	assert.Nil(t, result)
}

func TestJWKSTokenParser_JWKSEndpointUnreachable(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server, _ := oauthclienttest.NewJWKSServer(t, oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))
	tokenString := oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims())
	serverURL := server.URL
	server.Close() // nothing is listening any more

	tp := NewJWKSTokenParser(serverURL, &http.Client{Timeout: 2 * time.Second}, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), tokenString)

	require.Error(t, err)
	assert.Nil(t, result)
}

func TestJWKSTokenParser_JWKSEndpointReturnsEmptyKeySet(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server, _ := oauthclienttest.NewJWKSServer(t) // no keys
	tp := NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	result, err := tp.DecodeAndValidateStoredIDToken(context.Background(), oauthclienttest.SignRS256(t, key, "key-1", oauthclienttest.ValidClaims()))

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "public key not found for token kid")
}

func TestJWKSTokenParser_RefreshJWKSStoresKeys(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	server, _ := oauthclienttest.NewJWKSServer(t, oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))
	tp := NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	assert.Empty(t, tp.cachedJWKS.Keys)

	err := tp.refreshJWKS(context.Background())

	require.NoError(t, err)
	assert.Len(t, tp.cachedJWKS.Keys, 1)
	assert.Equal(t, "key-1", tp.cachedJWKS.Keys[0].Kid)
}

// A malformed jwksURL fails at request construction, before any network call.
func TestJWKSTokenParser_RefreshJWKSInvalidURL(t *testing.T) {
	tp := NewJWKSTokenParser("http://\x7f-invalid", nil, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	err := tp.refreshJWKS(context.Background())

	assert.Error(t, err)
}

// -----------------------------------------------------------------------------
// jwkToRSAPublicKey
// -----------------------------------------------------------------------------

func TestJWKToRSAPublicKey_ValidKey(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)

	pub, err := jwkToRSAPublicKey(oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))

	require.NoError(t, err)
	assert.NotNil(t, pub)
	assert.Equal(t, key.N, pub.N)
	assert.Equal(t, key.E, pub.E)
}

// modulusOfBits is an odd base64url modulus of exactly bits bits, 2^(bits-1) + 1.
func modulusOfBits(bits int) string {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

func exponentOf(e ...byte) string {
	return base64.RawURLEncoding.EncodeToString(e)
}

// 2048 bits is the least RFC 7518 section 3.3 allows, and is accepted.
func TestJWKToRSAPublicKey_AcceptsA2048BitModulus(t *testing.T) {
	pub, err := jwkToRSAPublicKey(oauth.JWK{Kty: "RSA", N: modulusOfBits(2048), E: "AQAB"})

	require.NoError(t, err)
	assert.Equal(t, 2048, pub.N.BitLen())
	assert.Equal(t, 65537, pub.E)
}

func TestJWKToRSAPublicKey_Rejections(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	valid := oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey)

	testCases := []struct {
		name string
		jwk  oauth.JWK
	}{
		{"unsupported kty", oauth.JWK{Kty: "EC", N: valid.N, E: valid.E}},
		{"empty kty", oauth.JWK{Kty: "", N: valid.N, E: valid.E}},
		{"lowercase kty is not accepted", oauth.JWK{Kty: "rsa", N: valid.N, E: valid.E}},
		{"invalid base64 modulus", oauth.JWK{Kty: "RSA", N: "!!!not base64!!!", E: valid.E}},
		{"invalid base64 exponent", oauth.JWK{Kty: "RSA", N: valid.N, E: "!!!not base64!!!"}},
		{"standard base64 padding is rejected", oauth.JWK{Kty: "RSA", N: valid.N + "==", E: valid.E}},
		// RFC 7518 section 3.3: "A key of size 2048 bits or larger MUST be used" (#709 finding 6).
		{"a 2047-bit modulus", oauth.JWK{Kty: "RSA", N: modulusOfBits(2047), E: "AQAB"}},
		{"a 1024-bit modulus", oauth.JWK{Kty: "RSA", N: modulusOfBits(1024), E: "AQAB"}},
		{"an empty modulus", oauth.JWK{Kty: "RSA", N: "", E: "AQAB"}},
		// An exponent that is even, below 3 or longer than four bytes (#709 finding 6).
		{"an empty exponent", oauth.JWK{Kty: "RSA", N: valid.N, E: ""}},
		{"exponent 0", oauth.JWK{Kty: "RSA", N: valid.N, E: exponentOf(0x00)}},
		{"exponent 1", oauth.JWK{Kty: "RSA", N: valid.N, E: exponentOf(0x01)}},
		{"exponent 2", oauth.JWK{Kty: "RSA", N: valid.N, E: exponentOf(0x02)}},
		{"exponent 4", oauth.JWK{Kty: "RSA", N: valid.N, E: exponentOf(0x04)}},
		{"exponent 65536", oauth.JWK{Kty: "RSA", N: valid.N, E: exponentOf(0x01, 0x00, 0x00)}},
		{"exponent 65537 in five bytes", oauth.JWK{Kty: "RSA", N: valid.N, E: exponentOf(0x00, 0x00, 0x01, 0x00, 0x01)}},
		{"a five-byte exponent", oauth.JWK{Kty: "RSA", N: valid.N, E: exponentOf(0x01, 0x00, 0x00, 0x00, 0x01)}},
		{"a nine-byte exponent that overflows an int", oauth.JWK{Kty: "RSA", N: valid.N,
			E: exponentOf(0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pub, err := jwkToRSAPublicKey(tc.jwk)

			require.Error(t, err)
			assert.Nil(t, pub)
		})
	}
}

// The exponent is decoded big-endian from its base64 bytes.
func TestJWKToRSAPublicKey_DecodesExponent(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	base := oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey)

	testCases := []struct {
		name string
		e    []byte
		want int
	}{
		{"single byte", []byte{0x03}, 3},
		{"two bytes", []byte{0x01, 0x01}, 257},
		{"the usual 65537", []byte{0x01, 0x00, 0x01}, 65537},
		{"65537 in four bytes", []byte{0x00, 0x01, 0x00, 0x01}, 65537},
		{"four bytes", []byte{0x7f, 0xff, 0xff, 0xff}, 2147483647},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jwk := base
			jwk.E = base64.RawURLEncoding.EncodeToString(tc.e)

			pub, err := jwkToRSAPublicKey(jwk)

			require.NoError(t, err)
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
		tp := NewJWKSTokenParser("https://auth.example.com", nil, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

		assert.Nil(t, tp.getPublicKeyFromCache("key-1"))
		assert.Nil(t, tp.getPublicKeyFromCache(""))
	})

	t.Run("matching kid returns the key", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
		tp.cachedJWKS = cachedKeys(t, oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))

		pub := tp.getPublicKeyFromCache("key-1")

		assert.NotNil(t, pub)
		assert.Equal(t, key.N, pub.N)
	})

	t.Run("non-matching kid returns nil", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
		tp.cachedJWKS = cachedKeys(t, oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))

		assert.Nil(t, tp.getPublicKeyFromCache("key-2"))
	})

	t.Run("empty kid with a single key returns that key", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
		tp.cachedJWKS = cachedKeys(t, oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))

		pub := tp.getPublicKeyFromCache("")

		assert.NotNil(t, pub)
		assert.Equal(t, key.N, pub.N)
	})

	t.Run("empty kid with several keys returns nil", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
		tp.cachedJWKS = cachedKeys(t,
			oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey),
			oauthclienttest.JWKFromPublicKey("key-2", &attacker.PublicKey),
		)

		assert.Nil(t, tp.getPublicKeyFromCache(""))
	})

	t.Run("empty kid with a single undecodable key returns nil", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
		tp.cachedJWKS = cachedKeys(t, oauth.JWK{Kty: "EC", Kid: "key-1"})

		assert.Nil(t, tp.getPublicKeyFromCache(""))
	})

	// #709 finding 7, OIDC Core 1.0 section 10.1: a key whose use is present and not sig, or whose
	// alg is present and not RS256, is not used, whether a kid names it or it is the only key.
	// Present is present with any value: an empty string, a JSON null or a number is no absent
	// member. Member names are case-sensitive, so a USE member is not use.
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
		usable bool
	}{
		{"use sig and alg RS256", func(map[string]any) {}, true},
		{"use and alg absent", func(m map[string]any) { delete(m, "use"); delete(m, "alg") }, true},
		{"use enc", func(m map[string]any) { m["use"] = "enc" }, false},
		{"use enc and alg absent", func(m map[string]any) { m["use"] = "enc"; delete(m, "alg") }, false},
		{"alg RS512", func(m map[string]any) { m["alg"] = "RS512" }, false},
		{"alg RS512 and use absent", func(m map[string]any) { delete(m, "use"); m["alg"] = "RS512" }, false},
		{"alg none", func(m map[string]any) { m["alg"] = "none" }, false},
		{"use an empty string", func(m map[string]any) { m["use"] = "" }, false},
		{"use null", func(m map[string]any) { m["use"] = nil }, false},
		{"use a number", func(m map[string]any) { m["use"] = 1 }, false},
		{"use an array holding sig", func(m map[string]any) { m["use"] = []string{"sig"} }, false},
		{"alg an empty string", func(m map[string]any) { m["alg"] = "" }, false},
		{"alg null", func(m map[string]any) { m["alg"] = nil }, false},
		{"alg a boolean", func(m map[string]any) { m["alg"] = true }, false},
		{"use SIG", func(m map[string]any) { m["use"] = "SIG" }, false},
		{"use absent beside a USE member", func(m map[string]any) { delete(m, "use"); m["USE"] = "enc" }, true},
	} {
		encoded, err := json.Marshal(oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))
		require.NoError(t, err)
		var members map[string]any
		require.NoError(t, json.Unmarshal(encoded, &members))
		tc.change(members)
		document, err := json.Marshal(map[string]any{"keys": []any{members}})
		require.NoError(t, err)
		for _, kid := range []string{"key-1", ""} {
			t.Run(tc.name+" under kid "+fmt.Sprintf("%q", kid), func(t *testing.T) {
				tp := NewJWKSTokenParser("https://auth.example.com", nil, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
				keys, err := decodeJWKS(document)
				require.NoError(t, err)
				tp.cachedJWKS = keys

				pub := tp.getPublicKeyFromCache(kid)

				if tc.usable {
					require.NotNil(t, pub)
					assert.Equal(t, key.N, pub.N)
				} else {
					assert.Nil(t, pub)
				}
			})
		}
	}

	t.Run("matching kid on an undecodable key returns nil", func(t *testing.T) {
		tp := NewJWKSTokenParser("https://auth.example.com", nil, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
		tp.cachedJWKS = cachedKeys(t, oauth.JWK{Kty: "EC", Kid: "key-1"})

		assert.Nil(t, tp.getPublicKeyFromCache("key-1"))
	})
}

// =============================================================================
// The JWKS read bound, goal 9 of #338.
//
// refreshJWKS is the third of the admin console's three reads of the auth
// server and the only one that decodes straight off the body rather than
// reading it first, so neither the token client's cases nor the middleware's
// observe it. The counting body from token_client_bounds_test.go is the same
// seam seen through the parser's own injected client.
// =============================================================================

// oversizedJWKS is a valid JWKS document padded past the cap by one key's
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
func oversizedJWKS(t *testing.T) *countingBody {
	t.Helper()
	prefix := `{"keys":[{"kty":"RSA","kid":"key-1","alg":"RS256","use":"sig","e":"AQAB","n":"`
	suffix := `"}]}`
	padding := MaxTokenResponseBytes + 1024 - len(prefix) - len(suffix)
	return &countingBody{remaining: []byte(prefix + strings.Repeat("x", padding) + suffix)}
}

func TestRefreshJWKS_RefusesADocumentOverTheCap(t *testing.T) {
	body := oversizedJWKS(t)

	tp := NewJWKSTokenParser("https://auth.example.com",
		clientReturning(http.StatusOK, body), nil,
		oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	err := tp.refreshJWKS(context.Background())

	require.Error(t, err)
	require.ErrorIs(t, err, boundedread.ErrResponseTooLarge,
		"the document is refused as oversized rather than reaching the decoder truncated: %v", err)
	assert.Equal(t, int64(MaxTokenResponseBytes)+1, body.read.Load(),
		"one byte past the cap is read, which is what makes the overrun detectable, and no more")
	assert.Empty(t, tp.cachedJWKS.Keys, "nothing is cached from a document that was refused")
}

// The document exactly at the cap is accepted, so the case above is the overrun
// and not the size. It is the one boundary a reader would otherwise have to take
// on trust, since the two padded documents above and below it are a megabyte
// apart.
func TestRefreshJWKS_AcceptsADocumentOfExactlyTheCap(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwk := oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey)
	encoded, err := json.Marshal(oauth.JWKS{Keys: []oauth.JWK{jwk}})
	require.NoError(t, err)

	// Pad the one field of unbounded length until the encoding is the cap to the byte.
	jwk.Kid = "key-1" + strings.Repeat("x", MaxTokenResponseBytes-len(encoded))
	encoded, err = json.Marshal(oauth.JWKS{Keys: []oauth.JWK{jwk}})
	require.NoError(t, err)
	require.Len(t, encoded, MaxTokenResponseBytes)

	tp := NewJWKSTokenParser("https://auth.example.com",
		clientReturning(http.StatusOK, io.NopCloser(bytes.NewReader(encoded))), nil,
		oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	require.NoError(t, tp.refreshJWKS(context.Background()))
	require.Len(t, tp.cachedJWKS.Keys, 1)
	assert.Equal(t, jwk.Kid, tp.cachedJWKS.Keys[0].Kid)
}

// The benign member of the class: a document under the cap still decodes, so the
// case above cannot be read as "large JWKS documents are refused".
func TestRefreshJWKS_AcceptsADocumentUnderTheCap(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	encoded, err := json.Marshal(oauth.JWKS{Keys: []oauth.JWK{oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey)}})
	require.NoError(t, err)
	require.Less(t, len(encoded), MaxTokenResponseBytes)

	tp := NewJWKSTokenParser("https://auth.example.com",
		clientReturning(http.StatusOK, io.NopCloser(bytes.NewReader(encoded))), nil,
		oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	require.NoError(t, tp.refreshJWKS(context.Background()))
	require.Len(t, tp.cachedJWKS.Keys, 1)
	assert.Equal(t, "key-1", tp.cachedJWKS.Keys[0].Kid)
}

// cachedKeys is keys as refreshJWKS caches them: encoded as the auth server publishes them and read
// back through decodeJWKS.
func cachedKeys(t *testing.T, keys ...oauth.JWK) publishedKeys {
	t.Helper()
	encoded, err := json.Marshal(oauth.JWKS{Keys: keys})
	require.NoError(t, err)
	decoded, err := decodeJWKS(encoded)
	require.NoError(t, err)
	return decoded
}

// A key whose use or alg is no string is kept under its kid and never used, and the other keys of
// the document are read as before; a key that is no JSON object refuses the document.
func TestDecodeJWKS_AKeyOfTheWrongShapeIsNeverUsed(t *testing.T) {
	key, other := oauthclienttest.Keys(t)
	good, err := json.Marshal(oauthclienttest.JWKFromPublicKey("key-1", &key.PublicKey))
	require.NoError(t, err)
	odd, err := json.Marshal(oauthclienttest.JWKFromPublicKey("key-2", &other.PublicKey))
	require.NoError(t, err)
	odd = bytes.Replace(odd, []byte(`"use":"sig"`), []byte(`"use":["sig"]`), 1)

	keys, err := decodeJWKS([]byte(`{"keys":[` + string(good) + `,` + string(odd) + `]}`))
	require.NoError(t, err)
	tp := NewJWKSTokenParser("https://auth.example.com", nil, nil, oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
	tp.cachedJWKS = keys

	require.Len(t, keys.Keys, 2)
	assert.Equal(t, "key-2", keys.Keys[1].Kid)
	assert.NotNil(t, tp.getPublicKeyFromCache("key-1"))
	assert.Nil(t, tp.getPublicKeyFromCache("key-2"))

	_, err = decodeJWKS([]byte(`{"keys":[` + string(good) + `,"a string"]}`))
	assert.Error(t, err)
}
