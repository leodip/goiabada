// Package oauthclienttest signs real RS256 tokens and serves the keys that verify them, so a
// test can drive the admin console's JWKS parser with what the auth server would send rather
// than with a stub that proves only that an error propagates. It is a separate package for the
// reason core/sessionstore/sessiontest is: test support declared beside the parser would be
// compiled into the admin console binary, and no binary links this one (#427).
//
// It imports nothing from oauthclient, whose own internal tests import it: anything the other
// way round would be an import cycle.
package oauthclienttest

import (
	"context"
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
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/oauth"
)

// Issuer and ClientID are what ValidClaims names in iss and aud. ClientID is deliberately not
// the production admin-console-client: a parser comparing aud against that constant rather
// than against the client identifier it was constructed with fails every test that uses this.
const (
	Issuer   = "https://auth.example.com"
	ClientID = "console-under-test"
)

// StaticIssuer is an issuer port that always answers itself, standing in for the per-request
// settings snapshot the admin console reads its expected issuer from.
type StaticIssuer string

// Issuer returns the issuer the value names.
func (s StaticIssuer) Issuer(context.Context) string { return string(s) }

var (
	keysOnce    sync.Once
	signingKey  *rsa.PrivateKey
	attackerKey *rsa.PrivateKey
	keysErr     error
)

// Keys returns the key the "auth server" publishes and one it never publishes. RSA key
// generation is slow, so both are generated once per test binary.
func Keys(t testing.TB) (signing, attacker *rsa.PrivateKey) {
	t.Helper()
	keysOnce.Do(func() {
		signingKey, keysErr = rsa.GenerateKey(rand.Reader, 2048)
		if keysErr != nil {
			return
		}
		attackerKey, keysErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	require.NoError(t, keysErr)
	return signingKey, attackerKey
}

// JwkFromPublicKey publishes pub under kid, as the auth server's /certs does.
func JwkFromPublicKey(kid string, pub *rsa.PublicKey) oauth.Jwk {
	return oauth.Jwk{
		Alg: "RS256",
		Kid: kid,
		Kty: "RSA",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// NewJwksServer serves the given keys at /certs and counts how many times it is hit, so a test
// can assert the parser caches rather than refetching per token.
func NewJwksServer(t testing.TB, keys ...oauth.Jwk) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	server := NewMutableJwksServer(t, keys...)
	return server.Server, &server.Hits
}

// JwksServer serves at /certs the keys it was last told to publish and counts the fetches, so a
// test can change the auth server's key set under a parser that has already cached it.
type JwksServer struct {
	*httptest.Server
	// Hits counts the requests for /certs, answered or refused.
	Hits atomic.Int32

	mu   sync.Mutex
	keys []oauth.Jwk
	down bool
}

// NewMutableJwksServer starts a JwksServer publishing keys.
func NewMutableJwksServer(t testing.TB, keys ...oauth.Jwk) *JwksServer {
	t.Helper()
	s := &JwksServer{keys: keys}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/certs" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		s.Hits.Add(1)
		s.mu.Lock()
		keys, down := s.keys, s.down
		s.mu.Unlock()
		if down {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oauth.Jwks{Keys: keys})
	}))
	t.Cleanup(s.Close)
	return s
}

// Publish replaces the keys /certs publishes, as a rotation or a key deletion on the auth
// server does.
func (s *JwksServer) Publish(keys ...oauth.Jwk) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = keys
}

// GoDown makes /certs answer 503 from now on, an auth server that cannot give out its keys.
func (s *JwksServer) GoDown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = true
}

// Clock is a clock a test moves by hand, for the parser's JWKS age, which is all the parser
// reads it for: a token's exp and nbf are still checked against the real time. It starts at the
// real time.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// NewClock returns a Clock reading the real time until it is moved.
func NewClock() *Clock {
	return &Clock{now: time.Now()}
}

// Now reads the clock.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// SignRS256 signs claims with key, naming kid in the header unless it is empty.
func SignRS256(t testing.TB, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// ValidClaims is an ID token's claims that every check accepts: Issuer, ClientID as the one
// audience, an expiry an hour out and issued now.
func ValidClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub": "1234567890",
		"iss": Issuer,
		"aud": ClientID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
}
