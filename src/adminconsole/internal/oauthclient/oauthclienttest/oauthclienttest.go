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
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/certs" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oauth.Jwks{Keys: keys})
	}))
	t.Cleanup(server.Close)
	return server, &hits
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
