// Package dpoptest builds DPoP proofs for tests the way a client builds them: ES256 over one of two
// published P-256 keys, signed with the standard library alone. It is test support beside the
// package it concerns, compiled into no binary, as otptest is.
//
// It imports nothing from dpop, so a test sending a proof checks the server against a proof the
// server did not build, and each key's thumbprint is a literal worked out apart from Go, by the
// RFC 7638 definition, so a test asserting cnf.jkt does not recompute it the way the server does.
package dpoptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// Key is a client's P-256 key pair: the public JWK its proofs carry, and that JWK's RFC 7638
// SHA-256 thumbprint, the value of cnf.jkt in a token bound to it.
type Key struct {
	priv *ecdsa.PrivateKey
	// JWK is the public key as a proof's jwk header member carries it.
	JWK map[string]any
	// Thumbprint is the JWK's RFC 7638 thumbprint, base64url without padding.
	Thumbprint string
}

// RFC7517Key is RFC 7517 appendix A.2's P-256 private key.
func RFC7517Key(t testing.TB) Key {
	t.Helper()
	return newKey(t, "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
		"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		"cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s")
}

// RFC7515Key is RFC 7515 appendix A.3's P-256 private key, another client's key beside
// RFC7517Key.
func RFC7515Key(t testing.TB) Key {
	t.Helper()
	return newKey(t, "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
		"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		"oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U")
}

func newKey(t testing.TB, d, x, y, thumbprint string) Key {
	t.Helper()
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), unb64(t, d))
	if err != nil {
		t.Fatalf("dpoptest: the private key does not parse: %v", err)
	}
	point, err := priv.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("dpoptest: the public key does not encode: %v", err)
	}
	if b64(point[1:33]) != x || b64(point[33:]) != y {
		t.Fatalf("dpoptest: the private key's public point is not the RFC's")
	}
	return Key{
		priv:       priv,
		JWK:        map[string]any{"kty": "EC", "crv": "P-256", "x": x, "y": y},
		Thumbprint: thumbprint,
	}
}

// Proof signs a proof for a request with method htm to htu, issued at iat, with a fresh jti, and
// carrying nonce when it is not empty.
func (k Key) Proof(t testing.TB, htm, htu string, iat time.Time, nonce string) string {
	t.Helper()
	claims := map[string]any{"jti": NewJTI(t), "htm": htm, "htu": htu, "iat": iat.Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return k.Sign(t, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": k.JWK}, claims)
}

// ResourceProof signs a proof for a request with method htm to htu at a resource, issued at iat,
// with a fresh jti and the ath of accessToken (RFC 9449 section 7.1), and no nonce.
func (k Key) ResourceProof(t testing.TB, htm, htu string, iat time.Time, accessToken string) string {
	t.Helper()
	return k.Sign(t, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": k.JWK},
		map[string]any{"jti": NewJTI(t), "htm": htm, "htu": htu, "iat": iat.Unix(), "ath": ATH(accessToken)})
}

// ATH is the ath of accessToken as RFC 9449 section 4.2 defines it: the base64url encoding, without
// padding, of the SHA-256 hash of the token's ASCII characters.
func ATH(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return b64(sum[:])
}

// Sign signs header and claims exactly as given, ES256 with k, for a proof Proof does not build.
func (k Key) Sign(t testing.TB, header, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("dpoptest: the header does not encode: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("dpoptest: the claims do not encode: %v", err)
	}
	input := b64(headerJSON) + "." + b64(claimsJSON)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatalf("dpoptest: signing failed: %v", err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + b64(signature)
}

// NewJTI returns a random proof identifier.
func NewJTI(t testing.TB) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("dpoptest: no randomness: %v", err)
	}
	return hex.EncodeToString(b)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(t testing.TB, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("dpoptest: %q is not base64url: %v", s, err)
	}
	return b
}
