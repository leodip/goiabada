package dpop_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/dpop"
)

// The proofs here are built the way a client builds them, from fixed keys: three published in
// RFCs, with the thumbprints the RFCs give, and the rest generated once with openssl into
// testdata, their thumbprints computed apart from this package, from openssl's own output.

const (
	publicBaseURL = "https://auth.example.com"
	tokenPath     = "/auth/token"
	tokenHTU      = publicBaseURL + tokenPath
	testJTI       = "9a6c3e1f-5b0d-4f7a-8c2e-1d3b5f7a9c0e"
)

// now is the server's clock in every case that does not set its own.
var now = time.Unix(1_800_000_000, 0)

// absent, as a header or claim value, leaves that member out of the proof.
var absent = struct{ absent bool }{true}

// testKey is a client's key pair: the public JWK it puts in its proofs, the algorithm it signs
// with, and how it signs.
type testKey struct {
	alg  string
	jwk  map[string]any
	sign func(t *testing.T, alg string, input []byte) []byte
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

// withJWK returns a copy of k whose JWK has the members given changed, absent removing one.
func (k testKey) withJWK(members map[string]any) testKey {
	jwk := map[string]any{}
	for n, v := range k.jwk {
		jwk[n] = v
	}
	for n, v := range members {
		if v == absent {
			delete(jwk, n)
			continue
		}
		jwk[n] = v
	}
	k.jwk = jwk
	return k
}

func hashFor(t *testing.T, alg string) crypto.Hash {
	t.Helper()
	switch alg[len(alg)-3:] {
	case "256":
		return crypto.SHA256
	case "384":
		return crypto.SHA384
	case "512":
		return crypto.SHA512
	}
	t.Fatalf("no hash for %s", alg)
	return 0
}

func digest(t *testing.T, alg string, input []byte) []byte {
	t.Helper()
	h := hashFor(t, alg).New()
	h.Write(input)
	return h.Sum(nil)
}

func ecTestKey(t *testing.T, priv *ecdsa.PrivateKey, alg, crv string, size int) testKey {
	t.Helper()
	point, err := priv.PublicKey.Bytes()
	require.NoError(t, err)
	require.Len(t, point, 1+2*size)
	return testKey{
		alg: alg,
		jwk: map[string]any{"kty": "EC", "crv": crv, "x": b64(point[1 : 1+size]), "y": b64(point[1+size:])},
		sign: func(t *testing.T, signAlg string, input []byte) []byte {
			t.Helper()
			if !slices.Contains([]string{"ES256", "ES384", "ES512"}, signAlg) {
				signAlg = alg
			}
			r, s, err := ecdsa.Sign(rand.Reader, priv, digest(t, signAlg, input))
			require.NoError(t, err)
			sig := make([]byte, 2*size)
			r.FillBytes(sig[:size])
			s.FillBytes(sig[size:])
			return sig
		},
	}
}

func rsaTestKey(t *testing.T, priv *rsa.PrivateKey, alg string) testKey {
	t.Helper()
	return testKey{
		alg: alg,
		jwk: map[string]any{
			"kty": "RSA",
			"n":   b64(priv.N.Bytes()),
			"e":   b64(big.NewInt(int64(priv.E)).Bytes()),
		},
		sign: func(t *testing.T, signAlg string, input []byte) []byte {
			t.Helper()
			if !slices.Contains([]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}, signAlg) {
				signAlg = alg
			}
			h := hashFor(t, signAlg)
			d := digest(t, signAlg, input)
			if strings.HasPrefix(signAlg, "PS") {
				sig, err := rsa.SignPSS(rand.Reader, priv, h, d,
					&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
				require.NoError(t, err)
				return sig
			}
			sig, err := rsa.SignPKCS1v15(nil, priv, h, d)
			require.NoError(t, err)
			return sig
		},
	}
}

func ed25519TestKey(priv ed25519.PrivateKey, alg string) testKey {
	return testKey{
		alg: alg,
		jwk: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64(priv.Public().(ed25519.PublicKey))},
		sign: func(_ *testing.T, _ string, input []byte) []byte {
			return ed25519.Sign(priv, input)
		},
	}
}

// rfcP256Key is RFC 7517 appendix A.2's EC private key.
func rfcP256Key(t *testing.T) testKey {
	t.Helper()
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), unb64(t, "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"))
	require.NoError(t, err)
	k := ecTestKey(t, priv, "ES256", "P-256", 32)
	require.Equal(t, "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", k.jwk["x"])
	require.Equal(t, "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", k.jwk["y"])
	return k
}

// rfcRSAKey is RFC 7517 appendix A.2's 2048-bit RSA private key, the key whose thumbprint RFC 7638
// section 3.1 works out.
func rfcRSAKey(t *testing.T, alg string) testKey {
	t.Helper()
	n := "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	d := "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q"
	p := "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs"
	q := "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk"
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).SetBytes(unb64(t, n)), E: 65537},
		D:         new(big.Int).SetBytes(unb64(t, d)),
		Primes:    []*big.Int{new(big.Int).SetBytes(unb64(t, p)), new(big.Int).SetBytes(unb64(t, q))},
	}
	require.NoError(t, priv.Validate())
	priv.Precompute()
	k := rsaTestKey(t, priv, alg)
	require.Equal(t, n, k.jwk["n"])
	require.Equal(t, "AQAB", k.jwk["e"])
	return k
}

// rfcEd25519Key is RFC 8037 appendix A.1's Ed25519 private key.
func rfcEd25519Key(t *testing.T, alg string) testKey {
	t.Helper()
	k := ed25519TestKey(ed25519.NewKeyFromSeed(unb64(t, "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")), alg)
	require.Equal(t, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", k.jwk["x"])
	return k
}

func readPEMKey(t *testing.T, name string) any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	return key
}

func pemECKey(t *testing.T, name, alg, crv string, size int) testKey {
	t.Helper()
	priv, ok := readPEMKey(t, name).(*ecdsa.PrivateKey)
	require.True(t, ok)
	return ecTestKey(t, priv, alg, crv, size)
}

func pemRSAKey(t *testing.T, name, alg string) testKey {
	t.Helper()
	priv, ok := readPEMKey(t, name).(*rsa.PrivateKey)
	require.True(t, ok)
	return rsaTestKey(t, priv, alg)
}

func defaultClaims() map[string]any {
	return map[string]any{"jti": testJTI, "htm": "POST", "htu": tokenHTU, "iat": now.Unix()}
}

// buildProof signs a proof with k. header and claims change the defaults, a dpop+jwt header naming
// k's algorithm and key, and a token request's claims at now; absent removes a member.
func buildProof(t *testing.T, k testKey, header, claims map[string]any) string {
	t.Helper()
	h := map[string]any{"typ": "dpop+jwt", "alg": k.alg, "jwk": k.jwk}
	for n, v := range header {
		if v == absent {
			delete(h, n)
			continue
		}
		h[n] = v
	}
	c := defaultClaims()
	for n, v := range claims {
		if v == absent {
			delete(c, n)
			continue
		}
		c[n] = v
	}
	hj, err := json.Marshal(h)
	require.NoError(t, err)
	cj, err := json.Marshal(c)
	require.NoError(t, err)
	return signRaw(t, k, string(hj), string(cj))
}

// signRaw signs the header and payload JSON exactly as given, for what json.Marshal cannot write.
func signRaw(t *testing.T, k testKey, headerJSON, payloadJSON string) string {
	t.Helper()
	input := b64([]byte(headerJSON)) + "." + b64([]byte(payloadJSON))
	var alg struct {
		Alg string `json:"alg"`
	}
	_ = json.Unmarshal([]byte(headerJSON), &alg)
	return input + "." + b64(k.sign(t, alg.Alg, []byte(input)))
}

func newChecker(t *testing.T, baseURL string) *dpop.Checker {
	t.Helper()
	c, err := dpop.NewChecker(baseURL)
	require.NoError(t, err)
	return c
}

// tokenRequest is a token request at now carrying the proofs given, its freshness from iat.
func tokenRequest(proofs ...string) dpop.Request {
	return dpop.Request{Proofs: proofs, Method: "POST", Path: tokenPath, Now: now}
}
