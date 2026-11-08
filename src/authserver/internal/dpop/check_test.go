package dpop_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/dpop"
)

// Thumbprints computed apart from this package: the RFCs' own for their keys, and for the
// testdata keys SHA-256 over RFC 7638's members as openssl prints them.
const (
	rfcRSAThumbprint     = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" // RFC 7638 section 3.1
	rfcEd25519Thumbprint = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" // RFC 8037 appendix A.3
	rfc9449Thumbprint    = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" // RFC 9449 section 6.1
	rfcP256Thumbprint    = "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s"
	p384Thumbprint       = "-EEJ6noQQxLWzgHYtDp1XqDacNbAw0h-dfW_ljLE7ws"
	p521Thumbprint       = "mqi1DbCI8fDuAOitqhQTKvbOjUuOhABFxgP_SzrLriM"
	rsa8192Thumbprint    = "QhJGlLgkDWMKQe_3vDN2o40SEE_CF3NIcr9Rk3E3a0Q"
)

func requireAccepted(t *testing.T, c *dpop.Checker, req dpop.Request) *dpop.Proof {
	t.Helper()
	p, err := c.Check(req)
	require.NoError(t, err)
	require.NotNil(t, p)
	return p
}

func requireInvalid(t *testing.T, c *dpop.Checker, req dpop.Request) {
	t.Helper()
	p, err := c.Check(req)
	require.ErrorIs(t, err, dpop.ErrInvalidProof)
	require.NotErrorIs(t, err, dpop.ErrNonceRequired)
	require.Nil(t, p)
}

func requireNonceRequired(t *testing.T, c *dpop.Checker, req dpop.Request) {
	t.Helper()
	p, err := c.Check(req)
	require.ErrorIs(t, err, dpop.ErrNonceRequired)
	require.NotErrorIs(t, err, dpop.ErrInvalidProof)
	require.Nil(t, p)
}

func TestSigningAlgorithms_IsTheFixedList(t *testing.T) {
	want := []string{"ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512",
		"Ed25519", "EdDSA"}
	require.Equal(t, want, dpop.SigningAlgorithms())

	// The list is the caller's copy: changing it changes nothing the checker accepts.
	algs := dpop.SigningAlgorithms()
	algs[0] = "HS256"
	assert.Equal(t, want, dpop.SigningAlgorithms())
}

// RFC 9449's own example proofs, at the moment they were made, pass with the thumbprint the RFC
// gives, and the second with the ath of the access token beside it.
func TestCheck_AcceptsRFC9449sExampleProofs(t *testing.T) {
	tokenProof := "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
	p := requireAccepted(t, newChecker(t, "https://server.example.com"), dpop.Request{
		Proofs: []string{tokenProof}, Method: "POST", Path: "/token", Now: time.Unix(1562262616, 0),
	})
	assert.Equal(t, &dpop.Proof{
		Thumbprint: rfc9449Thumbprint,
		JTI:        "-BwC3ESc6acc2lTc",
		HTU:        "https://server.example.com/token",
		IssuedAt:   time.Unix(1562262616, 0),
	}, p)

	resourceProof := "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA"
	resource := newChecker(t, "https://resource.example.org")
	req := dpop.Request{
		Proofs: []string{resourceProof}, Method: "GET", Path: "/protectedresource",
		AccessToken: "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU", Now: time.Unix(1562262618, 0),
	}
	p = requireAccepted(t, resource, req)
	assert.Equal(t, rfc9449Thumbprint, p.Thumbprint)
	assert.Equal(t, "e1j3V_bKic8-LAEB", p.JTI)

	// The same proof beside another access token, or at another method, is not this request's.
	other := req
	other.AccessToken = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxV"
	requireInvalid(t, resource, other)
	other = req
	other.Method = "POST"
	requireInvalid(t, resource, other)
}

// Every algorithm on the list is accepted, with its key's RFC 7638 thumbprint.
func TestCheck_AcceptsEveryListedAlgorithm(t *testing.T) {
	tests := []struct {
		alg        string
		key        func(t *testing.T) testKey
		thumbprint string
	}{
		{"ES256", rfcP256Key, rfcP256Thumbprint},
		{"ES384", func(t *testing.T) testKey { return pemECKey(t, "p384.pem", "ES384", "P-384", 48) }, p384Thumbprint},
		{"ES512", func(t *testing.T) testKey { return pemECKey(t, "p521.pem", "ES512", "P-521", 66) }, p521Thumbprint},
		{"PS256", func(t *testing.T) testKey { return rfcRSAKey(t, "PS256") }, rfcRSAThumbprint},
		{"PS384", func(t *testing.T) testKey { return rfcRSAKey(t, "PS384") }, rfcRSAThumbprint},
		{"PS512", func(t *testing.T) testKey { return rfcRSAKey(t, "PS512") }, rfcRSAThumbprint},
		{"RS256", func(t *testing.T) testKey { return rfcRSAKey(t, "RS256") }, rfcRSAThumbprint},
		{"RS384", func(t *testing.T) testKey { return rfcRSAKey(t, "RS384") }, rfcRSAThumbprint},
		{"RS512", func(t *testing.T) testKey { return rfcRSAKey(t, "RS512") }, rfcRSAThumbprint},
		{"Ed25519", func(t *testing.T) testKey { return rfcEd25519Key(t, "Ed25519") }, rfcEd25519Thumbprint},
		{"EdDSA", func(t *testing.T) testKey { return rfcEd25519Key(t, "EdDSA") }, rfcEd25519Thumbprint},
	}
	c := newChecker(t, publicBaseURL)
	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			p := requireAccepted(t, c, tokenRequest(buildProof(t, tt.key(t), nil, nil)))
			assert.Equal(t, tt.thumbprint, p.Thumbprint)
		})
	}
}

// The thumbprint is RFC 7638's: the required members only, so a JWK's other members, as in RFC
// 7638's own example key, leave it unchanged.
func TestCheck_ThumbprintTakesTheRequiredMembersOnly(t *testing.T) {
	k := rfcRSAKey(t, "RS256").withJWK(map[string]any{"alg": "RS256", "kid": "2011-04-29", "use": "sig"})
	p := requireAccepted(t, newChecker(t, publicBaseURL), tokenRequest(buildProof(t, k, nil, nil)))
	assert.Equal(t, rfcRSAThumbprint, p.Thumbprint)
}

func TestCheck_ReturnsTheProofsFacts(t *testing.T) {
	proof := buildProof(t, rfcP256Key(t), nil, map[string]any{
		"htu": "HTTPS://Auth.Example.COM:443/auth/./token?state=1#frag", "iat": now.Unix() - 30,
	})
	p := requireAccepted(t, newChecker(t, publicBaseURL), tokenRequest(proof))
	assert.Equal(t, &dpop.Proof{
		Thumbprint: rfcP256Thumbprint,
		JTI:        testJTI,
		HTU:        "https://auth.example.com/auth/token",
		IssuedAt:   time.Unix(now.Unix()-30, 0),
	}, p)
}

func TestCheck_RSAKeysMustBe2048To8192Bits(t *testing.T) {
	c := newChecker(t, publicBaseURL)

	t.Run("2048 bits", func(t *testing.T) {
		requireAccepted(t, c, tokenRequest(buildProof(t, rfcRSAKey(t, "RS256"), nil, nil)))
	})
	t.Run("8192 bits", func(t *testing.T) {
		p := requireAccepted(t, c, tokenRequest(buildProof(t, pemRSAKey(t, "rsa8192.pem", "RS256"), nil, nil)))
		assert.Equal(t, rsa8192Thumbprint, p.Thumbprint)
	})
	for _, name := range []string{"rsa1024.pem", "rsa2047.pem", "rsa8200.pem"} {
		t.Run(name, func(t *testing.T) {
			for _, alg := range []string{"RS256", "PS256"} {
				requireInvalid(t, c, tokenRequest(buildProof(t, pemRSAKey(t, name, alg), nil, nil)))
			}
		})
	}
}

// The key's type, and an EC or OKP key's curve, must be the ones the algorithm names.
func TestCheck_RefusesAKeyThatDoesNotMatchItsAlgorithm(t *testing.T) {
	ed448 := testKey{
		alg: "EdDSA",
		jwk: map[string]any{"kty": "OKP", "crv": "Ed448", "x": b64(make([]byte, 57))},
		sign: func(*testing.T, string, []byte) []byte {
			return make([]byte, 114)
		},
	}
	// RFC 8037 appendix A.6's X25519 public key.
	x25519 := testKey{
		alg:  "EdDSA",
		jwk:  map[string]any{"kty": "OKP", "crv": "X25519", "x": "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"},
		sign: func(*testing.T, string, []byte) []byte { return make([]byte, 64) },
	}
	tests := []struct {
		name string
		key  func(t *testing.T) testKey
		alg  string
	}{
		{"an RSA key under ES256", func(t *testing.T) testKey { return rfcRSAKey(t, "RS256") }, "ES256"},
		{"a P-384 key under ES256", func(t *testing.T) testKey { return pemECKey(t, "p384.pem", "ES384", "P-384", 48) }, "ES256"},
		{"a P-256 key under ES384", rfcP256Key, "ES384"},
		{"a P-521 key under ES384", func(t *testing.T) testKey { return pemECKey(t, "p521.pem", "ES512", "P-521", 66) }, "ES384"},
		{"an Ed448 key under EdDSA", func(*testing.T) testKey { return ed448 }, "EdDSA"},
		{"an Ed448 key under Ed25519", func(*testing.T) testKey { return ed448 }, "Ed25519"},
		{"an X25519 key under EdDSA", func(*testing.T) testKey { return x25519 }, "EdDSA"},
		// The Ed25519 key itself, signing validly, so only its crv refuses it.
		{"an Ed25519 key labelled X25519 under EdDSA", func(t *testing.T) testKey {
			return rfcEd25519Key(t, "EdDSA").withJWK(map[string]any{"crv": "X25519"})
		}, "EdDSA"},
		{"an Ed25519 key labelled Ed448 under Ed25519", func(t *testing.T) testKey {
			return rfcEd25519Key(t, "Ed25519").withJWK(map[string]any{"crv": "Ed448"})
		}, "Ed25519"},
		{"an EC key under RS256", rfcP256Key, "RS256"},
		{"an EC key under PS256", rfcP256Key, "PS256"},
		{"an EC key under EdDSA", rfcP256Key, "EdDSA"},
		{"an Ed25519 key under ES256", func(t *testing.T) testKey { return rfcEd25519Key(t, "EdDSA") }, "ES256"},
		{"an Ed25519 key under RS256", func(t *testing.T) testKey { return rfcEd25519Key(t, "EdDSA") }, "RS256"},
		{"an RSA key under EdDSA", func(t *testing.T) testKey { return rfcRSAKey(t, "RS256") }, "EdDSA"},
		{"a P-256 key labelled P-384 under ES256", func(t *testing.T) testKey {
			return rfcP256Key(t).withJWK(map[string]any{"crv": "P-384"})
		}, "ES256"},
		{"a P-256 key labelled P-384 under ES384", func(t *testing.T) testKey {
			return rfcP256Key(t).withJWK(map[string]any{"crv": "P-384"})
		}, "ES384"},
	}
	c := newChecker(t, publicBaseURL)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireInvalid(t, c, tokenRequest(buildProof(t, tt.key(t), map[string]any{"alg": tt.alg}, nil)))
		})
	}
}

// none, every symmetric algorithm and anything else off the list is refused, whatever the key.
func TestCheck_RefusesAlgorithmsOffTheList(t *testing.T) {
	c := newChecker(t, publicBaseURL)
	k := rfcP256Key(t)
	for _, alg := range []any{"none", "HS256", "HS384", "HS512", "ES256K", "RSA-OAEP", "Ed448", "es256", "ES256 ",
		"", absent, 256, nil} {
		t.Run(strings.TrimSpace(strings.ReplaceAll(toString(alg), " ", "_")), func(t *testing.T) {
			requireInvalid(t, c, tokenRequest(buildProof(t, k, map[string]any{"alg": alg}, nil)))
		})
	}

	t.Run("an unsigned proof", func(t *testing.T) {
		signed := buildProof(t, k, map[string]any{"alg": "none"}, nil)
		requireInvalid(t, c, tokenRequest(signed[:strings.LastIndex(signed, ".")+1]))
	})

	t.Run("HS256 with an oct key", func(t *testing.T) {
		oct := testKey{
			alg:  "HS256",
			jwk:  map[string]any{"kty": "oct", "k": b64([]byte("a shared secret of thirty-two by"))},
			sign: func(*testing.T, string, []byte) []byte { return make([]byte, 32) },
		}
		requireInvalid(t, c, tokenRequest(buildProof(t, oct, nil, nil)))
	})
}

func toString(v any) string {
	switch v := v.(type) {
	case string:
		if v == "" {
			return "empty"
		}
		return v
	case nil:
		return "null"
	case int:
		return "number"
	case []any:
		return "an array"
	}
	return "absent"
}

// The jwk must be a public key: a private member, or a symmetric key, is refused (RFC 9449
// section 4.3 check 7).
func TestCheck_RefusesAPrivateOrSymmetricKey(t *testing.T) {
	c := newChecker(t, publicBaseURL)
	tests := []struct {
		name string
		key  func(t *testing.T) testKey
	}{
		{"an EC key with d", func(t *testing.T) testKey {
			return rfcP256Key(t).withJWK(map[string]any{"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"})
		}},
		{"an OKP key with d", func(t *testing.T) testKey {
			return rfcEd25519Key(t, "EdDSA").withJWK(map[string]any{"d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"})
		}},
		{"an EC key labelled oct", func(t *testing.T) testKey {
			return rfcP256Key(t).withJWK(map[string]any{"kty": "oct", "k": "c2VjcmV0"})
		}},
	}
	for _, member := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		tests = append(tests, struct {
			name string
			key  func(t *testing.T) testKey
		}{"an RSA key with " + member, func(t *testing.T) testKey {
			return rfcRSAKey(t, "RS256").withJWK(map[string]any{member: "AQAB"})
		}})
	}
	tests = append(tests, struct {
		name string
		key  func(t *testing.T) testKey
	}{"an RSA key with oth", func(t *testing.T) testKey {
		return rfcRSAKey(t, "RS256").withJWK(map[string]any{"oth": []any{map[string]any{"r": "AQAB"}}})
	}})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireInvalid(t, c, tokenRequest(buildProof(t, tt.key(t), nil, nil)))
		})
	}
}

// A key whose members are not a well-formed key of its type is refused: an EC point off its curve,
// a coordinate of the wrong length or not in canonical base64url, an RSA modulus or exponent that
// is not minimal or not usable.
func TestCheck_RefusesAMalformedKey(t *testing.T) {
	c := newChecker(t, publicBaseURL)
	p256 := rfcP256Key(t)
	y := unb64(t, p256.jwk["y"].(string))
	y[len(y)-1] ^= 1
	x := unb64(t, p256.jwk["x"].(string))
	// x's last character carries two spare bits; one set leaves the same bytes, encoded
	// non-canonically.
	xLast := p256.jwk["x"].(string)
	nonCanonicalX := xLast[:len(xLast)-1] + string(rune(xLast[len(xLast)-1]+1))
	require.Equal(t, "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D5", nonCanonicalX)

	rsaKey := rfcRSAKey(t, "RS256")
	n := unb64(t, rsaKey.jwk["n"].(string))
	ed := rfcEd25519Key(t, "EdDSA")

	tests := []struct {
		name string
		key  testKey
	}{
		{"a point off its curve", p256.withJWK(map[string]any{"y": b64(y)})},
		{"x one byte short", p256.withJWK(map[string]any{"x": b64(x[1:])})},
		{"x one byte long", p256.withJWK(map[string]any{"x": b64(append([]byte{0}, x...))})},
		{"x not canonical", p256.withJWK(map[string]any{"x": nonCanonicalX})},
		{"x padded", p256.withJWK(map[string]any{"x": p256.jwk["x"].(string) + "="})},
		{"a modulus in standard base64", rsaKey.withJWK(map[string]any{"n": strings.NewReplacer("-", "+", "_", "/").Replace(rsaKey.jwk["n"].(string))})},
		{"x not a string", p256.withJWK(map[string]any{"x": 5})},
		{"no y", p256.withJWK(map[string]any{"y": absent})},
		{"no crv", p256.withJWK(map[string]any{"crv": absent})},
		{"an unknown crv", p256.withJWK(map[string]any{"crv": "secp256k1"})},
		{"no kty", p256.withJWK(map[string]any{"kty": absent})},
		{"kty in lower case", p256.withJWK(map[string]any{"kty": "ec"})},
		{"an RSA modulus with a leading zero", rsaKey.withJWK(map[string]any{"n": b64(append([]byte{0}, n...))})},
		{"an even exponent", rsaKey.withJWK(map[string]any{"e": "AQAA"})},
		{"an exponent of 1", rsaKey.withJWK(map[string]any{"e": "AQ"})},
		{"an exponent with a leading zero", rsaKey.withJWK(map[string]any{"e": "AAEAAQ"})},
		{"an exponent of five bytes", rsaKey.withJWK(map[string]any{"e": "AQAAAAE"})},
		{"no exponent", rsaKey.withJWK(map[string]any{"e": absent})},
		{"no modulus", rsaKey.withJWK(map[string]any{"n": absent})},
		{"an Ed25519 key one byte short", ed.withJWK(map[string]any{"x": b64(make([]byte, 31))})},
		{"an Ed25519 key with no x", ed.withJWK(map[string]any{"x": absent})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireInvalid(t, c, tokenRequest(buildProof(t, tt.key, nil, nil)))
		})
	}

	for _, jwk := range []any{absent, "a key", nil, []any{}, 5} {
		t.Run("a jwk that is "+toString(jwk), func(t *testing.T) {
			requireInvalid(t, c, tokenRequest(buildProof(t, p256, map[string]any{"jwk": jwk}, nil)))
		})
	}
}

func TestCheck_RefusesABadSignature(t *testing.T) {
	c := newChecker(t, publicBaseURL)
	k := rfcP256Key(t)
	good := buildProof(t, k, nil, nil)
	segments := strings.Split(good, ".")

	t.Run("a payload changed after signing", func(t *testing.T) {
		changed := buildProof(t, k, nil, map[string]any{"jti": "another"})
		requireInvalid(t, c, tokenRequest(segments[0]+"."+strings.Split(changed, ".")[1]+"."+segments[2]))
	})
	t.Run("signed by another key", func(t *testing.T) {
		other := ed25519TestKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), "EdDSA")
		header := mustHeaderJSON(t, rfcEd25519Key(t, "EdDSA"))
		requireInvalid(t, c, tokenRequest(signRaw(t, other, header,
			`{"jti":"j","htm":"POST","htu":"`+tokenHTU+`","iat":1800000000}`)))
	})
	t.Run("a signature one byte short", func(t *testing.T) {
		sig := unb64(t, segments[2])
		requireInvalid(t, c, tokenRequest(segments[0]+"."+segments[1]+"."+b64(sig[:len(sig)-1])))
	})
	t.Run("a signature one byte long", func(t *testing.T) {
		sig := unb64(t, segments[2])
		requireInvalid(t, c, tokenRequest(segments[0]+"."+segments[1]+"."+b64(append(sig, 0))))
	})
	t.Run("an empty signature", func(t *testing.T) {
		requireInvalid(t, c, tokenRequest(segments[0]+"."+segments[1]+"."))
	})
	t.Run("an ES256 signature in DER", func(t *testing.T) {
		sig := unb64(t, segments[2])
		der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])})
		require.NoError(t, err)
		requireInvalid(t, c, tokenRequest(segments[0]+"."+segments[1]+"."+b64(der)))
	})
	t.Run("a PS256 signature whose salt is not the hash's length", func(t *testing.T) {
		// RFC 7518 section 3.5: the salt is as long as the hash's output.
		priv, ok := readPEMKey(t, "rsa8192.pem").(*rsa.PrivateKey)
		require.True(t, ok)
		k := rsaTestKey(t, priv, "PS256")
		k.sign = func(t *testing.T, _ string, input []byte) []byte {
			sig, err := rsa.SignPSS(rand.Reader, priv, hashFor(t, "PS256"), digest(t, "PS256", input),
				&rsa.PSSOptions{SaltLength: 20})
			require.NoError(t, err)
			return sig
		}
		requireInvalid(t, c, tokenRequest(buildProof(t, k, nil, nil)))
	})
	t.Run("an RS256 proof signed as PS256", func(t *testing.T) {
		k := rfcRSAKey(t, "PS256")
		h := mustHeaderJSON(t, k)
		h = strings.Replace(h, `"alg":"PS256"`, `"alg":"RS256"`, 1)
		input := b64([]byte(h)) + "." + b64([]byte(`{"jti":"j","htm":"POST","htu":"`+tokenHTU+`","iat":1800000000}`))
		requireInvalid(t, c, tokenRequest(input+"."+b64(k.sign(t, "PS256", []byte(input)))))
	})
}

func mustHeaderJSON(t *testing.T, k testKey) string {
	t.Helper()
	segments := strings.Split(buildProof(t, k, nil, nil), ".")
	return string(unb64(t, segments[0]))
}

// typ is compared as a media type: case-insensitively, with or without application/ (RFC 7515
// section 4.1.9).
func TestCheck_TypIsDPoPJWTAsAMediaType(t *testing.T) {
	c := newChecker(t, publicBaseURL)
	k := rfcP256Key(t)
	for _, typ := range []string{"dpop+jwt", "application/dpop+jwt", "DPoP+JWT", "APPLICATION/DPOP+JWT", "Application/dpop+JWT"} {
		t.Run(typ, func(t *testing.T) {
			requireAccepted(t, c, tokenRequest(buildProof(t, k, map[string]any{"typ": typ}, nil)))
		})
	}
	for _, typ := range []any{absent, "JWT", "jwt", "at+jwt", "application/at+jwt", "application/jwt", "logout+jwt",
		"dpop", "dpop+jwt ", " dpop+jwt", "application/dpop+jwt; charset=utf-8", "text/dpop+jwt", "", 1, nil} {
		t.Run("refused "+toString(typ), func(t *testing.T) {
			requireInvalid(t, c, tokenRequest(buildProof(t, k, map[string]any{"typ": typ}, nil)))
		})
	}
}

// jti, htm, htu and iat are required, each of its JSON type (RFC 9449 section 4.2).
func TestCheck_RequiresTheProofsClaims(t *testing.T) {
	c := newChecker(t, publicBaseURL)
	k := rfcP256Key(t)
	tests := []struct {
		name   string
		claims map[string]any
	}{
		{"no jti", map[string]any{"jti": absent}},
		{"an empty jti", map[string]any{"jti": ""}},
		{"a numeric jti", map[string]any{"jti": 5}},
		{"a null jti", map[string]any{"jti": nil}},
		{"no htm", map[string]any{"htm": absent}},
		{"a null htm", map[string]any{"htm": nil}},
		{"an array htm", map[string]any{"htm": []any{"POST"}}},
		{"no htu", map[string]any{"htu": absent}},
		{"a null htu", map[string]any{"htu": nil}},
		{"no iat", map[string]any{"iat": absent}},
		{"an iat in a string", map[string]any{"iat": "1800000000"}},
		{"a null iat", map[string]any{"iat": nil}},
		{"a boolean iat", map[string]any{"iat": true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireInvalid(t, c, tokenRequest(buildProof(t, k, nil, tt.claims)))
		})
	}

	header := mustHeaderJSON(t, k)
	for name, payload := range map[string]string{
		"a payload that is an array":  `["jti","htm","htu","iat"]`,
		"a payload that is null":      `null`,
		"a claim name in other case":  `{"JTI":"j","htm":"POST","htu":"` + tokenHTU + `","iat":1800000000}`,
		"a payload that is not JSON":  `{"jti":"j",`,
		"an iat that is out of range": `{"jti":"j","htm":"POST","htu":"` + tokenHTU + `","iat":1e400}`,
	} {
		t.Run(name, func(t *testing.T) {
			requireInvalid(t, c, tokenRequest(signRaw(t, k, header, payload)))
		})
	}

	t.Run("a header member name in other case", func(t *testing.T) {
		h := strings.Replace(header, `"typ"`, `"TYP"`, 1)
		requireInvalid(t, c, tokenRequest(signRaw(t, k, h, `{"jti":"j","htm":"POST","htu":"`+tokenHTU+`","iat":1800000000}`)))
	})
}

// htm must equal the request's method exactly.
func TestCheck_HTMMustBeTheRequestsMethod(t *testing.T) {
	c := newChecker(t, publicBaseURL)
	k := rfcP256Key(t)
	for _, htm := range []string{"post", "Post", "GET", "POST ", "PUT"} {
		t.Run(htm, func(t *testing.T) {
			requireInvalid(t, c, tokenRequest(buildProof(t, k, nil, map[string]any{"htm": htm})))
		})
	}
	get := tokenRequest(buildProof(t, k, nil, map[string]any{"htm": "GET"}))
	get.Method = "GET"
	requireAccepted(t, c, get)
}

// htu must name the public base URL followed by the request's path, the two compared after RFC
// 3986 syntax-based and scheme-based normalization, query and fragment ignored (#42 decision 6).
func TestCheck_HTUMustNameThePublicBaseURLAndTheRequestsPath(t *testing.T) {
	k := rfcP256Key(t)
	accepted := []struct {
		name    string
		baseURL string
		path    string
		htu     string
		want    string
	}{
		{"exactly", publicBaseURL, tokenPath, "https://auth.example.com/auth/token", "https://auth.example.com/auth/token"},
		{"scheme and host in upper case", publicBaseURL, tokenPath, "HTTPS://AUTH.Example.COM/auth/token", "https://auth.example.com/auth/token"},
		{"the default port", publicBaseURL, tokenPath, "https://auth.example.com:443/auth/token", "https://auth.example.com/auth/token"},
		{"an empty port", publicBaseURL, tokenPath, "https://auth.example.com:/auth/token", "https://auth.example.com/auth/token"},
		{"dot segments", publicBaseURL, tokenPath, "https://auth.example.com/./auth/x/../token", "https://auth.example.com/auth/token"},
		{"a dot-dot above the root", publicBaseURL, tokenPath, "https://auth.example.com/../auth/token", "https://auth.example.com/auth/token"},
		{"an unreserved character percent-encoded", publicBaseURL, tokenPath, "https://auth.example.com/%61uth/t%6Fken", "https://auth.example.com/auth/token"},
		{"a query", publicBaseURL, tokenPath, "https://auth.example.com/auth/token?client_id=a", "https://auth.example.com/auth/token"},
		{"a fragment", publicBaseURL, tokenPath, "https://auth.example.com/auth/token#top", "https://auth.example.com/auth/token"},
		{"an empty query and fragment", publicBaseURL, tokenPath, "https://auth.example.com/auth/token?#", "https://auth.example.com/auth/token"},
		{"a percent-encoding in lower case", publicBaseURL, "/api/v1/users/a%2Fb", "https://auth.example.com/api/v1/users/a%2fb", "https://auth.example.com/api/v1/users/a%2Fb"},
		{"an empty path", publicBaseURL, "/", "https://auth.example.com", "https://auth.example.com/"},
		{"http's default port", "http://localhost:80", tokenPath, "http://LOCALHOST/auth/token", "http://localhost/auth/token"},
		{"a port other than the default", "http://localhost:9090", tokenPath, "http://localhost:9090/auth/token", "http://localhost:9090/auth/token"},
		{"a base URL naming the default port", "https://auth.example.com:443", tokenPath, "https://auth.example.com/auth/token", "https://auth.example.com/auth/token"},
		{"a base URL in upper case", "HTTPS://AUTH.EXAMPLE.COM", tokenPath, "https://auth.example.com/auth/token", "https://auth.example.com/auth/token"},
		{"a base URL carrying a path", "https://example.com/goiabada", tokenPath, "https://example.com/goiabada/auth/token", "https://example.com/goiabada/auth/token"},
		{"an IPv6 host", "https://[2001:DB8::1]:8443", tokenPath, "https://[2001:db8::1]:8443/auth/token", "https://[2001:db8::1]:8443/auth/token"},
	}
	for _, tt := range accepted {
		t.Run(tt.name, func(t *testing.T) {
			req := tokenRequest(buildProof(t, k, nil, map[string]any{"htu": tt.htu}))
			req.Path = tt.path
			p := requireAccepted(t, newChecker(t, tt.baseURL), req)
			assert.Equal(t, tt.want, p.HTU)
		})
	}

	refused := []struct {
		name    string
		baseURL string
		htu     any
	}{
		{"another scheme", publicBaseURL, "http://auth.example.com/auth/token"},
		{"another host", publicBaseURL, "https://other.example.com/auth/token"},
		{"a subdomain", publicBaseURL, "https://a.auth.example.com/auth/token"},
		{"another port", publicBaseURL, "https://auth.example.com:8443/auth/token"},
		{"another path", publicBaseURL, "https://auth.example.com/auth/revoke"},
		{"a trailing slash", publicBaseURL, "https://auth.example.com/auth/token/"},
		{"a path in other case", publicBaseURL, "https://auth.example.com/auth/Token"},
		{"a reserved character percent-encoded", publicBaseURL, "https://auth.example.com/auth%2Ftoken"},
		{"the path alone", publicBaseURL, "/auth/token"},
		{"no scheme", publicBaseURL, "auth.example.com/auth/token"},
		{"a scheme-relative URL", publicBaseURL, "//auth.example.com/auth/token"},
		{"another scheme altogether", publicBaseURL, "ftp://auth.example.com/auth/token"},
		{"userinfo", publicBaseURL, "https://user@auth.example.com/auth/token"},
		{"an empty host", publicBaseURL, "https:///auth/token"},
		{"a broken percent-encoding", publicBaseURL, "https://auth.example.com/auth/%zztoken"},
		{"a truncated percent-encoding", publicBaseURL, "https://auth.example.com/auth/token%2"},
		{"a space", publicBaseURL, "https://auth.example.com/auth/token "},
		{"a non-numeric port", publicBaseURL, "https://auth.example.com:https/auth/token"},
		{"an empty htu", publicBaseURL, ""},
		{"the internal base URL", publicBaseURL, "http://goiabada-authserver:9090/auth/token"},
		{"the host without the base URL's path", "https://example.com/goiabada", "https://example.com/auth/token"},
		{"the bare path of a base URL with a path", "https://example.com/goiabada", "/goiabada/auth/token"},
	}
	for _, tt := range refused {
		t.Run("refused "+tt.name, func(t *testing.T) {
			requireInvalid(t, newChecker(t, tt.baseURL), tokenRequest(buildProof(t, k, nil, map[string]any{"htu": tt.htu})))
		})
	}

	t.Run("refused at another request path", func(t *testing.T) {
		req := tokenRequest(buildProof(t, k, nil, nil))
		req.Path = "/userinfo"
		requireInvalid(t, newChecker(t, publicBaseURL), req)
	})
}

// NewChecker takes only an absolute http or https URL with a host and nothing after its path.
func TestNewChecker_RefusesABaseURLThatCannotNameARequest(t *testing.T) {
	for _, baseURL := range []string{"", "auth.example.com", "/auth", "ftp://auth.example.com", "https://",
		"https://auth.example.com?x=1", "https://auth.example.com#f", "https://user@auth.example.com",
		"https://auth.example.com:port"} {
		t.Run(baseURL, func(t *testing.T) {
			c, err := dpop.NewChecker(baseURL)
			require.Error(t, err)
			assert.Nil(t, c)
		})
	}
}

// ath, when the request carries an access token, must be the base64url SHA-256 of its ASCII
// (RFC 9449 section 4.2).
func TestCheck_ATHMustHashTheAccessTokenWhenOneIsPresented(t *testing.T) {
	c := newChecker(t, publicBaseURL)
	k := rfcP256Key(t)
	accessToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1In0.c2ln"
	sum := sha256.Sum256([]byte(accessToken))
	ath := b64(sum[:])

	withToken := func(proof string) dpop.Request {
		req := tokenRequest(proof)
		req.AccessToken = accessToken
		return req
	}

	requireAccepted(t, c, withToken(buildProof(t, k, nil, map[string]any{"ath": ath})))

	otherSum := sha256.Sum256([]byte(accessToken + "x"))
	for name, value := range map[string]any{
		"no ath":                   absent,
		"another token's hash":     b64(otherSum[:]),
		"the hash padded":          ath + "=",
		"the hash in hex":          hex.EncodeToString(sum[:]),
		"the token itself":         accessToken,
		"a numeric ath":            5,
		"an empty ath":             "",
		"the hash in standard b64": strings.NewReplacer("-", "+", "_", "/").Replace(ath) + "+",
	} {
		t.Run(name, func(t *testing.T) {
			requireInvalid(t, c, withToken(buildProof(t, k, nil, map[string]any{"ath": value})))
		})
	}

	// Without an access token, as at the token endpoint, ath is not asked for and is not read.
	requireAccepted(t, c, tokenRequest(buildProof(t, k, nil, map[string]any{"ath": "anything"})))
}

// Without a nonce check, iat must lie within 60 seconds either side of the server's clock.
func TestCheck_IATMustBeWithinAMinuteOfTheServersClock(t *testing.T) {
	c := newChecker(t, publicBaseURL)
	k := rfcP256Key(t)
	for _, offset := range []float64{-60, -59.5, 0, 59.75, 60} {
		requireAccepted(t, c, tokenRequest(buildProof(t, k, nil, map[string]any{"iat": float64(now.Unix()) + offset})))
	}
	for _, offset := range []float64{-61, -60.25, 60.25, 61, -3600, 3600} {
		requireInvalid(t, c, tokenRequest(buildProof(t, k, nil, map[string]any{"iat": float64(now.Unix()) + offset})))
	}

	// The window is measured from the clock to the instant, fractions of a second included.
	req := tokenRequest(buildProof(t, k, nil, map[string]any{"iat": now.Unix() - 60}))
	req.Now = now.Add(500 * time.Millisecond)
	requireInvalid(t, c, req)
	req = tokenRequest(buildProof(t, k, nil, map[string]any{"iat": now.Unix() + 60}))
	req.Now = now.Add(-500 * time.Millisecond)
	requireInvalid(t, c, req)

	// A fractional iat is a NumericDate too.
	p := requireAccepted(t, c, tokenRequest(buildProof(t, k, nil, map[string]any{"iat": float64(now.Unix()) + 0.25})))
	assert.Equal(t, now.Add(250*time.Millisecond), p.IssuedAt)

	// A nonce claim is not read when freshness comes from iat.
	requireAccepted(t, c, tokenRequest(buildProof(t, k, nil, map[string]any{"nonce": "anything"})))
}

// With a nonce check, freshness comes from the nonce alone: iat must be a number, but is not
// compared with the clock. A missing or unaccepted nonce is answered use_dpop_nonce, and only once
// every other check has passed.
func TestCheck_NonceMakesTheProofFresh(t *testing.T) {
	c := newChecker(t, publicBaseURL)
	k := rfcP256Key(t)
	var asked []string
	withNonce := func(proof string) dpop.Request {
		req := tokenRequest(proof)
		req.NonceIsValid = func(nonce string) bool {
			asked = append(asked, nonce)
			return nonce == "minted-by-the-server"
		}
		return req
	}

	for _, iat := range []any{now.Unix() - 3600, now.Unix() + 3600, 1, 0, -5, 1.5} {
		p := requireAccepted(t, c, withNonce(buildProof(t, k, nil, map[string]any{"nonce": "minted-by-the-server", "iat": iat})))
		assert.Equal(t, "minted-by-the-server", p.Nonce)
	}
	assert.Contains(t, asked, "minted-by-the-server")

	for name, nonce := range map[string]any{
		"no nonce":             absent,
		"a nonce not accepted": "minted-elsewhere",
		"an empty nonce":       "",
	} {
		t.Run(name, func(t *testing.T) {
			requireNonceRequired(t, c, withNonce(buildProof(t, k, nil, map[string]any{"nonce": nonce, "iat": now.Unix() - 3600})))
		})
	}

	for name, claims := range map[string]map[string]any{
		"a numeric nonce":                {"nonce": 5},
		"a null nonce":                   {"nonce": nil},
		"no iat":                         {"nonce": "minted-by-the-server", "iat": absent},
		"an iat in a string":             {"nonce": "minted-by-the-server", "iat": "1800000000"},
		"no nonce and another htu":       {"nonce": absent, "htu": "https://other.example.com/auth/token"},
		"no nonce and another method":    {"nonce": absent, "htm": "GET"},
		"a stale nonce and no jti":       {"nonce": "minted-elsewhere", "jti": absent},
		"an accepted nonce, another htu": {"nonce": "minted-by-the-server", "htu": "https://other.example.com/auth/token"},
	} {
		t.Run("invalid with "+name, func(t *testing.T) {
			requireInvalid(t, c, withNonce(buildProof(t, k, nil, claims)))
		})
	}

	t.Run("invalid with no nonce and a bad signature", func(t *testing.T) {
		segments := strings.Split(buildProof(t, k, nil, nil), ".")
		requireInvalid(t, c, withNonce(segments[0]+"."+segments[1]+"."+b64(make([]byte, 64))))
	})
}

// One DPoP header, of at most 8 KiB, holding one compact JWS (RFC 9449 section 4.3 checks 1 and 2;
// #42 decision 9's cap).
func TestCheck_OneProofOfAtMost8KiB(t *testing.T) {
	c := newChecker(t, publicBaseURL)
	k := rfcP256Key(t)
	good := buildProof(t, k, nil, nil)

	requireInvalid(t, c, tokenRequest())
	requireInvalid(t, c, tokenRequest(good, good))
	requireInvalid(t, c, tokenRequest(good, buildProof(t, k, nil, map[string]any{"jti": "another"})))
	requireInvalid(t, c, tokenRequest(""))

	requireAccepted(t, c, tokenRequest(proofOfLength(t, k, dpop.MaxProofBytes)))
	requireInvalid(t, c, tokenRequest(proofOfLength(t, k, dpop.MaxProofBytes+1)))
	assert.Equal(t, 8192, dpop.MaxProofBytes)
}

// proofOfLength returns a valid proof exactly n bytes long, padded with a claim and a header
// member: a segment's base64url is never 1 more than a multiple of 4 long, so the payload alone
// cannot reach every length.
func proofOfLength(t *testing.T, k testKey, n int) string {
	t.Helper()
	for extra := 0; extra < 3; extra++ {
		for pad := 0; pad < n; pad++ {
			p := buildProof(t, k, map[string]any{"kid": strings.Repeat("k", extra)}, map[string]any{"pad": strings.Repeat("a", pad)})
			if len(p) == n {
				return p
			}
			if len(p) > n {
				break
			}
		}
	}
	t.Fatalf("no proof of %d bytes", n)
	return ""
}

// The shared structural check runs on the proof (#709): what it refuses, the proof reader refuses,
// signature valid or not.
func TestCheck_RunsTheSharedStructuralCheck(t *testing.T) {
	c := newChecker(t, publicBaseURL)
	k := rfcP256Key(t)
	claims := `{"jti":"j","htm":"POST","htu":"` + tokenHTU + `","iat":1800000000}`
	header := mustHeaderJSON(t, k)

	requireAccepted(t, c, tokenRequest(signRaw(t, k, header, claims)))

	withMember := func(member string) string {
		return strings.TrimSuffix(header, "}") + "," + member + "}"
	}
	t.Run("an empty crit", func(t *testing.T) {
		requireInvalid(t, c, tokenRequest(signRaw(t, k, withMember(`"crit":[]`), claims)))
	})
	t.Run("a nested JWT's cty", func(t *testing.T) {
		requireInvalid(t, c, tokenRequest(signRaw(t, k, withMember(`"cty":"jwt"`), claims)))
	})
	t.Run("invalid UTF-8 in the payload", func(t *testing.T) {
		requireInvalid(t, c, tokenRequest(signRaw(t, k, header, `{"jti":"j`+"\xff"+`","htm":"POST","htu":"`+tokenHTU+`","iat":1800000000}`)))
	})
	good := signRaw(t, k, header, claims)
	t.Run("padding", func(t *testing.T) {
		requireInvalid(t, c, tokenRequest(good+"="))
	})
	t.Run("a line break", func(t *testing.T) {
		requireInvalid(t, c, tokenRequest(good[:20]+"\r\n"+good[20:]))
	})
	t.Run("four segments", func(t *testing.T) {
		requireInvalid(t, c, tokenRequest(good+".e30"))
	})
	t.Run("an access token's shape", func(t *testing.T) {
		requireInvalid(t, c, tokenRequest(signRaw(t, k, strings.Replace(header, `"dpop+jwt"`, `"at+jwt"`, 1), claims)))
	})
}
