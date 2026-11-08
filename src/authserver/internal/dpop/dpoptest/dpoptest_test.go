package dpoptest_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/dpop"
	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
)

// Each key's thumbprint literal is RFC 7638 section 3's SHA-256 over the required members in
// lexicographic order, written out here as the RFC defines it.
func TestKeys_ThumbprintIsRFC7638s(t *testing.T) {
	for name, key := range map[string]dpoptest.Key{"RFC 7517": dpoptest.RFC7517Key(t), "RFC 7515": dpoptest.RFC7515Key(t)} {
		t.Run(name, func(t *testing.T) {
			canonical := `{"crv":"P-256","kty":"EC","x":"` + key.JWK["x"].(string) + `","y":"` + key.JWK["y"].(string) + `"}`
			sum := sha256.Sum256([]byte(canonical))
			assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), key.Thumbprint)
		})
	}
}

// The proofs this package builds are ones the server's checker accepts, with the key's
// thumbprint.
func TestProof_IsAcceptedByTheChecker(t *testing.T) {
	checker, err := dpop.NewChecker("https://auth.example.com")
	require.NoError(t, err)
	now := time.Unix(1_800_000_000, 0)
	key := dpoptest.RFC7515Key(t)

	proof, err := checker.Check(dpop.Request{
		Proofs: []string{key.Proof(t, "POST", "https://auth.example.com/auth/token", now, "")},
		Method: "POST", Path: "/auth/token", Now: now,
	})
	require.NoError(t, err)
	assert.Equal(t, key.Thumbprint, proof.Thumbprint)
}

// ATH is RFC 9449 section 7.1's example: the access token of figure 13 and the ath its proof
// carries.
func TestATH_IsRFC9449sExample(t *testing.T) {
	assert.Equal(t, "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo", dpoptest.ATH("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"))
}

// A resource proof is one the checker accepts for the access token it names, with no nonce.
func TestResourceProof_IsAcceptedForItsAccessToken(t *testing.T) {
	checker, err := dpop.NewChecker("https://auth.example.com")
	require.NoError(t, err)
	now := time.Unix(1_800_000_000, 0)
	key := dpoptest.RFC7517Key(t)

	proof, err := checker.Check(dpop.Request{
		Proofs: []string{key.ResourceProof(t, "GET", "https://auth.example.com/userinfo", now, "an-access-token")},
		Method: "GET", Path: "/userinfo", AccessToken: "an-access-token", Now: now,
	})
	require.NoError(t, err)
	assert.Equal(t, key.Thumbprint, proof.Thumbprint)
}
