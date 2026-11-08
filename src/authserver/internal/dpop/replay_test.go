package dpop_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/authserver/internal/dpop"
)

// A proof's replay key is the hex SHA-256 of its normalized htu and its jti, a space between them,
// as the replay store keeps it (#42 decision 9). The expected values are sha256sum's, over the text
// RFC 9449 section 4.1's example token-request proof names.
func TestProof_ReplayKeyIsTheHashOfItsHTUAndJTI(t *testing.T) {
	proof := dpop.Proof{HTU: "https://server.example.com/token", JTI: "-BwC3ESc6acc2lTc"}

	assert.Equal(t, "462c64cca02281f55a11dd7d75a15fa32a13d06b1c710a6df24776076741b096", proof.ReplayKey())
}

// One jti names another proof at another URL, and another jti another proof at the same URL. What
// the key does not take, the key, the time, the nonce, does not change it.
func TestProof_ReplayKeyNamesOneProof(t *testing.T) {
	proof := dpop.Proof{HTU: "https://server.example.com/token", JTI: "-BwC3ESc6acc2lTc"}

	otherJTI := proof
	otherJTI.JTI = "e1j3V_bKic8-LAEB"
	assert.Equal(t, "69b6602db2e1dd722034564e95eb594faa180f4750801526675dd9dd73efa893", otherJTI.ReplayKey())

	otherHTU := proof
	otherHTU.HTU = "https://resource.example.org/protectedresource"
	assert.Equal(t, "d54c882d40d7c366d08310571c0f02d3f1c13826389ac9704e8d9c6c3cd9bb2d", otherHTU.ReplayKey())

	sameProof := proof
	sameProof.Thumbprint = "another key"
	sameProof.IssuedAt = time.Unix(1, 0)
	sameProof.Nonce = "another nonce"
	assert.Equal(t, proof.ReplayKey(), sameProof.ReplayKey())
}

// The replay record of a proof at the token endpoint is kept until its nonce expires there: the
// last moment Accepts takes it is ExpiresAt itself, ten minutes after the nonce was minted, and
// a moment later it is refused (#42 decision 8).
func TestNonces_ExpiresAtIsTheLastMomentTheNonceIsAccepted(t *testing.T) {
	nonces := dpop.NewNonces(sessionKey)
	nonce := nonces.Mint(now)

	expiresAt, ok := nonces.ExpiresAt(nonce)

	assert.True(t, ok)
	assert.Equal(t, now.Add(10*time.Minute), expiresAt)
	assert.True(t, nonces.Accepts(nonce, expiresAt), "at its expiry")
	assert.False(t, nonces.Accepts(nonce, expiresAt.Add(time.Nanosecond)), "a moment after it")
	assert.False(t, nonces.Accepts(nonce, expiresAt.Add(500*time.Millisecond)), "half a second after it")
}

// A nonce minted within a second has the expiry of that second's start: the nonce holds whole
// seconds, so the moment it was minted is read as that.
func TestNonces_ExpiresAtReadsTheNoncesWholeSecond(t *testing.T) {
	nonces := dpop.NewNonces(sessionKey)
	nonce := nonces.Mint(now.Add(900 * time.Millisecond))

	expiresAt, ok := nonces.ExpiresAt(nonce)

	assert.True(t, ok)
	assert.Equal(t, now.Add(10*time.Minute), expiresAt)
}

// A value the server did not mint under this key has no expiry.
func TestNonces_ExpiresAtOnlyForTheServersNonces(t *testing.T) {
	nonces := dpop.NewNonces(sessionKey)

	for name, value := range map[string]string{
		"empty":               "",
		"another key's nonce": dpop.NewNonces(otherSessionKey).Mint(now),
		"not a nonce":         "eyJhbGciOiJub25lIn0",
	} {
		t.Run(name, func(t *testing.T) {
			_, ok := nonces.ExpiresAt(value)
			assert.False(t, ok)
		})
	}
}

// At a resource a proof is accepted while its iat lies within the minute either side of the
// server's clock, so its replay record is kept until iat plus 60 seconds, the last moment Check
// takes it (#42 decision 8), rounded up to the whole second so no store's precision can end the
// record before that moment.
func TestProof_IssuedAtWindowEndsSixtySecondsAfterIat(t *testing.T) {
	tests := []struct {
		name     string
		issuedAt time.Time
		want     time.Time
	}{
		{"a whole second", time.Unix(1_800_000_000, 0), time.Unix(1_800_000_060, 0)},
		{"a fraction of a second, rounded up", time.Unix(1_800_000_000, 250_000_000), time.Unix(1_800_000_061, 0)},
		{"a nanosecond past the second", time.Unix(1_800_000_000, 1), time.Unix(1_800_000_061, 0)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, dpop.Proof{IssuedAt: tc.issuedAt}.IssuedAtWindowEnds())
		})
	}
}
