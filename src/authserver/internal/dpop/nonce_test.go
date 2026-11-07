package dpop_test

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/authserver/internal/dpop"
)

// Two auth server instances share a configuration, and so a session authentication key; a third
// has another key, as after a rotation.
var (
	sessionKey      = []byte(strings.Repeat("k", 64))
	otherSessionKey = []byte(strings.Repeat("o", 64))
)

// RFC 9449 section 8.1: a nonce is one or more NQCHAR, %x21 / %x23-5B / %x5D-7E.
var nqchars = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+$`)

func TestNonces_MintAValueAProofCanCarry(t *testing.T) {
	nonce := dpop.NewNonces(sessionKey).Mint(now)

	assert.Regexp(t, nqchars, nonce)
	assert.True(t, dpop.NewNonces(sessionKey).Accepts(nonce, now))
}

// A nonce is good for ten minutes from the moment it was minted, at any instance sharing the key
// (#42 decision 7), and no longer.
func TestNonces_AreGoodForTenMinutes(t *testing.T) {
	nonce := dpop.NewNonces(sessionKey).Mint(now)
	nonces := dpop.NewNonces(sessionKey)

	assert.True(t, nonces.Accepts(nonce, now.Add(10*time.Minute)), "ten minutes on")
	assert.False(t, nonces.Accepts(nonce, now.Add(10*time.Minute+time.Second)), "a second past ten minutes")
	assert.False(t, nonces.Accepts(nonce, now.Add(24*time.Hour)), "a day on")
}

// An instance whose clock is a little behind the one that minted the nonce still takes it, for as
// long as the window the resources allow a proof's iat (#42 decision 8), so a client is not sent
// round a retry loop between two instances; a nonce from further ahead is refused.
func TestNonces_AllowAMinuteOfClockSkewBetweenInstances(t *testing.T) {
	nonce := dpop.NewNonces(sessionKey).Mint(now)
	nonces := dpop.NewNonces(sessionKey)

	assert.True(t, nonces.Accepts(nonce, now.Add(-60*time.Second)), "a minute behind")
	assert.False(t, nonces.Accepts(nonce, now.Add(-61*time.Second)), "more than a minute behind")
}

// Every instance sharing the session authentication key accepts the nonces of the others; under
// another key, as after a rotation, none is accepted (#42 decision 7).
func TestNonces_AreAcceptedOnlyUnderTheKeyThatMintedThem(t *testing.T) {
	nonce := dpop.NewNonces(sessionKey).Mint(now)

	assert.True(t, dpop.NewNonces(sessionKey).Accepts(nonce, now), "an instance sharing the key")
	assert.False(t, dpop.NewNonces(otherSessionKey).Accepts(nonce, now), "an instance under another key")
	assert.Regexp(t, nqchars, dpop.NewNonces(otherSessionKey).Mint(now))
}

// Only a nonce the server minted is accepted: an altered one, a truncated one, one extended or
// re-encoded, and values no server mints are refused.
func TestNonces_RefuseWhatTheServerDidNotMint(t *testing.T) {
	nonces := dpop.NewNonces(sessionKey)
	nonce := nonces.Mint(now)

	flipped := []byte(nonce)
	if flipped[3] == 'A' {
		flipped[3] = 'B'
	} else {
		flipped[3] = 'A'
	}
	lastFlipped := []byte(nonce)
	if lastFlipped[len(lastFlipped)-2] == 'A' {
		lastFlipped[len(lastFlipped)-2] = 'B'
	} else {
		lastFlipped[len(lastFlipped)-2] = 'A'
	}

	for name, value := range map[string]string{
		"empty":                    "",
		"its timestamp altered":    string(flipped),
		"its tag altered":          string(lastFlipped),
		"a character short":        nonce[:len(nonce)-1],
		"a character longer":       nonce + "A",
		"padded":                   nonce + "==",
		"a line break inside":      nonce[:10] + "\n" + nonce[10:],
		"in standard base64":       strings.NewReplacer("-", "+", "_", "/").Replace(nonce) + "+",
		"a value no server mints":  "eyJhbGciOiJub25lIn0",
		"another key's nonce":      dpop.NewNonces(otherSessionKey).Mint(now),
		"a nonce from an hour ago": nonces.Mint(now.Add(-time.Hour)),
		"a nonce from an hour on":  nonces.Mint(now.Add(time.Hour)),
	} {
		t.Run(name, func(t *testing.T) {
			assert.False(t, nonces.Accepts(value, now))
		})
	}
}
