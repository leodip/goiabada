package otp

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rfcKey is the secret of RFC 4226 Appendix D and RFC 6238 Appendix B, the ASCII string
// "12345678901234567890", and rfcKeyBase32 the same twenty bytes as an authenticator is given
// them, which is how MatchStep receives a secret.
const (
	rfcKey       = "12345678901234567890"
	rfcKeyBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
)

// Every expected value below is transcribed from RFC 4226 Appendix D, never computed: the HMAC
// of Table 1, the truncated value of Table 2 and the HOTP value beside it. The HMAC and the
// truncation are pinned apart from the code, so a defect in either is named where it is rather
// than surfacing as a wrong six digits.
func TestHOTP_RFC4226AppendixD(t *testing.T) {
	vectors := []struct {
		hmac      string
		truncated uint32
		code      string
	}{
		{"cc93cf18508d94934c64b65d8ba7667fb7cde4b0", 0x4c93cf18, "755224"},
		{"75a48a19d4cbe100644e8ac1397eea747a2d33ab", 0x41397eea, "287082"},
		{"0bacb7fa082fef30782211938bc1c5e70416ff44", 0x082fef30, "359152"},
		{"66c28227d03a2d5529262ff016a1e6ef76557ece", 0x66ef7655, "969429"},
		{"a904c900a64b35909874b33e61c5938a8e15ed1c", 0x61c5938a, "338314"},
		{"a37e783d7b7233c083d4f62926c7a25f238d0316", 0x33c083d4, "254676"},
		{"bc9cd28561042c83f219324d3c607256c03272ae", 0x7256c032, "287922"},
		{"a4fb960c0bc06e1eabb804e5b397cdc4b45596fa", 0x04e5b397, "162583"},
		{"1b3c89f65e6c9e883012052823443f048b4332db", 0x2823443f, "399871"},
		{"1637409809a679dc698207310c8c7fc07290d9e5", 0x2679dc69, "520489"},
	}

	for count, v := range vectors {
		t.Run(fmt.Sprintf("count %d", count), func(t *testing.T) {
			counter := uint64(count)

			sum := hotpHMAC([]byte(rfcKey), counter)
			assert.Equal(t, v.hmac, hex.EncodeToString(sum), "HMAC-SHA-1, Table 1")
			assert.Equal(t, v.truncated, dynamicTruncation(sum), "truncated value, Table 2")
			assert.Equal(t, v.code, hotpCode([]byte(rfcKey), counter), "HOTP value, Table 2")
		})
	}
}

// RFC 6238 Appendix B, the six SHA-1 rows. The RFC prints eight digits; the profile here is six,
// the low six of the same truncated value, so each code is the RFC's with its first two digits
// dropped. The T column pins the time-to-counter mapping (T0 = 0, X = 30), the last row beyond 32
// bits, and is checked twice: the code at that counter, and MatchStep, given the RFC's instant,
// naming that counter as the step.
func TestTOTP_RFC6238AppendixB(t *testing.T) {
	vectors := []struct {
		unix    int64
		counter uint64
		rfcCode string
	}{
		{59, 0x0000000000000001, "94287082"},
		{1111111109, 0x00000000023523EC, "07081804"},
		{1111111111, 0x00000000023523ED, "14050471"},
		{1234567890, 0x000000000273EF07, "89005924"},
		{2000000000, 0x0000000003F940AA, "69279037"},
		{20000000000, 0x0000000027BC86AA, "65353130"},
	}

	for _, v := range vectors {
		t.Run(fmt.Sprintf("time %d", v.unix), func(t *testing.T) {
			code := v.rfcCode[2:]

			assert.Equal(t, code, hotpCode([]byte(rfcKey), v.counter))

			step, match := MatchStep(code, rfcKeyBase32, time.Unix(v.unix, 0).UTC())
			require.Equal(t, Matched, match, "the RFC's code must be accepted at the RFC's instant")
			assert.Equal(t, int64(v.counter), step, "the step must be the RFC's T")
		})
	}
}

// A secret is read as the library read it, in this order: surrounding whitespace trimmed, padded
// with "=" to a multiple of eight, upper-cased, then decoded with the standard base32 alphabet
// (RFC 4648 section 6). So every secret stored before keeps the key it had, but for one that
// decodes to no key, which is refused.
func TestDecodeSecret(t *testing.T) {
	accepted := []struct{ name, secret string }{
		{"as minted, 32 characters", rfcKeyBase32},
		{"lower case", "gezdgnbvgy3tqojqgezdgnbvgy3tqojq"},
		{"surrounding whitespace", " \t" + rfcKeyBase32 + "\n"},
	}
	for _, c := range accepted {
		t.Run(c.name, func(t *testing.T) {
			key, err := decodeSecret(c.secret)
			require.NoError(t, err)
			assert.Equal(t, []byte(rfcKey), key)
		})
	}

	// "Hello!" is 6 bytes, 10 base32 characters and 6 of padding. Read with or without the
	// padding, it is the same key.
	for _, secret := range []string{"JBSWY3DPEE", "JBSWY3DPEE======"} {
		t.Run("a secret of 6 bytes as "+secret, func(t *testing.T) {
			key, err := decodeSecret(secret)
			require.NoError(t, err)
			assert.Equal(t, []byte("Hello!"), key)
		})
	}

	refused := []struct{ name, secret string }{
		{"interior spaces", "GEZD GNBV GY3T QOJQ"},
		{"a character outside the alphabet", "GEZDGNBVGY3TQOJ1"},
		{"punctuation", "INVALID!SECRET!!"},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			_, err := decodeSecret(c.secret)
			assert.Error(t, err)
		})
	}

	// Each of these is valid base32 for the empty key, which every deployment derives the same
	// codes from (#111 decision 9).
	for _, secret := range []string{"", "   ", " \t\n "} {
		t.Run(fmt.Sprintf("no key, from %q", secret), func(t *testing.T) {
			_, err := decodeSecret(secret)
			require.ErrorIs(t, err, errSecretEmpty)
		})
	}
}
