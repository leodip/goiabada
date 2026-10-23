package otptest_test

import (
	"encoding/base32"
	"fmt"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The secret of RFC 4226 Appendix D and RFC 6238 Appendix B, the ASCII string
// "12345678901234567890", in base32 as an authenticator is given it.
const rfcKeyBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// Every other tier takes its one-time codes from this package, so it answers to the same RFC
// vectors as the production primitive, transcribed and never computed. RFC 4226's values are
// counter-based, and counter c is the step of the instant 30c seconds after the epoch.
func TestCode_RFC4226AppendixD(t *testing.T) {
	codes := []string{"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489"}

	for count, want := range codes {
		t.Run(fmt.Sprintf("count %d", count), func(t *testing.T) {
			at := time.Unix(int64(count)*30, 0).UTC()
			assert.Equal(t, want, otptest.Code(t, rfcKeyBase32, at))
		})
	}
}

// RFC 6238 Appendix B's six SHA-1 rows, each code the low six of the eight digits the RFC prints.
// The rows include instants inside a step rather than at its start (59, 1111111109), so the
// mapping from time to step is pinned, and one beyond 32 bits of step (20000000000).
func TestCode_RFC6238AppendixB(t *testing.T) {
	vectors := []struct {
		unix    int64
		rfcCode string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, v := range vectors {
		t.Run(fmt.Sprintf("time %d", v.unix), func(t *testing.T) {
			assert.Equal(t, v.rfcCode[2:], otptest.Code(t, rfcKeyBase32, time.Unix(v.unix, 0).UTC()))
		})
	}
}

// An authenticator reads a secret leniently, as the browser suite's helper does: case, padding
// and whitespace do not change the key.
func TestCode_ReadsASecretAsAnAuthenticatorDoes(t *testing.T) {
	at := time.Unix(59, 0).UTC()
	for _, secret := range []string{
		"gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
		" GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ ",
	} {
		assert.Equal(t, "287082", otptest.Code(t, secret, at), "secret %q", secret)
	}

	// "Hello!", whose 10 base32 characters are no multiple of eight, is one key with or without
	// its padding.
	assert.Equal(t, otptest.Code(t, "JBSWY3DPEE", at), otptest.Code(t, "JBSWY3DPEE======", at))
}

// A secret as the server mints one: 20 random bytes, 160 bits as RFC 4226 section 4 recommends,
// written as unpadded base32.
func TestNewSecret(t *testing.T) {
	secret := otptest.NewSecret(t)

	assert.Len(t, secret, 32)
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)
	assert.Len(t, key, 20)

	assert.NotEqual(t, secret, otptest.NewSecret(t), "two secrets must differ")
}
