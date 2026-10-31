// Package otptest computes one-time codes for tests the way an authenticator app does: RFC 6238
// TOTP over HMAC-SHA-1, six digits, a 30-second step from the Unix epoch. It is test support
// beside the package it concerns, compiled into no binary, as hostporttest is (#646 decision 2).
//
// It is a second implementation on purpose and imports nothing from otp, its base32 reading
// included, so a test sending a code checks the production verifier against an answer the
// verifier did not compute, and otp's own tests can use it without an import cycle. Both are
// pinned by the same RFC 4226 and RFC 6238 vectors. A secret or key URL a test needs in the
// server's own shape comes from the production generator, otp.KeyGenerator.GenerateKeyURL and
// then otp.SecretFromKeyURL; NewSecret is for a test that only needs a random one.
package otptest

import (
	"crypto/hmac"
	"crypto/rand"
	//nolint:gosec // G505: RFC 6238's TOTP is HMAC-SHA-1, which is what an authenticator computes
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"
)

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// Code returns the six-digit code an authenticator shows for a base32 secret at an instant. The
// secret is read as leniently as an authenticator reads one, case, "=" padding and whitespace
// anywhere ignored; a character outside the base32 alphabet fails the test.
func Code(t testing.TB, secret string, at time.Time) string {
	t.Helper()

	key := decode(t, secret)

	var counter [8]byte
	//nolint:gosec // G115: a test's instant is after 1970
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30))

	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)

	offset := sum[19] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 | uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1000000)
}

// stepSeconds is RFC 6238's X, the 30-second step Code counts.
const stepSeconds = 30

// stepMargin is how near the end of a step NextStepCode and PreviousStepCode wait for the next
// one to begin. A test sends the code within milliseconds, so two seconds keeps the step it was
// derived against from turning before the server checks it.
const stepMargin = 2 * time.Second

// NextStepCode returns the code an authenticator whose clock runs one step ahead shows now: the
// code of the step after the current one, which the server refuses as a clock running ahead
// (#142). Near the end of a step it first waits for the next step to begin, so the step cannot turn
// before the server checks the code and make it the current step's.
func NextStepCode(t testing.TB, secret string) string {
	t.Helper()

	return Code(t, secret, awayFromStepEnd().Add(stepSeconds*time.Second))
}

// PreviousStepCode returns the code of the step before the current one, the oldest the server
// accepts, so a test that spends it leaves the current step's code unspent above it. Near the end
// of a step it first waits for the next step to begin, since the previous step's code is refused
// from then on.
func PreviousStepCode(t testing.TB, secret string) string {
	t.Helper()

	return Code(t, secret, awayFromStepEnd().Add(-stepSeconds*time.Second))
}

// awayFromStepEnd returns the current instant, first waiting for the next step to begin when fewer
// than stepMargin of this one are left.
func awayFromStepEnd() time.Time {
	now := time.Now()
	left := stepSeconds*time.Second - time.Duration(now.UnixNano()%int64(stepSeconds*time.Second))
	if left < stepMargin {
		time.Sleep(left)
		now = time.Now()
	}
	return now
}

// NewSecret returns a random secret in the shape the server mints: 20 bytes from crypto/rand,
// written as unpadded base32.
func NewSecret(t testing.TB) string {
	t.Helper()

	key := make([]byte, 20)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("otptest: %v", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
}

// decode reads base32 five bits at a time, as the browser suite's TOTP helper does, dropping the
// trailing bits that make up no whole byte.
func decode(t testing.TB, secret string) []byte {
	t.Helper()

	var key []byte
	var bits uint32
	var held uint
	for _, r := range strings.ToUpper(secret) {
		if r == '=' || r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		value := strings.IndexRune(base32Alphabet, r)
		if value < 0 {
			t.Fatalf("otptest: %q in the secret is not base32", r)
		}
		//nolint:gosec // G115: an index into a 32-character alphabet
		bits = bits<<5 | uint32(value)
		held += 5
		if held >= 8 {
			held -= 8
			//nolint:gosec // G115: bits holds at most 12, so shifted down by held it is one byte
			key = append(key, byte(bits>>held))
			bits &= 1<<held - 1
		}
	}
	return key
}
