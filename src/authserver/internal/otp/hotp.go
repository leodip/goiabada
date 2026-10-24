package otp

import (
	"crypto/hmac"
	//nolint:gosec // G505: RFC 4226 and RFC 6238 fix HMAC-SHA-1 for this profile, and RFC 6194 section 3.3 finds no indication that attacks on SHA-1 extend to HMAC-SHA-1
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// passcodeDigits is the length of a passcode, the six digits of RFC 4226 section 5.3 that every
// authenticator shows.
const passcodeDigits = 6

var (
	errPasscodeLength = errors.New("the passcode is not six characters")
	errSecretBase32   = errors.New("the secret is not base32")
	errSecretEmpty    = errors.New("the secret decodes to no key")
)

// decodeSecret reads a base32 secret into the key its HMAC is keyed with, exactly as pquerna/otp
// read it, in this order: surrounding whitespace trimmed, padded with "=" to a multiple of eight,
// upper-cased, then decoded with the standard alphabet of RFC 4648 section 6. Every secret ever
// stored was read this way, the library's own unpadded ones and those the account API accepted
// before #247, so each keeps its key: a lower-case secret and one with surrounding spaces still
// read, and one with interior spaces still does not.
//
// A secret that decodes to no key, the empty string or whitespace alone, is refused, where the
// library keyed the HMAC with nothing. HOTP happily derives a code from the empty key, and that code
// depends only on the time step, so it is the same everywhere and anyone can compute it (#111
// decision 9). Refusing it here covers every caller at once, including a stored secret that
// decrypts to empty or to whitespace alone.
func decodeSecret(secret string) ([]byte, error) {
	secret = strings.TrimSpace(secret)
	if n := len(secret) % 8; n != 0 {
		secret += strings.Repeat("=", 8-n)
	}
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return nil, errSecretBase32
	}
	if len(key) == 0 {
		return nil, errSecretEmpty
	}
	return key, nil
}

// hotpHMAC is HMAC-SHA-1 over the counter as eight big-endian bytes, RFC 4226 section 5.3 step 1.
func hotpHMAC(key []byte, counter uint64) []byte {
	mac := hmac.New(sha1.New, key)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac.Write(message[:])
	return mac.Sum(nil)
}

// dynamicTruncation is RFC 4226 section 5.3 step 2: the low four bits of the last byte choose an
// offset, and the four bytes there, with the top bit cleared, are the 31-bit value the code is
// read from.
func dynamicTruncation(sum []byte) uint32 {
	offset := sum[len(sum)-1] & 0x0f
	return binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
}

// hotpCode is the six-digit HOTP value for a counter, RFC 4226 section 5.3 step 3, zero-padded.
// TOTP is this over the time step (RFC 6238 section 4).
func hotpCode(key []byte, counter uint64) string {
	return fmt.Sprintf("%06d", dynamicTruncation(hotpHMAC(key, counter))%1_000_000)
}

// passcodeMatches reports whether a passcode is the code a secret gives at a counter. The passcode
// is trimmed and must then be exactly six characters, and the comparison is constant-time, so a
// near miss takes as long as a far one. A wrong length and an unreadable secret are errors, which
// MatchStep turns into the same refusal as a wrong code.
func passcodeMatches(passcode string, counter uint64, secret string) (bool, error) {
	passcode = strings.TrimSpace(passcode)
	if len(passcode) != passcodeDigits {
		return false, errPasscodeLength
	}

	key, err := decodeSecret(secret)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare([]byte(hotpCode(key, counter)), []byte(passcode)) == 1, nil
}
