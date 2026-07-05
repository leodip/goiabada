package stringutil

import (
	"crypto/rand"
	"io"
	"log/slog"
	"strconv"
)

// randomStringFromReader returns a length-character string drawn uniformly from
// alphabet, using r as the randomness source. It uses rejection sampling to
// avoid the modulo bias that a bare `b % len(alphabet)` introduces when
// len(alphabet) does not divide 256: any byte at or above the largest multiple
// of n that fits in a byte is discarded, so every accepted byte maps to exactly
// one alphabet index with equal probability. It assumes len(alphabet) <= 256
// (true for all callers here). Returns an error if r fails before enough bytes
// are drawn; returns ("", nil) for length <= 0 or an empty alphabet.
func randomStringFromReader(r io.Reader, length int, alphabet string) (string, error) {
	n := len(alphabet)
	if length <= 0 || n == 0 {
		return "", nil
	}

	// Largest multiple of n representable in a byte. Bytes >= limit are rejected.
	// If n divides 256, limit == 256 and nothing is ever rejected.
	limit := 256 - (256 % n)

	out := make([]byte, length)
	var scratch [1]byte
	for i := 0; i < length; {
		if _, err := io.ReadFull(r, scratch[:]); err != nil {
			return "", err
		}
		b := int(scratch[0])
		if b >= limit {
			continue // reject to keep the distribution uniform
		}
		out[i] = alphabet[b%n]
		i++
	}
	return string(out), nil
}

// randomStringFromAlphabet is the crypto/rand-backed convenience wrapper around
// randomStringFromReader. It preserves the package's historical contract of
// returning "" when the system CSPRNG is unavailable.
func randomStringFromAlphabet(length int, alphabet string) string {
	s, err := randomStringFromReader(rand.Reader, length, alphabet)
	if err != nil {
		return ""
	}
	return s
}

func GenerateSecurityRandomString(length int) string {
	const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_."
	return randomStringFromAlphabet(length, chars)
}

func GenerateRandomLetterString(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	return randomStringFromAlphabet(length, letters)
}

func ConvertToString(v interface{}) string {
	switch val := v.(type) {
	case int:
		return strconv.Itoa(val)
	case bool:
		return strconv.FormatBool(val)
	case string:
		return val
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	default:
		slog.Warn("ConvertToString: unsupported type", "type", val)
		return ""
	}
}

func GenerateRandomNumberString(length int) string {
	const chars = "0123456789"
	return randomStringFromAlphabet(length, chars)
}
