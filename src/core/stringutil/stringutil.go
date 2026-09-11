package stringutil

import (
	"crypto/rand"
	"fmt"
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

// cryptoRandReader is the system CSPRNG presented as an io.Reader that cannot
// fail. crypto/rand.Read has not returned an error since Go 1.24: on a failed
// read it calls the runtime's fatal handler, which no recover can catch, so the
// process is gone before Read could return one.
//
// io.ReadFull(rand.Reader, p) reads the same source and is deliberately not the
// call here. It hands the error back, and randomStringFromAlphabet has no error
// return of its own, so it would have to invent a value; the value it used to
// invent was "", and an empty security token, ceremony id or continuation id is
// exactly what this contract exists to make impossible (#211).
type cryptoRandReader struct{}

func (cryptoRandReader) Read(p []byte) (int, error) {
	_, _ = rand.Read(p) // cannot fail; the process dies first, see above
	return len(p), nil
}

// randomStringFromAlphabet is the crypto/rand-backed convenience wrapper around
// randomStringFromReader. It cannot fail: cryptoRandReader never returns an
// error, so the error randomStringFromReader declares is always nil here and a
// branch on it would be dead code.
func randomStringFromAlphabet(length int, alphabet string) string {
	s, _ := randomStringFromReader(cryptoRandReader{}, length, alphabet)
	return s
}

// GenerateSecurityRandomString returns length characters drawn uniformly from
// [0-9a-zA-Z-_.], the alphabet the ceremony ids, continuation ids and security
// tokens in this repository are minted over.
//
// A CSPRNG failure ends the process rather than this call: it never returns a
// short, empty or non-random string, so callers need no guard against one
// (#211).
func GenerateSecurityRandomString(length int) string {
	const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_."
	return randomStringFromAlphabet(length, chars)
}

// GenerateRandomLetterString returns length characters drawn uniformly from
// [A-Za-z]. Like GenerateSecurityRandomString, a CSPRNG failure ends the
// process rather than this call (#211).
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
		// The type rather than val, which is what this record has always claimed to carry and
		// never did: "type" held the value itself, so an unconvertible value of an unknown
		// type was written into the log under a key naming what it is not (#320 decision 3).
		slog.Warn("unable to convert a value to a string, the type is not supported",
			"type", fmt.Sprintf("%T", v))
		return ""
	}
}

// GenerateRandomNumberString returns length characters drawn uniformly from
// [0-9]. Like GenerateSecurityRandomString, a CSPRNG failure ends the process
// rather than this call (#211).
func GenerateRandomNumberString(length int) string {
	const chars = "0123456789"
	return randomStringFromAlphabet(length, chars)
}
