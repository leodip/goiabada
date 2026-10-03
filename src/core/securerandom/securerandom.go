// Package securerandom draws strings from the system CSPRNG: String over the alphabet the
// ceremony ids, continuation ids, client secrets and security tokens in this repository are
// minted over, and StringFromAlphabet over one the caller names. Every character is drawn
// uniformly, by rejection sampling, so an alphabet whose length does not divide 256 introduces no
// modulo bias (#85).
//
// Neither returns an error, and neither can return a short, empty or non-random string: a CSPRNG
// failure ends the process rather than the call (#211).
package securerandom

import (
	"crypto/rand"
	"io"
)

// randomStringFromReader returns a length-character string drawn uniformly from
// alphabet, using r as the randomness source. It uses rejection sampling to
// avoid the modulo bias that a bare `b % len(alphabet)` introduces when
// len(alphabet) does not divide 256: any byte at or above the largest multiple
// of n that fits in a byte is discarded, so every accepted byte maps to exactly
// one alphabet index with equal probability. It assumes len(alphabet) <= 256,
// which StringFromAlphabet enforces. Returns an error if r fails before enough
// bytes are drawn; returns ("", nil) for length <= 0 or an empty alphabet.
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
// call here. It hands the error back, and StringFromAlphabet has no error return
// of its own, so it would have to invent a value; the value it used to invent was
// "", and an empty security token, ceremony id or continuation id is exactly what
// this contract exists to make impossible (#211).
type cryptoRandReader struct{}

func (cryptoRandReader) Read(p []byte) (int, error) {
	_, _ = rand.Read(p) // cannot fail; the process dies first, see above
	return len(p), nil
}

// String returns length characters drawn uniformly from [0-9a-zA-Z-_.], the alphabet the
// ceremony ids, continuation ids and security tokens in this repository are minted over.
//
// A CSPRNG failure ends the process rather than this call: it never returns a short, empty or
// non-random string, so callers need no guard against one (#211).
func String(length int) string {
	const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_."
	return StringFromAlphabet(length, chars)
}

// StringFromAlphabet returns length characters drawn uniformly from alphabet, using the system
// CSPRNG. A CSPRNG failure ends the process rather than this call (#211).
//
// The domain is a BYTE alphabet of 1 to 256 bytes, indexed by byte, in which a multi-byte rune is
// not a unit. Outside it the answer is "": a non-positive length, an empty alphabet, or an
// alphabet above 256 bytes. That last bound is enforced here and merely assumed by the sampler:
// the rejection limit is 256 - (256 % n), zero once n exceeds 256, so every byte is rejected and
// the draw never returns (#385).
//
// The error randomStringFromReader declares is always nil here, because cryptoRandReader never
// returns one, so a branch on it would be dead code.
func StringFromAlphabet(length int, alphabet string) string {
	if len(alphabet) > 256 {
		return ""
	}
	s, _ := randomStringFromReader(cryptoRandReader{}, length, alphabet)
	return s
}
