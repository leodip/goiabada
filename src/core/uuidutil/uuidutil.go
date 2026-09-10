// Package uuidutil supplies the random identifiers this server hands out --
// subjects, session identifiers, JTIs, key identifiers -- and validates ones it
// reads back. It holds two functions, no types, and depends on nothing outside
// the standard library.
//
// The values are RFC 9562 version 4 UUIDs in the canonical 36-character
// 8-4-4-4-12 lowercase form, which is the shape every column, claim, JSON body
// and template in this repository already carries. Callers hold them as
// strings: nothing here takes the bits apart again, and no code path branches
// on a version or a variant.
package uuidutil

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
)

// The reasons Parse refuses a string. They are matched with errors.Is, so a
// test can assert that a case was refused for the reason it was written for
// rather than merely refused.
var (
	errWrongLength = errors.New("uuidutil: wrong length, want 36 characters")
	errHyphen      = errors.New("uuidutil: hyphen expected at index 8, 13, 18 and 23")
	errNonHex      = errors.New("uuidutil: non-hex character")
)

// New returns a fresh RFC 9562 version 4 UUID in the canonical 36-character
// lowercase form. It draws 16 bytes from the system CSPRNG per call, so two
// calls colliding has probability around 2^-122.
//
// It cannot return a zero, short or partly random identifier. crypto/rand.Read
// has not returned an error since Go 1.24: on a failed read it calls the
// runtime's fatal handler, which no recover can catch, so the process is gone
// before New could return anything at all. That is this package's contract, and
// it is the point of the package (#278) -- an identifier stands for a user, a
// session or a key, so it is either drawn from the CSPRNG or not produced.
//
// io.ReadFull(rand.Reader, b) reads the same source and is deliberately not the
// call here. It hands the error back instead, and a caller that has no error
// return of its own must then invent a value; the empty string is the value
// that gets invented, and an empty identifier is exactly what this contract
// exists to make impossible. Changing New to return an error would push that
// choice out to every one of its call sites.
func New() string {
	var b [16]byte
	_, _ = rand.Read(b[:])      // cannot fail; see the contract above
	b[6] = (b[6] & 0x0f) | 0x40 // version 4, RFC 9562 section 4.2
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10x, RFC 9562 section 4.1

	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}

// Parse checks that s is a UUID in the canonical 36-character 8-4-4-4-12 form
// and returns it lowercased. Hex digits of either case are accepted. The
// version and variant nibbles are not inspected, so the nil UUID and a UUID of
// any version parse.
//
// The braced "{...}", "urn:uuid:..." and unhyphenated 32-hex spellings are
// legal UUIDs that other parsers accept, and this one refuses them on purpose:
// nothing in this repository produces or receives them, so accepting them would
// widen the set of strings that can reach a column or a claim while serving no
// caller (#278). A value that arrives in one of those forms is a value from
// somewhere unexpected, which is worth an error rather than a silent
// normalisation.
func Parse(s string) (string, error) {
	if len(s) != 36 {
		return "", errWrongLength
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return "", errHyphen
			}
		default:
			if !isHexDigit(c) {
				return "", errNonHex
			}
		}
	}
	return strings.ToLower(s), nil
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
