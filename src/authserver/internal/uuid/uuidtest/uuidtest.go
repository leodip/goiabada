// Package uuidtest checks, for tests, that an identifier production emits is a
// UUID in the canonical 36-character 8-4-4-4-12 form uuid.New produces. Nothing
// in production parses a UUID: every identifier is minted by uuid.New and then
// carried as a string, so the check belongs to the tests that assert on it.
package uuidtest

import (
	"errors"
	"strings"
)

// The reasons Parse refuses a string. They are matched with errors.Is, so a
// test can assert that a case was refused for the reason it was written for
// rather than merely refused.
var (
	errWrongLength = errors.New("uuidtest: wrong length, want 36 characters")
	errHyphen      = errors.New("uuidtest: hyphen expected at index 8, 13, 18 and 23")
	errNonHex      = errors.New("uuidtest: non-hex character")
)

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
