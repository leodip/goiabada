package ceremony

import (
	"strings"

	"github.com/leodip/goiabada/core/securerandom"
)

// IdLength is the length of a ceremony id. It matches the length of the continuation id emaillinks
// issues, and for the same reason that package's own comment gives: over a 65-character alphabet
// this is far more entropy than the value needs. Nobody outside the session ever sees it and it
// authorizes nothing on its own.
const IdLength = 32

// idAlphabet is what NewId draws from and IsWellFormedId accepts. It is securerandom.String's
// alphabet, and every character of it is an RFC 3986 unreserved one, so an id needs no escaping in
// the query it travels in.
const idAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_."

// QueryParameter is the name a ceremony's id travels under in the URL of every step of it (#246,
// #437). It is not the form field's name, which is ceremonyId, on purpose: a POST reads the id from
// its body alone, and a query that could never be spelled as the field can never satisfy that check.
// Both names are duplicated in the templates that carry them, because a template cannot read a Go
// constant.
const QueryParameter = "ceremony"

// NewId draws a ceremony's id. Only HandleAuthorizeGet calls it, because that is the one place an
// auth context is created.
func NewId() string {
	return securerandom.StringFromAlphabet(IdLength, idAlphabet)
}

// IsWellFormedId reports whether id has the length and the alphabet NewId produces. It is the shape
// check for an id that arrives from outside the session and is only ever echoed back into a link,
// as the registration page does with the one its "Register" link carried: a value of any other shape
// is dropped rather than repeated into a page (#246, #437). It says nothing about whether the id
// names a ceremony that exists.
func IsWellFormedId(id string) bool {
	if len(id) != IdLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !strings.ContainsRune(idAlphabet, rune(id[i])) {
			return false
		}
	}
	return true
}
