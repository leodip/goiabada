package ceremony

import (
	"crypto/subtle"
	"net/http"
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

// IdField is the name of the hidden form field naming a ceremony on every form a step renders, and
// RequestedId reads a POST's ceremony from it alone. It is duplicated in the auth-flow templates,
// because a template cannot read a Go constant. A rename in one place alone renders a form whose
// every submission is refused, which the integration cases catch: they read the field out of the
// rendered page rather than building the form.
const IdField = "ceremonyId"

// RequestedId is the ceremony id a request names, and the one rule for which ceremony that is: the
// form's field (IdField) on a POST, and the URL's parameter (QueryParameter) on anything else. The
// step boundary loads the ceremony a step acts on through it, and the one-time-code rate limit counts
// against the user of that same ceremony through it, so the budget a submission spends always belongs
// to the user whose code the step checks.
//
// A POST reads its body alone, with r.PostFormValue and not r.FormValue: the step forms post to
// action="", so r.Form would let /auth/pwd?ceremonyId=... supply the id, and only the submitted body
// is a submission. The URL's parameter is named differently on purpose, so even a query naming the
// field can never satisfy a POST, and on a POST the query is not read at all, so the id in the URL of
// a stale form's page cannot stand in for the one the form carries (#79, #437).
func RequestedId(r *http.Request) string {
	if r.Method == http.MethodPost {
		return r.PostFormValue(IdField)
	}
	return r.URL.Query().Get(QueryParameter)
}

// idMatches reports whether a stored ceremony is the one a request names. An empty stored id is
// refused rather than matched against an empty name: "" equal to "" would accept a request naming no
// ceremony at all, which is every forged form (#79).
//
// Constant time, like accounthandlers' emailedCodeMatches and the client secret comparison in
// protocolvalidation.ValidateTokenRequest. Not because this value is guessed at, but because a plain
// comparison stopping at the first differing byte is the kind of thing that is cheap to avoid and
// expensive to notice later.
func idMatches(storedId string, namedId string) bool {
	if storedId == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(storedId), []byte(namedId)) == 1
}

// NewId draws a ceremony's id. Only authflow.Authorization.Run calls it, because that is the one
// place an auth context is created.
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
