// Package boundedread holds the one rule this tree applies to a response body it reads from a
// peer: read to one byte past the ceiling, and refuse the whole answer if that byte arrived.
//
// It is a package rather than a helper in one of the callers because the rule is shared across
// packages and modules -- the admin console's apiclient, oauthclient and middleware reading the
// auth server, and the countries generator reading its dataset -- and a rule with a sentinel per
// caller is a rule per caller. A reader arriving at any read site finds the same function and the
// same error, and does not have to work out which convention that site is in (#386 decision 4).
// It lives in core rather than the admin console so the generators read through it too (#432).
//
// The ceiling itself is not here. Each caller's means something different -- the admin API's
// response bound, the session store's wire bound, the token endpoint's, the generator's dataset
// and commit lookup -- and each is declared beside the code that knows why it is that number.
package boundedread

import (
	"errors"
	"io"

	"github.com/leodip/goiabada/core/errs"
)

// ErrResponseTooLarge is returned when a response body exceeds the ceiling it was read under.
//
// The answer is refused rather than cut. Cutting is what this tree did before and it has two
// costs: an oversized answer arrives as a parse failure, indistinguishable from a malformed one,
// and a truncated prefix that happens to be balanced decodes with keys missing and nothing says
// so -- which is what a JWKS document reaching json.NewDecoder through a LimitReader could do.
//
// No caller needs to match on it to behave correctly. Every site already answers a failed read the
// same way it answers a failed parse: the admin console's error classifier falls through to a 500,
// a refresh clears the session and continues, a JWKS fetch leaves the cache as it was, a session
// store call fails without retrying, and the countries generator fails its run. The sentinel is
// what makes the reason readable in a record and assertable in a test.
var ErrResponseTooLarge = errors.New("the response exceeded the maximum size")

// Read reads body under max bytes, refusing an overrun rather than cutting it. One byte past the
// ceiling is read: if that byte arrived the answer is oversized, nothing is returned, and no
// prefix can reach a decoder.
//
// Whatever did arrive is returned alongside a read error, because a caller that treats a failed
// read as a success -- the auth server's key rotation is one -- needs the partial body. Nothing
// is returned on an overrun, so a prefix cannot reach a decoder by that route either.
func Read(body io.Reader, max int64) ([]byte, error) {
	read, err := io.ReadAll(io.LimitReader(body, max+1))
	if int64(len(read)) > max {
		return nil, errs.Wrapf(ErrResponseTooLarge, "the peer answered with more than %d bytes", max)
	}
	if err != nil {
		return read, errs.Errorf("failed to read response body: %w", err)
	}
	return read, nil
}
