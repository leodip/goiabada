package oidc

import (
	"errors"
	"math"
	"strconv"

	"github.com/leodip/goiabada/core/errs"
)

// ParseMaxAge reads the max_age authorization request parameter of OIDC Core 1.0 section
// 3.1.2.1, "the allowable elapsed time in seconds since the last time the End-User was actively
// authenticated by the OP".
//
// An empty value is absent and answers nil with no error, because RFC 6749 section 3.1 says
// "Parameters sent without a value MUST be treated as if they were omitted from the request".
// Anything else must be ASCII digits and nothing else: a sign, a space, a decimal point or a
// non-ASCII digit is an error, which the authorization endpoint answers with invalid_request
// (RFC 6749 4.1.2.1, "includes an invalid parameter value"). strconv.Atoi, which this replaced,
// accepted "+5" and "-1" and ignored a value it could not parse, so a malformed max_age either
// forced a login nobody asked for or constrained nothing at all.
//
// A digit string beyond int64 is held as math.MaxInt64 rather than refused. The specification
// sets no upper bound, and every such value names an interval longer than any session can live,
// so it constrains nothing either way; refusing it would reject a request the specification
// allows (#243).
func ParseMaxAge(raw string) (*int64, error) {
	if raw == "" {
		return nil, nil
	}

	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return nil, errs.New("max_age is not a non-negative integer")
		}
	}

	maxAge, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		if !errors.Is(err, strconv.ErrRange) {
			return nil, errs.Wrap(err, "unable to parse max_age")
		}
		maxAge = math.MaxInt64
	}
	return &maxAge, nil
}
