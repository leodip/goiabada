// Package randomstring holds the two non-security random-string helpers this server mints
// human-transcribable values over: the letter half and the digit half of an email verification
// code.
//
// It is not in core because only the auth server issues one; the admin console draws no random
// string of either kind. The rejection sampling itself stays shared, in core/stringutil, because
// core/stringutil.GenerateSecurityRandomString is built on the same primitive and both processes
// link that (#385).
//
// Non-security is the distinction that matters here rather than a weaker source: both draw from
// the same CSPRNG through the same uniform sampler. What differs is the alphabet, chosen so a
// person can read the value off a screen and type it into another one, which is why neither is
// the thing to reach for when minting a token, a ceremony id or a continuation id.
package randomstring

import "github.com/leodip/goiabada/core/stringutil"

// Letters returns length characters drawn uniformly from [A-Za-z]. A CSPRNG failure ends the
// process rather than this call (#211).
func Letters(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	return stringutil.RandomStringFromAlphabet(length, letters)
}

// Digits returns length characters drawn uniformly from [0-9]. A CSPRNG failure ends the process
// rather than this call (#211).
func Digits(length int) string {
	const chars = "0123456789"
	return stringutil.RandomStringFromAlphabet(length, chars)
}
