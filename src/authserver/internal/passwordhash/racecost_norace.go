//go:build !race

package passwordhash

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// The bcrypt cost level this build uses, for the hashes Hash writes and for the dummy hash
// the enumeration-safe sign-in paths compare against (#691). Without the race detector
// there is nothing to speed up, so this file carries today's values: the dummy is the
// cost-10 hash those paths have always compared against, and the cost the gate below
// selects is bcrypt.DefaultCost, so its answer changes nothing. It stays a runtime read
// rather than a constant so both builds run the same Hash.

// DummyHash is a pre-computed bcrypt hash that a refusal compares the typed password against, so
// it costs one comparison as a wrong password does and the response time says nothing about the
// account. Its two callers, the sign-in form (authflow.PasswordSubmission) and the password grant
// (protocolvalidation.TokenValidator), each compare against it in two cases: an address naming no
// account, so the time does not say which emails have accounts; and an account with no password
// yet, whose empty stored hash bcrypt would refuse without doing any work, so the time does not
// say whether its user has set one. Both refuse whatever the comparison says, so its plaintext
// signs no one in (#681).
// The hash was generated using bcrypt.DefaultCost (10) for the string "dummy_password_for_timing_safe_comparison".
const DummyHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// raceBuildHashCost is the cost Hash uses when the gate below reports a run under go test.
const raceBuildHashCost = bcrypt.DefaultCost

// raceBuildTestRun reports whether this build is running under go test. In this build
// either answer selects the values above, which are today's, so neither costs anything.
func raceBuildTestRun() bool {
	return testing.Testing()
}
