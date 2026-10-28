//go:build !race

package passwordhash

import (
	"flag"

	"golang.org/x/crypto/bcrypt"
)

// The bcrypt cost level this build uses, for the hashes Hash writes and for the dummy hash
// the enumeration-safe sign-in paths compare against (#691). Without the race detector
// there is nothing to speed up, so this file carries today's values: the dummy the gate below
// selects is the cost-10 hash those paths have always compared against, and the cost it
// selects is bcrypt.DefaultCost, so its answer changes nothing. It stays a runtime read
// rather than a constant so both builds run the same Hash and DummyHash.

// raceBuildDummyHash is the dummy DummyHash returns when the gate below reports a run under
// go test: in this build, today's.
const raceBuildDummyHash = defaultDummyHash

// raceBuildHashCost is the cost Hash uses when the gate below reports a run under go test.
const raceBuildHashCost = bcrypt.DefaultCost

// raceBuildTestRun reports whether this build is running under go test. The test runner
// registers the flags it owns on the default flag set before any test runs, so finding one
// tells it without importing the test framework itself, which the refused-package table
// keeps out of a shipped binary (#331, #462). In this build either answer selects the
// values above, which are today's, so neither costs anything.
func raceBuildTestRun() bool {
	return flag.Lookup("test.v") != nil
}
